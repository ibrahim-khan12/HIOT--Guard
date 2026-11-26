"""Record split-local batches with fresh logical sessions in isolated GNS3 projects."""
import argparse
import base64
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import time
import traceback
from urllib.error import URLError
from urllib.request import Request, urlopen

from run_forwarding_pilot import Experiment, LINKS
from final_corpus_profiles import ALLOCATION, WINDOWS, endpoints, sessions
from module2.pcap import complete_pcap

TOOLS = Path(__file__).resolve().parent
LINK_NAMES = ('upstream', 'downstream', 'direct')
NODES = ('actor', 'middle', 'sink')
GROUPS = defaultdict(list)
for session in sessions():
    GROUPS[session['capture_group']].append(session)


def read_with_retry(operation, name):
    """Retry read-only operations when the VM console proxy drops a response."""
    for attempt in range(6):
        try:
            return operation()
        except (OSError, URLError, http.client.HTTPException) as error:
            if attempt == 5:
                raise RuntimeError(f'Could not read {name} after six attempts') from error
            print(f'{name}: retrying interrupted read ({type(error).__name__})', flush=True)
            time.sleep(1 + attempt)


def run_worker_operation(lab, role, path, reached):
    # Check state after an interrupted response before repeating an operation.
    for attempt in range(6):
        try:
            return lab.worker(role, path, {})
        except (OSError, http.client.HTTPException) as error:
            state = read_with_retry(lambda: lab.worker(role), f'{role} state after interrupted {path}')
            if state.get('error'):
                raise RuntimeError(f'{role}: {state["error"]}') from error
            if state['busy'] or reached(state):
                return
            if attempt == 5:
                raise
            print(f'{role}: operation {path} was not observed, retrying', flush=True)
            time.sleep(1 + attempt)


def write(path, value):
    pending = path.with_suffix('.tmp')
    pending.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    pending.replace(path)


def fingerprint(sources):
    return {name: hashlib.sha256(body).hexdigest() for name, body in sources.items()}


def get_sources():
    return {name: (TOOLS / (name + '.py')).read_bytes() for name in (
        'pilot_worker', 'forwarding_worker', 'final_corpus_profiles', 'final_corpus_worker')}


def setup(server, folder, sources):
    lab = Experiment(server, folder, create=True)
    lab.data['source_sha256'] = fingerprint(sources)
    transport = (TOOLS / 'final_corpus_console.py').read_bytes()
    lab.data['console_sha256'] = hashlib.sha256(transport).hexdigest()
    encoded = {name: base64.b64encode(body).decode() for name, body in sources.items()}
    code = ['import base64,sys,types']
    for name in tuple(sources)[:-1]:
        code += [f"m=types.ModuleType('{name}')", 'sys.modules[m.__name__]=m',
                 f"exec(base64.b64decode('{encoded[name]}'),m.__dict__)"]
    console = base64.b64encode(transport).decode()
    code += [f"exec(base64.b64decode('{console}'))", f"exec(base64.b64decode('{encoded['final_corpus_worker']}'))"]
    try:
        for role, adapters in (('actor', 3), ('middle', 2), ('sink', 2)):
            env = {'PILOT_ROLE': role, 'PILOT_TOKEN': lab.data['token'],
                   'FORWARDING_SOURCE_SHA256': lab.data['source_sha256']['forwarding_worker']}
            node = lab.api('/nodes', {'compute_id': 'local', 'name': 'evaluation-' + role,
                           'node_type': 'docker', 'console_type': 'http',
                           'properties': {'image': 'iomt-hospital:2', 'adapters': adapters,
                                          'console_http_port': 8080,
                                          'start_command': 'python -u -c "' + '; '.join(code) + '"',
                                          'environment': '\n'.join(k + '=' + v for k, v in env.items())}})
            lab.data['nodes'][role] = node['node_id']
            lab.save()
        for link_name in LINK_NAMES:
            link = lab.api('/links', {'nodes': [{'node_id': lab.data['nodes'][role], 'adapter_number': adapter,
                                                 'port_number': 0} for role, adapter in LINKS[link_name]]})
            lab.data['links'][link_name] = link['link_id']
            lab.save()
        for role in ('sink', 'middle', 'actor'):
            lab.api('/nodes/' + lab.data['nodes'][role] + '/start', {})
        for role in NODES:
            for attempt in range(25):
                try:
                    lab.worker(role)
                    break
                except (OSError, RuntimeError, http.client.HTTPException):
                    if attempt == 24:
                        raise
                    time.sleep(1)
            run_worker_operation(lab, role, '/setup', lambda state: state['ready'])
        wait_ready(lab, NODES, lambda states: all(state['ready'] for state in states.values()), timeout=90)
    except Exception:
        lab.api('/close', {})
        raise
    return lab


def wait_ready(lab, roles, done, timeout):
    deadline = time.monotonic() + timeout
    while True:
        states = {role: read_with_retry(lambda: lab.worker(role), f'{lab.folder.name}/{role} state') for role in roles}
        for role, state in states.items():
            if state.get('error'):
                raise RuntimeError(f'{lab.folder.name}/{role}: {state["error"]}')
        if all(not state['busy'] for state in states.values()) and done(states):
            return states
        if time.monotonic() > deadline:
            raise TimeoutError(f'Worker operation exceeded {timeout}s in {lab.folder.name}')
        time.sleep(2)


def record(x, group, output):
    folder = output / 'batches' / group
    folder.mkdir(parents=True, exist_ok=True)
    if (folder / 'manifest.json').exists():
        return
    for role in ('sink', 'middle', 'actor'):
        run_worker_operation(x, role, '/configure/' + group, lambda state: state.get('batch') == group)
    states = wait_ready(x, NODES, lambda values: all(state['batch'] == group for state in values.values()), timeout=90)
    expected_sessions = {item['session_id'] for item in GROUPS[group]}

    def complete(state):
        return set(state['receipt_ids']) == expected_sessions and len(state['receipt_ids']) == len(expected_sessions)

    files = {link: f'{group}-{link}-{secrets.token_hex(4)}.pcap' for link in LINK_NAMES}
    start = time.monotonic()
    with ExitStack() as captures:
        for link, file in files.items():
            ep = '/links/' + x.data['links'][link]
            x.api(ep + '/start_capture', {'capture_file_name': file, 'data_link_type': 'DLT_EN10MB'})
            captures.callback(x.api, ep + '/stop_capture', {})
        print(f'{group}: recording {len(GROUPS[group])} logical sessions across three captured links', flush=True)
        run_worker_operation(x, 'actor', '/emit/' + group, complete)
        result = wait_ready(x, ('actor',), lambda values: complete(values['actor']), timeout=230)
    duration = time.monotonic() - start
    receipts = [read_with_retry(lambda: x.worker('actor', '/receipt/' + session), f'{group}/{session} receipt')
                for session in result['actor']['receipt_ids']]
    captures = {}
    for link, file in files.items():
        url = x.data['server'] + '/v2' + x.project + '/files/project-files/captures/' + file
        def download():
            with urlopen(Request(url, headers=x.lab.headers), timeout=60) as response:
                return response.read(32 * 1024 * 1024 + 1)

        raw = read_with_retry(download, f'{group}/{link} capture')
        if not 24 < len(raw) <= 32 * 1024 * 1024:
            raise ValueError(f'Invalid capture size for {group}/{link}')
        _, facts = complete_pcap(raw)
        (folder / (link + '.pcap')).write_bytes(raw)
        captures[link] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'frames': facts['frames']}
    write(folder / 'manifest.json', {'capture_group': group, 'captures': captures, 'capture_seconds': duration,
                                    'sessions': [{**s, 'endpoints': list(endpoints(s))} for s in GROUPS[group]],
                                    'receipts': receipts, 'toolchain': states['actor']['versions'],
                                    'source_sha256': x.data['source_sha256'], 'console_sha256': x.data['console_sha256']})
    print(f'{group}: saved {sum(item["frames"] for item in captures.values())} frames in {duration:.1f}s', flush=True)


def collect_lane(server, output, lane, groups, sources, bundle):
    if all((output / 'batches' / group / 'manifest.json').exists() for group in groups):
        return
    folder = output / 'projects' / (lane + '-' + secrets.token_hex(4))
    lab = setup(server, folder, sources)
    try:
        if GROUPS[groups[0]][0]['stack'] == 'B':
            lab.install_bundle(bundle)
            wait_ready(lab, ('actor',), lambda values: values['actor'].get('stack_b_ready', False), timeout=550)
        for group in groups:
            record(lab, group, output)
    finally:
        lab.api('/close', {})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--server', default='http://192.168.209.142')
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--lane', choices=('training', 'dev-and-familiar', 'transfer'), action='append')
    args = parser.parse_args()
    sources = get_sources()
    args.output.mkdir(parents=True, exist_ok=True)
    plan = {'allocation': {split: list(spec) for split, spec in ALLOCATION.items()}, 'windows': list(WINDOWS),
            'group_size': 10, 'sessions': list(sessions()), 'source_sha256': fingerprint(sources),
            'design': 'independent logical endpoint/address/seed runs on shared synthetic workers; batch-grouped captures'}
    path = args.output / 'corpus-plan.json'
    if path.exists() and json.loads(path.read_text(encoding='utf-8')) != plan:
        raise ValueError('Collection code or allocation changed since the corpus plan was frozen')
    if not path.exists():
        write(path, plan)
    lanes = {'training': [f'train-{i:02}' for i in range(1, 5)],
             'dev-and-familiar': ['calibration-01', 'validation-01', 'familiar-01'],
             'transfer': ['transfer-01', 'transfer-02']}
    choices = args.lane or tuple(lanes)
    with ThreadPoolExecutor(max_workers=len(choices)) as workers:
        futures = [workers.submit(collect_lane, args.server, args.output, lane, lanes[lane], sources, args.bundle)
                   for lane in choices]
        errors = []
        for future in futures:
            try:
                future.result()
            except Exception as error:
                errors.append(str(error))
                traceback.print_exception(error)
    if errors:
        raise SystemExit('\n'.join(errors))


if __name__ == '__main__':
    main()
