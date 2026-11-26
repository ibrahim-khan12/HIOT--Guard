"""Run paired direct and two-hop captures on owned GNS3 links."""
import argparse
import base64
import contextlib
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from gns3 import GNS3, request_json


LINKS = {
    'upstream': (('actor', 0), ('middle', 0)),
    'downstream': (('middle', 1), ('sink', 0)),
    'direct': (('actor', 2), ('sink', 1)),
    'setup': (('actor', 1), ('nat', 0)),
}


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


class Experiment:
    def __init__(self, server, folder, create=False):
        self.lab = GNS3(server, folder)
        self.folder = folder
        self.path = folder / 'manifest.json'
        if create:
            folder.mkdir(parents=True, exist_ok=False)
            project = self.lab.api('/projects', {'name': 'Module 4 forwarding controls ' + folder.name, 'auto_close': False})
            self.data = {'server': server, 'project_id': project['project_id'], 'token': secrets.token_hex(24),
                         'nodes': {}, 'links': {}, 'purpose': 'development_only'}
            self.save()
        else:
            self.data = json.loads(self.path.read_text(encoding='utf-8'))
            if self.data['server'] != server:
                raise ValueError('Server differs from the saved manifest')
        self.project = '/projects/' + self.data['project_id']

    def save(self):
        write(self.path, self.data)

    def api(self, path, data=None):
        return self.lab.api(self.project + path, data, timeout=60)

    def worker(self, role, path='/state', data=None):
        node = self.api('/nodes/' + self.data['nodes'][role])
        server = urlsplit(self.data['server'])
        return request_json(f'http://{server.hostname}:{node["console"]}{path}', data,
                            {'Authorization': 'Bearer ' + self.data['token']}, timeout=10)

    def install_bundle(self, path):
        node = self.api('/nodes/' + self.data['nodes']['actor'])
        server = urlsplit(self.data['server'])
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            stream.seek(0)
            request = Request(f'http://{server.hostname}:{node["console"]}/offline-bundle', data=stream, method='POST',
                              headers={'Authorization': 'Bearer ' + self.data['token'], 'X-Bundle-SHA256': digest,
                                       'Content-Length': str(path.stat().st_size), 'Content-Type': 'application/x-tar'})
            with urlopen(request, timeout=180) as response:
                response.read()
        self.data['offline_bundle_sha256'] = digest
        self.save()

    def setup(self, refresh=False):
        directory = Path(__file__).resolve().parent
        sources = {name: (directory / (name + '.py')).read_bytes() for name in ('pilot_worker', 'forwarding_worker')}
        if refresh:
            history = self.data.setdefault('previous_source_sha256', [])
            history.append(self.data['source_sha256'])
        self.data['source_sha256'] = {name: hashlib.sha256(body).hexdigest() for name, body in sources.items()}
        encoded = {name: base64.b64encode(body).decode() for name, body in sources.items()}
        bootstrap = ("import base64,sys,types; m=types.ModuleType('pilot_worker'); sys.modules[m.__name__]=m; "
                     f"exec(base64.b64decode('{encoded['pilot_worker']}'),m.__dict__); "
                     f"exec(base64.b64decode('{encoded['forwarding_worker']}'))")
        nat = next(i['ip_address'] for i in self.lab.api('/compute/network/interfaces') if i['id'] == 'virbr0')
        for role, adapters in (('actor', 3), ('middle', 2), ('sink', 2)):
            environment = {'PILOT_ROLE': role, 'PILOT_TOKEN': self.data['token'], 'PILOT_NAT': nat,
                           'FORWARDING_SOURCE_SHA256': self.data['source_sha256']['forwarding_worker']}
            properties = {'image': 'iomt-hospital:2', 'adapters': adapters, 'console_http_port': 8080,
                          'start_command': 'python -u -c "' + bootstrap + '"',
                          'environment': '\n'.join(k + '=' + v for k, v in environment.items())}
            if refresh:
                endpoint = '/nodes/' + self.data['nodes'][role]
                self.api(endpoint + '/stop', {})
                request = Request(self.data['server'] + '/v2' + self.project + endpoint, method='PUT',
                                  data=json.dumps({'properties': properties}).encode(),
                                  headers={'Content-Type': 'application/json', **self.lab.headers})
                with urlopen(request, timeout=30) as response:
                    response.read()
                continue
            node = self.api('/nodes', {'compute_id': 'local', 'name': 'forwarding-' + role, 'node_type': 'docker',
                                       'console_type': 'http', 'properties': properties})
            self.data['nodes'][role] = node['node_id']
            self.save()
        if not refresh:
            self.data['nodes']['nat'] = self.api('/nodes', {'compute_id': 'local', 'name': 'forwarding-setup-nat', 'node_type': 'nat'})['node_id']
            self.save()
            for name, endpoints in LINKS.items():
                link = self.api('/links', {'nodes': [{'node_id': self.data['nodes'][role], 'adapter_number': adapter, 'port_number': 0}
                                                     for role, adapter in endpoints]})
                self.data['links'][name] = link['link_id']
                self.save()
        for role in ('sink', 'middle', 'actor'):
            self.api('/nodes/' + self.data['nodes'][role] + '/start', {})
            for attempt in range(25):
                try:
                    self.worker(role)
                    break
                except (OSError, RuntimeError, http.client.HTTPException):
                    if attempt == 24:
                        raise
                    time.sleep(1)
            self.worker(role, '/setup', {})
        self.save()
        print('Isolated topology started.', flush=True)

    def ready(self, stack='A', bundle=None):
        deadline = time.monotonic() + 780
        requested = False
        while time.monotonic() < deadline:
            states = {role: self.worker(role) for role in ('actor', 'middle', 'sink')}
            for role, state in states.items():
                if state.get('error') and (role != 'actor' or requested or not state['ready']):
                    raise RuntimeError(f'{role}: {state["error"]}')
                if state['worker_sha256'] != self.data['source_sha256']['forwarding_worker']:
                    raise ValueError('Worker source hash mismatch')
            if all(state['ready'] and not state['busy'] for state in states.values()):
                if stack == 'B' and not states['actor'].get('stack_b_ready'):
                    if bundle is None:
                        raise ValueError('Stack B needs --offline-bundle produced by prepare_stack_b_bundle.py')
                    self.install_bundle(bundle)
                    requested = True
                    print('Installing the verified bundle with the setup interface disabled.', flush=True)
                    time.sleep(2)
                    continue
                write(self.folder / 'toolchain.json', {role: state.get('versions', {}) for role, state in states.items()})
                return
            print('Setup status', {role: state['ready'] for role, state in states.items()}, flush=True)
            time.sleep(15)
        raise TimeoutError('Actor setup did not complete')

    def capture(self, stack, mode, repeat):
        session = f'{stack}-{repeat:02d}-{mode}'
        parent = self.folder / 'specificity' if mode == 'specificity' else self.folder
        output = parent / session
        completed = output / 'session.json'
        if completed.exists():
            return
        output.mkdir(parents=True, exist_ok=True)
        names = ('upstream', 'downstream') if mode == 'forwarded' else ('direct',)
        filenames = {link: f'{session}-{link}-{secrets.token_hex(4)}.pcap' for link in names}
        started = time.time()
        with contextlib.ExitStack() as captures:
            for link, filename in filenames.items():
                endpoint = '/links/' + self.data['links'][link]
                self.api(endpoint + '/start_capture', {'capture_file_name': filename, 'data_link_type': 'DLT_EN10MB'})
                captures.callback(self.api, endpoint + '/stop_capture', {})
            self.worker('actor', f'/run/{stack}/{mode}', {})
            deadline = time.monotonic() + 180
            while True:
                state = self.worker('actor')
                if not state['busy']:
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError(session + ' timed out')
                time.sleep(1)
        if state.get('error'):
            raise RuntimeError(session + ': ' + state['error'])
        metadata = {}
        for name, filename in filenames.items():
            url = self.data['server'] + '/v2' + self.project + '/files/project-files/captures/' + filename
            with urlopen(Request(url, headers=self.lab.headers), timeout=60) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
            if not 24 < len(raw) <= 32 * 1024 * 1024:
                raise ValueError(f'Invalid capture size for {session}/{name}')
            (output / (name + '.pcap')).write_bytes(raw)
            metadata[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        write(completed, {'stack': stack, 'mode': mode, 'repeat': repeat, 'seconds': time.time() - started,
                          'captures': metadata, 'receipts': state['receipts'], 'source_sha256': self.data['source_sha256'],
                          'purpose': 'development_only'})
        print(session, {n: d['bytes'] for n, d in metadata.items()}, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'refresh', 'record', 'controls', 'close'))
    parser.add_argument('--server', default='http://192.168.209.142')
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--repeats', type=int, choices=range(1, 6), default=2)
    parser.add_argument('--stack', choices=('A', 'B', 'both'), default='both')
    parser.add_argument('--offline-bundle', type=Path)
    args = parser.parse_args()
    lab = Experiment(args.server, args.folder, create=args.action == 'setup')
    if args.action in ('setup', 'refresh'):
        lab.setup(refresh=args.action == 'refresh')
    elif args.action == 'close':
        lab.api('/close', {})
    elif args.action == 'controls':
        lab.ready()
        for repeat in range(1, args.repeats + 1):
            lab.capture('A', 'specificity', repeat)
    else:
        for stack in ('A', 'B') if args.stack == 'both' else (args.stack,):
            lab.ready(stack, args.offline_bundle)
            for repeat in range(1, args.repeats + 1):
                for mode in ('direct', 'forwarded'):
                    lab.capture(stack, mode, repeat)


if __name__ == '__main__':
    main()
