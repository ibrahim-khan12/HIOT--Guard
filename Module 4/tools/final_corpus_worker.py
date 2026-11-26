"""Fixed benign GNS3 services and emitters for the fresh synthetic evaluation."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import random
import socket
import socketserver
import subprocess
import threading
import time
import uuid

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian
from pynetdicom import AE, evt

import pilot_worker as pilot
import forwarding_worker as forward
from final_corpus_profiles import DICOM, HL7, SOURCE_ROLES, address, sessions, topology

LINKS = {'actor': {'upstream': 'eth0', 'direct': 'eth2'},
         'middle': {'upstream': 'eth0', 'downstream': 'eth1'},
         'sink': {'downstream': 'eth0', 'direct': 'eth1'}}
SERVICES = []
ASSIGNED = []
BATCHES = {}
for session in sessions():
    BATCHES.setdefault(session['capture_group'], []).append(session)


def run_ip(commands):
    subprocess.run(['ip', '-batch', '-'], text=True, input='\n'.join(commands) + '\n',
                   check=True, capture_output=True, timeout=30)


def serve_hl7(local, upstream_source=None, receiver=None):
    def deliver(incoming, response_socket, outgoing=None):
        while message := forward.mllp_read(incoming):
            if outgoing:
                outgoing.sock.sendall(message)
                reply = forward.mllp_read(outgoing)
                if not reply:
                    raise ValueError('No reply from downstream EHR')
            else:
                control = message.split(b'\r', 1)[0].split(b'|')[9]
                reply = (b'\x0bMSH|^~\\&|S||R||20261126000000||ACK|ACK|P|2.5\rMSA|AA|'
                         + control + b'\r' + forward.HL7_END)
            response_socket.sendall(reply)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            messages = forward.MessageStream(self.request)
            if receiver is None:
                deliver(messages, self.request)
            else:
                with socket.create_connection((receiver, 2575), timeout=10,
                                              source_address=(upstream_source, 0)) as outgoing:
                    deliver(messages, self.request, forward.MessageStream(outgoing))

    server = forward.MLLPServer((local, 2575), Handler)
    threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True).start()
    SERVICES.append(server)


def serve_storage(local, upstream_source=None, receiver=None):
    def receive(event):
        if receiver is None:
            return 0
        dataset = event.dataset
        dataset.file_meta = event.file_meta
        return forward.store(receiver, upstream_source, dataset)

    service = AE(ae_title='PILOT_SCP')
    for uid in {uid for uid, _ in DICOM.values()}:
        service.add_supported_context(uid)
    SERVICES.append(service.start_server((local, 11112), block=False, evt_handlers=[(evt.EVT_C_STORE, receive)]))


def layout(session):
    suffixes, via = topology(session)
    ip = lambda link, role: address(link, session, suffixes[role])
    if pilot.ROLE == 'actor':
        return [(link, ip(link, role)) for role in SOURCE_ROLES for link in (via.get(role, 'direct'),)] + [
            ('upstream', ip('upstream', 'auxiliary')), ('direct', ip('direct', 'end_marker'))]
    if pilot.ROLE == 'middle':
        return [(link, ip(link, role)) for link in ('upstream', 'downstream') for role in ('relay', 'workstation')]
    return [(link, ip(link, role)) for link in ('direct', 'downstream') for role in ('ehr', 'pacs')]


def stop_server(server):
    server.shutdown()
    server.server_close()


def configure(group):
    if SERVICES:
        with ThreadPoolExecutor(max_workers=16) as workers:
            list(workers.map(stop_server, SERVICES))
        SERVICES.clear()
    commands = [f'addr del {ip}/24 dev {adapter}' for ip, adapter in ASSIGNED]
    addresses = [(ip, LINKS[pilot.ROLE][link]) for session in BATCHES[group] for link, ip in layout(session)]
    commands += [f'addr add {ip}/24 dev {adapter}' for ip, adapter in addresses]
    run_ip(commands)
    ASSIGNED[:] = addresses
    for session in BATCHES[group]:
        suffix, _ = topology(session)
        def ip(link, role):
            return address(link, session, suffix[role])
        if pilot.ROLE == 'middle':
            serve_hl7(ip('upstream', 'relay'), ip('downstream', 'relay'), ip('downstream', 'ehr'))
            serve_storage(ip('upstream', 'workstation'), ip('downstream', 'workstation'), ip('downstream', 'pacs'))
        elif pilot.ROLE == 'sink':
            for link in ('direct', 'downstream'):
                serve_hl7(ip(link, 'ehr'))
                serve_storage(ip(link, 'pacs'))
    pilot.STATE['batch'] = group


def send_hl7(stack, source, target, code, namespace, count):
    if stack == 'B':
        library = Path(pilot.STATE['stack_b_path'])
        pilot.command(['java', '-Xms8m', '-Xmx48m', '-cp', str(library) + ':' + str(library / '*'),
                       'PilotHL7', source, '2575', code, namespace, str(count), target], timeout=35)
        return
    with socket.create_connection((target, 2575), timeout=10, source_address=(source, 0)) as sock:
        reply = forward.MessageStream(sock)
        for _ in range(count):
            control = uuid.uuid4().hex
            payload = (f'\x0bMSH|^~\\&|SYNTH||RECV||20261126000000||ORU^R01|{control}|P|2.5\r'
                       f'PID|1||SYNTHETIC\rOBR|1\rOBX|1|NM|{code}^Observation^{namespace}||1|unit|||||F\r')
            sock.sendall(payload.encode() + forward.HL7_END)
            if b'MSA|AA|' + control.encode() + b'\r' not in forward.mllp_read(reply):
                raise RuntimeError('HL7 observation was not accepted')


def send_storage(stack, session, role, source, target, link):
    sop, modality = DICOM[role]
    uid = '2.25.' + str(uuid.uuid4().int)
    if stack == 'A':
        dataset = Dataset()
        dataset.file_meta = FileMetaDataset()
        dataset.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        dataset.SOPClassUID = sop
        dataset.SOPInstanceUID = uid
        dataset.Modality = modality
        dataset.PatientName = 'SYNTHETIC'
        if forward.store(target, source, dataset) != 0:
            raise RuntimeError('Synthetic storage was not accepted')
        return
    # Each session is sequential internally and has its own target route and files.
    dump = pilot.ROOT / (session['session_id'] + '.dump')
    payload = dump.with_suffix('.dcm')
    dump.write_text(f'(0008,0016) UI [{sop}]\n(0008,0018) UI [{uid}]\n(0008,0060) CS [{modality}]\n'
                    '(0010,0010) PN [SYNTHETIC]\n')
    payload.unlink(missing_ok=True)
    pilot.command(['/usr/bin/dump2dcm', str(dump), str(payload)])
    pilot.command(['ip', 'route', 'replace', target + '/32', 'dev', LINKS['actor'][link], 'src', source])
    try:
        pilot.command(['/usr/bin/storescu', '-R', '-to', '5', '-td', '10', target, '11112', str(payload)], timeout=25)
    finally:
        pilot.command(['ip', 'route', 'del', target + '/32', 'dev', LINKS['actor'][link]])


def emit_session(session):
    rng = random.Random(session['seed'] ^ 8265)
    suffix, via = topology(session)
    def ip(link, role):
        return address(link, session, suffix[role])
    stack = session['stack']
    start = time.monotonic()
    receipts = []
    first_finish = None
    rounds = (1, 83) if session['profile'] == 'sparse' else (1, 25, 58, 91)
    for offset in rounds:
        delay = start + offset + rng.random() * 2.5 - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        cases = [(role, role, via.get(role, 'direct')) for role in SOURCE_ROLES]
        cases.extend((role, 'auxiliary', 'upstream') for role in via if via[role] == 'direct')
        rng.shuffle(cases)
        for role, source_role, link in cases:
            target_role = ('relay' if role in HL7 else 'workstation') if link == 'upstream' else (
                'ehr' if role in HL7 else 'pacs')
            source, target = ip(link, source_role), ip(link, target_role)
            stamp = time.time()
            if role in HL7:
                code, namespace = HL7[role]
                if session['profile'] == 'mixed' and role in ('bedside_monitor', 'ecg_monitor') and stack == 'A':
                    forward.send_waveform(source, target)
                else:
                    count = 3 if session['profile'] == 'batched' else (2 if session['profile'] == 'mixed' else 1)
                    send_hl7(stack, source, target, code, namespace, count)
            else:
                send_storage(stack, session, role, source, target, link)
            receipts.append({'source': source, 'target': target, 'start': stamp, 'end': time.time()})
        if first_finish is None:
            first_finish = time.monotonic()
    # A real packet marks the end of each session after all endpoints had a full observation window.
    delay = max(start + 133, first_finish + 121) - time.monotonic()
    if delay > 0:
        time.sleep(delay)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as marker:
        marker.bind((ip('direct', 'end_marker'), 0))
        marker.sendto(b'HIOT-CAPTURE-END', (ip('direct', 'ehr'), 29882))
    return {'session_id': session['session_id'], 'recorded_exchanges': receipts,
            'marker_source': ip('direct', 'end_marker'), 'completed': time.time()}


def emit(group):
    pilot.STATE['receipts'] = []
    with ThreadPoolExecutor(max_workers=10) as workers:
        tasks = [workers.submit(emit_session, session) for session in BATCHES[group]]
        pilot.STATE['receipts'] = [task.result() for task in tasks]


def setup():
    for adapter in LINKS[pilot.ROLE].values():
        forward.interface(adapter, '10.112.0.', ())
    if pilot.ROLE == 'actor' and subprocess.run(['ip', 'link', 'show', 'eth1'], capture_output=True).returncode == 0:
        pilot.command(['ip', 'link', 'set', 'eth1', 'down'])
    pilot.STATE['versions'] = {'python': pilot.command(['python', '--version']).strip()}
    pilot.STATE['ready'] = True


class API(forward.API):
    def handle_pilot_operation(self):
        if pilot.STATE['busy']:
            return self.respond(409, {'error': 'busy'})
        if self.path == '/setup' and not pilot.STATE['ready']:
            pilot.background(setup)
            return self.respond(202, {'accepted': True})
        action, _, group = self.path[1:].partition('/')
        if group in BATCHES and pilot.STATE['ready']:
            if action == 'configure':
                pilot.background(lambda: configure(group))
                return self.respond(202, {'accepted': True})
            if action == 'emit' and pilot.ROLE == 'actor' and pilot.STATE.get('batch') == group:
                if BATCHES[group][0]['stack'] == 'B' and not pilot.STATE.get('stack_b_ready'):
                    return self.respond(409, {'error': 'stack B not ready'})
                pilot.background(lambda: emit(group))
                return self.respond(202, {'accepted': True})
        if self.path == '/offline-bundle':
            return super().handle_pilot_operation()
        return self.respond(400, {'error': 'invalid final corpus operation'})


pilot.ThreadingHTTPServer(('0.0.0.0', 8080), API).serve_forever()
