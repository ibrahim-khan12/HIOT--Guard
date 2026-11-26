"""Synthetic application gateways and senders for the isolated GNS3 experiment."""
import hashlib
import os
from pathlib import Path
import re
import socket
import socketserver
import tarfile
import threading
import time
import uuid

import pilot_worker as pilot
from pydicom.dataset import Dataset
from pynetdicom import AE, evt
from pynetdicom.sop_class import CTImageStorage, DigitalXRayImageStorageForPresentation, ModalityPerformedProcedureStep

COMMAND = pilot.command
UPSTREAM = '10.88.0.'
DOWNSTREAM = '10.89.0.'
DIRECT = '10.90.0.'
MEDICAL = {'pump': 11, 'ct': 12, 'bedside': 13, 'ecg': 14, 'portable_xray': 15, 'fixed_xray': 16}
HL7_END = b'\x1c\r'
MAX_BUNDLE = 256 * 1024 * 1024
POST_LOCK = threading.Lock()


def interface(name, network, suffixes):
    for _ in range(60):
        try:
            COMMAND(['ip', 'link', 'show', name])
            break
        except RuntimeError:
            time.sleep(.25)
    for suffix in suffixes:
        COMMAND(['ip', 'addr', 'replace', f'{network}{suffix}/24', 'dev', name])
    COMMAND(['ip', 'link', 'set', name, 'up'])


def mllp_read(stream):
    message = stream.read_until(HL7_END, 65536)
    if not message:
        return b''
    if not message.startswith(b'\x0bMSH|') or not message.endswith(HL7_END):
        raise ValueError('Incomplete MLLP message')
    return message


class MessageStream:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b''

    def read_until(self, marker, limit):
        while marker not in self.buffer and len(self.buffer) < limit:
            part = self.sock.recv(min(limit - len(self.buffer), 4096))
            if not part:
                break
            self.buffer += part
        part, sep, remaining = self.buffer.partition(marker)
        self.buffer = remaining
        return part + sep


class MLLPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_hl7(address, relay):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            incoming = MessageStream(self.request)
            if relay:
                with socket.create_connection((DOWNSTREAM + '2', 2575), timeout=10,
                                              source_address=(DOWNSTREAM + '21', 0)) as outgoing:
                    replies = MessageStream(outgoing)
                    while message := mllp_read(incoming):
                        outgoing.sendall(message)
                        reply = mllp_read(replies)
                        if not reply:
                            raise ValueError('Downstream ACK missing')
                        self.request.sendall(reply)
            else:
                while message := mllp_read(incoming):
                    control = message.split(b'\r', 1)[0].split(b'|')[9]
                    reply = b'\x0bMSH|^~\\&|S||R||20261124000000||ACK|ACK|P|2.5\rMSA|AA|'
                    self.request.sendall(reply + control + b'\r' + HL7_END)

    server = MLLPServer((address, 2575), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def store(address, source, dataset):
    ae = AE(ae_title='PILOT_SCU')
    ae.add_requested_context(dataset.SOPClassUID)
    ae.acse_timeout = ae.dimse_timeout = ae.network_timeout = 10
    assoc = ae.associate(address, 11112, bind_address=(source, 0))
    if not assoc.is_established:
        raise RuntimeError('DICOM association failed')
    try:
        response = assoc.send_c_store(dataset)
        return int(response.Status)
    finally:
        assoc.release()


def start_dicom(address, forward):
    def receive(event):
        if not forward:
            return 0
        dataset = event.dataset
        dataset.file_meta = event.file_meta
        try:
            return store(DOWNSTREAM + '2', DOWNSTREAM + '22', dataset)
        except Exception:
            return 0xA700

    ae = AE(ae_title='PILOT_SCP')
    for sop in (CTImageStorage, DigitalXRayImageStorageForPresentation):
        ae.add_supported_context(sop)
    handlers = [(evt.EVT_C_STORE, receive)]
    if address == DIRECT + '2':
        ae.add_supported_context(ModalityPerformedProcedureStep)
        handlers.extend([(evt.EVT_N_CREATE, accept_step), (evt.EVT_N_SET, accept_step)])
    ae.start_server((address, 11112), block=False, evt_handlers=handlers)


def accept_step(event):
    return 0, None


def setup():
    if pilot.ROLE == 'actor':
        interface('eth0', UPSTREAM, MEDICAL.values())
        interface('eth2', DIRECT, MEDICAL.values())
        COMMAND(['ip', 'link', 'set', 'eth1', 'down'])
        pilot.STATE['versions'] = {'python': COMMAND(['python', '--version']).strip()}
    elif pilot.ROLE == 'middle':
        interface('eth0', UPSTREAM, (21, 22))
        interface('eth1', DOWNSTREAM, (21, 22))
        start_hl7(UPSTREAM + '21', relay=True)
        start_dicom(UPSTREAM + '22', forward=True)
    elif pilot.ROLE == 'sink':
        interface('eth0', DOWNSTREAM, (2,))
        interface('eth1', DIRECT, (2,))
        for network in (DOWNSTREAM, DIRECT):
            start_hl7(network + '2', relay=False)
            start_dicom(network + '2', forward=False)
    pilot.STATE['ready'] = True


def prepare_stack_b(archive, digest):
    pilot.JAVA = pilot.JAVA.replace('"10.88.0.2"', 'a[5]')
    if 'a[5]' not in pilot.JAVA:
        raise ValueError('Cannot configure HAPI destination')
    directory = pilot.ROOT / digest
    directory.mkdir(exist_ok=True)
    seen = set()
    size = 0
    with tarfile.open(archive, 'r:') as bundle:
        for member in bundle:
            name = member.name
            size += member.size
            if (not member.isfile() or not re.fullmatch(r'[a-zA-Z0-9._+%~-]+\.(?:deb|jar)', name)
                    or name in seen or size > MAX_BUNDLE or len(seen) >= 128):
                raise ValueError('Invalid archive member')
            seen.add(name)
            with bundle.extractfile(member) as source, (directory / name).open('wb') as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
    packages = sorted(directory.glob('*.deb'))
    jars = sorted(directory.glob('*.jar'))
    if not packages or len(jars) != 5:
        raise ValueError('Bundle must include Debian dependencies and the five HAPI libraries')
    pilot.STATE['setup_phase'] = 'offline_install'
    COMMAND(['env', 'DEBIAN_FRONTEND=noninteractive', 'dpkg', '--unpack', *map(str, packages)], timeout=240)
    COMMAND(['env', 'DEBIAN_FRONTEND=noninteractive', 'dpkg', '--configure', '--pending'], timeout=240)
    if COMMAND(['dpkg', '--audit']).strip():
        raise RuntimeError('Offline package installation left unconfigured Debian packages')
    java_file = directory / 'PilotHL7.java'
    java_file.write_text(pilot.JAVA)
    COMMAND(['javac', '-cp', str(directory / '*'), str(java_file)])
    pilot.STATE['versions'].update({'java': COMMAND(['java', '-version']).strip(),
                                    'dcmtk': COMMAND(['/usr/bin/storescu', '--version']).strip(),
                                    'jars': {jar.name: hashlib.sha256(jar.read_bytes()).hexdigest() for jar in jars},
                                    'offline_bundle_sha256': digest})
    pilot.STATE['stack_b_path'] = str(directory)
    pilot.STATE['stack_b_ready'] = True
    pilot.STATE['setup_phase'] = 'ready'


def send_hl7(stack, source, target, code, namespace):
    if stack == 'B':
        dependencies = Path(pilot.STATE['stack_b_path'])
        COMMAND(['java', '-cp', str(dependencies) + ':' + str(dependencies / '*'),
                 'PilotHL7', source, '2575', code, namespace, '3', target], 25)
        return
    with socket.create_connection((target, 2575), timeout=10, source_address=(source, 0)) as sock:
        replies = MessageStream(sock)
        for _ in range(3):
            control = uuid.uuid4().hex
            message = (f'\x0bMSH|^~\\&|A||S||20261124000000||ORU^R01|{control}|P|2.5\r'
                       f'PID|1||SYNTHETIC\rOBR|1\rOBX|1|NM|{code}^Observation^{namespace}||1|unit|||||F\r').encode()
            sock.sendall(message + HL7_END)
            if b'MSA|AA|' + control.encode() + b'\r' not in mllp_read(replies):
                raise ValueError('HL7 sender did not receive a matched acceptance')


def send_dicom(stack, source, target, dx, adapter):
    uid = '2.25.' + str(uuid.uuid4().int)
    if stack == 'A':
        from agent import synthetic_image
        dataset = synthetic_image('xray' if dx else 'modality')
        dataset.SOPInstanceUID = dataset.file_meta.MediaStorageSOPInstanceUID = uid
        if store(target, source, dataset) != 0:
            raise RuntimeError('DICOM sender did not receive success')
        return
    sop = DigitalXRayImageStorageForPresentation if dx else CTImageStorage
    dump = pilot.ROOT / 'forwarding.dump'
    dataset = pilot.ROOT / 'forwarding.dcm'
    dump.write_text(f'(0008,0016) UI [{sop}]\n(0008,0018) UI [{uid}]\n(0008,0060) CS [{"DX" if dx else "CT"}]\n'
                    '(0010,0010) PN [SYNTHETIC]\n')
    COMMAND(['/usr/bin/dump2dcm', str(dump), str(dataset)])
    COMMAND(['ip', 'route', 'replace', target + '/32', 'dev', adapter, 'src', source])
    COMMAND(['/usr/bin/storescu', '-R', '-to', '5', '-td', '10', target, '11112', str(dataset)], 25)


def send_waveform(source, target):
    control = uuid.uuid4().hex
    message = (f'\x0bMSH|^~\\&|A||S||20261126000000||ORU^W01|{control}|P|2.5\r'
               'PID|1||SYNTHETIC\rOBR|1|||ECG^Waveform^99HIOT\r'
               'OBX|1|CD|ECG&CHN^^99HIOT|1|1^ONE^1&mv^^100^-8&8||||||F\r'
               'OBX|2|TS|ECG&TIM^^99HIOT|1|20261126000000||||||F\r'
               'OBX|3|NA|ECG&WAV^^99HIOT|1|0^1^0^-1^0||||||F\r').encode()
    with socket.create_connection((target, 2575), timeout=10, source_address=(source, 0)) as sock:
        sock.sendall(message + HL7_END)
        if b'MSA|AA|' + control.encode() + b'\r' not in mllp_read(MessageStream(sock)):
            raise ValueError('Waveform transaction did not receive a matched ACK')


def send_acquisition(source, target):
    sop = ModalityPerformedProcedureStep
    uid = '2.25.' + str(uuid.uuid4().int)
    ae = AE(ae_title='PILOT_SCU')
    ae.add_requested_context(sop)
    ae.acse_timeout = ae.dimse_timeout = ae.network_timeout = 10
    assoc = ae.associate(target, 11112, bind_address=(source, 0))
    if not assoc.is_established:
        raise RuntimeError('MPPS association failed')
    try:
        start = Dataset()
        start.Modality = 'DX'
        start.PerformedProcedureStepStatus = 'IN PROGRESS'
        status, _ = assoc.send_n_create(start, sop, uid, msg_id=1)
        if status.Status != 0:
            raise RuntimeError('MPPS N-CREATE failed')
        send_dicom('A', source, target, True, 'eth2')
        end = Dataset()
        end.PerformedProcedureStepStatus = 'COMPLETED'
        status, _ = assoc.send_n_set(end, sop, uid, msg_id=2)
        if status.Status != 0:
            raise RuntimeError('MPPS N-SET failed')
    finally:
        assoc.release()


def run(stack, mode):
    pilot.STATE['receipts'] = []
    network = DIRECT if mode == 'direct' else UPSTREAM
    adapter = 'eth2' if mode == 'direct' else 'eth0'
    targets = ('2', '2') if mode == 'direct' else ('21', '22')

    def measure(label, sender, *args):
        started = time.time()
        sender(*args)
        pilot.STATE['receipts'].append({'case': label, 'started': started, 'finished': time.time()})

    if mode == 'specificity':
        for label in ('bedside', 'ecg'):
            source = DIRECT + str(MEDICAL[label])
            measure(label + '_heart_rate', send_hl7, 'A', source, DIRECT + '2', '8867-4', 'LN')
            measure(label + '_waveform', send_waveform, source, DIRECT + '2')
        for label in ('portable_xray', 'fixed_xray'):
            measure(label + '_acquisition', send_acquisition, DIRECT + str(MEDICAL[label]), DIRECT + '2')
        return

    measure('pump', send_hl7, stack, network + '11', network + targets[0], 'LAB_RATE', '99HIOT')
    for _ in range(2):
        measure('ct', send_dicom, stack, network + '12', network + targets[1], False, adapter)
    if mode == 'direct':
        for label in ('bedside', 'ecg'):
            measure(label, send_hl7, stack, network + str(MEDICAL[label]), network + '2', '8867-4', 'LN')
        for label in ('portable_xray', 'fixed_xray'):
            measure(label, send_dicom, stack, network + str(MEDICAL[label]), network + '2', True, adapter)


class API(pilot.API):
    def receive_bundle(self):
        length = int(self.headers.get('Content-Length', '0'))
        expected = self.headers.get('X-Bundle-SHA256', '')
        if not 0 < length <= MAX_BUNDLE or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('Invalid bundle length or SHA-256')
        checksum = hashlib.sha256()
        archive = pilot.ROOT / (expected + '.tar')
        partial = archive.with_suffix('.part')
        self.connection.settimeout(30)
        try:
            with partial.open('wb') as output:
                while length:
                    block = self.rfile.read(min(length, 1024 * 1024))
                    if not block:
                        raise ValueError('Truncated bundle')
                    output.write(block)
                    checksum.update(block)
                    length -= len(block)
            if checksum.hexdigest() != expected:
                raise ValueError('Bundle SHA-256 mismatch')
            partial.replace(archive)
        finally:
            partial.unlink(missing_ok=True)
        return archive, expected

    def do_POST(self):
        if self.headers.get('Authorization') != 'Bearer ' + pilot.TOKEN:
            return self.respond(403, {})
        if not POST_LOCK.acquire(blocking=False):
            return self.respond(409, {'error': 'busy'})
        try:
            self.handle_pilot_operation()
        finally:
            POST_LOCK.release()

    def handle_pilot_operation(self):
        if pilot.STATE['busy']:
            return self.respond(409, {'error': 'busy'})
        if self.path == '/setup' and not pilot.STATE['ready']:
            pilot.background(setup)
        elif self.path == '/offline-bundle' and pilot.ROLE == 'actor' and pilot.STATE['ready']:
            try:
                archive, digest = self.receive_bundle()
            except (OSError, ValueError):
                return self.respond(400, {'error': 'invalid or incomplete bundle'})
            pilot.background(lambda: prepare_stack_b(archive, digest))
        elif (pilot.ROLE == 'actor' and pilot.STATE['ready'] and self.path in
              {*{f'/run/{stack}/{mode}' for stack in ('A', 'B') for mode in ('direct', 'forwarded')}, '/run/A/specificity'}):
            _, _, stack, mode = self.path.split('/')
            if stack == 'B' and not pilot.STATE.get('stack_b_ready'):
                return self.respond(409, {'error': 'Stack B is not ready'})
            pilot.background(lambda: run(stack, mode))
        else:
            return self.respond(400, {'error': 'invalid operation'})
        return self.respond(202, {'accepted': True})


pilot.STATE['worker_sha256'] = os.environ['FORWARDING_SOURCE_SHA256']
if __name__ == '__main__':
    pilot.ThreadingHTTPServer(('0.0.0.0', 8080), API).serve_forever()
