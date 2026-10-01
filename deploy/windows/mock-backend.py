"""Pinned TLS backend for the native MSI acceptance test; synthetic credentials."""
import argparse
import base64
import datetime
import ipaddress
import json
from pathlib import Path
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--config-dir', type=Path, required=True)
parser.add_argument('--default-config', type=Path, required=True)
parser.add_argument('--watch-dir', required=True)
args = parser.parse_args()
args.root.mkdir(parents=True, exist_ok=True)
args.config_dir.mkdir(parents=True, exist_ok=True)
tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TRAPD MSI test CA')])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .sign(tls_key, hashes.SHA256()))
cert_file = args.root / 'server.crt'
cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(args.config_dir / 'ca.crt').write_bytes(cert_file.read_bytes())
key_file = args.root / 'server.key'
key_file.write_bytes(tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
signing_key = ed25519.Ed25519PrivateKey.generate()
(args.config_dir / 'command_signing.pub').write_bytes(signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
config = json.loads(args.default_config.read_text(encoding='utf-8-sig'))
config.update(fs_watch_paths=[args.watch_dir], fim_paths=[args.watch_dir], fim_interval_secs=10,
              sigma_rules=['''title: TRAPD MSI Sigma smoke
id: trapd-msi-smoke
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: TRAPD_MSI_SIGMA_SMOKE
  condition: selection
level: high
'''])
# Match serde's ConfigEnvelope field order and the serialized AgentConfig order
# returned by diagnostics. The current agent verifier signs the typed encoding.
envelope = {'issued_at': now.replace(microsecond=0).isoformat().replace('+00:00', 'Z'), 'agent_id': 'windows-smoke', 'config': config}
canonical = json.dumps(envelope, separators=(',', ':'), ensure_ascii=False).encode()
signed = {'envelope': envelope, 'signature': base64.b64encode(signing_key.sign(canonical)).decode()}
# SignedConfig uses the same envelope wrapper as commands.
lock = threading.Lock()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body=None):
        data = json.dumps(body).encode() if body is not None else b''
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer test-agent-secret':
            self.reply(401)
            return
        if self.path.endswith('/config'):
            self.reply(200, signed)
        elif self.path.endswith('/commands'):
            self.reply(200, [])
        else:
            self.reply(404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 4 * 1024 * 1024:
            self.reply(413)
            return
        body = json.loads(self.rfile.read(length))
        status = 500 if self.path.endswith('/ingest/events') and (args.root / 'pause-ingest').exists() else 200
        if not self.path.endswith('/enroll') and self.headers.get('Authorization') != 'Bearer test-agent-secret':
            status = 401
        with lock:
            with (args.root / 'requests.ndjson').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps({'path': self.path, 'body': body, 'status': status}) + '\n')
        if self.path.endswith('/enroll'):
            self.reply(status, {'agent_id': 'windows-smoke', 'agent_secret': 'test-agent-secret', 'project_id': 'msi-test'})
        else:
            self.reply(status)

server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(cert_file), str(key_file))
server.socket = context.wrap_socket(server.socket, server_side=True)
(args.root / 'url.txt').write_text(f'https://127.0.0.1:{server.server_port}', encoding='utf-8')
server.serve_forever()
