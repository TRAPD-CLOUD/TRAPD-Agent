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
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--config-dir', type=Path, required=True)
parser.add_argument('--default-config', type=Path, required=True)
parser.add_argument('--watch-dir', required=True)
args = parser.parse_args()
args.root.mkdir(parents=True, exist_ok=True)
args.config_dir.mkdir(parents=True, exist_ok=True)
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TRAPD MSI test CA')])
now = datetime.datetime.now(datetime.timezone.utc)
ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256()))
(args.config_dir / 'ca.crt').write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
# rustls rejects a CA certificate presented as an end-entity certificate.
# Serve a distinct localhost certificate signed by the pinned test CA.
tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
cert = (x509.CertificateBuilder().subject_name(server_name).issuer_name(name)
        .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .sign(ca_key, hashes.SHA256()))
cert_file = args.root / 'server.crt'
cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
key_file = args.root / 'server.key'
key_file.write_bytes(tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
signing_key = ed25519.Ed25519PrivateKey.generate()
(args.config_dir / 'command_signing.pub').write_bytes(signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
config = json.loads(args.default_config.read_text(encoding='utf-8-sig'))
config.update(heartbeat_interval_secs=5, fs_watch_paths=[args.watch_dir], fim_paths=[args.watch_dir], fim_interval_secs=10,
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
        # Device pairing (unauthenticated, like the real backend). Poll stays
        # pending until the test creates the `approve-pairing` marker.
        if self.path.endswith('/agents/pair/start'):
            with lock:
                with (args.root / 'requests.ndjson').open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps({'path': self.path, 'body': body, 'status': 200}) + '\n')
            self.reply(200, {'device_code': 'pair_msi_test_device_code', 'user_code': 'ABCDE-FGHJK',
                             'verification_uri': 'https://trapd.invalid/pair',
                             'verification_uri_complete': 'https://trapd.invalid/pair?code=ABCDEFGHJK',
                             'expires_in': 600, 'interval': 1})
            return
        if self.path.endswith('/agents/pair/poll'):
            if (args.root / 'approve-pairing').exists():
                self.reply(200, {'enrollment_token': 'test-enrollment-token', 'project_id': 'msi-test'})
            else:
                self.reply(400, {'error': 'authorization_pending'})
            return
        status = 500 if ((self.path.endswith('/ingest/events') and (args.root / 'pause-ingest').exists())
                         or (self.path.endswith('/heartbeat') and (args.root / 'pause-heartbeat').exists())) else 200
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
