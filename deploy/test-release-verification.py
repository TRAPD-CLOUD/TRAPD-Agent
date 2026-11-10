#!/usr/bin/env python3
"""Exercise the real standalone shell entrypoints without root/network/services."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
PREFIX = "https://github.com/trapd-cloud/trapd-agent/releases/download/v9.8.7/"


class ReleaseVerification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.host = self.root / "host"
        for directory in ["usr/local/bin", "usr/lib/trapd-agent", "etc/trapd", "etc/trapd-release", "etc/systemd/system", "etc/logrotate.d", "var/log", "var/lib"]:
            (self.host / directory).mkdir(parents=True, exist_ok=True)
        self.key = self.root / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.key)], check=True, capture_output=True)
        pub = subprocess.check_output(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"])[-32:]
        self.trust = self.host / "etc/trapd-release/release_signing.pub"
        self.trust.write_bytes(pub)
        self.trust.chmod(0o644)
        self.trust.parent.chmod(0o755)
        self.old = b'#!/bin/sh\necho "trapd-agent v1.0.0"\n'
        self.agent = self.host / "usr/local/bin/trapd-agent"
        self.agent.write_bytes(self.old)
        self.agent.chmod(0o755)
        self.updater = self.host / "usr/local/bin/trapd-update"
        self.updater.write_text("old updater")
        self.ebpf = self.host / "usr/lib/trapd-agent/trapd-agent-exec"
        self.ebpf.write_bytes(b"old ebpf")
        for name, data in {"trapd-agent-linux-x86_64": b'#!/bin/sh\necho "trapd-agent v9.8.7"\n', "trapd-agent-exec": b"new ebpf", "trapd-update.sh": b'#!/bin/sh\necho refreshed > "$REFRESH_MARKER"\n'}.items():
            (self.assets / name).write_bytes(data)
            (self.assets / (name + ".sha256")).write_text(hashlib.sha256(data).hexdigest() + "  " + name + "\n")
        self.sign()
        self.fake("curl", '''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args=sys.argv[1:]
url=next(a for a in args if a.startswith("https://"))
if url.endswith("/latest"):
 print(json.dumps({"tag_name": "v9.8.7"})); sys.exit(0)
source=pathlib.Path(os.environ["ASSETS"])/url.rsplit("/",1)[-1]
if not source.exists(): sys.exit(22)
shutil.copyfile(source,args[args.index("-o")+1])
''')
        self.fake("systemctl", '#!/bin/sh\necho "$*" >> "$SERVICE_MARKER"\n')
        # Filesystem effects remain real; only root ownership is unavailable in CI.
        self.fake("install", '''#!/usr/bin/env python3
import os, subprocess, sys
args=sys.argv[1:]; clean=[]
while args:
 a=args.pop(0)
 if a in ("-o", "-g"): args.pop(0)
 else: clean.append(a)
sys.exit(subprocess.call(["/usr/bin/install", *clean]))
''')
        self.env = dict(os.environ, PATH=str(self.bin) + ":" + os.environ["PATH"], ASSETS=str(self.assets), SERVICE_MARKER=str(self.root / "services"), REFRESH_MARKER=str(self.root / "refreshed"))
        for name in ["TRAPD_RELEASE_PUBKEY_B64", "TRAPD_UPDATE_NO_SELF_REFRESH"]:
            self.env.pop(name, None)

    def fake(self, name, text):
        p = self.bin / name
        p.write_text(text)
        p.chmod(0o755)

    def spec(self, name):
        data = (self.assets / name).read_bytes()
        return dict(url=PREFIX + name, sha256=hashlib.sha256(data).hexdigest(), size=len(data))

    def sign(self, version="9.8.7", os_name="linux"):
        for filename, asset in [("release-linux.json", "trapd-agent-linux-x86_64"), ("release-updater.json", "trapd-update.sh")]:
            statement = dict(self.spec(asset), version=version, os=os_name, arch="x86_64")
            if asset != "trapd-update.sh":
                statement["ebpf"] = self.spec("trapd-agent-exec")
            payload = json.dumps(statement, separators=(",", ":"))
            raw = self.root / "payload"
            raw.write_text(payload)
            signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(raw)])
            (self.assets / filename).write_text(json.dumps(dict(payload=payload, signature=base64.b64encode(signature).decode())))

    def run_script(self, name):
        text = (HERE / name).read_text()
        # Redirect all deployment paths; bypass only the entrypoint root check.
        for prefix in ["/usr/local/bin", "/usr/lib/trapd-agent", "/etc", "/var/log", "/var/lib"]:
            text = text.replace(prefix, str(self.host) + prefix)
        text = text.replace('if [[ $EUID -ne 0 ]]; then', 'if false; then')
        script = self.root / name
        script.write_text(text)
        return subprocess.run(["bash", str(script)], env=self.env, capture_output=True, text=True, timeout=20)

    def assert_untouched(self):
        self.assertEqual(self.agent.read_bytes(), self.old)
        self.assertEqual(self.ebpf.read_bytes(), b"old ebpf")
        self.assertEqual(self.updater.read_text(), "old updater")
        self.assertFalse((self.root / "services").exists())
        self.assertFalse((self.root / "refreshed").exists())

    def test_missing_trust_key_refuses_both_paths_before_changes(self):
        self.trust.unlink()
        for name in ["install.sh", "trapd-update.sh"]:
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script(name).returncode, 0)
                self.assert_untouched()

    def test_tampered_artifact_and_matching_unsigned_checksum_refused(self):
        (self.assets / "trapd-agent-linux-x86_64").write_bytes(b"malicious")
        (self.assets / "trapd-agent-linux-x86_64.sha256").write_text(hashlib.sha256(b"malicious").hexdigest())
        for name in ["install.sh", "trapd-update.sh"]:
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script(name).returncode, 0)
                self.assert_untouched()

    def test_tampered_updater_is_not_installed_or_executed(self):
        (self.assets / "trapd-update.sh").write_text("malicious")
        for name in ["install.sh", "trapd-update.sh"]:
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script(name).returncode, 0)
                self.assert_untouched()

    def test_bad_ebpf_prevents_all_changes(self):
        (self.assets / "trapd-agent-exec").write_bytes(b"bad ebpf")
        for name in ["install.sh", "trapd-update.sh"]:
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script(name).returncode, 0)
                self.assert_untouched()

    def test_wrong_version_or_platform_rejected(self):
        for version, platform in [("9.8.6", "linux"), ("9.8.7", "windows")]:
            self.sign(version, platform)
            for name in ["install.sh", "trapd-update.sh"]:
                with self.subTest(version=version, platform=platform, name=name):
                    self.assertNotEqual(self.run_script(name).returncode, 0)
                    self.assert_untouched()

    def test_missing_or_wrong_signature_rejected(self):
        manifest = self.assets / "release-updater.json"
        original = manifest.read_bytes()
        for contents in [None, b'{"payload":"{}","signature":"bad"}']:
            if contents is None:
                manifest.unlink()
            else:
                manifest.write_bytes(contents)
            for name in ["install.sh", "trapd-update.sh"]:
                with self.subTest(name=name, contents=contents):
                    result = self.run_script(name)
                    self.assertNotEqual(result.returncode, 0)
                    self.assert_untouched()
            manifest.write_bytes(original)

    def test_valid_signature_under_different_key_rejected(self):
        self.trust.write_bytes(bytes(32))
        for name in ["install.sh", "trapd-update.sh"]:
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script(name).returncode, 0)
                self.assert_untouched()

    def test_signed_asset_substitution_rejected(self):
        # Both statements are validly signed, but the updater cannot authorize
        # replacing the agent. Substitution must fail despite identical version.
        (self.assets / "release-linux.json").write_bytes((self.assets / "release-updater.json").read_bytes())
        for name in ["install.sh", "trapd-update.sh"]:
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script(name).returncode, 0)
                self.assert_untouched()

    def test_downgrade_rejected_before_self_refresh(self):
        self.old = b'#!/bin/sh\necho "trapd-agent v10.0.0"\n'
        self.agent.write_bytes(self.old)
        for name in ["install.sh", "trapd-update.sh"]:
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script(name).returncode, 0)
                self.assert_untouched()

    def test_bootstrap_from_out_of_band_key(self):
        self.env["TRAPD_RELEASE_PUBKEY_B64"] = base64.b64encode(self.trust.read_bytes()).decode()
        expected = self.trust.read_bytes()
        self.trust.unlink()
        self.agent.unlink()
        result = self.run_script("install.sh")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.trust.read_bytes(), expected)
        self.assertEqual(self.agent.read_bytes(), (self.assets / "trapd-agent-linux-x86_64").read_bytes())

    def test_env_cannot_replace_pinned_key(self):
        self.env["TRAPD_RELEASE_PUBKEY_B64"] = base64.b64encode(bytes(32)).decode()
        self.assertNotEqual(self.run_script("install.sh").returncode, 0)
        self.assert_untouched()

    def test_env_bootstrap_rejects_unsafe_existing_key_directory(self):
        self.env["TRAPD_RELEASE_PUBKEY_B64"] = base64.b64encode(self.trust.read_bytes()).decode()
        self.trust.unlink()
        self.trust.parent.chmod(0o777)
        self.assertNotEqual(self.run_script("install.sh").returncode, 0)
        self.assert_untouched()
        self.trust.parent.chmod(0o755)
        self.trust.parent.rmdir()
        other = self.host / "key-redirect"
        other.mkdir()
        self.trust.parent.symlink_to(other, target_is_directory=True)
        self.assertNotEqual(self.run_script("install.sh").returncode, 0)
        self.assert_untouched()

    def test_manual_update_after_self_refresh_still_verifies_bundle(self):
        self.env["TRAPD_UPDATE_NO_SELF_REFRESH"] = "1"
        result = self.run_script("trapd-update.sh")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.agent.read_bytes(), (self.assets / "trapd-agent-linux-x86_64").read_bytes())
        self.assertEqual(self.ebpf.read_bytes(), b"new ebpf")
        self.assertIn("restart trapd-agent", (self.root / "services").read_text())

    def test_valid_first_install_and_pinned_key(self):
        result = self.run_script("install.sh")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.agent.read_bytes(), (self.assets / "trapd-agent-linux-x86_64").read_bytes())
        self.assertEqual(self.ebpf.read_bytes(), b"new ebpf")
        self.assertEqual(self.updater.read_bytes(), (self.assets / "trapd-update.sh").read_bytes())

    def test_valid_self_refresh_executes_only_verified_script(self):
        result = self.run_script("trapd-update.sh")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue((self.root / "refreshed").exists())

    @unittest.skipUnless(os.environ.get("TRAPD_TEST_XTASK"), "set TRAPD_TEST_XTASK to the built Rust release signer")
    def test_rust_release_signer_output_is_accepted_by_bootstrap(self):
        private_der = subprocess.check_output(["openssl", "pkey", "-in", str(self.key), "-outform", "DER"])
        self.assertEqual(private_der[:16].hex(), "302e020100300506032b657004220420")
        signing_env = dict(self.env, RELEASE_SIGNING_KEY=base64.b64encode(private_der[-32:]).decode(), BINARY_SIGNING_KEY="")
        for filename, asset in [("release-linux.json", "trapd-agent-linux-x86_64"), ("release-updater.json", "trapd-update.sh")]:
            args = [os.environ["TRAPD_TEST_XTASK"], "sign-release", "--version", "9.8.7", "--os", "linux", "--arch", "x86_64", "--tag", "v9.8.7", "--asset-name", asset, "--file", str(self.assets / asset)]
            if asset != "trapd-update.sh":
                args += ["--ebpf-asset-name", "trapd-agent-exec", "--ebpf-file", str(self.assets / "trapd-agent-exec")]
            (self.assets / filename).write_bytes(subprocess.check_output(args, env=signing_env))
        result = self.run_script("install.sh")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.agent.read_bytes(), (self.assets / "trapd-agent-linux-x86_64").read_bytes())


if __name__ == "__main__":
    unittest.main()
