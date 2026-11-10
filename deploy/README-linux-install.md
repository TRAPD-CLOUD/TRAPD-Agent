# Linux installation and legacy updater migration

`install.sh` requires **Python 3.9+ and OpenSSL 3+**, plus curl, sha256sum and
systemd. Python's standard library parses the existing release statements and
hashes artifacts; OpenSSL verifies Ed25519. No Python packages or downloaded
verification programs are installed or executed.

## Bootstrap trust

Obtain the release public key through an independently authenticated operator
channel. It is the same raw 32-byte Ed25519 key used by the signed agent updater,
not the command-signing key. Do not fetch it from the release being verified.
The installer itself must also come from a trusted, reviewed source: artifact
signatures cannot make an already malicious bootstrap script trustworthy.

Either provision the raw key at `/etc/trapd-release/release_signing.pub` (directory
root:root 0755, file root:root 0644), or supply its base64 encoding on first install:

```sh
# Download the bootstrap script from your trusted distribution channel; review it.
less install.sh
sudo TRAPD_RELEASE_PUBKEY_B64='<independently obtained public key>' \
  TRAPD_BACKEND_URL=https://api.example.com \
  TRAPD_ENROLL_TOKEN='<enrollment token>' bash install.sh
```

The installer verifies all three artifacts before replacing any executable:

- `release-linux.json` authenticates the Linux agent and its coupled eBPF object.
- `release-updater.json` authenticates `trapd-update.sh`, including self-refresh.

Both files use the existing `cargo xtask sign-release` format:
`{"payload":"<exact signed JSON bytes>","signature":"<base64 Ed25519>"}`.
Signatures cover version, OS/architecture, complete artifact URL, size and SHA256.
The verifier requires the requested tag and expected artifact names. Missing or
invalid signatures, missing companions, bad keys and altered files abort before
installation. Published `.sha256` files are informational and provide no fallback.
A replacement cannot downgrade the installed version; an unknown installed
version aborts. An equal version may be reinstalled for repair. On a new host,
release freshness still depends on selecting the intended signed release.

Existing pinned keys cannot be silently replaced with a different environment
value. Rotate that trust anchor explicitly through the independent provisioning
channel. The release key remains outside the agent-writable configuration tree.
Backend CA and command-signing-key provisioning are still required for the
control channel; this change does not alter its HTTPS/TLS policy.

## Existing hosts

Old installed checksum-only updaters do **not** become safe just because this
repository changes. Before migrating them:

1. Disable their timer: `sudo systemctl disable --now trapd-update.timer`.
2. Provision the independent release key and install the trusted, reviewed new
   bootstrap script. Re-run it only against a release containing both signed
   statements. Do not rely on the old updater to authenticate its replacement.
3. Confirm the agent's signed update channel has both its release key and command
   key, and that `trapd-agent-update.path` is enabled. Backend rollout authorization
   remains mandatory for that channel.

The installer always disables the legacy daily timer. `sudo trapd-update` remains
an explicit manual recovery path; it checks the release key, signatures and
non-downgrade rule before updating itself or the agent. It does not provide the
backend rollout directive, health rollback or transactional recovery of the
normal signed agent updater. Use the latter for automatic fleet updates.

Releases without these new signed assets deliberately fail closed. There is no
insecure migration switch. Publish the signed release before distributing the
new installer to hosts.

## Release and maintenance

Release publication now requires `RELEASE_SIGNING_KEY`; an absent/invalid secret
fails the release job before GitHub publication. The existing Linux statement is
published separately and still registered with the backend alongside the Windows
statement. The updater-script statement is not an agent rollout record. Ordinary
pull-request CI does not require release secrets.

`release-verification.sh` is the shared source for the verifier embedded in both
standalone scripts. After editing it, regenerate and test:

```sh
python3 deploy/embed-release-verifier.py
python3 deploy/embed-release-verifier.py --check
python3 deploy/test-release-verification.py
```

The integration tests use temporary directories, real Ed25519 signatures and real
OpenSSL verification. Downloads and service operations are isolated; they do not
install software or change services on the test host.
