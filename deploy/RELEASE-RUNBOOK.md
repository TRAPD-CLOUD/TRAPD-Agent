# Agent release runbook

How agent releases are signed, published and verified, where the keys live,
and what to do when a key has to change.

## Trust model in one paragraph

Two independent Ed25519 keys protect the fleet. The **release key** signs a
statement per artifact (version, platform, URL, SHA-256, size, optional eBPF
companion) in CI. The **command key** is held by the backend and signs the
update directive that tells a host to install a version. An agent installs an
update only when both signatures verify against the public keys pinned on the
host. A compromised backend therefore cannot mint a release, and a compromised
GitHub repository or CI cannot order hosts to install anything.

## Where each key lives

| Material | Location | Who can read it |
| --- | --- | --- |
| Release key seed (secret) | GitHub secret `RELEASE_SIGNING_KEY` in `TRAPD-Agent`, plus one offline backup | Release workflow only |
| Release public key | Repo variable `TRAPD_HOSTED_RELEASE_PUBKEY`; backend env `TRAPD_RELEASE_SIGNING_PUBKEY`; hosts at `/etc/trapd-release/release_signing.pub` (Windows: `config\release_signing.pub`) | Public |
| Command public key | Repo variable `TRAPD_HOSTED_COMMAND_PUBKEY`; hosts at `/etc/trapd/command_signing.pub` | Public |
| Maintenance public key | Repo variable `TRAPD_HOSTED_MAINTENANCE_PUBKEY` (uninstall/stop protection) | Public |
| Backend URL and CA | Repo variables `TRAPD_HOSTED_BACKEND_URL`, `TRAPD_HOSTED_CA_PEM` | Public |
| Publish token | Secret `TRAPD_RELEASE_PUBLISH_TOKEN` (CI) and backend env of the same name | CI and backend |

`/etc/trapd-release` is read-only for the agent service. The agent can write
`/etc/trapd`, so the release key must never be placed there.

The release key never exists on a developer machine after generation. Keep the
offline backup on encrypted removable media or in a password manager vault that
only release owners can open. Do not store it in the backend, in Supabase, or in
any other repository.

## Before the first production release

1. **Replace the dev trust anchors.** As of 2026-11-26 the repo variables point
   at a development stack: `TRAPD_HOSTED_BACKEND_URL=https://dev.trapd.de` and
   `TRAPD_HOSTED_CA_PEM` is a *Caddy Local Authority* root. A build with these
   values pins a CA that production will never present. Set both to the
   production backend and its real CA before tagging a release meant for
   customers.
2. Set `TRAPD_HOSTED_MAINTENANCE_PUBKEY`; without it the Debian package ships
   without uninstall protection (the workflow only warns).
3. Confirm the backend has `TRAPD_RELEASE_SIGNING_PUBKEY` equal to
   `TRAPD_HOSTED_RELEASE_PUBKEY`. The backend refuses statements it cannot
   verify.

## Generating a release key (one time)

On an offline machine with a checkout of this repository:

```sh
cargo xtask release-keygen
```

It prints the secret seed and the public key, both base64.

1. Store the seed as the `RELEASE_SIGNING_KEY` secret
   (`gh secret set RELEASE_SIGNING_KEY -R TRAPD-CLOUD/TRAPD-Agent`), then write
   the offline backup. Clear the terminal and shell history.
2. Store the public key as `TRAPD_HOSTED_RELEASE_PUBKEY` and as
   `TRAPD_RELEASE_SIGNING_PUBKEY` in the backend environment.

The current key was generated on 2026-10-06.

## Cutting a release

1. Bump the version in `agent/Cargo.toml`, merge to `main`, wait for green CI.
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. `release.yml` builds Linux, Windows exe and MSI, the eBPF object and the
   `.deb`, writes `SHA256SUMS` and SBOMs, signs `release-statements.ndjson`
   (fails hard without `RELEASE_SIGNING_KEY`) and publishes the GitHub release.
4. If `TRAPD_BACKEND_URL` and `TRAPD_RELEASE_PUBLISH_TOKEN` are set, the
   workflow posts the statements to `/api/v1/agent-releases`. New releases
   start **paused at 0 %** rollout; nothing reaches hosts until an operator
   raises the rollout.
5. Verify the published release (next section) before raising the rollout.

## Verifying a published release

Run this from any machine; it only needs the public key.

```sh
mkdir rel && cd rel
gh release download vX.Y.Z -R TRAPD-CLOUD/TRAPD-Agent \
  -p release-statements.ndjson -p release-linux.json \
  -p trapd-agent-linux-x86_64 -p trapd-agent-exec
python3 -I - "$(gh variable get TRAPD_HOSTED_RELEASE_PUBKEY -R TRAPD-CLOUD/TRAPD-Agent)" <<'EOF'
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
key = Ed25519PublicKey.from_public_bytes(base64.b64decode(sys.argv[1]))
for line in open("release-statements.ndjson"):
    entry = json.loads(line)
    key.verify(base64.b64decode(entry["signature"]), entry["payload"].encode())
    p = json.loads(entry["payload"])
    print("signature ok:", p["os"], p["version"])
p = json.loads(json.load(open("release-linux.json"))["payload"])
def sha(path): return hashlib.sha256(open(path, "rb").read()).hexdigest()
assert sha("trapd-agent-linux-x86_64") == p["sha256"], "binary digest mismatch"
assert sha("trapd-agent-exec") == p["ebpf"]["sha256"], "eBPF digest mismatch"
print("digests ok")
EOF
```

`verify` raises on a bad signature, so any traceback means: do not roll out.

Verification record:

| Release | Date | Result |
| --- | --- | --- |
| v0.7.11 | 2026-11-26 | Linux and Windows statements verify against `TRAPD_HOSTED_RELEASE_PUBKEY`; Linux binary and eBPF digests match |

## Rotating the release key

The agent pins exactly one release key and a self-update replaces only the
binary (and eBPF object), never `/etc/trapd-release/release_signing.pub`. A
rotation therefore reaches a host only through a package install or upgrade
(`.deb`, MSI or `install.sh`), which is run as root/SYSTEM by the operator.

Planned rotation (for example yearly, or when a release owner leaves):

1. Generate the new key as above, but do not replace the secret yet.
2. Update `TRAPD_HOSTED_RELEASE_PUBKEY`, then build packages with the new key
   pinned while CI still signs with the old key, and have every host install
   that package. The release published by this step must still be signed with
   the old key.
3. Once all hosts report the new package, replace `RELEASE_SIGNING_KEY` and
   `TRAPD_RELEASE_SIGNING_PUBKEY` (backend) with the new values.
4. Hosts that missed step 2 stop accepting self-updates; they keep running and
   need a manual package upgrade.

Step 2 is not automated today: hosts accept only one key, so there is no
overlap window. Supporting two pinned keys during rotation is a follow-up.

## Suspected key compromise

1. Pause every rollout in the backend (`agent_releases.paused = true`) and set
   `revoked = true` on any release you did not build yourself. An
   attacker with only the release key still needs a command-key signed
   directive, so pausing removes the fast path.
2. Delete the `RELEASE_SIGNING_KEY` secret so CI cannot sign further releases.
3. Generate a new key, rotate as above via package installs, and record the
   incident in `SECURITY.md` follow-up notes.
4. If the command key may also be affected, treat it as a fleet incident: both
   keys together allow arbitrary code on every host.
