# Debian/Ubuntu package (`trapd-agent_<version>_amd64.deb`)

A ready-made package for the **hosted TRAPD service**. The service's public trust
anchors and backend URL are baked in at build time, so the install needs no
token and no configuration: the agent starts in pairing mode and shows a code
that the user enters in the TRAPD web interface. Self-hosters use the web
installer (`install.sh`), which embeds the anchors of their own server.

## Install

```sh
sudo apt install ./trapd-agent_<version>_amd64.deb
sudo cat /var/lib/trapd/pairing.txt   # code + page to enter it on (also printed by the install)
```

## Build

```sh
deploy/deb/build-deb.sh <version> <agent-binary> <ebpf-object> <trust-dir> <out-dir>
```

Needs `dpkg-deb` only. `<version>` may be `1.2.3`, `v1.2.3` or `1.2.3-beta.1`
(becomes `1.2.3~beta.1`, which sorts before `1.2.3`). The package is `amd64`
only (see *Limits*).

`<trust-dir>` must contain, and the build fails without any of them:

| File | Content | Installed to |
|---|---|---|
| `ca.crt` | PEM CA (bundle) that pins the backend | `/etc/trapd/ca.crt` |
| `command_signing.pub` | raw 32-byte Ed25519 **public** key | `/etc/trapd/command_signing.pub` |
| `release_signing.pub` | raw 32-byte Ed25519 **public** key | `/etc/trapd-release/release_signing.pub` |
| `backend_url` | one line, `https://host[:port][/path]` | `/usr/share/trapd-agent/backend_url`, copied into `agent.env` on first install |

Only public material belongs here. The build rejects a PEM private key in
`ca.crt`, but it **cannot** tell a raw 32-byte Ed25519 public key from a raw
32-byte private seed: stage the derived public keys, never the signing secrets.

`TRAPD_DEB_MAINTAINER` overrides the `Maintainer:` field (default is a
placeholder). `SOURCE_DATE_EPOCH` makes file times reproducible.

## Test

```sh
deploy/deb/test-deb.sh                # builds dummy packages, validates, installs in ubuntu:24.04 and debian:12
REQUIRE_DOCKER=1 deploy/deb/test-deb.sh   # CI: a missing Docker/image is an error, not a skip
```

The container part uses plain `dpkg` without systemd and a stubbed `systemctl`
to check the systemd code paths. It does not start the agent.

## Layout and the self-update

| Path | Notes |
|---|---|
| `/usr/bin/trapd-agent` | FHS location. The signed updater replaces `std::env::current_exe()`, i.e. exactly this file, so no `/usr/local/bin` is involved. |
| `/usr/lib/trapd-agent/trapd-agent-exec` | eBPF object, the updater's default target. |
| `/usr/lib/systemd/system/trapd-agent.service` | `deploy/trapd-agent.service` with the binary path rewritten (asserted at build time). |
| `/usr/lib/systemd/system/trapd-agent-update.{path,service}` | `deploy/deb/` copies of the units `install.sh` writes inline, with `/usr/bin` in `ReadWritePaths`. |
| `/etc/trapd/agent.env` | created by `postinst` only if absent; **not** a conffile, so edits and tokens survive upgrades. |
| `/etc/trapd/binary.sha256` | self-integrity baseline, refreshed by `postinst` on every install/upgrade. |
| `/etc/logrotate.d/trapd` | conffile. |

The legacy checksum-only `trapd-update` timer is **not** shipped: the release
key is baked in, so only the signed in-agent update applies.

Interaction between dpkg and the self-update:

- A package upgrade overwrites `/usr/bin/trapd-agent` and the eBPF object
  unconditionally, restarts the agent and refreshes the baseline. Packages are
  only offered when newer than the installed package version, so this does not
  downgrade a self-updated binary in practice.
- After a self-update the binary no longer matches the package's `md5sums`
  (`debsums` reports it). That is expected.
- The updater leaves `trapd-agent.prev` / `.trapd-agent.new` (and the eBPF
  equivalents) next to the binaries. dpkg does not know them; `postrm` removes
  them on `remove` and `purge`.
- The trust anchors are ordinary package files (not conffiles): a package
  upgrade replaces them, which is how anchors are rotated.

## Lifecycle

- **install**: refuses if a script-based install is present
  (`/usr/local/bin/trapd-agent` or `/etc/systemd/system/trapd-agent.service`),
  because that unit would shadow the packaged one. The message lists the removal
  steps; credentials in `/var/lib/trapd` are reused.
- **remove**: stops and disables the units, keeps `/var/lib/trapd`
  (credentials) and `/etc/trapd/agent.env`, so a reinstall keeps the device identity.
- **purge**: deletes `/var/lib/trapd`, `/var/log/trapd`, `/etc/trapd` and
  `/etc/trapd-release`. **This removes the device credentials and the mTLS key;
  the device has to pair again.** Symlinked data directories are unlinked, never followed.
- Without systemd (containers, chroots) or when `policy-rc.d` denies, units are
  not started; nothing fails.

## Limits and open points

- `amd64` only. `aarch64` needs an arm64 agent build and is not covered.
- The package itself is not covered by the signed release statements; its first
  install is protected by the repository's SHA-256 file and by the channel it is
  fetched from (an apt repository with a signed `Release` file would be the next step).
- No `copyright` file (the repository has no license file yet), so `lintian`
  would warn; `lintian` was not run.
- Not tested against a real systemd: the units pass `systemd-analyze verify`
  syntax-wise, the install paths were tested with a stubbed `systemctl`.

## Honeytokens (opt-in)

The packaged service keeps `/home` and `/root` read-only for the agent, so
honeytoken decoys planted there fail. To allow them on a host that has
honeytoken paths configured, enable the shipped drop-in (it is never enabled by
the package, and it survives upgrades):

```sh
sudo install -D -m 0644 /usr/share/trapd-agent/deception.conf \
     /etc/systemd/system/trapd-agent.service.d/deception.conf
sudo systemctl daemon-reload && sudo systemctl restart trapd-agent
```

It sets `ProtectHome=false`, `ProtectSystem=full` and adds `CAP_DAC_OVERRIDE`,
`CAP_CHOWN` and `CAP_FOWNER`. Remove the file (and reload) to go back to the
read-only default. With `install.sh`, pass `TRAPD_ENABLE_DECEPTION=1`.
