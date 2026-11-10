#!/usr/bin/env bash
# TRAPD Agent Installer
#
# Recommended install (download → inspect → run). Never pipe a remote script
# straight into `sudo bash`: that prevents you from reviewing what runs as root,
# and passing the enrollment token as a URL query parameter leaks it into shell
# history and web-server / proxy access logs. Fetch the script, read it, then
# run it with the token supplied via the environment (not the URL):
#
#   curl -fsSL -H "X-Enroll-Token: enroll_xxxx" \
#        "https://api.example.com/install.sh" -o install.sh
#   less install.sh                       # inspect before trusting it
#   sudo TRAPD_BACKEND_URL=https://api.example.com \
#        TRAPD_ENROLL_TOKEN=enroll_xxxx \
#        TRAPD_RELEASE_PUBKEY_B64=<independently-obtained-public-key> \
#        bash install.sh
#
# Usage (manual):
#   sudo TRAPD_BACKEND_URL=https://api.example.com \
#        TRAPD_ENROLL_TOKEN=enroll_xxxx \
#        TRAPD_RELEASE_PUBKEY_B64=<independently-obtained-public-key> \
#        bash install.sh
#
# Optional: TRAPD_ENABLE_DECEPTION=1 also installs the systemd drop-in that lets
# the agent plant honeytoken decoys in /home, /root, /srv and /opt (see
# deploy/trapd-agent-deception.conf). Off by default; an existing drop-in is kept.
set -euo pipefail

REPO="trapd-cloud/trapd-agent"
BINARY_NAME="trapd-agent-linux-x86_64"
EBPF_BINARY_NAME="trapd-agent-exec"
INSTALL_BIN="/usr/local/bin/trapd-agent"
EBPF_INSTALL_DIR="/usr/lib/trapd-agent"
EBPF_INSTALL_BIN="${EBPF_INSTALL_DIR}/trapd-agent-exec"
UPDATE_BIN="/usr/local/bin/trapd-update"
SERVICE_FILE="/etc/systemd/system/trapd-agent.service"
UPDATE_SERVICE_FILE="/etc/systemd/system/trapd-update.service"
UPDATE_TIMER_FILE="/etc/systemd/system/trapd-update.timer"
DECEPTION_DROPIN_DIR="/etc/systemd/system/trapd-agent.service.d"
DECEPTION_DROPIN_FILE="${DECEPTION_DROPIN_DIR}/deception.conf"
LOGROTATE_FILE="/etc/logrotate.d/trapd"
ENV_DIR="/etc/trapd"
LOG_DIR="/var/log/trapd"
STATE_DIR="/var/lib/trapd"

# ── Preflight checks ────────────────────────────────────────────────────────
for cmd in curl systemctl sha256sum; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' is required but not installed." >&2
        exit 1
    fi
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)." >&2
    exit 1
fi

# BEGIN GENERATED RELEASE VERIFIER
# Shared bootstrap verifier. Embedded into standalone scripts by
# deploy/embed-release-verifier.py; never fetch or execute a remote verifier.
release_verifier() {
    python3 - "$@" <<'TRAPD_VERIFY_PY'
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def reject(message):
    raise ValueError(message)


def protected_key(path):
    for entry in (path.parent, path):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            reject("release key and directory must be root-owned, non-symlink and not group/world writable")
    if not path.is_file():
        reject("release key must be a regular file")
    raw = path.read_bytes()
    if len(raw) != 32:
        reject("release key must contain exactly 32 raw Ed25519 public-key bytes")
    return raw


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("duplicate JSON key")
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=unique_object)


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        reject("release version must be MAJOR.MINOR.PATCH")
    return tuple(map(int, value.split(".")))


try:
    mode, key_name, stage_name, *args = sys.argv[1:]
    key, stage = Path(key_name), Path(stage_name)
    if mode in ("install", "update"):
        supplied = os.environ.get("TRAPD_RELEASE_PUBKEY_B64", "") if mode == "install" else ""
        if supplied:
            if key.parent.exists() or key.parent.is_symlink():
                info = key.parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    reject("release key directory must be root-owned, non-symlink and not group/world writable")
            raw = base64.b64decode(supplied, validate=True)
            if len(raw) != 32:
                reject("TRAPD_RELEASE_PUBKEY_B64 must decode to exactly 32 bytes")
            if key.exists() or key.is_symlink():
                if protected_key(key) != raw:
                    reject("supplied release key differs from pinned key; rotate trust out-of-band")
        else:
            raw = protected_key(key)
        (stage / "release-key.raw").write_bytes(raw)
        # RFC 8410 SubjectPublicKeyInfo wrapping the existing raw Ed25519 key.
        (stage / "release-key.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + raw)
    elif mode == "verify":
        tag, current = args
        if not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+", tag):
            reject("unsafe or unsupported release tag")
        expected_version = tag.removeprefix("v")
        if current and version(expected_version) < version(current):
            reject("refusing release downgrade")
        prefix = "https://github.com/trapd-cloud/trapd-agent/releases/download/" + tag + "/"

        def artifact(spec, name):
            if not isinstance(spec, dict) or spec.get("url") != prefix + name:
                reject("signed artifact URL/name does not match requested release")
            size = spec.get("size")
            digest = spec.get("sha256")
            if type(size) is not int or not 0 < size <= 200 * 1024 * 1024:
                reject("invalid signed artifact size")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                reject("invalid signed digest")
            path = stage / name
            if path.stat().st_size != size:
                reject("artifact size differs from signed size: " + name)
            hasher = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(chunk)
            if hasher.hexdigest() != digest:
                reject("artifact differs from signed digest: " + name)

        for statement_name, asset_name in (("release-linux.json", "trapd-agent-linux-x86_64"), ("release-updater.json", "trapd-update.sh")):
            statement = stage / statement_name
            if statement.stat().st_size > 65536:
                reject("release statement too large")
            blob = parse(statement.read_text(encoding="utf-8"))
            if not isinstance(blob, dict) or set(blob) != {"payload", "signature"} or not isinstance(blob["payload"], str):
                reject("malformed signed release")
            signature = base64.b64decode(blob["signature"], validate=True)
            if len(signature) != 64:
                reject("invalid Ed25519 signature length")
            payload_path, sig_path = stage / "payload", stage / "signature"
            payload_path.write_bytes(blob["payload"].encode("utf-8"))
            sig_path.write_bytes(signature)
            subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", str(stage / "release-key.der"), "-in", str(payload_path), "-sigfile", str(sig_path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            payload = parse(blob["payload"])
            if not isinstance(payload, dict) or payload.get("version") != expected_version or payload.get("os") != "linux" or payload.get("arch") != "x86_64":
                reject("signed release version/platform mismatch")
            artifact(payload, asset_name)
            if asset_name == "trapd-agent-linux-x86_64":
                artifact(payload.get("ebpf"), "trapd-agent-exec")
    else:
        reject("unknown verification mode")
except (ValueError, TypeError, KeyError, OSError, subprocess.CalledProcessError) as error:
    print("ERROR: release verification failed: " + str(error), file=sys.stderr)
    sys.exit(1)
TRAPD_VERIFY_PY
}

prepare_release_verification() {
    for cmd in python3 openssl curl sha256sum; do
        command -v "$cmd" >/dev/null || { echo "ERROR: $cmd is required for signed releases." >&2; return 1; }
    done
    # Ed25519 pkeyutl -rawin needs OpenSSL 3 or newer. Verification also fails
    # closed if the installed provider does not support Ed25519.
    case "$(openssl version)" in
        "OpenSSL 3."*|"OpenSSL 4."*) ;;
        *) echo "ERROR: OpenSSL 3 or newer is required." >&2; return 1 ;;
    esac
    RELEASE_STAGE="$(mktemp -d /tmp/trapd-release.XXXXXXXX)"
    trap 'rm -rf "$RELEASE_STAGE"' EXIT
    release_verifier "$1" "$RELEASE_KEY_FILE" "$RELEASE_STAGE"
}

stage_verified_release() {
    local name base="https://github.com/${REPO}/releases/download/${LATEST_TAG}"
    [[ "$LATEST_TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: invalid release tag." >&2; return 1; }
    for name in release-linux.json release-updater.json; do
        curl -fsSL --max-time 60 --max-filesize 65536 "$base/$name" -o "$RELEASE_STAGE/$name"
    done
    for name in "$BINARY_NAME" "$EBPF_BINARY_NAME" trapd-update.sh; do
        curl -fsSL --max-time 300 --max-filesize 209715200 "$base/$name" -o "$RELEASE_STAGE/$name"
    done
    release_verifier verify "$RELEASE_KEY_FILE" "$RELEASE_STAGE" "$LATEST_TAG" "$CURRENT_VERSION"
}
# END GENERATED RELEASE VERIFIER

RELEASE_KEY_DIR="/etc/trapd-release"
RELEASE_KEY_FILE="${RELEASE_KEY_DIR}/release_signing.pub"
prepare_release_verification install
CURRENT_VERSION=""
if [[ -e "$INSTALL_BIN" ]]; then
    CURRENT_VERSION="$("$INSTALL_BIN" --version | awk '{print $2}' | sed 's/^v//')"
    [[ -n "$CURRENT_VERSION" ]] || { echo "ERROR: installed version unavailable; refusing replacement." >&2; exit 1; }
fi

# ── Fetch latest release tag ────────────────────────────────────────────────
echo "Fetching latest release..."
LATEST_TAG=$(curl -sf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [[ -z "$LATEST_TAG" ]]; then
    echo "ERROR: Could not determine latest release tag from GitHub API." >&2
    exit 1
fi

echo "Latest release: ${LATEST_TAG}"

# Stage and authenticate the entire set before installing any executable.
# A compromised mirror may replace hashes too; only the independent release
# key can authorize the exact version, names, sizes and bytes installed here.
stage_verified_release
install -d -m 0755 -o root -g root "$RELEASE_KEY_DIR"
install -m 0644 -o root -g root "$RELEASE_STAGE/release-key.raw" "$RELEASE_KEY_FILE"
install -m 0755 "$RELEASE_STAGE/$BINARY_NAME" "${INSTALL_BIN}.new"
mv -f "${INSTALL_BIN}.new" "$INSTALL_BIN"
install -d -m 0755 "$EBPF_INSTALL_DIR"
install -m 0644 "$RELEASE_STAGE/$EBPF_BINARY_NAME" "$EBPF_INSTALL_BIN"
command -v restorecon &>/dev/null && restorecon -F "$INSTALL_BIN" "$EBPF_INSTALL_BIN" || true
mkdir -p "$ENV_DIR"
echo "sha256:$(sha256sum "$INSTALL_BIN" | awk '{print $1}')" > "${ENV_DIR}/binary.sha256"
chmod 600 "${ENV_DIR}/binary.sha256"
# The downloaded binary passed checksum verification before replacement.
# A prior self-update's signature cannot authenticate this new installation.
# Preserve the independently provisioned release verification key.
rm -f "${ENV_DIR}/binary.sig"

# ── Create directories ───────────────────────────────────────────────────────
# systemd's StateDirectory=/LogsDirectory= also create these, but doing it here
# keeps a manual (non-systemd) run working too.
if [[ -L "$LOG_DIR" ]]; then
    echo "ERROR: refusing symlink log directory ${LOG_DIR}." >&2
    exit 1
fi
mkdir -p "$ENV_DIR" "$LOG_DIR" "$STATE_DIR"
chmod 700 "$STATE_DIR"
chmod 700 "$LOG_DIR"
# The config dir holds agent.env (enrollment token + backend URL), the mTLS
# client key (agent.key) and CA certs.  Make it owner-only so an unprivileged
# user cannot even enumerate which sensitive files are present.
chmod 700 "$ENV_DIR"

# Control-channel hardening (fail-closed). Provision BEFORE first start:
#   - ${ENV_DIR}/ca.crt              PEM CA that pins the backend. REQUIRED unless
#                                    TRAPD_TLS_ALLOW_SYSTEM_ROOTS=1 is set; without
#                                    it the agent refuses to connect at all.
#   - ${ENV_DIR}/command_signing.pub raw 32-byte Ed25519 public key used to verify
#                                    BOTH signed response-commands AND the remote
#                                    config; without it remote config is rejected.

# ── Write agent.env (from env vars if provided) ──────────────────────────────
ENV_FILE="${ENV_DIR}/agent.env"

# Strip any trailing slash from the backend URL so the agent never builds
# double-slash request paths.
TRAPD_BACKEND_URL="${TRAPD_BACKEND_URL:-}"
TRAPD_BACKEND_URL="${TRAPD_BACKEND_URL%/}"

if [[ -n "${TRAPD_BACKEND_URL}" && -n "${TRAPD_ENROLL_TOKEN:-}" ]]; then
    echo "Writing agent config to ${ENV_FILE}..."
    cat > "$ENV_FILE" <<ENVEOF
TRAPD_BACKEND_URL=${TRAPD_BACKEND_URL}
TRAPD_ENROLL_TOKEN=${TRAPD_ENROLL_TOKEN}
TRAPD_OUTPUT=file
RUST_LOG=info
ENVEOF
    chmod 600 "$ENV_FILE"
    echo "Config written — agent will enroll automatically on first start."
elif [[ -f "$ENV_FILE" ]]; then
    echo "Keeping existing ${ENV_FILE} (not overwriting)."
else
    echo ""
    echo "⚠️  TRAPD_BACKEND_URL or TRAPD_ENROLL_TOKEN not set."
    echo "   Edit ${ENV_FILE} before starting the agent:"
    cat > "$ENV_FILE" <<ENVEOF
TRAPD_BACKEND_URL=https://your-backend.example.com
TRAPD_ENROLL_TOKEN=enroll_xxxx
TRAPD_OUTPUT=file
RUST_LOG=info
ENVEOF
    chmod 600 "$ENV_FILE"
fi

# ── Write trapd-agent.service (hardened, $HOME-independent) ───────────────────
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=TRAPD Security Agent
Documentation=https://github.com/trapd-cloud/trapd-agent
After=network.target network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/trapd-agent
Restart=always
RestartSec=5
TimeoutStopSec=30
UMask=0077

Environment=TRAPD_OUTPUT=file
Environment=RUST_LOG=info
# Canonical, \$HOME-independent locations.  Setting these explicitly means the
# agent never depends on systemd providing \$HOME (it does not for system
# services) — this was the historical enrollment crash-loop root cause.
Environment=TRAPD_STATE_DIR=${STATE_DIR}
Environment=TRAPD_CONFIG_DIR=${ENV_DIR}
Environment=TRAPD_LOG_DIR=${LOG_DIR}
Environment=HOME=${STATE_DIR}
Environment=TRAPD_EBPF_PATH=${EBPF_INSTALL_BIN}
EnvironmentFile=-/etc/trapd/agent.env

# systemd creates/owns these with correct permissions on every start.
StateDirectory=trapd
StateDirectoryMode=0700
LogsDirectory=trapd
LogsDirectoryMode=0700
ConfigurationDirectory=trapd

# ── Hardening ────────────────────────────────────────────────────────────────
ProtectSystem=strict
# read-only (not hidden): FIM and ransomware-watch must see /home and /root,
# while the agent itself still cannot modify them.
ProtectHome=read-only
# false: the agent must watch the REAL /tmp for ransomware/dropper activity. A
# private tmpfs is a separate filesystem (own inodes) and would hide all host
# /tmp writes — unlike the bind-mounted, read-only /home above where inotify
# still sees changes.
PrivateTmp=false
ReadWritePaths=-/etc/trapd -/var/lib/trapd -/var/log/trapd
NoNewPrivileges=true
# Capabilities for eBPF loading, network containment and file quarantine.
# CAP_DAC_READ_SEARCH lets the (root) agent read root-owned/0640 logs such as
# /var/log/auth.log and hash files under /home, /root for FIM (read-only).
# CAP_KILL permits response signals to processes owned by other users.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_IPC_LOCK CAP_LINUX_IMMUTABLE CAP_DAC_READ_SEARCH CAP_KILL CAP_CHOWN CAP_FOWNER
MemoryDenyWriteExecute=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
ProtectControlGroups=true
SystemCallFilter=@system-service @network-io @file-system @process bpf perf_event_open
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

# ── Optional: honeytoken drop-in (opt-in) ────────────────────────────────────
# The base unit above is read-only for /home and /root, so decoys planted there
# fail. Installed only on request, because it widens what a compromised agent
# could modify. Kept on later runs, so a re-install does not silently drop it.
if [[ "${TRAPD_ENABLE_DECEPTION:-}" == "1" ]]; then
    install -d -m 0755 "$DECEPTION_DROPIN_DIR"
    cat > "$DECEPTION_DROPIN_FILE" <<'EOF'
# Opt-in: lets the agent plant honeytoken decoys on this host. Keep identical to
# the [Service] section of deploy/trapd-agent-deception.conf (checked in CI).
[Service]
ProtectSystem=full
ProtectHome=false
# Merged with the base unit's CapabilityBoundingSet.
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER
EOF
    chmod 644 "$DECEPTION_DROPIN_FILE"
    echo "Honeytoken drop-in installed (${DECEPTION_DROPIN_FILE})."
elif [[ -f "$DECEPTION_DROPIN_FILE" ]]; then
    echo "Keeping existing honeytoken drop-in (${DECEPTION_DROPIN_FILE})."
fi

# ── Install already-verified legacy updater (manual recovery only) ───────────
install -m 0755 "$RELEASE_STAGE/trapd-update.sh" "$UPDATE_BIN"

# ── Write update service + timer ─────────────────────────────────────────────
cat > "$UPDATE_SERVICE_FILE" <<'EOF'
[Unit]
Description=TRAPD Agent Auto-Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/trapd-update
EOF

cat > "$UPDATE_TIMER_FILE" <<'EOF'
[Unit]
Description=Daily TRAPD Agent Auto-Update

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# ── Signed self-update: apply helper ─────────────────────────────────────────
# The agent runs with ProtectSystem=strict and cannot write /usr/local/bin. It
# only stages a verified update under /var/lib/trapd/update/. This path unit
# starts a short-lived root helper (the *current* binary) that re-verifies the
# signatures, swaps the binary, restarts the agent and rolls back if the new
# version does not report healthy.
APPLY_SERVICE_FILE="/etc/systemd/system/trapd-agent-update.service"
APPLY_PATH_FILE="/etc/systemd/system/trapd-agent-update.path"

cat > "$APPLY_SERVICE_FILE" <<'EOF'
[Unit]
Description=TRAPD Agent apply staged update
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/trapd-agent --apply-update
Environment=TRAPD_STATE_DIR=/var/lib/trapd
Environment=TRAPD_CONFIG_DIR=/etc/trapd
Environment=TRAPD_LOG_DIR=/var/log/trapd
Environment=RUST_LOG=info
TimeoutStartSec=300
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/usr/local/bin /usr/lib/trapd-agent /var/lib/trapd /etc/trapd
EOF

cat > "$APPLY_PATH_FILE" <<'EOF'
[Unit]
Description=Watch for a staged TRAPD Agent update

[Path]
PathChanged=/var/lib/trapd/update/staged.offer.json
Unit=trapd-agent-update.service

[Install]
WantedBy=multi-user.target
EOF

# ── Logrotate config ──────────────────────────────────────────────────────────
cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/trapd/events.ndjson {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 0600 root root
}
EOF

# ── Enable services ───────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now trapd-agent
systemctl enable --now trapd-agent-update.path
# The signed in-agent channel owns automatic rollout. Never enable the legacy
# timer as a fallback when trust provisioning is missing.
systemctl disable --now trapd-update.timer 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "✅ TRAPD Agent ${LATEST_TAG} installed and started."
echo ""
if systemctl is-active --quiet trapd-agent; then
    echo "   Status: running"
    echo "   Logs:   journalctl -u trapd-agent -f"
else
    echo "   Status: check 'journalctl -u trapd-agent' for errors"
fi
