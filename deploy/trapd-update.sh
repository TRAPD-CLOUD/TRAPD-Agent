#!/usr/bin/env bash
# TRAPD Agent auto-updater.
#
# Installed once by deploy/install.sh to /usr/local/bin/trapd-update and run
# on demand via `sudo trapd-update`. The legacy daily timer is disabled.
#
# Manual legacy recovery only. Automatic updates use the signed agent channel.
# All artifacts, including this script's self-refresh, require the independently
# provisioned release key. No checksum-only fallback is permitted.
set -euo pipefail

REPO="trapd-cloud/trapd-agent"
BINARY_NAME="trapd-agent-linux-x86_64"
EBPF_BINARY_NAME="trapd-agent-exec"
INSTALL_BIN="/usr/local/bin/trapd-agent"
EBPF_INSTALL_DIR="/usr/lib/trapd-agent"
EBPF_INSTALL_BIN="${EBPF_INSTALL_DIR}/trapd-agent-exec"
UPDATE_BIN="/usr/local/bin/trapd-update"
CONFIG_DIR="/etc/trapd"

log() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") trapd-update: $*"; }

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)." >&2
    exit 1
fi
RELEASE_KEY_FILE="/etc/trapd-release/release_signing.pub"
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
prepare_release_verification update
CURRENT_VERSION="$("$INSTALL_BIN" --version | awk '{print $2}' | sed 's/^v//')"
[[ -n "$CURRENT_VERSION" ]] || { log "ERROR: installed version unavailable; refusing update." >&2; exit 1; }

LATEST_TAG=$(curl -sf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [[ -z "$LATEST_TAG" ]]; then
    log "ERROR: Could not fetch latest release tag." >&2
    exit 1
fi

# Verify ALL artifacts before replacing the updater or agent, even if the
# advertised version matches. Failed/missing signatures abort the whole run.
stage_verified_release
if [[ -z "${TRAPD_UPDATE_NO_SELF_REFRESH:-}" ]] && ! cmp -s "$RELEASE_STAGE/trapd-update.sh" "$0"; then
    log "Installing verified updater (${LATEST_TAG}) and re-running."
    install -m 0755 "$RELEASE_STAGE/trapd-update.sh" "${UPDATE_BIN}.new"
    mv -f "${UPDATE_BIN}.new" "$UPDATE_BIN"
    rm -rf "$RELEASE_STAGE"
    TRAPD_UPDATE_NO_SELF_REFRESH=1 exec "$UPDATE_BIN" "$@"
fi

if [[ "$CURRENT_VERSION" == "${LATEST_TAG#v}" ]]; then
    log "Already up to date (${CURRENT_VERSION})."
    exit 0
fi

log "Updating ${CURRENT_VERSION} → ${LATEST_TAG}..."
install -m 0755 "$RELEASE_STAGE/$BINARY_NAME" "${INSTALL_BIN}.new"
install -d -m 0755 "$EBPF_INSTALL_DIR"
install -m 0644 "$RELEASE_STAGE/$EBPF_BINARY_NAME" "${EBPF_INSTALL_BIN}.new"
mv -f "${EBPF_INSTALL_BIN}.new" "$EBPF_INSTALL_BIN"
mv -f "${INSTALL_BIN}.new" "$INSTALL_BIN"
command -v restorecon &>/dev/null && restorecon -F "$INSTALL_BIN" "$EBPF_INSTALL_BIN" || true
mkdir -p "$CONFIG_DIR"
echo "sha256:$(sha256sum "$INSTALL_BIN" | awk '{print $1}')" > "$CONFIG_DIR/binary.sha256"
chmod 600 "$CONFIG_DIR/binary.sha256"
systemctl restart trapd-agent
log "Updated to ${LATEST_TAG}."
