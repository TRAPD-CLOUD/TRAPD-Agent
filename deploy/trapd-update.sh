#!/usr/bin/env bash
# TRAPD Agent auto-updater.
#
# Installed once by deploy/install.sh to /usr/local/bin/trapd-update and run
# daily by trapd-update.timer (plus on demand via `sudo trapd-update`).
#
# ── Why this script re-downloads and replaces itself on every run ─────────────
# Earlier versions of this script were generated inline by install.sh (baked
# into a heredoc) and installed exactly once. A local copy on an already-
# installed host therefore never picked up bug fixes made here later — for
# example, the "refresh the self-integrity baseline after replacing the
# binary" step below was added on 2026-06-01, but any host installed before
# that date kept running an updater that swapped in a new binary WITHOUT
# refreshing /etc/trapd/binary.sha256, and the agent's own binary_integrity
# check then treated its own upgrade as tampering (BINARY INTEGRITY VIOLATION,
# permanent crash-loop) — invisible until the next release actually shipped.
# That failure mode cannot be fixed by "fixing the code" alone, because the
# fix would still never reach hosts already running a stale copy. So this
# script's FIRST action is to fetch the current release's copy of itself,
# verify it, and — if different — replace itself and re-exec, so every run
# always executes the latest logic before doing anything else.
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

# Verify a downloaded artifact against its published SHA256 before installing it
# as root. A missing or mismatching checksum aborts the run so a tampered
# release asset (or a MITM/CDN compromise) can never replace a trusted binary
# or this very script.
verify_checksum() {
    local file="$1" sums_url="$2" sums_file
    sums_file="$(mktemp)"
    if ! curl -fsSL "$sums_url" -o "$sums_file"; then
        rm -f "$sums_file"
        log "ERROR: could not download checksum ($sums_url) — refusing unverified artifact." >&2
        exit 1
    fi
    local expected actual
    expected="$(awk '{print $1}' "$sums_file" | head -1)"
    actual="$(sha256sum "$file" | awk '{print $1}')"
    rm -f "$sums_file"
    if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        log "ERROR: SHA256 mismatch for ${file##*/} — refusing to install." >&2
        exit 1
    fi
}

LATEST_TAG=$(curl -sf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [[ -z "$LATEST_TAG" ]]; then
    log "ERROR: Could not fetch latest release tag." >&2
    exit 1
fi

# ── Self-refresh ────────────────────────────────────────────────────────────
# TRAPD_UPDATE_NO_SELF_REFRESH guards against a re-exec loop; it is set right
# before the exec below, so a second pass through this script (running the
# freshly-installed copy) skips straight to the version check.
if [[ -z "${TRAPD_UPDATE_NO_SELF_REFRESH:-}" ]]; then
    SELF_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/trapd-update.sh"
    TMP_SELF="$(mktemp /tmp/trapd-update.XXXXXXXX)"
    # verify_checksum calls `exit` on mismatch, which — called directly — would
    # abort this entire run over a failed *self-refresh*, not just skip it. Run
    # it in a subshell so that `exit` only ends the subshell; its exit status
    # still drives the `&&` chain normally.
    if curl -fsSL "$SELF_URL" -o "$TMP_SELF" 2>/dev/null \
        && (verify_checksum "$TMP_SELF" "${SELF_URL}.sha256") 2>/dev/null \
        && ! cmp -s "$TMP_SELF" "$0"; then
        log "Updater itself changed (${LATEST_TAG}) — replacing and re-running."
        chmod +x "$TMP_SELF"
        mv -f "$TMP_SELF" "$UPDATE_BIN"
        TRAPD_UPDATE_NO_SELF_REFRESH=1 exec "$UPDATE_BIN" "$@"
    fi
    rm -f "$TMP_SELF"
fi

# `trapd-agent --version` prints "trapd-agent v0.4.0"; take field 2 and strip the
# leading "v" so it compares cleanly against the de-prefixed release tag below.
# Without the strip, "v0.4.0" never equals "0.4.0" and the gate re-downloads daily.
CURRENT_VERSION=$("$INSTALL_BIN" --version 2>/dev/null | awk '{print $2}' | sed 's/^v//' || echo "unknown")
LATEST_VERSION="${LATEST_TAG#v}"

if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
    log "Already up to date (${CURRENT_VERSION})."
    exit 0
fi

log "Updating ${CURRENT_VERSION} → ${LATEST_TAG}..."

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${BINARY_NAME}"
TMP_BINARY="$(mktemp /tmp/trapd-agent.XXXXXXXX)"
curl -fL "$DOWNLOAD_URL" -o "$TMP_BINARY"
verify_checksum "$TMP_BINARY" "${DOWNLOAD_URL}.sha256"
chmod +x "$TMP_BINARY"
mv -f "$TMP_BINARY" "$INSTALL_BIN"

# Refresh the self-integrity baseline to the freshly installed (and already
# checksum-verified) binary. Without this, the agent's selfprotect::binary_integrity
# check reads the OLD baseline at ${CONFIG_DIR}/binary.sha256, sees its own legit
# update as a "BINARY INTEGRITY VIOLATION", and refuses to start (crash loop).
# The download above is verified against the release .sha256, so this baseline is
# anchored to a trusted artifact — it does not weaken tamper detection at rest.
mkdir -p "$CONFIG_DIR"
echo "sha256:$(sha256sum "$INSTALL_BIN" | awk '{print $1}')" > "$CONFIG_DIR/binary.sha256"
chmod 600 "$CONFIG_DIR/binary.sha256"

EBPF_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${EBPF_BINARY_NAME}"
TMP_EBPF="$(mktemp /tmp/trapd-agent-exec.XXXXXXXX)"
if curl -fL "$EBPF_URL" -o "$TMP_EBPF" 2>/dev/null; then
    verify_checksum "$TMP_EBPF" "${EBPF_URL}.sha256"
    chmod 644 "$TMP_EBPF"
    mkdir -p "$EBPF_INSTALL_DIR"
    mv -f "$TMP_EBPF" "$EBPF_INSTALL_BIN"
    log "eBPF binary updated."
fi

systemctl restart trapd-agent
log "Updated to ${LATEST_TAG}."
