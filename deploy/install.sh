#!/usr/bin/env bash
set -euo pipefail

REPO="trapd-cloud/trapd-agent"
BINARY_NAME="trapd-agent-linux-x86_64"
INSTALL_BIN="/usr/local/bin/trapd-agent"
UPDATE_BIN="/usr/local/bin/trapd-update"
SERVICE_FILE="/etc/systemd/system/trapd-agent.service"
UPDATE_SERVICE_FILE="/etc/systemd/system/trapd-update.service"
UPDATE_TIMER_FILE="/etc/systemd/system/trapd-update.timer"
LOGROTATE_FILE="/etc/logrotate.d/trapd"
ENV_DIR="/etc/trapd"
LOG_DIR="/var/log/trapd"

# ── Preflight checks ────────────────────────────────────────────────────────
for cmd in curl systemctl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' is required but not installed." >&2
        exit 1
    fi
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)." >&2
    exit 1
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

# ── Download binary ─────────────────────────────────────────────────────────
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${BINARY_NAME}"
TMP_BINARY="/tmp/trapd-agent-${LATEST_TAG}"

echo "Downloading ${BINARY_NAME}..."
curl -fL "$DOWNLOAD_URL" -o "$TMP_BINARY"
chmod +x "$TMP_BINARY"
mv "$TMP_BINARY" "$INSTALL_BIN"
echo "Installed to ${INSTALL_BIN}"

# ── Create directories ───────────────────────────────────────────────────────
mkdir -p "$ENV_DIR" "$LOG_DIR"

# ── Write trapd-agent.service ────────────────────────────────────────────────
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=TRAPD Security Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/trapd-agent
Restart=always
RestartSec=5
Environment=TRAPD_OUTPUT=file
Environment=RUST_LOG=info
EnvironmentFile=-/etc/trapd/agent.env

[Install]
WantedBy=multi-user.target
EOF

# ── Write trapd-update script ────────────────────────────────────────────────
cat > "$UPDATE_BIN" <<UPDATER
#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO}"
BINARY_NAME="${BINARY_NAME}"
INSTALL_BIN="${INSTALL_BIN}"

log() { echo "\$(date -u +"%Y-%m-%dT%H:%M:%SZ") trapd-update: \$*"; }

LATEST_TAG=\$(curl -sf "https://api.github.com/repos/\${REPO}/releases/latest" \\
    | grep '"tag_name"' \\
    | head -1 \\
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [[ -z "\$LATEST_TAG" ]]; then
    log "ERROR: Could not fetch latest release tag." >&2
    exit 1
fi

CURRENT_VERSION=\$("\$INSTALL_BIN" --version 2>/dev/null | awk '{print \$2}' || echo "unknown")
LATEST_VERSION="\${LATEST_TAG#v}"

if [[ "\$CURRENT_VERSION" == "\$LATEST_VERSION" ]]; then
    log "Already up to date (\$CURRENT_VERSION)."
    exit 0
fi

log "Updating \$CURRENT_VERSION → \$LATEST_TAG..."
DOWNLOAD_URL="https://github.com/\${REPO}/releases/download/\${LATEST_TAG}/\${BINARY_NAME}"
TMP_BINARY="/tmp/trapd-agent-new"
curl -fL "\$DOWNLOAD_URL" -o "\$TMP_BINARY"
chmod +x "\$TMP_BINARY"
mv "\$TMP_BINARY" "\$INSTALL_BIN"
systemctl restart trapd-agent
log "Updated to \${LATEST_TAG}."
UPDATER

chmod +x "$UPDATE_BIN"
echo "Installed updater to ${UPDATE_BIN}"

# ── Write trapd-update.service ───────────────────────────────────────────────
cat > "$UPDATE_SERVICE_FILE" <<'EOF'
[Unit]
Description=TRAPD Agent Auto-Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/trapd-update
EOF

# ── Write trapd-update.timer ─────────────────────────────────────────────────
cat > "$UPDATE_TIMER_FILE" <<'EOF'
[Unit]
Description=Daily TRAPD Agent Auto-Update

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# ── Logrotate config ──────────────────────────────────────────────────────────
if [[ -f "$(dirname "$0")/logrotate.conf" ]]; then
    cp "$(dirname "$0")/logrotate.conf" "$LOGROTATE_FILE"
else
    cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/trapd/events.ndjson {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
fi
echo "Installed logrotate config to ${LOGROTATE_FILE}"

# ── Enable services ───────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now trapd-agent
systemctl enable --now trapd-update.timer

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "✅ TRAPD Agent ${LATEST_TAG} installed."
echo ""
echo "Configure credentials:"
echo "  nano ${ENV_DIR}/agent.env"
echo ""
echo "  TRAPD_BACKEND_URL=https://your-backend.com"
echo "  TRAPD_TOKEN=your-token"
echo ""
echo "  systemctl restart trapd-agent"
