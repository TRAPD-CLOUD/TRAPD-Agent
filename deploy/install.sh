#!/bin/bash
set -e

cargo build --release

cp target/release/trapd-agent /usr/local/bin/
mkdir -p /etc/trapd /var/log/trapd
cp deploy/trapd-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now trapd-agent

echo "Done. Edit /etc/trapd/agent.env to set TRAPD_BACKEND_URL and TRAPD_TOKEN"
