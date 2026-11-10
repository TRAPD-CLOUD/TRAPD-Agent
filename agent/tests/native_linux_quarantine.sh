#!/usr/bin/env bash
# Exercise the real restore transaction with a subset of the deployed capabilities.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
for unit in deploy/trapd-agent.service deploy/install.sh; do
    for capability in CAP_CHOWN CAP_FOWNER; do
        grep '^CapabilityBoundingSet=.*CAP_DAC_READ_SEARCH' "$unit" | grep -qw "$capability"
    done
done
binary=$(cargo test --offline -p trapd-agent --no-run --message-format=json | python3 -c '
import json,sys
for line in sys.stdin:
    message=json.loads(line)
    if message.get("reason")=="compiler-artifact" and message.get("profile",{}).get("test") and message.get("target",{}).get("name")=="trapd-agent" and message.get("executable"):
        print(message["executable"])
')
[[ -x "$binary" ]]
# No DAC override, no full root capability set; CHOWN/FOWNER must be sufficient.
docker run --rm --network none --cap-drop ALL --cap-add CHOWN --cap-add FOWNER \
    -v "$binary:/test:ro" ubuntu:24.04 /test \
    prevention::linuxpin::tests::ownership_roundtrip_under_service_capabilities --exact --ignored --nocapture
