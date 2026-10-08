#!/bin/bash
set -euo pipefail
mkdir -p /sys/kernel/tracing
mount -t tracefs tracefs /sys/kernel/tracing || true
export TRAPD_OFFLINE=1 TRAPD_OUTPUT=stdout TRAPD_STATE_DIR=/test/state TRAPD_LOG_DIR=/test/logs TRAPD_EBPF_PATH=/test/trapd-agent-exec
/test/agent > /test/events.ndjson 2>/test/agent.log & agent=$!
echo "$agent" > /test/agent.pid
trap 'kill -TERM "$agent" 2>/dev/null || true' EXIT
sleep 8
/test/probe /test/decoy.txt 2097152
/test/probe /test/decoy.txt 65536
ln -s decoy-invalid /test/invalid-alias
/test/failed-exec /test/invalid-alias
cat /test/decoy.txt >/dev/null
stat /test/decoy.txt >/dev/null
sleep 2
cat /test/decoy.txt >/dev/null
sleep 2
if [[ "$MODE" == inode ]]; then
ln /test/decoy.txt /test/alias.txt
cat /test/alias.txt >/dev/null
fi
sleep 2
if [[ "$MODE" == inode ]]; then
ln -s decoy.txt /test/link.txt
cd /test
cat link.txt >/dev/null
fi
sleep 2
/test/probe /test/decoy.txt 1
/test/probe /test/decoy.txt 2
/test/probe /test/decoy.txt 513
if [[ "$MODE" == inode ]]; then
ln /test/decoy-exec /test/exec-alias
ln -s decoy-exec /test/exec-link
./exec-alias /test/decoy.txt 0
./exec-link /test/decoy.txt 0
/test/thread-exec ./exec-alias /test/decoy.txt
fi
mv /test/decoy.txt /test/decoy-renamed.txt
sleep 4
kill -TERM "$agent"
# Give the collector a bounded drain period.
for i in {1..25}; do kill -0 "$agent" 2>/dev/null || break; sleep 1; done
kill -KILL "$agent" 2>/dev/null || true
wait "$agent" 2>/dev/null || true
trap - EXIT
