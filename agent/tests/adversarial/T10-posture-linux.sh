#!/usr/bin/env bash
# T10 (Linux): weaken ptrace_scope, then restore.
# Expected: selfprotect.platform_posture_changed (high, key yama_ptrace_scope) within
# 15 min (the next posture round), info (strengthened) after restore.
# Fast path: restart the agent after the change, the start-up round compares at once.
set -euo pipefail
[ "${TRAPD_ADVERSARIAL_OK:-}" = "1" ] || { echo "refusing: set TRAPD_ADVERSARIAL_OK=1"; exit 1; }
F=/proc/sys/kernel/yama/ptrace_scope
[ -w "$F" ] || { echo "yama not available"; exit 1; }
OLD=$(cat "$F")
trap 'echo "$OLD" > "$F"' EXIT
[ "$OLD" -ge 1 ] || { echo "ptrace_scope already 0; set it to 1 first"; exit 1; }
echo 0 > "$F"
echo "ptrace_scope=0; wait for the next posture round (<= 15 min) or restart the agent"
read -r -p "press enter to restore" _
