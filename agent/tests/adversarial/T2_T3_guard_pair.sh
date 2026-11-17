#!/usr/bin/env bash
# Adversarial rows T2 (kill) and T3 (suspend) against the guard pair on Linux.
#
#   TRAPD_ADVERSARIAL_OK=1 sudo -E ./T2_T3_guard_pair.sh <kill|suspend> <agent|guard>
#
# kill     kill -9 the target; its peer must restart it and emit
#          selfprotect.peer_lost (reason "died").
# suspend  kill -STOP the target (agent alive but mute); its peer must notice
#          within ~10 s, kill and restart it, and emit selfprotect.peer_lost
#          (reason "hung").
#
# Safe: only signals the two TRAPD units, resumes a stopped process on exit and
# leaves both services running. Needs root, systemd and the deb/install.sh
# install (units trapd-agent and trapd-guard).
set -euo pipefail

[[ "${TRAPD_ADVERSARIAL_OK:-}" == 1 ]] || { echo "refusing: set TRAPD_ADVERSARIAL_OK=1" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
mode="${1:-}"; target="${2:-agent}"
[[ "$mode" == kill || "$mode" == suspend ]] || { echo "usage: $0 <kill|suspend> <agent|guard>" >&2; exit 2; }
[[ "$target" == agent || "$target" == guard ]] || { echo "target must be agent or guard" >&2; exit 2; }
other=$([[ "$target" == agent ]] && echo guard || echo agent)
unit="trapd-$target.service"
events=/var/log/trapd/events.ndjson

pid_of() { systemctl show -p MainPID --value "trapd-$1.service"; }
old_pid="$(pid_of "$target")"
other_pid="$(pid_of "$other")"
[[ "$old_pid" -gt 1 && "$other_pid" -gt 1 ]] || { echo "both services must be running first" >&2; exit 2; }
before="$(wc -l < "$events" 2>/dev/null || echo 0)"

cleanup() { kill -CONT "$old_pid" 2>/dev/null || true; }
trap cleanup EXIT

if [[ "$mode" == kill ]]; then
    kill -KILL "$old_pid"
else
    kill -STOP "$old_pid"
fi
echo "T2/T3 $mode $target (pid $old_pid) at $(date -u +%T)"

deadline=$((SECONDS + 60))
new_pid=
while (( SECONDS < deadline )); do
    cur="$(pid_of "$target")"
    if [[ "$cur" -gt 1 && "$cur" != "$old_pid" ]] && systemctl is-active --quiet "$unit"; then new_pid="$cur"; break; fi
    sleep 1
done
[[ -n "$new_pid" ]] || { echo "FAIL: $target was not restarted within 60 s"; exit 1; }
echo "ok: $target restarted (pid $new_pid)"

want_reason=$([[ "$mode" == kill ]] && echo died || echo hung)
for _ in $(seq 1 30); do
    if tail -n +"$((before + 1))" "$events" 2>/dev/null | grep -F 'selfprotect.peer_lost' | grep -F "\"peer\":\"$target\"" | grep -qF "\"reason\":\"$want_reason\""; then
        echo "PASS: selfprotect.peer_lost (peer=$target reason=$want_reason) was emitted"
        exit 0
    fi
    sleep 1
done
echo "FAIL: no selfprotect.peer_lost event (peer=$target reason=$want_reason) in $events" >&2
echo "      (needs TRAPD_OUTPUT=file; otherwise look for the event in the backend)" >&2
exit 1
