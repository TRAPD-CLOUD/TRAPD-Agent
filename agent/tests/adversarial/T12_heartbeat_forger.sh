#!/usr/bin/env bash
# Adversarial row T12: the agent is stopped and a forger keeps its heartbeat
# alive, so the host still looks "online" in the console.
#
#   TRAPD_ADVERSARIAL_OK=1 TRAPD_BACKEND_URL=https://... TRAPD_AGENT_ID=... \
#   TRAPD_TEST_BEARER=... sudo -E ./T12_heartbeat_forger.sh [minutes]
#
# TRAPD_TEST_BEARER is a bearer the backend accepts for this agent. On a bound
# agent that is a session token, which only the identity key can mint; for the
# test, use a dedicated test agent that is still on its legacy secret, or a
# session token minted with the key by your own tooling (the on-host attacker
# case this row stands for). It is read from the environment only, never
# printed and never written to disk.
#
# Expected (backend side, phase 09 L6):
#   * agent.liveness_echo_missing (high) after two unanswered challenges: the
#     forger receives liveness_nonce values but never sends agent.liveness_echo
#     through the event pipeline;
#   * agent.mute_but_alive (high) after TRAPD_MUTE_AFTER_MINUTES (default 30)
#     if the agent had a telemetry baseline;
#   * selfprotect.tamper_cluster (critical) once both are open.
# The forger claims agent_version 9.9.9 so the backend issues challenges.
#
# Safe: stops only trapd-agent (and with it trapd-guard, PartOf), restarts both
# on exit, sends nothing but heartbeats.
set -euo pipefail

[[ "${TRAPD_ADVERSARIAL_OK:-}" == 1 ]] || { echo "refusing: set TRAPD_ADVERSARIAL_OK=1" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
: "${TRAPD_BACKEND_URL:?set TRAPD_BACKEND_URL}" "${TRAPD_AGENT_ID:?set TRAPD_AGENT_ID}" "${TRAPD_TEST_BEARER:?set TRAPD_TEST_BEARER}"
[[ "$TRAPD_AGENT_ID" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || { echo "TRAPD_AGENT_ID has unexpected characters" >&2; exit 2; }
minutes="${1:-40}"
[[ "$minutes" =~ ^[0-9]+$ && "$minutes" -ge 12 ]] || { echo "minutes must be a number >= 12" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl required" >&2; exit 2; }

url="${TRAPD_BACKEND_URL%/}/api/v1/agents/${TRAPD_AGENT_ID}/heartbeat"
host="$(hostname)"

cleanup() { systemctl start trapd-agent.service || true; echo "agent restarted"; }
trap cleanup EXIT

systemctl stop trapd-agent.service
echo "T12: agent stopped at $(date -u +%T); forging heartbeats for $minutes min"

nonces=0
end=$(( $(date +%s) + minutes * 60 ))
while (( $(date +%s) < end )); do
    body=$(printf '{"agent_id":"%s","hostname":"%s","agent_version":"9.9.9","timestamp":"%s","metrics":{}}' \
        "$TRAPD_AGENT_ID" "$host" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
    # The bearer goes through a header file descriptor, not argv (ps-visible).
    resp=$(curl -sS --max-time 15 -X POST "$url" \
        -H @<(printf 'Authorization: Bearer %s\n' "$TRAPD_TEST_BEARER") \
        -H 'Content-Type: application/json' --data "$body" -w '\n%{http_code}') || resp=$'\n000'
    code="${resp##*$'\n'}"
    if [[ "${resp%$'\n'*}" == *liveness_nonce* ]]; then
        nonces=$((nonces + 1))
    fi
    echo "$(date -u +%T) heartbeat HTTP $code, challenges seen (never echoed): $nonces"
    sleep 60
done

echo "Done. Verify in the console for agent $TRAPD_AGENT_ID:"
echo "  agent.liveness_echo_missing (high), agent.mute_but_alive (high, if baselined),"
echo "  selfprotect.tamper_cluster (critical). PASS = at least the first one is open."
[[ "$nonces" -ge 2 ]] || echo "WARN: fewer than 2 challenges seen; the backend may treat this agent as <= 0.7.9 or the interval is longer than the run"
