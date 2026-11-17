#!/usr/bin/env bash
# T4 (Linux): silence the agent with an iptables owner-match DROP rule.
# Expected: selfprotect.network_silenced (high, source iptables, reason uid)
# within ~65 s. The rule is removed on exit.
#
# Requires: root on a disposable test host, TRAPD_ADVERSARIAL_OK=1,
# AGENT_UID (default 0, the uid the agent runs as).
set -euo pipefail
[ "${TRAPD_ADVERSARIAL_OK:-}" = "1" ] || { echo "Refusing to run: set TRAPD_ADVERSARIAL_OK=1 on a disposable test host." >&2; exit 2; }
uid="${AGENT_UID:-0}"
rule=(OUTPUT -m owner --uid-owner "$uid" -m comment --comment trapd-adversarial-t4 -j DROP)
cleanup() { iptables -D "${rule[@]}" 2>/dev/null || true; echo "rule removed"; }
trap cleanup EXIT
iptables -A "${rule[@]}"
echo "iptables DROP for uid $uid added; waiting 75 s for the network guard..."
sleep 75
echo "Verify: selfprotect.network_silenced, filter name 'trapd-adversarial-t4', reason uid."
