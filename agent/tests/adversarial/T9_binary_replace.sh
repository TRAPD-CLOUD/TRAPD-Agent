#!/usr/bin/env bash
# Adversarial row T9: replace the installed agent binary with a modified copy
# and restart the service.
#
#   TRAPD_ADVERSARIAL_OK=1 sudo -E ./T9_binary_replace.sh
#
# Expected:
#   * the agent refuses to start (fail-closed binary integrity) and first
#     sends selfprotect.binary_tampered (high);
#   * the guard does not restart a tampered agent and records
#     selfprotect.peer_binary_tampered (critical); that record is delivered by
#     the agent's next healthy start (after this script restores the binary);
#   * journald: SYSLOG_IDENTIFIER=trapd-agent-security with
#     TRAPD_RULE_ID=selfprotect.binary_tampered, written before any network.
#
# Safe: the original binary is backed up first and restored on exit (also on
# error), then the service is started again.
set -euo pipefail

[[ "${TRAPD_ADVERSARIAL_OK:-}" == 1 ]] || { echo "refusing: set TRAPD_ADVERSARIAL_OK=1" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }

bin="$(systemctl show -p ExecStart --value trapd-agent.service | sed -n 's/.*path=\([^ ;]*\).*/\1/p')"
bin="${bin:-/usr/local/bin/trapd-agent}"
[[ -f "$bin" ]] || { echo "agent binary not found at $bin" >&2; exit 2; }
backup="$(mktemp /var/tmp/trapd-agent.orig.XXXXXX)"
cp -p "$bin" "$backup"
reference="$(mktemp /var/tmp/trapd-agent.ref.XXXXXX)"
cp -p "$bin" "$reference"
since="$(date '+%Y-%m-%d %H:%M:%S')"

restore() {
    # Stop first: the running binary cannot be overwritten (ETXTBSY), and a
    # rename over it is only safe once nothing restarts it meanwhile.
    systemctl stop trapd-agent.service trapd-guard.service 2>/dev/null || true
    if mv -f "$backup" "$bin" && cmp -s "$bin" "$reference"; then
        echo "original binary restored"
    else
        echo "ERROR: restore failed; the original is at $backup" >&2
    fi
    rm -f "$reference"
    systemctl reset-failed trapd-agent.service trapd-guard.service 2>/dev/null || true
    systemctl start trapd-agent.service || true
}
trap restore EXIT

# Same binary plus one trailing byte: still runs, but its hash no longer
# matches the signed baseline.
tampered="$(mktemp /var/tmp/trapd-agent.tampered.XXXXXX)"
cp -p "$bin" "$tampered"
printf '\0' >> "$tampered"
# Replace by rename: the running file cannot be written in place (ETXTBSY).
chmod 0755 "$tampered"
mv -f "$tampered" "$bin"
echo "T9: replaced $bin with a modified copy at $(date -u +%T)"

systemctl restart trapd-agent.service || true
sleep 20

# The refused binary does not run the sensor; its process may still show as
# active while the restart-loop guard spaces the retries, so the verdict is
# the integrity log line plus the local security entry.
refused="$(journalctl -q -u trapd-agent --since "$since" -o cat 2>/dev/null | grep -c 'BINARY INTEGRITY VIOLATION' || true)"
hits="$(journalctl -q --since "$since" SYSLOG_IDENTIFIER=trapd-agent-security TRAPD_RULE_ID=selfprotect.binary_tampered -o cat 2>/dev/null | wc -l)"
echo "integrity violations logged: $refused; binary_tampered entries: $hits"
if [[ "$refused" -ge 1 && "$hits" -ge 1 ]]; then
    echo "RESULT: PASS (refused to run and reported)"
else
    echo "RESULT: FAIL (expected a refused start plus a binary_tampered entry)"
    exit 1
fi
