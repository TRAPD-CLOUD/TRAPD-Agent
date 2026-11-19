#!/usr/bin/env bash
# T11 (Linux): move the wall clock and restore it.
# Expected: selfprotect.time_jump (medium) within ~30 s, direction=backward then forward.
set -euo pipefail
[ "${TRAPD_ADVERSARIAL_OK:-}" = "1" ] || { echo "refusing: set TRAPD_ADVERSARIAL_OK=1"; exit 1; }
[ "$(id -u)" = "0" ] || { echo "needs root"; exit 1; }
command -v timedatectl >/dev/null && NTP=$(timedatectl show -p NTP --value) || NTP=no
restore() {
  # Put the clock back by the same amount we moved it (sleep time included).
  date -s "@$(( $(date +%s) + 3600 ))" >/dev/null
  [ "$NTP" = "yes" ] && timedatectl set-ntp true || true
}
trap restore EXIT
[ "$NTP" = "yes" ] && timedatectl set-ntp false
date -s "@$(( $(date +%s) - 3600 ))" >/dev/null   # one hour back
sleep 70                                          # >= 2 agent clock ticks
echo "done; restoring clock (a second time_jump, forward, is expected)"
