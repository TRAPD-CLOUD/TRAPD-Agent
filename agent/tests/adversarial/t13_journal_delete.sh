#!/usr/bin/env bash
# T13 (WP3): deleting the local tamper journal (or restoring an old copy) before
# its entries reached the backend must be detected server-side.
#
# What it does (Linux, run as root on a bound, enrolled TEST agent):
#   1. stops trapd-agent, backs up tamper_journal.ndjson to a temp dir
#   2. deletes the journal file, starts the agent: it begins a new chain at
#      seq 1 and uploads it; the backend already holds a higher seq
#   3. waits, then stops the agent, puts the ORIGINAL file back, restarts it
# The original file is always restored (also on error), so the agent's chain
# matches the backend again afterwards. Entries created during the test were
# rejected by the backend and are discarded with the temporary file.
set -euo pipefail
[ "${TRAPD_ADVERSARIAL_OK:-}" = "1" ] || { echo "refusing: set TRAPD_ADVERSARIAL_OK=1"; exit 2; }
[ "$(id -u)" = "0" ] || { echo "run as root"; exit 2; }
STATE="${TRAPD_STATE_DIR:-/var/lib/trapd}"
J="$STATE/tamper_journal.ndjson"
[ -f "$J" ] || { echo "no journal at $J (agent not bound yet, or journal disabled)"; exit 2; }
BACKUP="$(mktemp -d)"
cp -p "$J" "$BACKUP/journal"
restore() {
  systemctl stop trapd-agent || true
  cp -p "$BACKUP/journal" "$J"
  systemctl start trapd-agent || true
  rm -rf "$BACKUP"
}
trap restore EXIT
systemctl stop trapd-agent
rm -f "$J"
systemctl start trapd-agent
echo "journal deleted; waiting 90 s for the agent to upload its new chain ..."
sleep 90
echo "RESULT: expected a high finding 'selfprotect.journal_gap' (reason: fork or regression) for this agent."
echo "Verify in the console (Findings) or: select * from findings where finding_type='selfprotect.journal_gap';"
echo "The agent log shows: 'backend rejected the tamper journal'."
