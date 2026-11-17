#!/usr/bin/env bash
# T1 (WP1): a copied credentials.json must not be usable from another host.
# Safe: read-only on the agent state, one unauthenticated-equivalent heartbeat
# probe, nothing is created or modified.
set -euo pipefail
[ "${TRAPD_ADVERSARIAL_OK:-}" = "1" ] || { echo "refusing: set TRAPD_ADVERSARIAL_OK=1"; exit 2; }
: "${TRAPD_BACKEND_URL:?set TRAPD_BACKEND_URL}"
CREDS="${TRAPD_STATE_DIR:-/var/lib/trapd}/credentials.json"
secret=$(jq -r '.agent_secret // empty' "$CREDS")
agent_id=$(jq -r '.agent_id' "$CREDS")
if [ -z "$secret" ]; then
  echo "PASS: credentials.json holds no bearer secret (bound identity); a copy is useless"
  exit 0
fi
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $secret" -H 'Content-Type: application/json' -d '{}' \
  "${TRAPD_BACKEND_URL%/}/api/v1/agents/${agent_id}/heartbeat")
if [ "$code" = "401" ]; then
  echo "PASS: the copied secret is rejected (HTTP 401)"
else
  echo "FAIL: copied secret accepted or unexpected status ($code); identity not bound?"
  exit 1
fi
