#!/usr/bin/env bash
# T5 (Linux): redirect the backend host through /etc/hosts.
# Expected: selfprotect.backend_redirected (high, vector hosts) within ~65 s.
# Usage: BACKEND_HOST=api.example.eu TRAPD_ADVERSARIAL_OK=1 ./t5_hosts_redirect.sh
set -euo pipefail
[ "${TRAPD_ADVERSARIAL_OK:-}" = "1" ] || { echo "Refusing to run: set TRAPD_ADVERSARIAL_OK=1 on a disposable test host." >&2; exit 2; }
: "${BACKEND_HOST:?set BACKEND_HOST to the agent's backend host name}"
backup="$(mktemp)"
cp -p /etc/hosts "$backup"
cleanup() { cat "$backup" > /etc/hosts; rm -f "$backup"; echo "hosts restored"; }
trap cleanup EXIT
echo "203.0.113.66 $BACKEND_HOST # trapd adversarial T5" >> /etc/hosts
echo "hosts entry added; waiting 75 s for the network guard..."
sleep 75
echo "Verify: selfprotect.backend_redirected, vector hosts, subject '203.0.113.66 $BACKEND_HOST'."
