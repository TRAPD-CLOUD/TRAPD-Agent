#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
fixture_file=$(mktemp)
trap 'rm -f "$fixture_file"' EXIT
OCSF_CONTRACT_FIXTURE_FILE="$fixture_file" cargo test -p trapd-schema --test ocsf_contract emit_contract -- --exact
python3 scripts/ocsf/validate.py "$fixture_file"
