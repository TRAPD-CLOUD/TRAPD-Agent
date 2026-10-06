#!/usr/bin/env bash
# The honeytoken drop-in exists twice: as deploy/trapd-agent-deception.conf
# (shipped in the .deb) and as a heredoc inside install.sh, which must work when
# fetched on its own. This fails when the two drift apart, and when the opt-in
# is no longer off by default.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="$HERE/trapd-agent-deception.conf"
INSTALL="$HERE/install.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# [Service] section of the file vs. the heredoc body written by install.sh.
sed -n '/^\[Service\]/,$p' "$CONF" > "$TMP/file.service"
awk '
    /cat > "\$DECEPTION_DROPIN_FILE" <<.EOF.$/ { inside = 1; next }
    inside && /^EOF$/ { exit }
    inside { print }
' "$INSTALL" | sed -n '/^\[Service\]/,$p' > "$TMP/script.service"

[[ -s "$TMP/file.service" && -s "$TMP/script.service" ]] || { echo "FAIL: drop-in section not found" >&2; exit 1; }
diff -u "$TMP/file.service" "$TMP/script.service" || { echo "FAIL: install.sh drop-in differs from $CONF" >&2; exit 1; }
echo "ok   install.sh drop-in matches trapd-agent-deception.conf"

grep -q '^\[Service\]$' "$CONF" && ok=1 || ok=0
[[ "$ok" == 1 ]] || { echo "FAIL: no [Service] section" >&2; exit 1; }
grep -q 'TRAPD_ENABLE_DECEPTION:-}" == "1"' "$INSTALL" && echo "ok   drop-in is opt-in" || { echo "FAIL: opt-in guard missing" >&2; exit 1; }
# The base unit must stay hardened: the drop-in is the only place that lifts it.
for f in "$HERE/trapd-agent.service"; do
    grep -q '^ProtectHome=read-only' "$f" && grep -q '^ProtectSystem=strict' "$f" \
        && ! grep -q 'CAP_DAC_OVERRIDE' <(grep -v '^[[:space:]]*#' "$f") \
        && echo "ok   base unit stays hardened" || { echo "FAIL: base unit lost its hardening" >&2; exit 1; }
done
bash -n "$INSTALL" && echo "ok   bash -n install.sh"
