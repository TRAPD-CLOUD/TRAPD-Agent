#!/usr/bin/env bash
# Runs inside a Debian/Ubuntu container (see test-deb.sh). Installs the built
# packages with plain dpkg and checks files, modes, scripts and edge cases.
set -uo pipefail

V1=/work/v1.deb
V2=/work/v2.deb
FAILS=0
export TRAPD_DEB_NO_WAIT=1

ok()   { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; FAILS=$((FAILS + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else fail "$d"; fi; }
mode() { stat -c '%a %U:%G' "$1" 2>/dev/null; }
expect_mode() { [[ "$(mode "$1")" == "$2" ]] && ok "$1 is $2" || fail "$1: got '$(mode "$1")', want '$2'"; }

STUB=/tmp/stubbin
mkdir -p "$STUB"
cat > "$STUB/systemctl" <<'STUBEOF'
#!/bin/sh
echo "$*" >> /tmp/systemctl.log
exit 0
STUBEOF
chmod +x "$STUB/systemctl"

echo "== fresh install without systemd"
dpkg -i "$V1" >/tmp/install1.log 2>&1 && ok "dpkg -i succeeds without systemd" || { fail "dpkg -i"; cat /tmp/install1.log; }
expect_mode /usr/bin/trapd-agent "755 root:root"
expect_mode /usr/lib/trapd-agent/trapd-agent-exec "644 root:root"
expect_mode /etc/trapd/ca.crt "644 root:root"
expect_mode /etc/trapd/command_signing.pub "644 root:root"
expect_mode /etc/trapd-release/release_signing.pub "644 root:root"
expect_mode /etc/trapd/agent.env "600 root:root"
expect_mode /etc/trapd/binary.sha256 "600 root:root"
expect_mode /var/lib/trapd "700 root:root"
expect_mode /var/log/trapd "700 root:root"
expect_mode /usr/lib/systemd/system/trapd-agent.service "644 root:root"
check "no setuid/setgid or world-writable file in the package" \
    bash -c '! dpkg -L trapd-agent | while read -r p; do [ -f "$p" ] && stat -c "%a" "$p"; done | grep -Eq "^[0-7]{4}$|[2367]$"'
check "agent.env points at the baked backend and has no token" \
    bash -c 'grep -qx "TRAPD_BACKEND_URL=https://api.example.test" /etc/trapd/agent.env && ! grep -q TRAPD_ENROLL_TOKEN /etc/trapd/agent.env'
check "baseline matches the installed binary" \
    bash -c '[ "$(cat /etc/trapd/binary.sha256)" = "sha256:$(sha256sum /usr/bin/trapd-agent | cut -d" " -f1)" ]'
check "main unit runs /usr/bin/trapd-agent" grep -qx 'ExecStart=/usr/bin/trapd-agent' /usr/lib/systemd/system/trapd-agent.service
check "apply unit runs /usr/bin and may write /usr/bin" \
    bash -c 'grep -qx "ExecStart=/usr/bin/trapd-agent --apply-update" /usr/lib/systemd/system/trapd-agent-update.service && grep -q "^ReadWritePaths=/usr/bin " /usr/lib/systemd/system/trapd-agent-update.service'
check "no active /usr/local/bin reference in any unit" \
    bash -c '! grep -hv "^[[:space:]]*#" /usr/lib/systemd/system/trapd-agent*.service /usr/lib/systemd/system/trapd-agent-update.path | grep -q /usr/local/bin'
check "logrotate conffile registered" bash -c 'dpkg-query -W -f="\${Conffiles}" trapd-agent | grep -q /etc/logrotate.d/trapd'
check "postinst printed the pairing hint" grep -q 'pairing.txt' /tmp/install1.log

echo "== reinstall keeps operator edits"
echo "# local edit" >> /etc/trapd/agent.env
dpkg -i "$V1" >/dev/null 2>&1 && ok "reinstall succeeds" || fail "reinstall"
check "agent.env edit preserved" grep -qx '# local edit' /etc/trapd/agent.env

echo "== policy-rc.d denial: units are enabled but never started"
mkdir -p /run/systemd/system
[[ -e /usr/sbin/policy-rc.d ]] && mv /usr/sbin/policy-rc.d /tmp/policy-rc.d.orig
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
: > /tmp/systemctl.log
PATH="$STUB:$PATH" dpkg -i "$V1" >/dev/null 2>&1 && ok "install under a denying policy succeeds" || fail "install under policy"
check "units still enabled" grep -qx 'enable trapd-agent.service trapd-agent-update.path' /tmp/systemctl.log
check "no start/restart under policy" bash -c '! grep -Eq "^(start|try-restart) " /tmp/systemctl.log'
rm -f /usr/sbin/policy-rc.d

echo "== upgrade with systemd present (stubbed systemctl)"
: > /tmp/systemctl.log
PATH="$STUB:$PATH" dpkg -i "$V2" >/tmp/install2.log 2>&1 && ok "upgrade succeeds" || { fail "upgrade"; cat /tmp/install2.log; }
check "binary replaced by v2" grep -q 'v2-binary' /usr/bin/trapd-agent
check "baseline follows the new binary" \
    bash -c '[ "$(cat /etc/trapd/binary.sha256)" = "sha256:$(sha256sum /usr/bin/trapd-agent | cut -d" " -f1)" ]'
check "daemon-reload called" grep -qx 'daemon-reload' /tmp/systemctl.log
check "units enabled" grep -qx 'enable trapd-agent.service trapd-agent-update.path' /tmp/systemctl.log
check "agent restarted on upgrade" grep -qx 'try-restart trapd-agent.service' /tmp/systemctl.log
check "operator edit still there after upgrade" grep -qx '# local edit' /etc/trapd/agent.env

echo "== signed updater leftovers are cleaned on remove"
touch /usr/bin/trapd-agent.prev /usr/bin/.trapd-agent.new /usr/lib/trapd-agent/trapd-agent-exec.prev
: > /tmp/systemctl.log
PATH="$STUB:$PATH" dpkg -r trapd-agent >/dev/null 2>&1 && ok "remove succeeds" || fail "remove"
check "agent and path unit stopped" grep -qx 'stop trapd-agent-update.path trapd-agent.service' /tmp/systemctl.log
check "units disabled" grep -qx 'disable trapd-agent.service trapd-agent-update.path' /tmp/systemctl.log
check "binary removed" bash -c '[ ! -e /usr/bin/trapd-agent ]'
check ".prev/.new leftovers removed" \
    bash -c '[ ! -e /usr/bin/trapd-agent.prev ] && [ ! -e /usr/bin/.trapd-agent.new ] && [ ! -e /usr/lib/trapd-agent ]'
check "agent.env kept on remove" test -f /etc/trapd/agent.env
check "state directory kept on remove" test -d /var/lib/trapd

echo "== purge removes identity and config"
echo '{}' > /var/lib/trapd/credentials.json
echo secret > /etc/trapd/agent.key
dpkg -P trapd-agent >/dev/null 2>&1 && ok "purge succeeds" || fail "purge"
check "state, log and config directories gone" \
    bash -c '[ ! -e /var/lib/trapd ] && [ ! -e /var/log/trapd ] && [ ! -e /etc/trapd ] && [ ! -e /etc/trapd-release ]'

echo "== purge does not follow a symlinked data directory"
dpkg -i "$V1" >/dev/null 2>&1
mkdir -p /tmp/precious && echo keep > /tmp/precious/file
dpkg -r trapd-agent >/dev/null 2>&1
rm -rf /var/lib/trapd && ln -s /tmp/precious /var/lib/trapd
dpkg -P trapd-agent >/dev/null 2>&1
check "symlink target untouched" test -f /tmp/precious/file
rm -f /var/lib/trapd; rm -rf /etc/trapd /var/log/trapd

echo "== script-based install is refused"
mkdir -p /usr/local/bin && echo x > /usr/local/bin/trapd-agent
if dpkg -i "$V1" >/tmp/conflict.log 2>&1; then fail "install over install.sh must fail"; else ok "install over install.sh fails"; fi
check "message explains the conflict" grep -q 'script-based install' /tmp/conflict.log
check "package not left half-installed" bash -c '! dpkg -s trapd-agent 2>/dev/null | grep -q "^Status: install ok installed"'
rm -f /usr/local/bin/trapd-agent
echo x > /etc/systemd/system/trapd-agent.service 2>/dev/null || { mkdir -p /etc/systemd/system && echo x > /etc/systemd/system/trapd-agent.service; }
if dpkg -i "$V1" >/dev/null 2>&1; then fail "install over install.sh unit must fail"; else ok "install over install.sh unit fails"; fi
rm -f /etc/systemd/system/trapd-agent.service

echo
if [[ "$FAILS" -eq 0 ]]; then echo "CONTAINER TESTS PASSED"; else echo "CONTAINER TESTS FAILED: $FAILS"; exit 1; fi
