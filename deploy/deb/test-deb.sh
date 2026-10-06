#!/usr/bin/env bash
# Reproducible test for deploy/deb: builds packages from dummy inputs, checks the
# build-time validation, then installs them with plain dpkg in Debian/Ubuntu
# containers. Needs dpkg-deb; Docker for the install part (REQUIRE_DOCKER=1 makes
# a missing Docker or image an error instead of a skip).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$HERE/build-deb.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0
ok()   { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; FAILS=$((FAILS + 1)); }

# ── Dummy inputs: just enough ELF header to pass the build's machine check ───
elf() { # <file> <machine-bytes> <extra text>
    { printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00'; printf "$2"; printf '\x01\x00\x00\x00'; printf '%s\n' "$3"; } > "$1"
}
elf "$TMP/agent1" '\x3e\x00' 'GLIBC_2.31 GLIBC_2.17 v1-binary'
elf "$TMP/agent2" '\x3e\x00' 'GLIBC_2.31 v2-binary'
elf "$TMP/ebpf" '\xf7\x00' 'bpf-object'
mkdir -p "$TMP/trust" "$TMP/out"
if command -v openssl >/dev/null; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
        -subj "/CN=trapd-test-ca" -keyout "$TMP/ca.key" -out "$TMP/trust/ca.crt" 2>/dev/null
else
    printf -- '-----BEGIN CERTIFICATE-----\nMIIBdGVzdA==\n-----END CERTIFICATE-----\n' > "$TMP/trust/ca.crt"
fi
head -c 32 /dev/zero | tr '\0' 'c' > "$TMP/trust/command_signing.pub"
head -c 32 /dev/zero | tr '\0' 'r' > "$TMP/trust/release_signing.pub"
echo 'https://api.example.test/' > "$TMP/trust/backend_url"

echo "== syntax"
for f in "$HERE"/maintainer/*; do
    if dash -n "$f" 2>/dev/null || sh -n "$f"; then ok "sh -n $(basename "$f")"; else fail "sh -n $f"; fi
done
for f in "$BUILD" "$HERE/test-deb.sh" "$HERE/test-in-container.sh"; do
    bash -n "$f" && ok "bash -n $(basename "$f")" || fail "bash -n $f"
done
if command -v shellcheck >/dev/null; then
    shellcheck -s sh "$HERE"/maintainer/* && ok "shellcheck maintainer scripts" || fail "shellcheck maintainer"
    shellcheck "$BUILD" && ok "shellcheck build-deb.sh" || fail "shellcheck build-deb.sh"
else
    echo "  skip shellcheck (not installed)"
fi

echo "== build"
DEB1="$("$BUILD" 0.5.0 "$TMP/agent1" "$TMP/ebpf" "$TMP/trust" "$TMP/out")"
DEB2="$("$BUILD" 0.5.1 "$TMP/agent2" "$TMP/ebpf" "$TMP/trust" "$TMP/out")"
DEBP="$("$BUILD" v0.6.0-beta.1 "$TMP/agent2" "$TMP/ebpf" "$TMP/trust" "$TMP/out")"
[[ "$(basename "$DEB1")" == "trapd-agent_0.5.0_amd64.deb" ]] && ok "file name" || fail "file name: $DEB1"
[[ "$(basename "$DEBP")" == "trapd-agent_0.6.0~beta.1_amd64.deb" ]] && ok "pre-release maps to ~" || fail "pre-release name: $DEBP"
INFO="$(dpkg-deb --info "$DEB1")"
grep -q 'Package: trapd-agent' <<<"$INFO" && ok "control: package" || fail "control: package"
grep -q 'Architecture: amd64' <<<"$INFO" && ok "control: architecture" || fail "control: architecture"
grep -q 'Depends: libc6 (>= 2.31)' <<<"$INFO" && ok "control: libc6 floor from binary" || fail "control: depends ($(grep Depends <<<"$INFO"))"
dpkg --compare-versions "0.6.0~beta.1" lt "0.6.0" && ok "pre-release sorts before release" || fail "version order"
LIST="$(dpkg-deb --contents "$DEB1")"
for p in ./usr/bin/trapd-agent ./usr/lib/trapd-agent/trapd-agent-exec ./etc/trapd/ca.crt \
         ./etc/trapd/command_signing.pub ./etc/trapd-release/release_signing.pub \
         ./usr/lib/systemd/system/trapd-agent.service ./usr/lib/systemd/system/trapd-agent-update.path \
         ./usr/lib/systemd/system/trapd-agent-update.service ./etc/logrotate.d/trapd ./usr/share/trapd-agent/deception.conf; do
    grep -q " ${p}\$" <<<"$LIST" && ok "contains $p" || fail "missing $p"
done
! grep -q "systemd/system/trapd-agent.service.d" <<<"$LIST" && ok "deception drop-in is not enabled by the package" || fail "package enables the deception drop-in"
! grep -qE ' \./.*(agent\.key|credentials|\.env|\.pem|\.key)$' <<<"$LIST" && ok "no key/credential/env file shipped" || fail "unexpected sensitive file in package"
! grep -qE '^[-d]......[sS]|^[-d].....[sS]' <<<"$LIST" && ok "no setuid/setgid entries" || fail "setuid entry"
[[ "$(dpkg-deb --fsys-tarfile "$DEB1" | tar -t | grep -c .)" -gt 5 ]] && ok "tar readable" || fail "tar"

echo "== build-time validation (each must fail)"
expect_fail() { # <description> <expected-message> <command...>
    local desc="$1" msg="$2" out; shift 2
    if out="$("$@" 2>&1)"; then fail "$desc: build succeeded"; else
        grep -q -- "$msg" <<<"$out" && ok "$desc" || fail "$desc: wrong message: $out"; fi
}
for f in ca.crt command_signing.pub release_signing.pub backend_url; do
    cp -r "$TMP/trust" "$TMP/trust-$f"; rm "$TMP/trust-$f/$f"
    expect_fail "missing $f" "missing trust anchor" "$BUILD" 0.5.0 "$TMP/agent1" "$TMP/ebpf" "$TMP/trust-$f" "$TMP/out-x"
done
cp -r "$TMP/trust" "$TMP/trust-short"; head -c 31 /dev/zero > "$TMP/trust-short/command_signing.pub"
expect_fail "31-byte command key" "32-byte" "$BUILD" 0.5.0 "$TMP/agent1" "$TMP/ebpf" "$TMP/trust-short" "$TMP/out-x"
cp -r "$TMP/trust" "$TMP/trust-pem"; printf -- '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' > "$TMP/trust-pem/ca.crt"
expect_fail "private key in ca.crt" "PEM certificate" "$BUILD" 0.5.0 "$TMP/agent1" "$TMP/ebpf" "$TMP/trust-pem" "$TMP/out-x"
{ cat "$TMP/trust/ca.crt"; printf -- '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'; } > "$TMP/ca-with-key.crt"
cp -r "$TMP/trust" "$TMP/trust-pk"; cp "$TMP/ca-with-key.crt" "$TMP/trust-pk/ca.crt"
expect_fail "ca.crt bundle that contains a private key" "private key" "$BUILD" 0.5.0 "$TMP/agent1" "$TMP/ebpf" "$TMP/trust-pk" "$TMP/out-x"
for url in 'http://api.example.test' 'https://user:pw@api.example.test' 'https://api.example.test/?a=b' 'https://api.example.test/ x'; do
    cp -r "$TMP/trust" "$TMP/trust-url"; printf '%s\n' "$url" > "$TMP/trust-url/backend_url"
    expect_fail "backend_url '$url'" "backend_url" "$BUILD" 0.5.0 "$TMP/agent1" "$TMP/ebpf" "$TMP/trust-url" "$TMP/out-x"
    rm -rf "$TMP/trust-url"
done
echo 'not elf' > "$TMP/notelf"
expect_fail "non-ELF agent binary" "not an ELF" "$BUILD" 0.5.0 "$TMP/notelf" "$TMP/ebpf" "$TMP/trust" "$TMP/out-x"
expect_fail "wrong ELF machine for the agent" "ELF machine" "$BUILD" 0.5.0 "$TMP/ebpf" "$TMP/ebpf" "$TMP/trust" "$TMP/out-x"
expect_fail "bad version" "not MAJOR" "$BUILD" 'latest' "$TMP/agent1" "$TMP/ebpf" "$TMP/trust" "$TMP/out-x"
[[ ! -e "$TMP/out-x" ]] && ok "failed builds leave no output" || fail "failed build created output"

echo "== install in containers"
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    [[ -z "${REQUIRE_DOCKER:-}" ]] && echo "  SKIP docker not available" || fail "docker not available"
else
    mkdir -p "$TMP/work"
    cp "$DEB1" "$TMP/work/v1.deb"; cp "$DEB2" "$TMP/work/v2.deb"; cp "$HERE/test-in-container.sh" "$TMP/work/"
    for image in ${IMAGES:-ubuntu:24.04 debian:12}; do
        echo "-- $image"
        if ! docker image inspect "$image" >/dev/null 2>&1 && ! docker pull -q "$image" >/dev/null 2>&1; then
            [[ -z "${REQUIRE_DOCKER:-}" ]] && echo "  SKIP cannot pull $image" || fail "cannot pull $image"
            continue
        fi
        if docker run --rm -v "$TMP/work:/work:ro" "$image" bash /work/test-in-container.sh; then
            ok "$image"
        else
            fail "$image"
        fi
    done
fi

echo
if [[ "$FAILS" -eq 0 ]]; then echo "ALL DEB TESTS PASSED"; else echo "DEB TESTS FAILED: $FAILS"; exit 1; fi
