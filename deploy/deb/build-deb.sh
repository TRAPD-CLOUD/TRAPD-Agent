#!/usr/bin/env bash
# Build trapd-agent_<version>_amd64.deb for the hosted TRAPD service.
#
#   deploy/deb/build-deb.sh <version> <agent-binary> <ebpf-object> <trust-dir> <out-dir>
#
# <trust-dir> holds the PUBLIC trust anchors that get baked into the package:
#   ca.crt               PEM CA (or bundle) that pins the backend
#   command_signing.pub  raw 32-byte Ed25519 public key (signed commands + config)
#   release_signing.pub  raw 32-byte Ed25519 public key (signed self-update)
#   backend_url          one line, https://host[:port][/path]
# A missing or malformed file aborts the build: there is no package without
# anchors, because an agent without them either refuses to connect or (with
# TRAPD_TLS_ALLOW_SYSTEM_ROOTS) silently weakens the pinning.
#
# Only dpkg-deb and coreutils are needed. See deploy/README-deb.md.
set -euo pipefail
umask 022

die() { echo "build-deb: ERROR: $*" >&2; exit 1; }

[[ $# -eq 5 ]] || die "usage: $0 <version> <agent-binary> <ebpf-object> <trust-dir> <out-dir>"
VERSION_IN="$1"; AGENT_BIN="$2"; EBPF_OBJ="$3"; TRUST_DIR="$4"; OUT_DIR="$5"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$HERE")"
MAINTAINER="${TRAPD_DEB_MAINTAINER:-TRAPD <support@trapd.invalid>}"

command -v dpkg-deb >/dev/null || die "dpkg-deb is required"

# ── Version ──────────────────────────────────────────────────────────────────
# Accepts 1.2.3, v1.2.3 and semver pre-releases (1.2.3-beta.1). Debian sorts "~"
# before the release, so 1.2.3-beta.1 becomes 1.2.3~beta.1 and 1.2.3 upgrades it.
VERSION="${VERSION_IN#v}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
    || die "version '${VERSION_IN}' is not MAJOR.MINOR.PATCH[-prerelease]"
DEB_VERSION="${VERSION//-/\~}"

# ── Inputs ───────────────────────────────────────────────────────────────────
elf_check() { # <file> <what> <machine-hex-le or "any">
    local f="$1" what="$2" machine="$3" magic mach
    [[ -f "$f" ]] || die "$what not found: $f"
    magic="$(od -An -tx1 -N4 "$f" | tr -d ' \n')"
    [[ "$magic" == "7f454c46" ]] || die "$what is not an ELF file: $f"
    if [[ "$machine" != any ]]; then
        mach="$(od -An -tx1 -j18 -N2 "$f" | tr -d ' \n')"
        [[ "$mach" == "$machine" ]] || die "$what has ELF machine 0x${mach}, expected ${machine} (${f})"
    fi
}
elf_check "$AGENT_BIN" "agent binary" "3e00"   # EM_X86_64
elf_check "$EBPF_OBJ" "eBPF object" "f700"     # EM_BPF

[[ -d "$TRUST_DIR" ]] || die "trust dir not found: $TRUST_DIR"
for f in ca.crt command_signing.pub release_signing.pub backend_url; do
    [[ -f "$TRUST_DIR/$f" && ! -L "$TRUST_DIR/$f" ]] || die "missing trust anchor: $TRUST_DIR/$f"
done

if ! grep -q -- '-----BEGIN CERTIFICATE-----' "$TRUST_DIR/ca.crt" \
    || ! grep -q -- '-----END CERTIFICATE-----' "$TRUST_DIR/ca.crt"; then
    die "ca.crt is not a PEM certificate"
fi
if grep -q 'PRIVATE KEY' "$TRUST_DIR/ca.crt"; then
    die "ca.crt contains a private key - refusing to package it"
fi
if command -v openssl >/dev/null; then
    openssl x509 -noout -in "$TRUST_DIR/ca.crt" 2>/dev/null || die "ca.crt does not parse as an X.509 certificate"
fi
for f in command_signing.pub release_signing.pub; do
    [[ "$(stat -c %s "$TRUST_DIR/$f")" == 32 ]] || die "$f must be a raw 32-byte Ed25519 public key"
done

BACKEND_URL="$(cat "$TRUST_DIR/backend_url")"
BACKEND_URL="${BACKEND_URL%$'\n'}"
BACKEND_URL="${BACKEND_URL%/}"
[[ "$BACKEND_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] \
    || die "backend_url must be one line https://host[:port][/path] (no credentials, query or whitespace)"

[[ "$MAINTAINER" =~ ^[^[:cntrl:]]+\<[^\<\>[:space:]]+\>$ ]] || die "TRAPD_DEB_MAINTAINER must look like 'Name <mail>'"

# ── Stage ────────────────────────────────────────────────────────────────────
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

install -d -m 0755 "$ROOT/DEBIAN" "$ROOT/usr/bin" "$ROOT/usr/lib/trapd-agent" \
    "$ROOT/usr/lib/systemd/system" "$ROOT/etc/trapd" "$ROOT/etc/trapd-release" \
    "$ROOT/etc/logrotate.d" "$ROOT/usr/share/trapd-agent"

install -m 0755 "$AGENT_BIN" "$ROOT/usr/bin/trapd-agent"
install -m 0644 "$EBPF_OBJ" "$ROOT/usr/lib/trapd-agent/trapd-agent-exec"

# Same unit as the script install, with the FHS binary path. A silent no-op here
# would ship a unit that starts nothing, so the result is asserted.
sed 's#/usr/local/bin/trapd-agent#/usr/bin/trapd-agent#g' "$DEPLOY_DIR/trapd-agent.service" \
    > "$ROOT/usr/lib/systemd/system/trapd-agent.service"
grep -qx 'ExecStart=/usr/bin/trapd-agent' "$ROOT/usr/lib/systemd/system/trapd-agent.service" \
    || die "could not derive the unit: deploy/trapd-agent.service has no 'ExecStart=/usr/local/bin/trapd-agent' line"
if grep -q '/usr/local/bin' "$ROOT/usr/lib/systemd/system/trapd-agent.service"; then
    # Only comments may mention it; an active line would break the update path.
    grep -v '^[[:space:]]*#' "$ROOT/usr/lib/systemd/system/trapd-agent.service" | grep -q '/usr/local/bin' \
        && die "trapd-agent.service still references /usr/local/bin outside comments"
fi
install -m 0644 "$HERE/trapd-agent-update.service" "$ROOT/usr/lib/systemd/system/trapd-agent-update.service"
install -m 0644 "$HERE/trapd-agent-update.path" "$ROOT/usr/lib/systemd/system/trapd-agent-update.path"

install -m 0644 "$TRUST_DIR/ca.crt" "$ROOT/etc/trapd/ca.crt"
install -m 0644 "$TRUST_DIR/command_signing.pub" "$ROOT/etc/trapd/command_signing.pub"
install -m 0644 "$TRUST_DIR/release_signing.pub" "$ROOT/etc/trapd-release/release_signing.pub"
printf '%s\n' "$BACKEND_URL" > "$ROOT/usr/share/trapd-agent/backend_url"
chmod 0644 "$ROOT/usr/share/trapd-agent/backend_url"
install -m 0644 "$DEPLOY_DIR/trapd.logrotate" "$ROOT/etc/logrotate.d/trapd"
# Opt-in honeytoken drop-in: shipped, never enabled by the package.
install -m 0644 "$DEPLOY_DIR/trapd-agent-deception.conf" "$ROOT/usr/share/trapd-agent/deception.conf"

for s in preinst postinst prerm postrm; do
    install -m 0755 "$HERE/maintainer/$s" "$ROOT/DEBIAN/$s"
done
printf '/etc/logrotate.d/trapd\n' > "$ROOT/DEBIAN/conffiles"

# libc6 floor = highest GLIBC_x.y symbol version the binary needs, so a build
# host newer than the target distro is caught at install time, not at start.
GLIBC="$(grep -aoE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' "$AGENT_BIN" | sed 's/^GLIBC_//' | sort -V | tail -n 1 || true)"
DEPENDS="libc6"
[[ -n "$GLIBC" ]] && DEPENDS="libc6 (>= ${GLIBC})"

INSTALLED_SIZE="$(du -sk --exclude=DEBIAN "$ROOT" | awk '{print $1}')"
cat > "$ROOT/DEBIAN/control" <<EOF
Package: trapd-agent
Version: ${DEB_VERSION}
Architecture: amd64
Maintainer: ${MAINTAINER}
Installed-Size: ${INSTALLED_SIZE}
Depends: ${DEPENDS}
Recommends: systemd
Section: admin
Priority: optional
Homepage: https://github.com/trapd-cloud/trapd-agent
Description: TRAPD security agent
 Endpoint telemetry, detection and response agent for the hosted TRAPD
 service. The package carries the service's public trust anchors and starts in
 pairing mode: it shows a code to enter in the TRAPD web interface.
EOF

( cd "$ROOT" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' | sort -z | xargs -0 md5sum ) \
    > "$ROOT/DEBIAN/md5sums"
chmod 0644 "$ROOT/DEBIAN/md5sums" "$ROOT/DEBIAN/control" "$ROOT/DEBIAN/conffiles"

if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
    find "$ROOT" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
fi

mkdir -p "$OUT_DIR"
OUT="${OUT_DIR%/}/trapd-agent_${DEB_VERSION}_amd64.deb"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$OUT" >/dev/null
echo "$OUT"
