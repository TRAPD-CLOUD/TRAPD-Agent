#!/usr/bin/env bash
# Load every eBPF program through the verifier of older kernels.
#
# The CI runner's own kernel is recent and accepts constructs that 5.15 LTS
# rejects (for example uninitialised stack reads, issue #217). This boots each
# kernel listed below in QEMU (TCG, no KVM needed) inside an Ubuntu container
# and runs `ebpf_verifier_check` against the object. Nothing is attached.
#
# Usage: scripts/ebpf_verifier_kernels.sh <ebpf-object> <ebpf_verifier_check-binary>
# Needs docker. Exit code is non-zero when any kernel rejects any program.
set -euo pipefail

obj="$(realpath "$1")"
checker="$(realpath "$2")"
# Ubuntu 22.04 GA kernel: the oldest 5.15 verifier our users run.
# Override with a space-separated list in EBPF_TEST_KERNELS.
read -ra KERNELS <<< "${EBPF_TEST_KERNELS:-linux-image-5.15.0-25-generic}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/in"
cp "$obj" "$work/in/obj"
cp "$checker" "$work/in/ebpf_verifier_check"

cat > "$work/in/guest.sh" <<'GUEST'
#!/bin/bash
set -euo pipefail
pkg="$1"
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends \
    qemu-system-x86 busybox-static cpio >/dev/null
cd /tmp && apt-get download -qq "$pkg" && dpkg -x /tmp/"$pkg"_*.deb /k

R=/tmp/root
mkdir -p $R/{bin,lib64,lib/x86_64-linux-gnu,proc,sys,dev}
cp /bin/busybox $R/bin/
for a in sh mount poweroff cat; do ln -s busybox "$R/bin/$a"; done
cp /in/ebpf_verifier_check /in/obj $R/bin/
# The checker is linked on the runner; ship its loader and libraries with it.
cp /in/lib64/* $R/lib64/
cp /in/lib/* $R/lib/x86_64-linux-gnu/
cat > $R/init <<'INIT'
#!/bin/sh
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
echo "KERNEL $(cat /proc/sys/kernel/osrelease)"
/bin/ebpf_verifier_check /bin/obj
echo "CHECK_EXIT $?"
poweroff -f
INIT
chmod +x $R/init
(cd $R && find . | cpio -o -H newc 2>/dev/null) | gzip > /tmp/initrd.gz
timeout 1200 qemu-system-x86_64 -m 1024 -nographic -no-reboot \
    -kernel /k/boot/vmlinuz-* -initrd /tmp/initrd.gz \
    -append "console=ttyS0 panic=-1 quiet loglevel=3" 2>&1 | tr -d '\r' | tee /tmp/console
grep -q '^CHECK_EXIT 0$' /tmp/console
GUEST
chmod +x "$work/in/guest.sh"

mkdir -p "$work/in/lib64" "$work/in/lib"
cp /lib64/ld-linux-x86-64.so.2 "$work/in/lib64/"
ldd "$checker" | awk '/=> \//{print $3}' | xargs -I{} cp {} "$work/in/lib/"

status=0
for pkg in "${KERNELS[@]}"; do
    echo "::group::verifier on ${pkg}"
    if ! docker run --rm -v "$work/in:/in:ro" ubuntu:22.04 /in/guest.sh "$pkg"; then
        echo "::error::eBPF verifier rejected a program on ${pkg}"
        status=1
    fi
    echo "::endgroup::"
done
exit $status
