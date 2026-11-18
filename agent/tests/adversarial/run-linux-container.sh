#!/usr/bin/env bash
# Run the Linux adversarial rows that need no backend (T2, T3, T6, T9) against
# a real systemd inside a throwaway privileged container.
#
#   TRAPD_ADVERSARIAL_OK=1 ./run-linux-container.sh <path-to-release-trapd-agent>
#
# Why a container: the rows kill, freeze, debug and replace the agent; a
# disposable systemd host keeps that off the developer machine. Rows that
# change kernel-global state (T10 sysctl, T11 clock) are NOT run here, because
# a privileged container shares the host kernel and clock. Rows that need a
# backend (T1, T4, T5, T12, T13) need a staging deployment.
#
# Needs docker. The container and image are removed on exit.
set -euo pipefail

[[ "${TRAPD_ADVERSARIAL_OK:-}" == 1 ]] || { echo "refusing: set TRAPD_ADVERSARIAL_OK=1" >&2; exit 2; }
bin="${1:?usage: $0 <path-to-trapd-agent binary>}"
[[ -x "$bin" ]] || { echo "not an executable: $bin" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
deploy="$(cd "$here/../../../deploy" && pwd)"
name="trapd-adv-$$"
image="trapd-adv-systemd:$$"
work="$(mktemp -d)"

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker rmi -f "$image" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

cp "$bin" "$work/trapd-agent"
cp "$deploy/trapd-agent.service" "$deploy/trapd-guard.service" "$work/"
cp -r "$here" "$work/adversarial"
cat > "$work/Dockerfile" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      systemd systemd-sysv gdb procps >/dev/null && apt-get clean
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
docker build --network host -q -t "$image" "$work" >/dev/null
docker run -d --name "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
    -v "$work:/field:ro" "$image" >/dev/null
sleep 5
docker exec "$name" bash -c '
    install -m0755 /field/trapd-agent /usr/local/bin/trapd-agent
    install -m0644 /field/trapd-agent.service /field/trapd-guard.service /etc/systemd/system/
    mkdir -p /etc/trapd && printf "TRAPD_OFFLINE=1\n" > /etc/trapd/agent.env
    systemctl daemon-reload && systemctl enable --now trapd-agent trapd-guard >/dev/null 2>&1
    sleep 15; systemctl is-active trapd-agent trapd-guard'

fails=0
run() {
    echo "=== $*"
    if docker exec -e TRAPD_ADVERSARIAL_OK=1 "$name" timeout 200 bash "$@" 2>&1 | tee "$work/out" | tail -4; then :; fi
    grep -q "PASS" "$work/out" || fails=$((fails + 1))
    sleep 5
}
run /field/adversarial/T2_T3_guard_pair.sh kill agent
run /field/adversarial/T2_T3_guard_pair.sh kill guard
run /field/adversarial/T2_T3_guard_pair.sh suspend agent
run /field/adversarial/T2_T3_guard_pair.sh suspend guard

# T6 under a freezing debugger: the guard must end the tracer and restart the
# agent well before the debugger would let go (75 s).
echo "=== T6 debugger attach (gdb freezes the agent)"
if docker exec "$name" bash -c '
    P=$(systemctl show -p MainPID --value trapd-agent)
    (timeout 100 gdb -q -batch -p "$P" -ex "shell sleep 75" -ex detach >/dev/null 2>&1 &)
    for i in $(seq 1 45); do
        sleep 1
        N=$(systemctl show -p MainPID --value trapd-agent)
        if [ "$N" != "$P" ] && [ "$N" != 0 ]; then echo "agent back after ${i}s"; break; fi
    done
    sleep 5
    grep selfprotect.peer_lost /var/log/trapd/events.ndjson | tail -1 | grep -q "\"tracer_pid\""'; then
    echo "PASS: tracer ended, agent restarted, tracer recorded"
else
    echo "FAIL: agent stayed frozen or the tracer was not recorded"; fails=$((fails + 1))
fi

run /field/adversarial/T9_binary_replace.sh

echo
[[ "$fails" -eq 0 ]] && echo "ALL PASS" || { echo "$fails row(s) FAILED"; exit 1; }
