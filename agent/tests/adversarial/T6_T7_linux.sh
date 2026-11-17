#!/usr/bin/env bash
# Adversarial rows T6/T7 (Linux): attach a debugger, preload a library.
# Expected: selfprotect.debugger_attached and selfprotect.module_injected
# (anonymous_rwx, T7 implant) findings for the agent process within ~60 s (one self-check tick + jitter).
#
# Safe: the debugger attaches and detaches immediately; the preload library is
# a harmless no-op shared object built in a temp dir and removed on exit.
# Refuses to run without TRAPD_ADVERSARIAL_OK=1 and only targets the running
# trapd-agent (or $AGENT_PID).
set -euo pipefail

if [ "${TRAPD_ADVERSARIAL_OK:-}" != "1" ]; then
  echo "refusing to run: set TRAPD_ADVERSARIAL_OK=1 (this tampers with the local agent on purpose)" >&2
  exit 2
fi

AGENT_PID="${AGENT_PID:-$(pgrep -xo trapd-agent || true)}"
[ -n "$AGENT_PID" ] || { echo "trapd-agent is not running" >&2; exit 1; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== T6a: ptrace attach to pid $AGENT_PID (hold 75 s so a 30 s tick sees it)"
if command -v gdb >/dev/null; then
  # T7 (memory implant): the attached debugger also maps one anonymous rwx page in
  # the agent (what an injected stub looks like), holds both for 75 s, then
  # unmaps it and detaches. Expected extra finding: module_injected / anonymous_rwx.
  timeout 100 gdb -q -batch -p "$AGENT_PID" \
    -ex 'set $m = (long)mmap(0, 4096, 7, 0x22, -1, 0)' \
    -ex 'shell sleep 75' \
    -ex 'call (int)munmap($m, 4096)' -ex detach -ex quit >/dev/null 2>&1 &
elif command -v strace >/dev/null; then
  timeout 75 strace -p "$AGENT_PID" -o /dev/null >/dev/null 2>&1 &
else
  echo "neither gdb nor strace installed" >&2; exit 1
fi
TRACER=$!

echo "== T6b: LD_PRELOAD. A library can only be preloaded at process start, so the live path needs an"
echo "   agent restart; the classifier is covered by unit tests. Build the no-op library:"
cat > "$WORK/noop.c" <<'C'
void trapd_adversarial_noop(void) {}
C
if command -v cc >/dev/null; then
  cc -shared -fPIC -o "$WORK/noop.so" "$WORK/noop.c"
  echo "   to exercise the live detector restart the agent once with:"
  echo "   systemctl edit trapd-agent  ->  Environment=LD_PRELOAD=$WORK/noop.so  (then remove it again)"
fi

wait "$TRACER" 2>/dev/null || true
echo "== verify: console -> host -> findings, or the agent log should show"
echo "   rule=selfprotect.debugger_attached subject='pid $AGENT_PID traced by pid ...'"
