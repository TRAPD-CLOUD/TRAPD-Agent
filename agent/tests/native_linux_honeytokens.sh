#!/bin/bash
# Privileged, network-isolated acceptance on the host kernel. Only test files change.
set -euo pipefail
mode=${1:-inode}
[[ "$mode" == inode || "$mode" == fallback ]] || exit 2
root=$(cd "$(dirname "$0")/../.." && pwd)
fixture="$root/agent/tests/fixtures/native-linux"
dir=$(mktemp -d /tmp/trapd-native-honeytokens.XXXXXXXX)
container="trapd-native-$(basename "$dir")"
image=ubuntu:24.04
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker run --rm --network none -v "$dir:/test" "$image" sh -c 'rm -rf /test/*' >/dev/null 2>&1 || true
  rmdir "$dir" 2>/dev/null || true
}
trap cleanup EXIT
cp "$root/target/release/trapd-agent" "$dir/agent"
cp "$root/target/bpfel-unknown-none/release/trapd-agent-exec" "$dir/trapd-agent-exec"
cp "$fixture/actions.sh" "$dir/run.sh"
cc -O2 -o "$dir/probe" "$fixture/open_probe.c"
cc -O2 -o "$dir/failed-exec" "$fixture/failed_exec.c"
cc -O2 -pthread -o "$dir/thread-exec" "$fixture/thread_exec.c"
cp "$dir/probe" "$dir/decoy-exec"
python3 - "$dir" <<'PY'
import hashlib,json,os,sys
from pathlib import Path
p=Path(sys.argv[1]);(p/'state').mkdir();(p/'logs').mkdir()
(p/'decoy-invalid').write_bytes(b'not an executable format\n')
(p/'decoy.txt').write_bytes(b'fixture-decoy-only\n');os.chmod(p/'decoy.txt',0o600)
conf={key:False for key in ['prevention_enabled','memory_scan_enabled','fim_enabled','inventory_enabled','vuln_scan_enabled','cis_benchmark_enabled']}
conf.update(fs_watch_paths=[],honeytoken_detection_enabled=True)
(p/'state/agent_config.json').write_text(json.dumps(conf))
tokens=[]
for prefix,name,mode in [('11111111','decoy.txt',384),('22222222','decoy-exec',448),('33333333','decoy-invalid',448)]:
 data=(p/name).read_bytes();os.chmod(p/name,mode)
 tokens.append(dict(id=prefix+'-0000-0000-0000-000000000111',path='/test/'+name,kind='password_note',mode=mode,size_bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),mimic_neighbor=False,deployed_at='2026-10-07T00:00:00Z',breadcrumbs=[]))
(p/'state/honeytokens.json').write_text(json.dumps({'tokens':tokens}))
(p/'no-btf').write_bytes(b'')
PY
mounts=()
if [[ "$mode" == fallback ]]; then mounts=(-v "$dir/no-btf:/sys/kernel/btf/vmlinux:ro"); fi
docker run --rm --name "$container" --privileged --pid host --network none -e MODE="$mode" \
  -v "$dir:/test" "${mounts[@]}" "$image" bash /test/run.sh > "$dir/actions.log" 2>&1
python3 - "$dir" "$mode" <<'PY'
import collections,json,sys
from pathlib import Path
p=Path(sys.argv[1]);mode=sys.argv[2];pid=int((p/'agent.pid').read_text());hits=[]
for line in (p/'events.ndjson').read_text().splitlines():
 try:e=json.loads(line)
 except ValueError:continue
 d=e.get('data',{})
 if isinstance(d,dict) and d.get('token_id','').startswith(('11111111-','22222222-','33333333-')):hits.append(e)
assert hits,'no Honeytoken data'
assert not any(e['data']['token_id'].startswith('33333333-') and e['data']['access_kind'] in ['exec','open'] for e in hits),'failed exec became content access'
assert not any(e['data'].get('accessor',{}).get('pid')==pid for e in hits),'agent self access leaked'
counts=collections.Counter((e['data']['access_kind'],e['data'].get('mode')) for e in hits)
assert counts['open','alert'] >= (7 if mode=='inode' else 2),counts
assert counts['modify','alert']==3,counts
assert counts['rename','alert']==1,counts
assert counts['stat','signal']>=1 and counts['statx','signal']>=1,counts
assert not any(e['data'].get('open_flags',0)&0x10000 for e in hits),'failed O_DIRECTORY emitted'
if mode=='inode':
 assert counts['exec','alert']==3,counts
 assert counts['mmap','alert']==3,counts
else:assert counts['mmap','alert']==0,counts
log=(p/'agent.log').read_text()
assert 'Shutdown complete' in log,'agent did not shut down cleanly'
assert ('attached with verified kernel BTF' if mode=='inode' else 'kernel BTF layout unavailable') in log
print(mode, 'PASS', json.dumps({kind+'/'+grade:n for (kind,grade),n in sorted(counts.items())}))
PY
