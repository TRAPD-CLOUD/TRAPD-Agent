# OCSF 1.9.0 validation

Run the independent offline check from the repository root:

```sh
python3 -m pip install -r scripts/ocsf/requirements.txt
scripts/ocsf_validate.sh
```

Python jsonschema is development tooling only. Production has no new dependency.
After package installation the check uses no network service. CI uses the same command.

The Rust test serializes every current EventClass × EventAction combination through
production to_ocsf. Exhaustive Rust matches require updating coverage when an enum
variant is added. Actual typed collector fixtures cover process launch/exec/exit,
file open, network connection, DNS query/response, authentication, system snapshot,
detection, and command remediation. Additional cases cover closed connections and
local prevention without a command identifier. The cross product checks fallback
behavior; it does not imply all combinations are produced by collectors.

## Independent source

The checker uses the official [OCSF 1.9.0 release](https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0),
commit `856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`. The complete compiled schema
comes from [the official v2 export](https://schema.ocsf.io/1.9.0/export/v2/schema).
Original bytes are gzip compressed in `scripts/ocsf/upstream-1.9.0.json.gz`.
`provenance.json` records the URL, release commit, original content SHA256, and
selected host profile. The checker verifies the hash. The upstream Apache 2.0
license accompanies the snapshot.

The official legacy export fails for this release because process.euid belongs
to multiple platform profiles. The v2 export preserves these profiles. Our
checker translates compiled attributes, objects, type inheritance, requirements,
enums, ranges, and regexes to JSON Schema Draft 7. This is a local translation of
official data, not a JSON Schema distributed by OCSF. The host profile enables
device/actor evidence on base, DNS, network, and remediation records. Other
profile attributes are excluded.

All present standard fields are checked recursively: nested required fields and upstream OR constraints,
scalar/array types, enum membership, ranges, regexes, Other enum siblings,
classification arithmetic, explicit profile/version, and a separately reviewed
source action mapping. Unmapped evidence is intentionally unconstrained because
upstream defines unmapped as a generic object. Twenty-one negative mutation checks
prove the checker rejects missing objects/nested fields, invalid enums, malformed
IPs, wrong scalar types, and ports outside the allowed range. Recommended upstream
attributes are not treated as required.

## Mapping policy and limits

| Source | OCSF class / activity |
| --- | --- |
| Process create, exec, fork | Process Activity 1007 / Launch 1 |
| Process terminate, ptrace, setuid | 1007 / Terminate 2, Open 3, Set User ID 5 |
| Filesystem create, modify, integrity_violation, delete, unlink, rename, chown, chmod, open | File System Activity 1001 / 1, 3, 3, 4, 4, 5, 6, 7, 14 |
| Network connection, accept, bind | Network Activity 4001 / Open 1, Open 1, Listen 7; closed connections use Close 2 |
| Network tls_handshake | Network Activity 4001 / Other 99 |
| Network dns_query/dns_response with qname | DNS Activity 4003 / Query 1, Response 2 |
| User logon, logon_failed, session_open, session_close | Authentication 3002 / 1, 1, 1, 2 |
| Detection detected, honeytoken_access | Detection Finding 2004 / Create 1 |
| System snapshot | Device Inventory Info 5001 / Collect 2 |
| Prevention with command_id | Remediation Activity 7001 / Isolate 1, Evict 2, Restore 3, Deceive 6, or Other 99 |
| Remaining combinations | Base Event 0 / Other 99 |

Remediation Isolate covers network isolation, IP block, quarantine, and process
freeze; Evict covers process termination; Restore covers their undo actions;
Deceive covers honeytoken deployment and deception escalation. Other command
outcomes retain the source action as activity_name. Local prevention without
command_id uses Base Event because Remediation requires command_uid.

Memory, kernel, IPC, and generic logs use Base Event / Other. Unrecognized actions
in the other source classes also use Base Event. Raw eBPF DnsData lacks qname and
cannot honestly become a DNS query object; it uses Base Event, while typed DNS
resolution evidence provides the name. Ransomware indicators, agent tamper,
write rate anomalies, kill attempts, namespace changes, memory anomalies, module
loads, and drop reports retain their source evidence under unmapped.trapd without
invented domain fields. These are conformant fallback records, not complete domain
normalization. This check does not claim support for every upstream class or full
validation of arbitrary external OCSF events by the production Rust validator.

Sparse process/file/authentication records without the required observed identities
use Base Event Other, retaining the original source class, action, and evidence.
Authentication targets identify the actual agent host. DNS without known IPs
identifies the actual observing client host; no IP address is invented.
