#!/usr/bin/env python3
"""Offline OCSF contract validation against the pinned official compiled export."""
import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path

from jsonschema import Draft7Validator

HERE = Path(__file__).resolve().parent
SUPPORTED = {0, 1001, 1007, 2004, 3002, 4001, 4003, 5001, 7001}
CAPTIONS = {0: "Base Event", 1001: "File System Activity", 1007: "Process Activity",
            2004: "Detection Finding", 3002: "Authentication", 4001: "Network Activity",
            4003: "DNS Activity", 5001: "Device Inventory Info", 7001: "Remediation Activity"}


def upstream_schema():
    raw = gzip.decompress((HERE / "upstream-1.9.0.json.gz").read_bytes())
    provenance = json.loads((HERE / "provenance.json").read_text())
    assert hashlib.sha256(raw).hexdigest() == provenance["sha256"], "upstream hash mismatch"
    source = json.loads(raw)
    assert source["version"] == provenance["version"] == "1.9.0"
    types = source["dictionary"]["types"]["attributes"]

    def scalar(name):
        primitive = {"integer_t": "integer", "long_t": "integer", "float_t": "number",
                     "string_t": "string", "boolean_t": "boolean", "json_t": "object"}
        definition = types[name]
        result = ({"type": primitive[name]} if name in primitive else scalar(definition["type"]))
        if "range" in definition:
            result.update(minimum=definition["range"][0], maximum=definition["range"][1])
        if "regex" in definition:
            result["pattern"] = definition["regex"]
        return result

    def attribute(attr):
        if attr["type"] == "object_t":
            result = {"$ref": "#/definitions/" + attr["object_type"]}
        else:
            result = scalar(attr["type"])
        if "enum" in attr:
            result["enum"] = [int(k) if result.get("type") == "integer" else k for k in attr["enum"]]
        if "range" in attr:
            result.update(minimum=attr["range"][0], maximum=attr["range"][1])
        if attr.get("is_array"):
            result = {"type": "array", "items": result}
        return result

    def entity(item):
        attrs = {k: a for k, a in item["attributes"].items() if not a.get("profiles") or "host" in a["profiles"]}
        result = {"type": "object", "properties": {k: attribute(a) for k, a in attrs.items()},
                  "additionalProperties": item["name"] == "object"}
        required = [k for k, a in attrs.items() if a.get("requirement") == "required"]
        if required:
            result["required"] = required
        # OCSF enumerations explicitly require the source-specific sibling for Other.
        rules = []
        for k, a in attrs.items():
            if "99" in a.get("enum", {}) and a.get("sibling") in attrs:
                rules.append({"if": {"required": [k], "properties": {k: {"const": 99}}},
                              "then": {"required": [a["sibling"]]}})
        for constraint, fields in item.get("constraints", {}).items():
            if constraint == "at_least_one":
                rules.append({"anyOf": [{"required": [key]} for key in fields]})
            elif constraint == "just_one":
                rules.append({"oneOf": [{"required": [key]} for key in fields]})
            else:
                raise ValueError(f"unsupported upstream constraint {constraint}: {item['name']}")
        if rules:
            result["allOf"] = rules
        return result

    definitions = {name: entity(item) for name, item in source["objects"].items()}
    schemas = {}
    for item in source["classes"].values():
        if item["uid"] in SUPPORTED:
            schema = entity(item)
            schema.update({"$schema": "http://json-schema.org/draft-07/schema#", "definitions": definitions})
            Draft7Validator.check_schema(schema)
            schemas[item["uid"]] = schema
    assert set(schemas) == SUPPORTED
    return schemas



# TRAPD mapping policy reviewed against upstream activity descriptions. Unknown
# source combinations deliberately remain Base Event / Other, preserving evidence.
MAPPING = {
    "process": (1007, {"create": 1, "exec": 1, "fork": 1, "terminate": 2, "ptrace": 3, "setuid": 5}),
    "filesystem": (1001, {"create": 1, "modify": 3, "integrity_violation": 3, "delete": 4,
                         "unlink": 4, "rename": 5, "chmod": 7, "chown": 6, "open": 14}),
    "network": (4001, {"connection": 1, "bind": 7, "accept": 1, "tls_handshake": 99}),
    "user": (3002, {"logon": 1, "logon_failed": 1, "session_open": 1, "session_close": 2}),
    "detection": (2004, {"detected": 1, "honeytoken_access": 1}),
    "system": (5001, {"snapshot": 2}),
}
PREVENTION = {"network_isolated": 1, "ip_blocked": 1, "file_quarantined": 1, "process_frozen": 1,
              "process_blocked": 2, "network_deisolated": 3, "ip_unblocked": 3, "file_restored": 3,
              "process_thawed": 3, "honeytoken_deployed": 6, "deception_escalation": 6}


def expected_mapping(source):
    klass, action, data = source["class"], source["action"], source["data"]
    if klass == "prevention" and data.get("command_id"):
        return 7001, PREVENTION.get(action, 99)
    if klass == "network" and action in ("dns_query", "dns_response") and isinstance(data.get("qname"), str):
        return 4003, 2 if action == "dns_response" else 1
    if klass == "network" and action == "connection" and data.get("state") == "closed":
        return 4001, 2
    uid, actions = MAPPING.get(klass, (0, {}))
    return (uid, actions[action]) if action in actions else (0, 99)


def validator_self_check(schemas, events):
    """Prove the independent checker catches representative contract violations."""
    by_class = {item["ocsf"]["class_uid"]: item["ocsf"] for item in events}
    mutations = [
        (1007, lambda v: v.pop("process")),
        (1001, lambda v: v["file"].pop("name")),
        (5001, lambda v: v["device"].pop("type_id")),
        (2004, lambda v: v["finding_info"].pop("uid")),
        (3002, lambda v: v.pop("user")),
        (4003, lambda v: v["query"].pop("hostname")),
        (4001, lambda v: v.update(connection_info={"protocol_name": "tcp"})),
        (4001, lambda v: v.update(src_endpoint={"port": 65536})),
        (4001, lambda v: v.update(src_endpoint={"port": "443"})),
        (4001, lambda v: v.update(src_endpoint={"ip": "invalid"})),
        (4003, lambda v: v.update(answers=[{}])),
        (1007, lambda v: v["process"].update(pid="123")),
        (1007, lambda v: v.update(activity_id=6)),
        (1007, lambda v: v["metadata"].update(product=[])),
        (7001, lambda v: v.pop("command_uid")),
        (0, lambda v: v.update(severity_id=7)),
        (3002, lambda v: [v.pop(k, None) for k in ["service", "dst_endpoint"]]),
        (4001, lambda v: [v.pop(k, None) for k in ["src_endpoint", "dst_endpoint"]]),
        (4003, lambda v: [v.pop(k, None) for k in ["src_endpoint", "dst_endpoint"]]),
        (1007, lambda v: v.update(actor={})),
        (4001, lambda v: v.update(src_endpoint={}, dst_endpoint={})),
    ]
    for uid, mutate in mutations:
        event = copy.deepcopy(by_class[uid])
        mutate(event)
        assert not Draft7Validator(schemas[uid]).is_valid(event), f"checker missed class {uid} mutation"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path, help="JSON emitted by the Rust ocsf_contract integration test")
    args = parser.parse_args()
    schemas = upstream_schema()
    events = json.loads(args.fixtures.read_text())
    failures = []
    pairs = set()
    classes = set()
    for item in events:
        event = item["ocsf"]
        uid = event["class_uid"]
        pairs.add((item["source"]["class"], item["source"]["action"]))
        classes.add(uid)
        if item["name"] == "typed/detection":
            if event["finding_info"].get("title") != "Finding title" or event["finding_info"].get("desc") != "Finding explanation":
                failures.append("typed/detection: missing canonical finding title/detail")
        if item["name"] == "typed/file-open":
            actor = event.get("actor", {}).get("process", {})
            if actor.get("pid") != 42 or actor.get("name") != "cat":
                failures.append("typed/file-open: executing process must be actor pid42/name cat")
        if item["name"] == "typed/user-logon-invalid-ip":
            if "ip" in event.get("src_endpoint", {}):
                failures.append("typed/user-logon-invalid-ip: unparseable IP leaked into standard endpoint")
            if event.get("unmapped", {}).get("trapd", {}).get("data", {}).get("src_addr") != "not-an-ip":
                failures.append("typed/user-logon-invalid-ip: original evidence was lost")
        if item["name"] == "filesystem/username-only":
            actor = event.get("actor", {})
            if "process" in actor or actor.get("user", {}).get("name") != "fixture":
                failures.append("filesystem/username-only: actor must contain observed user without invented process")
        if item["name"] == "typed/ptrace":
            actor = event.get("actor", {}).get("process", {})
            target = event.get("process", {})
            if actor.get("pid") != 77 or actor.get("name") != "gdb" or target.get("pid") != 88 or "name" in target:
                failures.append("typed/ptrace: actor gdb77 / unnamed target88 required")
        if uid == 3002 and isinstance(item["source"]["data"].get("success"), bool):
            expected_status = 1 if item["source"]["data"]["success"] else 2
            if event.get("status_id") != expected_status:
                failures.append(f'{item["name"]}: authentication outcome missing or incorrect')
        # Findings use lifecycle states (New/In Progress/...), never generic activity success/failure.
        if uid == 2004 and "success" in item["source"]["data"] and event.get("status_id") not in (None, 0, 1):
            failures.append(f'{item["name"]}: finding lifecycle misuses activity success/failure')
        if item["name"] == "typed/process-create-hash":
            hashes = event.get("process", {}).get("file", {}).get("hashes", [])
            if {"algorithm_id": 3, "value": "a" * 64} not in hashes:
                failures.append("typed/process-create-hash: missing standard SHA256 hash")
        if (uid, event["activity_id"]) != expected_mapping(item["source"]):
            failures.append(f'{item["name"]}: incorrect semantic class/activity mapping')
        for error in Draft7Validator(schemas[uid]).iter_errors(event):
            message = error.message
            if error.validator in ("anyOf", "oneOf"):
                message = f"{error.validator} constraint failed: {error.validator_value}"
            failures.append(f'{item["name"]} /{"/".join(map(str, error.path))}: {message[:240]}')
        if event["activity_id"] == 99 and event.get("type_name") != CAPTIONS[uid] + ": " + event["activity_name"]:
            failures.append(f'{item["name"]}: type_name must combine class caption and activity_name')
        if event["type_uid"] != uid * 100 + event["activity_id"]:
            failures.append(f'{item["name"]}: inconsistent type_uid')
        if event["category_uid"] != uid // 1000:
            failures.append(f'{item["name"]}: inconsistent category_uid')
        if event["metadata"].get("profiles") != ["host"]:
            failures.append(f'{item["name"]}: missing explicit host profile')
        if event["metadata"]["version"] != "1.9.0":
            failures.append(f'{item["name"]}: incorrect metadata.version')
    if classes != SUPPORTED:
        failures.append(f"missing class coverage: {SUPPORTED - classes}")
    validator_self_check(schemas, events)
    if failures:
        raise SystemExit("\n".join(failures[:40]) + f"\n{len(failures)} total failures")
    print(f"OCSF 1.9.0 upstream contract: {len(events)} fixtures, {len(pairs)} class/action pairs, {len(classes)} classes passed")


if __name__ == "__main__":
    main()
