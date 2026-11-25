# Endpoint security, response and updates

Static audit of Linux and Windows at `9e00c89`. Locations refer to that revision. Scenarios describe consequences under the listed preconditions. Backend authorization and host configuration are trust assumptions.

| ID | File:line | Attacker model | Description and concrete failure scenario | Severity | Proposed fix | Disposition |
|---|---|---|---|---|---|---|
| SR-01 | agent/src/http/mod.rs:107 | Network observer | An HTTP URL bypasses the configured TLS verifier entirely. The client can send an enrollment token or bearer over cleartext. Redirects can also replay enrollment POST bodies. | high | Require HTTPS and disable redirects on every backend client. | Open |
| SR-02 | agent/src/prevention/process.rs:30 | Local user, delayed legitimate command | A legacy Linux process action without a generation can signal the next process to acquire a recycled PID. | high | Require the existing signed generation field and use the pidfd path for manual actions. | Open |
| SR-03 | agent/src/http/mod.rs:126 | Local admin or provisioning failure | A partially provisioned or invalid client identity allows a bearer-only connection to a backend supporting both authentication modes. | medium | Reject a broken certificate/key pair. | Open |
| SR-04 | agent/src/update/apply.rs:84 | Local admin or storage failure | An unreadable or damaged update state is treated as first use. After rollback, the next poll can install the same failed release again. | medium | Fail closed when existing state cannot be validated. | Open |
| SR-05 | agent/src/enrollment/mod.rs:260, agent/src/enrollment/pairing.rs:190 | Backend error forwarded to local logs | An authentication service reflecting request data in an error can persist an enrollment or device credential in service logs. | medium | Report HTTP status and recognized protocol errors only. | Open |
| SR-06 | agent/src/prevention/command_puller.rs:250 | Misrouted tenant response | Rejecting a foreign command serializes its payload into this agent's audit stream, including script or bait content. Malformed payloads can also surface in decoder messages. | medium | Report bounded rejection metadata only. | Open |
| SR-07 | agent/src/prevention/commands.rs:370, agent/src/prevention/audit.rs:87 | Local admin or interrupted host | A restart between recording a nonce and dispatch leaves no proof of execution. A full telemetry channel can discard a completed result. Redelivery alone cannot establish the outcome. | medium | Persist intent and terminal result, correlate by agent and command, support an explicit interrupted outcome. | Open |

## Coverage and limits

* Commands and config use typed canonical JSON. They must structurally decode before verifying the existing signature. The signature and agent binding precede policy application. IoC updates are signed commands, Sigma rules are signed configuration. Maintenance tokens verify raw domain-prefixed bytes before claims parsing and use a dedicated key, purpose, lifetime and persistent nonce. Update directives and release statements use separate pinned keys. Exact-byte pre-decode verification for commands/config would require a versioned backend envelope carrying the signed payload bytes.
* Update verification checks platform, version, signed size and digest again at apply. The existing recovery journal, replacement, health marker and rollback tests exercise interrupted updates using a simulated service.
* Linux quarantine pins directories and uses no-replace restore. Windows has separate vault, service and registry ACL code. Windows process control checks creation time and image. Isolation and release have dedicated management allowlist and restore paths. Package operations use argument vectors and validate package identifiers. Operator-authorized remote scripts are an explicit exception to shell-free execution.
* Maintenance use reporting, Windows uninstall gate and protected service controls provide application-level authorization. Linux root and Windows principals with OS ownership privileges are outside an agent-only guarantee of continued execution. Service-stop reporting and remote liveness are detective controls. Local root can stop both Linux services. Enforcing authorization against such an administrator requires a host policy authority the administrator cannot replace.
* The supported legacy enrollment flow accepts an environment token. Launch-time environments and already-exported process snapshots cannot be retroactively scrubbed. Pairing avoids supplying an environment secret. Existing MSI token-file import and restricted persisted credential files reduce exposure.
* Backend tenant membership and the server's policies for issuing tokens, signing commands and requiring client certificates are outside this repository. File ownership, effective ACL inheritance, service controls, packet routing, and health rollback under actual power loss need host validation.

## Out of scope findings

Command batch decoding buffers the response before signature validation. Body-size limits belong to the parallel footprint workstream. No fuzz targets or general panic cleanup were added.
