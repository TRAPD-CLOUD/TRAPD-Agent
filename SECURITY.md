# Security Policy

TRAPD Agent runs with high privileges on customer machines, so vulnerabilities in it can be severe. We want to make responsible disclosure easy.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub:

1. Go to the **Security** tab of this repository.
2. Choose **Report a vulnerability** (GitHub private vulnerability reporting).

Problems in the TRAPD server side (web application, APIs, ingest, detection) belong in the `TRAPD-CLOUD/TRAPD` repository. If you are unsure which one is affected, report it here and we will route it.

If you cannot use GitHub, open a public issue that only says you need a private contact channel. Do not include any details about the vulnerability in it.

### What to include

- Affected component, agent version and operating system (Windows or Linux, kernel/build)
- The impact: what an attacker can do, and what they need to start (local user, administrator, network position, malicious server)
- Steps to reproduce or a proof of concept
- Whether the issue is exploitable in the default configuration
- Any suggested fix

Send the minimum data needed to demonstrate the issue. Do not include real customer data.

## What to expect

TRAPD is maintained by a small team. We aim to:

- acknowledge your report within **5 business days**,
- give you an initial assessment within **14 days**,
- keep you informed about progress, and
- credit you in the advisory if you want to be credited.

We ask for coordinated disclosure and propose **90 days** from the report before details are published. We will tell you if we need more time and why. For confirmed issues we publish a GitHub Security Advisory, request a CVE where appropriate, and describe affected versions, fixed versions and workarounds.

## Supported versions

The agent has not reached version 1.0 yet.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No. Please upgrade |

The agent has a signed self-update mechanism. Running the latest release is the recommended setup.

## Scope

In scope:

- Local privilege escalation through the agent, its installer, service, update or file handling
- Bypass of the agent's self-protection that works without administrator or root rights
- Flaws in signature verification of configuration, response commands or updates, including downgrade and replay
- Flaws in pairing, enrollment or the agent's identity and transport security (TLS pinning, token handling)
- Abuse of response actions (kill, suspend, isolate, quarantine, restore) by a party that is not an authorized operator
- Path traversal, symlink or race conditions in quarantine, restore or log handling
- Memory-safety problems in parsing of untrusted input (events, configuration, network data)
- Leakage of secrets, tokens or sensitive data in logs, files or telemetry
- Insecure defaults in installers and packages
- Vulnerabilities in dependencies that are actually reachable in the agent

Out of scope:

- Actions that require an already compromised administrator or root account, unless they defeat a protection the agent claims to provide against exactly that (see the security model in the README and `CAPABILITIES.md`)
- Detection evasion techniques against individual rules. Please report those as normal issues or detection-quality feedback, not as vulnerabilities
- Automated scanner output without a demonstrated impact
- Issues in unsupported versions or modified builds

## Testing rules

- Test only on machines you own or are allowed to test.
- Do not test against other people's TRAPD deployments.
- Avoid destructive actions and avoid degrading hosts or services you do not own.
- Stop and report as soon as you can show impact.

If you follow these rules and act in good faith, we will not pursue legal action against you for your research, and we will work with you to resolve the issue.

## Verifying releases

Release artifacts are verified before an update is applied. The verification keys and the procedure are described in the repository's deployment documentation (`deploy/`). If you find a way to get the agent to install an artifact that was not signed by the release key, treat it as a critical vulnerability and report it.
