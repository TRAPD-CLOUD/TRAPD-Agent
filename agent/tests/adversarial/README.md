# Adversarial test kit

Every script refuses to run unless `TRAPD_ADVERSARIAL_OK=1` and restores what it changes.

| Threat | Script | Action | Expected | Verify |
|---|---|---|---|---|
| T4 WFP block (Windows) | `T4-wfp-block-windows.ps1` | `New-NetFirewallRule -Direction Outbound -Action Block -Program <agent exe>` (EDRSilencer-style app-id block filter), removed after 75 s | `selfprotect.network_silenced`, high, evidence `filter_name`, `provider` ("Microsoft Windows Firewall"), `layer`, `reason=app_id`, within ~65 s (change notification) | Detections list; events queued during the block arrive after removal |
| T4 iptables owner DROP (Linux) | `T4-iptables-uid-linux.sh` | `iptables -A OUTPUT -m owner --uid-owner <uid> -j DROP` | `selfprotect.network_silenced`, high, `source=iptables`, `reason=uid` | as above; `nft` rules are parsed the same way |
| T5 hosts redirect (Windows) | `T5-hosts-redirect-windows.ps1 -BackendHost <host>` | hosts entry `203.0.113.66 <backend host>`, restored | `selfprotect.backend_redirected`, high, `vector=hosts` | Detections list |
| T5 hosts redirect (Linux) | `T5-hosts-redirect-linux.sh` | same on `/etc/hosts` | same | same |
| T5 TLS interception (MANUAL) | none | set `TRAPD_BACKEND_SPKI_PINS` to a wrong pin, restart the agent; or front the backend with a proxy whose CA is in `ca.crt` | handshake refused, `selfprotect.tls_pin_mismatch`, high, `observed_spki_sha256` lists the presented chain; delivered after the correct pin is restored | agent log; unset the variable and restart to recover. Report-only mode (no pins) writes `observed_spki_pins.json` to the state dir |
| T5 proxy / NRPT (MANUAL) | none | `netsh winhttp set proxy 127.0.0.1:3128`, or `Add-DnsClientNrptRule -Namespace .<backend domain> -NameServers 203.0.113.53`. Revert: `netsh winhttp reset proxy`, `Get-DnsClientNrptRule \| Remove-DnsClientNrptRule` | `selfprotect.backend_redirected`, vector `proxy_winhttp` (medium) / `nrpt` (high) | Detections list |
| T4 selective block (MANUAL) | none | set `TRAPD_NETWORK_PROBE_URL=https://<neutral EU endpoint>`, then block only the backend address | after 3 scans (~3 min) `selfprotect.backend_unreachable_selective`, medium | delivered once the block is removed |

Hosts-file and proxy findings that are legitimate (on-prem backend, corporate proxy) are silenced with `TRAPD_NETWORK_GUARD_ALLOW` (for example `203.0.113.66` or the proxy `host:port`).
