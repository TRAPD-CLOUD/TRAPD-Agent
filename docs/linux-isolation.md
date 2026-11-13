# Linux containment and migration

Full host isolation requires **nftables** (`nft`) and the agent's existing
`CAP_NET_ADMIN` permission. The agent prefers nft when installed; restart the
agent after installing it. `iptables`/`ip6tables` remain available for individual
IP blocks, but full isolation and release explicitly fail before any firewall
operation when this fallback is selected. There is no safe dual-stack fallback:
legacy IPv4 and IPv6 tools cannot share a transaction, and a failed second
commit or rollback could otherwise leave a partially released host.

## Effective policy

The agent owns `table inet trapd`. IP blocking retains the outbound `block`
chain. Isolation uses three base chains at priority -150: `isolate_input`,
`isolate_allow` (the existing output chain name), and `isolate_forward`.

- Input: allow loopback; allow replies from configured management/allowlist
  addresses only in conntrack `established,related`; drop everything else.
- Output: allow loopback and configured management/allowlist destinations;
  drop everything else.
- Forward: drop all routed IPv4 and IPv6 traffic, including traffic to allowlisted
  management peers. Hosts routing container/VM traffic must account for this.
- IPv6 link control: allow router advertisements, neighbor solicitations and
  neighbor advertisements inbound; allow router solicitations, neighbor
  solicitations and neighbor advertisements outbound. All require hop limit 255.
  This keeps IPv6 next-hop discovery working without exempting arbitrary ICMPv6
  or established connections to other peers. Existing operator policy can still
  restrict this traffic.

The isolation allowlist is capped at 256 addresses; generated scripts at 128 KiB.
Every Linux firewall subprocess has a ten-second deadline, an 8 KiB diagnostic
limit and a 1 MiB listing limit. Input/output pipes are nonblocking, drained in a
bounded loop, and timed-out process groups are killed and the child is reaped without helper
threads. A timeout/output-limit failure can have an uncertain kernel outcome; it
reports an error requiring local policy inspection before retry, never a claimed
success or a compensating flush.

Each change is one `nft -f -` transaction over all three chains and both address
families. Chain flushes and replacement rules commit together; a rejected
transaction retains the previous effective policy. Startup only adds missing
objects; it never flushes an existing isolation or IP block. Release empties only
the three isolation chains in one transaction and retains IP blocks and all
operator-managed policy. Mutations inside the agent are serialized so startup,
TTL changes, isolation and release cannot interleave their firewall commands.
An external firewall manager must not edit the agent-owned table.

Management addresses are resolved and validated by the existing engine before
this code executes. Exceptions are IP-wide, matching the existing protocol;
this does not create a general conntrack bypass for pre-isolation connections.
The existing Windows firewall implementation is unchanged.

## Upgrading existing isolation

Use local console/out-of-band access for a host already isolated by an older
agent. Keep both its current policy and backup copies of `iptables-save`,
`ip6tables-save`, and `nft list ruleset` output where the customer controls access.
Do not flush a firewall table or remove `TRAPD_BLOCK`.

For an existing nft deployment, upgrade and reissue a signed isolation command.
The output chain name is retained, and replacement adds input/forward protection
atomically. Startup alone preserves the old policy; it does not infer whether
empty newly created chains should be isolated.

For legacy iptables isolation, install nftables, restart the upgraded agent and
successfully apply a new signed isolation command with the required management
addresses. Verify the new `inet trapd` input, output and forward rules locally
before removing any legacy rule. Older output-only isolation may further
restrict the new allowlist until it is removed.

Only after verifying the new nft policy, remove the exact old output jumps using
these local administrative commands (repeat only if inspection shows duplicate
exact jumps):

```sh
sudo iptables -S OUTPUT
sudo ip6tables -S OUTPUT
sudo iptables -D OUTPUT -j TRAPD_ISOLATE
sudo ip6tables -D OUTPUT -j TRAPD_ISOLATE
```

These commands remove only legacy isolation hooks. Leave `TRAPD_BLOCK` and all
customer chains/jumps intact. Stop and investigate any failure; do not substitute
a table or chain flush. Verify both legacy jumps are absent and the new nft
policy remains effective. Subsequent signed release uses nft atomically. A host
that cannot install nft must retain its legacy policy until a local administrator
explicitly performs recovery; the upgraded agent will not report a successful
partial release.

## Verification scope

Unit regressions intercept the process boundary and inspect the actual serialized
nft batch, three hooks, final drops, dual-stack exceptions and release behavior.
They inject transaction failures and verify that initialization and failed
updates preserve the committed policy. Legacy full-isolation/release tests assert
no process is invoked. IP input validation and existing IPv6 block behavior remain
covered. No test changes the host firewall.

Kernel/netnamespace integration requires a disposable VM or a runner permitting
user/network namespaces; run both successful and deliberately invalid nft batches
there and inspect the full ruleset before/after. This workspace rejects user
namespace mapping, so privileged kernel integration was not run.

References: [nftables atomic replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement),
[nft manual](https://www.netfilter.org/projects/nftables/manpage.html),
[upstream iptables-restore manual](https://man7.org/linux/man-pages/man8/iptables-restore.8.html).
