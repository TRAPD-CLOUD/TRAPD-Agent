# Retired agent-side detection

The agent used to evaluate detection rules locally. That moved to the backend.
Kept here as the migration reference for the backend rule set:

- `rule-catalog.json`: the 80 rules + 3 prefixes with id, MITRE mapping, base/max
  severity, mode and dedup window (output of the former
  `trapd-agent diagnostics rule-catalog`).
- `sigma/`: the Sigma rules the agent shipped.
- `fixtures/`: benign corpora and honeytoken vectors; useful to measure
  false positives of the ported backend rules.

The rule logic itself is in git history before the "move detection to the
backend" change. Nothing in this directory is built or shipped.
