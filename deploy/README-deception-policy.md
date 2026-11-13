# Local approvals for signed deception placement

Signed `deploy_honeytoken` requests require customer approval in the agent
service's local `TRAPD_DECEPTION_PLACEMENTS` environment variable. An absent
variable or empty approval list denies all new signed placements. Invalid JSON,
unknown fields, more than 256 entries, or more than 64 KiB also fail closed.
This variable is deliberately absent from signed `AgentConfig` and command
payloads: possession of the command signing key cannot grant placement rights.

Each approval binds **one exact absolute path, bait kind, lowercase SHA-256
content digest, and numeric file mode**. There are no directory grants, globs,
or automatic approval of future backend-generated content. Prepare the bait
outside its eventual destination, inspect its bytes and intended use locally,
then calculate its SHA-256 digest. Approve only that reviewed digest; do not
copy unreviewed backend hashes into the local policy automatically.

```json
{
  "approvals": [
    {
      "path": "/srv/decoys/credentials.txt",
      "kind": "webroot_env",
      "sha256": "REPLACE_WITH_REVIEWED_CONTENT_SHA256",
      "mode": 384
    },
    {
      "path": "/srv/decoys/deployment-notes.txt",
      "kind": "breadcrumb",
      "sha256": "REPLACE_WITH_REVIEWED_NOTE_SHA256",
      "mode": 384
    }
  ]
}
```

The placeholders deliberately fail validation. `384`, `416`, and `420` mean
`0600`, `0640`, and `0644` respectively. These are the only approved modes.
A request mode of zero resolves to `0600`, regardless of neighboring files;
execute, set-ID, sticky, and group/other write permissions are rejected.
Changing any approved bytes, destination, kind, or mode requires a new local
approval and service restart. Out-of-band canary registrations and existing
bait format validation still apply. Windows writes hold one exclusive no-follow file handle through
content and timestamp writes; an IO failure can leave an unregistered partial
file, which requires local inspection rather than automatic deletion.

On Linux, put the compact JSON value in the root-owned service environment
file (`/etc/trapd/agent.env`, owner root, mode `0600`), using the
`TRAPD_DECEPTION_PLACEMENTS='{"approvals":[...]}'` assignment format. Protect
its parent directory from non-administrative writes. The existing optional
`trapd-agent-deception.conf` systemd drop-in grants filesystem capabilities;
it does not grant placement approvals. Both filesystem access and local policy
must permit the operation. Keep the base sandbox where its scope suffices.

On Windows, provision the same JSON variable in the **LocalSystem service's
administrator-controlled environment**, using exact local drive paths such as
`C:\Decoys\credentials.txt` (JSON spelling: `C:\\Decoys\\credentials.txt`).
Do not use a user-editable environment file. Locally create the destination
parent directories before requesting placement. The agent opens and holds
all plain ancestor directories without write/delete sharing during signed
placement; reparse points, junctions, sharing conflicts, UNC/device paths,
short-name aliases, alternate data streams, and ambiguous spellings fail
closed. A sharing conflict requires local investigation rather than disabling
the checks. Existing Windows locally generated decoys use their separate local
bait workflow; this policy covers remotely supplied signed content.

System directories, configured agent state/config/log directories, agent
control files (including `rtr-enabled`), startup and authorization destinations,
executable suffixes, and ambiguous paths are refused even if explicitly listed.
For example, use a backup data filename instead of active shell startup files,
SSH `authorized_keys`, or an active file named `config`. Linux publication
retains directory-fd traversal with `O_NOFOLLOW`, private staging, and atomic
no-replace publication. Existing hardlinked targets are never overwritten.
Local administrators remain responsible for mount layouts and the reviewed
content's meaning to applications consuming it.

Breadcrumbs now create exact-approved, UTF-8 `.txt`/`.md` notes only. General
append, including shell history and arbitrary configuration append, is removed.
A request containing any denied breadcrumb is rejected before the token is
written. Use a standalone note pointing to the approved bait instead. Existing
registered tokens can still be revoked without renewed placement approval;
content ownership checks remain mandatory. Legacy Linux appended breadcrumbs
are cleaned only through a no-follow regular-file handle, with a single-link
check and unchanged tail proof. Legacy Windows appended breadcrumbs require
local manual cleanup; remote cleanup never truncates them.

Roll out customer approvals before issuing new signed deployments. Old requests
without matching approvals fail explicitly and create nothing; do not fall back
to unrestricted placement. Test first with a harmless fake credential and note
in a dedicated data directory, confirm registration/health, then revoke them.
