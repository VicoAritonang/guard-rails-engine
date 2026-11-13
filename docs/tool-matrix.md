# Tool risk matrix

Tier is derived from two axes: how hard the effect is to undo, and how
far it reaches. Exposure is tracked separately because it measures a
different thing -- not what a call can break, but what it can leak or
let in.


## T0-inert

| Tool | Reversibility | Radius | Exposure | Capability | Controls | Why this grading |
|---|---|---|---|---|---|---|
| `calculator` | none | self | none | `-` | schema | Pure function over its arguments; nothing to undo and nothing to leak. |
| `current_time` | none | self | none | `-` | schema | Reads a clock. |
| `web_fetch` | none | self | untrusted | `web:read` | schema, capability, rate_limit, audit, taint_block, egress_allowlist, trifecta | T0 by effect and the most dangerous tool in the catalog: it is how attacker-authored text enters the context window, and a secret pasted into the query string leaves in the same request. |
| `web_search` | none | self | untrusted | `web:read` | schema, capability, rate_limit | No effect, but every snippet is text a stranger wrote. The query field is itself a low-bandwidth egress channel; that is accepted as residual risk rather than allowlisted, because there is no destination argument to constrain. |

## T1-read

| Tool | Reversibility | Radius | Exposure | Capability | Controls | Why this grading |
|---|---|---|---|---|---|---|
| `calendar_read` | none | org | private | `calendar:read` | schema, capability, rate_limit | A calendar is a map of who a company is talking to. |
| `code_interpreter` | compensable | self | none | `code:exec` | schema, capability, rate_limit, audit | Arbitrary code execution graded T1 entirely on the strength of the containment: no network, no host mount, destroyed after each call. Remove any one of those and this is a T4 -- the grading is a property of the sandbox, not of the tool. **Undo:** discard the sandbox, which is destroyed after every call |
| `db_query` | none | org | private | `db:read` | schema, capability, rate_limit, audit | Read-only by contract, org-wide by reach. Audited because 'which rows did the agent read' is the first question after an incident. |
| `get_customer` | none | org | private | `crm:read` | schema, capability, rate_limit | The canonical 'read private data' leg of the trifecta. |
| `kb_search` | none | org | private+untrusted | `kb:read` | schema, capability, rate_limit | Internal does not mean trusted: the knowledge base contains customer-submitted tickets, so it returns private data and attacker-authorable text at the same time. |
| `list_directory` | none | workspace | private | `fs:read` | schema, capability, rate_limit | Filenames are data too, but the blast radius is a listing. |
| `read_email` | none | org | private+untrusted | `mail:read` | schema, capability, rate_limit | An inbox is a channel any stranger on the internet can write to. Treating its contents as trusted because the mailbox is ours is how agents get hijacked by a message nobody opened. |
| `read_file` | none | workspace | private | `fs:read` | schema, capability, rate_limit | No effect; returns whatever the user put in the workspace. |

## T2-reversible

| Tool | Reversibility | Radius | Exposure | Capability | Controls | Why this grading |
|---|---|---|---|---|---|---|
| `create_ticket` | compensable | org | none | `ticket:write` | schema, capability, rate_limit, audit | Cheap to undo; the cost of getting it wrong is a colleague's attention, which is why it is governed but not gated. **Undo:** close the ticket as created in error |
| `update_customer` | compensable | org | none | `crm:write` | schema, capability, rate_limit, audit | Versioned records make this genuinely reversible. **Undo:** revert the profile to the prior revision |
| `update_record` | compensable | org | none | `db:write` | schema, capability, rate_limit, audit | Undo is real because the change log captures the prior row in the same transaction as the write. **Undo:** write back the prior row captured in the change log |
| `write_file` | compensable | workspace | none | `fs:write` | schema, capability, rate_limit, audit | Compensable only because the workspace is snapshotted before each write. Without that snapshot this is a T3. **Undo:** restore the previous version from the workspace snapshot |

## T3-external

| Tool | Reversibility | Radius | Exposure | Capability | Controls | Why this grading |
|---|---|---|---|---|---|---|
| `calendar_create` | compensable | external | none | `calendar:write` | schema, capability, rate_limit, audit, idempotency, taint_block, egress_allowlist, trifecta | An invite is an email with a different envelope. External attendees make this a third-party effect, so it is graded as one. **Undo:** cancel the event, which sends cancellations to attendees |
| `create_pull_request` | compensable | external | none | `vcs:write` | schema, capability, rate_limit, audit, idempotency, egress_allowlist, trifecta | External and visible, but gated behind human review before it has any effect, which is the only reason the taint block is waived. **Undo:** close the pull request |
| `delete_file` | irreversible | workspace | none | `fs:write` | schema, capability, rate_limit, audit, idempotency, taint_block, trifecta | Snapshots cover writes, not deletions of files the agent never wrote, so this is graded on the worst case. **Undo:** none. |
| `post_message` | compensable | external | none | `chat:write` | schema, capability, rate_limit, audit, idempotency, taint_block, egress_allowlist, trifecta | Deleting a message is a real undo and a weak one, which is exactly what T3 means: retraction is best-effort. **Undo:** delete the message, which does not un-read it |

## T4-irreversible

| Tool | Reversibility | Radius | Exposure | Capability | Controls | Why this grading |
|---|---|---|---|---|---|---|
| `delete_record` | irreversible | critical | none | `db:admin` | schema, capability, rate_limit, audit, idempotency, taint_block, dry_run, approval, trifecta | A hard delete against a system of record. Colleagues depend on the row and no later call brings it back. **Undo:** none. |
| `deploy_service` | irreversible | critical | none | `deploy:write` | schema, capability, rate_limit, audit, idempotency, taint_block, dry_run, approval, trifecta | Rollback restores the binary, not the rows a migration rewrote, so the deploy itself is graded irreversible. **Undo:** none. |
| `execute_shell` | irreversible | critical | none | `host:exec` | schema, capability, rate_limit, audit, idempotency, taint_block, dry_run, approval, trifecta | Unbounded by construction: the blast radius is whatever the host can reach. There is no argument schema that makes this safe, which is why it is gated on a human rather than on a pattern. **Undo:** none. |
| `grant_access` | irreversible | critical | none | `iam:admin` | schema, capability, rate_limit, audit, idempotency, taint_block, dry_run, approval, trifecta | Irreversible despite revocation being one call away: revoking stops future reads, it does not un-copy what was read in between. **Undo:** none. |
| `http_request` | irreversible | external | none | `net:write` | schema, capability, rate_limit, audit, idempotency, taint_block, egress_allowlist, dry_run, approval, trifecta | The effect is whatever the far end does with it, so it is graded as irreversible. Read-only fetching belongs to web_fetch. **Undo:** none. |
| `issue_refund` | irreversible | critical | none | `finance:refund` | schema, capability, rate_limit, audit, idempotency, taint_block, dry_run, approval, trifecta, amount_limit | Money leaving on a customer's say-so is the single most attractive target for a social-engineering prompt. **Undo:** none. |
| `rotate_credentials` | irreversible | critical | none | `iam:admin` | schema, capability, rate_limit, audit, idempotency, taint_block, dry_run, approval, trifecta | Every consumer of the old value breaks at once, and the old value is gone. A correct action with an outage-shaped failure mode. **Undo:** none. |
| `send_email` | irreversible | external | none | `mail:send` | schema, capability, rate_limit, audit, idempotency, taint_block, egress_allowlist, dry_run, approval, trifecta | Unrecallable and third-party visible. Graded at the same tier as a payment because the failure mode -- the wrong recipient reads private data -- is the same failure mode. **Undo:** none. |
| `transfer_funds` | irreversible | critical | none | `finance:transfer` | schema, capability, rate_limit, audit, idempotency, taint_block, egress_allowlist, dry_run, approval, trifecta, amount_limit | The worst case in the catalog. One call per session, a hard ceiling on the amount, and a human signature on every one. **Undo:** none. |
