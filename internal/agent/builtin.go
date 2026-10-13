package agent

import "sync"

// builtinTools is a catalog of the tools a real assistant-style agent is
// usually given, graded on the two risk axes.
//
// The gradings are the substance of this file, and every one of them is a
// claim someone could disagree with -- so each carries a Rationale, and the
// control matrix renders it. A few worth arguing with up front:
//
//   - send_email is T4, the same tier as a wire transfer. An email cannot be
//     recalled and reaches a third party, which is the definition of the tier.
//     Operators who want unattended email can lower it; the point is that they
//     have to do so explicitly and can see what they gave up.
//   - web_fetch is T0 by effect and carries four controls anyway, because it is
//     the doorway attacker-authored text walks through.
//   - grant_access is irreversible even though revoking is one call away.
//     Revocation stops future reads; it does not un-copy what was already read.
//   - deploy_service is irreversible because a rollback restores the binary,
//     not the rows a migration rewrote.
var builtinTools = []Tool{
	// ---------------------------------------------------------------- compute
	{
		Name: "calculator", Domain: "compute",
		Description:   "Evaluate an arithmetic expression.",
		Reversibility: RevNone, Radius: RadiusSelf, Exposure: ExposureNone,
		Params: []Param{
			{Name: "expression", Type: "string", Required: true, MaxLen: 512,
				Desc: "Arithmetic expression to evaluate."},
		},
		Rationale: "Pure function over its arguments; nothing to undo and nothing to leak.",
	},
	{
		Name: "current_time", Domain: "compute",
		Description:   "Return the current time in a timezone.",
		Reversibility: RevNone, Radius: RadiusSelf, Exposure: ExposureNone,
		Params: []Param{
			{Name: "timezone", Type: "string", MaxLen: 64, Desc: "IANA timezone name."},
		},
		Rationale: "Reads a clock.",
	},

	// -------------------------------------------------------------------- web
	{
		Name: "web_search", Domain: "web",
		Description:   "Search the public web and return result snippets.",
		Reversibility: RevNone, Radius: RadiusSelf, Exposure: ExposureUntrusted,
		Capability: "web:read", MaxPerSession: 20,
		Params: []Param{
			{Name: "query", Type: "string", Required: true, MaxLen: 1024},
			{Name: "top_k", Type: "integer", Desc: "Results to return, 1-20."},
		},
		Rationale: "No effect, but every snippet is text a stranger wrote. " +
			"The query field is itself a low-bandwidth egress channel; that is " +
			"accepted as residual risk rather than allowlisted, because there is " +
			"no destination argument to constrain.",
	},
	{
		Name: "web_fetch", Domain: "web",
		Description:   "Fetch a URL and return its text content.",
		Reversibility: RevNone, Radius: RadiusSelf, Exposure: ExposureUntrusted,
		Egress:     true,
		Capability: "web:read", MaxPerSession: 15,
		Params: []Param{
			{Name: "url", Type: "string", Required: true, MaxLen: 2048, Destination: true,
				Desc: "Absolute http(s) URL to fetch."},
		},
		Rationale: "T0 by effect and the most dangerous tool in the catalog: it is " +
			"how attacker-authored text enters the context window, and a secret " +
			"pasted into the query string leaves in the same request.",
	},

	// -------------------------------------------------------------- knowledge
	{
		Name: "kb_search", Domain: "knowledge",
		Description:   "Search the internal knowledge base.",
		Reversibility: RevNone, Radius: RadiusOrg,
		Exposure:   ExposurePrivate | ExposureUntrusted,
		Capability: "kb:read", MaxPerSession: 30,
		Params: []Param{
			{Name: "query", Type: "string", Required: true, MaxLen: 1024},
			{Name: "top_k", Type: "integer"},
		},
		Rationale: "Internal does not mean trusted: the knowledge base contains " +
			"customer-submitted tickets, so it returns private data and " +
			"attacker-authorable text at the same time.",
	},

	// ------------------------------------------------------------- filesystem
	{
		Name: "read_file", Domain: "filesystem",
		Description:   "Read a file from the agent workspace.",
		Reversibility: RevNone, Radius: RadiusWorkspace, Exposure: ExposurePrivate,
		Capability: "fs:read",
		Params: []Param{
			{Name: "path", Type: "string", Required: true, MaxLen: 1024},
		},
		Rationale: "No effect; returns whatever the user put in the workspace.",
	},
	{
		Name: "list_directory", Domain: "filesystem",
		Description:   "List the entries in a workspace directory.",
		Reversibility: RevNone, Radius: RadiusWorkspace, Exposure: ExposurePrivate,
		Capability: "fs:read",
		Params: []Param{
			{Name: "path", Type: "string", Required: true, MaxLen: 1024},
		},
		Rationale: "Filenames are data too, but the blast radius is a listing.",
	},
	{
		Name: "write_file", Domain: "filesystem",
		Description:   "Write a file in the agent workspace.",
		Reversibility: RevCompensable, Radius: RadiusWorkspace,
		Capability: "fs:write",
		Undo:       "restore the previous version from the workspace snapshot",
		Params: []Param{
			{Name: "path", Type: "string", Required: true, MaxLen: 1024},
			{Name: "content", Type: "string", Required: true, MaxLen: 1_000_000, Payload: true},
		},
		Rationale: "Compensable only because the workspace is snapshotted before " +
			"each write. Without that snapshot this is a T3.",
	},
	{
		Name: "delete_file", Domain: "filesystem",
		Description:   "Delete a file from the agent workspace.",
		Reversibility: RevIrreversible, Radius: RadiusWorkspace,
		Capability: "fs:write", MaxPerSession: 10,
		Params: []Param{
			{Name: "path", Type: "string", Required: true, MaxLen: 1024},
		},
		Rationale: "Snapshots cover writes, not deletions of files the agent " +
			"never wrote, so this is graded on the worst case.",
	},

	// ------------------------------------------------------------------- data
	{
		Name: "db_query", Domain: "data",
		Description:   "Run a read-only SQL query against the analytics replica.",
		Reversibility: RevNone, Radius: RadiusOrg, Exposure: ExposurePrivate,
		Capability: "db:read", Extra: CtrlAudit, MaxPerSession: 25,
		Params: []Param{
			{Name: "sql", Type: "string", Required: true, MaxLen: 8192,
				Desc: "SELECT statement; writes are rejected by the executor."},
		},
		Rationale: "Read-only by contract, org-wide by reach. Audited because " +
			"'which rows did the agent read' is the first question after an incident.",
	},
	{
		Name: "update_record", Domain: "data",
		Description:   "Update fields on a row in an operational table.",
		Reversibility: RevCompensable, Radius: RadiusOrg,
		Capability: "db:write", MaxPerSession: 20,
		Undo: "write back the prior row captured in the change log",
		Params: []Param{
			{Name: "table", Type: "string", Required: true, MaxLen: 128},
			{Name: "id", Type: "string", Required: true, MaxLen: 128},
			{Name: "patch", Type: "string", Required: true, MaxLen: 65536, Payload: true,
				Desc: "JSON object of columns to set."},
		},
		Rationale: "Undo is real because the change log captures the prior row " +
			"in the same transaction as the write.",
	},
	{
		Name: "delete_record", Domain: "data",
		Description:   "Permanently delete a row from an operational table.",
		Reversibility: RevIrreversible, Radius: RadiusCritical,
		Capability: "db:admin", MaxPerSession: 3,
		Params: []Param{
			{Name: "table", Type: "string", Required: true, MaxLen: 128},
			{Name: "id", Type: "string", Required: true, MaxLen: 128},
		},
		Rationale: "A hard delete against a system of record. Colleagues depend " +
			"on the row and no later call brings it back.",
	},

	// -------------------------------------------------------------------- crm
	{
		Name: "get_customer", Domain: "crm",
		Description:   "Fetch a customer profile.",
		Reversibility: RevNone, Radius: RadiusOrg, Exposure: ExposurePrivate,
		Capability: "crm:read", MaxPerSession: 30,
		Params: []Param{
			{Name: "customer_id", Type: "string", Required: true, MaxLen: 128},
		},
		Rationale: "The canonical 'read private data' leg of the trifecta.",
	},
	{
		Name: "update_customer", Domain: "crm",
		Description:   "Update a customer profile.",
		Reversibility: RevCompensable, Radius: RadiusOrg,
		Capability: "crm:write", MaxPerSession: 10,
		Undo: "revert the profile to the prior revision",
		Params: []Param{
			{Name: "customer_id", Type: "string", Required: true, MaxLen: 128},
			{Name: "patch", Type: "string", Required: true, MaxLen: 32768, Payload: true},
		},
		Rationale: "Versioned records make this genuinely reversible.",
	},

	// ------------------------------------------------------------------- mail
	{
		Name: "read_email", Domain: "mail",
		Description:   "Read messages from a mailbox folder.",
		Reversibility: RevNone, Radius: RadiusOrg,
		Exposure:   ExposurePrivate | ExposureUntrusted,
		Capability: "mail:read", MaxPerSession: 20,
		Params: []Param{
			{Name: "folder", Type: "string", MaxLen: 128},
			{Name: "limit", Type: "integer"},
		},
		Rationale: "An inbox is a channel any stranger on the internet can write " +
			"to. Treating its contents as trusted because the mailbox is ours is " +
			"how agents get hijacked by a message nobody opened.",
	},
	{
		Name: "send_email", Domain: "mail",
		Description:   "Send an email.",
		Reversibility: RevIrreversible, Radius: RadiusExternal,
		Egress:     true,
		Capability: "mail:send", MaxPerSession: 3,
		Params: []Param{
			{Name: "to", Type: "string", Required: true, MaxLen: 512, Destination: true},
			{Name: "subject", Type: "string", Required: true, MaxLen: 512},
			{Name: "body", Type: "string", Required: true, MaxLen: 100_000, Payload: true},
		},
		Rationale: "Unrecallable and third-party visible. Graded at the same tier " +
			"as a payment because the failure mode -- the wrong recipient reads " +
			"private data -- is the same failure mode.",
	},

	// ------------------------------------------------------------------- chat
	{
		Name: "post_message", Domain: "chat",
		Description:   "Post a message to a team chat channel.",
		Reversibility: RevCompensable, Radius: RadiusExternal,
		Egress:     true,
		Capability: "chat:write", MaxPerSession: 10,
		Undo: "delete the message, which does not un-read it",
		Params: []Param{
			{Name: "channel", Type: "string", Required: true, MaxLen: 128, Destination: true},
			{Name: "text", Type: "string", Required: true, MaxLen: 40_000, Payload: true},
		},
		Rationale: "Deleting a message is a real undo and a weak one, which is " +
			"exactly what T3 means: retraction is best-effort.",
	},

	// --------------------------------------------------------------- calendar
	{
		Name: "calendar_read", Domain: "calendar",
		Description:   "List calendar events in a date range.",
		Reversibility: RevNone, Radius: RadiusOrg, Exposure: ExposurePrivate,
		Capability: "calendar:read", MaxPerSession: 20,
		Params: []Param{
			{Name: "range", Type: "string", MaxLen: 128, Desc: "e.g. 2026-09-01/2026-09-30"},
		},
		Rationale: "A calendar is a map of who a company is talking to.",
	},
	{
		Name: "calendar_create", Domain: "calendar",
		Description:   "Create a calendar event and invite attendees.",
		Reversibility: RevCompensable, Radius: RadiusExternal,
		Egress:     true,
		Capability: "calendar:write", MaxPerSession: 5,
		Undo: "cancel the event, which sends cancellations to attendees",
		Params: []Param{
			{Name: "title", Type: "string", Required: true, MaxLen: 512},
			{Name: "start", Type: "string", Required: true, MaxLen: 64},
			{Name: "attendees", Type: "array", MaxLen: 64, Destination: true,
				Desc: "Email addresses to invite."},
			{Name: "notes", Type: "string", MaxLen: 16384, Payload: true},
		},
		Rationale: "An invite is an email with a different envelope. External " +
			"attendees make this a third-party effect, so it is graded as one.",
	},

	// ------------------------------------------------------------------- code
	{
		Name: "code_interpreter", Domain: "code",
		Description:   "Execute Python in a network-isolated sandbox.",
		Reversibility: RevCompensable, Radius: RadiusSelf,
		Capability: "code:exec", Extra: CtrlAudit, MaxPerSession: 20,
		Undo: "discard the sandbox, which is destroyed after every call",
		Params: []Param{
			{Name: "code", Type: "string", Required: true, MaxLen: 200_000, Payload: true},
			{Name: "timeout_seconds", Type: "integer"},
		},
		Rationale: "Arbitrary code execution graded T1 entirely on the strength of " +
			"the containment: no network, no host mount, destroyed after each " +
			"call. Remove any one of those and this is a T4 -- the grading is a " +
			"property of the sandbox, not of the tool.",
	},
	{
		Name: "execute_shell", Domain: "code",
		Description:   "Run a shell command on the application host.",
		Reversibility: RevIrreversible, Radius: RadiusCritical,
		Capability: "host:exec", MaxPerSession: 2,
		Params: []Param{
			{Name: "command", Type: "string", Required: true, MaxLen: 4096, Payload: true},
		},
		Rationale: "Unbounded by construction: the blast radius is whatever the " +
			"host can reach. There is no argument schema that makes this safe, " +
			"which is why it is gated on a human rather than on a pattern.",
	},

	// -------------------------------------------------------------------- vcs
	{
		Name: "create_pull_request", Domain: "vcs",
		Description:   "Open a pull request against a repository.",
		Reversibility: RevCompensable, Radius: RadiusExternal,
		Egress:     true,
		Capability: "vcs:write", MaxPerSession: 5,
		Undo: "close the pull request",
		// Waiving the taint block here is a deliberate trade, not an oversight.
		// A coding agent's entire job is to produce artefacts derived from
		// documents it read: issues, API docs, stack traces. Blocking
		// untrusted-derived content would block the product. The compensating
		// control is that a pull request is a *proposal* -- a human reviews it
		// before anything merges -- which is what makes the waiver defensible
		// here and nowhere else in this catalog.
		Waive: CtrlTaintBlock,
		Params: []Param{
			{Name: "repo", Type: "string", Required: true, MaxLen: 256, Destination: true},
			{Name: "title", Type: "string", Required: true, MaxLen: 512},
			{Name: "body", Type: "string", Required: true, MaxLen: 100_000, Payload: true},
			{Name: "branch", Type: "string", Required: true, MaxLen: 256},
		},
		Rationale: "External and visible, but gated behind human review before it " +
			"has any effect, which is the only reason the taint block is waived.",
	},

	// ------------------------------------------------------------------- http
	{
		Name: "http_request", Domain: "http",
		Description:   "Make an arbitrary HTTP request to an allowlisted host.",
		Reversibility: RevIrreversible, Radius: RadiusExternal,
		Egress:     true,
		Capability: "net:write", MaxPerSession: 5,
		Params: []Param{
			{Name: "method", Type: "string", Required: true, MaxLen: 8,
				Enum: []string{"GET", "POST", "PUT", "PATCH", "DELETE"}},
			{Name: "url", Type: "string", Required: true, MaxLen: 2048, Destination: true},
			{Name: "body", Type: "string", MaxLen: 200_000, Payload: true},
		},
		Rationale: "The effect is whatever the far end does with it, so it is " +
			"graded as irreversible. Read-only fetching belongs to web_fetch.",
	},

	// ---------------------------------------------------------------- finance
	{
		Name: "transfer_funds", Domain: "finance",
		Description:   "Transfer money to an external account.",
		Reversibility: RevIrreversible, Radius: RadiusCritical,
		Egress:         true,
		Capability:     "finance:transfer",
		AmountLimitUSD: 500, MaxPerSession: 1,
		Params: []Param{
			{Name: "destination_account", Type: "string", Required: true, MaxLen: 64,
				Destination: true},
			{Name: "amount", Type: "number", Required: true, Amount: true},
			{Name: "currency", Type: "string", Required: true, MaxLen: 3,
				Enum: []string{"USD", "EUR", "GBP", "IDR"}},
			{Name: "memo", Type: "string", MaxLen: 512, Payload: true},
		},
		Rationale: "The worst case in the catalog. One call per session, a hard " +
			"ceiling on the amount, and a human signature on every one.",
	},
	{
		Name: "issue_refund", Domain: "finance",
		Description:   "Refund a customer order.",
		Reversibility: RevIrreversible, Radius: RadiusCritical,
		Capability:     "finance:refund",
		AmountLimitUSD: 250, MaxPerSession: 3,
		Params: []Param{
			{Name: "order_id", Type: "string", Required: true, MaxLen: 128},
			{Name: "amount", Type: "number", Required: true, Amount: true},
			{Name: "reason", Type: "string", MaxLen: 512, Payload: true},
		},
		Rationale: "Money leaving on a customer's say-so is the single most " +
			"attractive target for a social-engineering prompt.",
	},

	// --------------------------------------------------------------- identity
	{
		Name: "grant_access", Domain: "identity",
		Description:   "Grant a principal a role on a resource.",
		Reversibility: RevIrreversible, Radius: RadiusCritical,
		Capability: "iam:admin", MaxPerSession: 2,
		Params: []Param{
			{Name: "principal", Type: "string", Required: true, MaxLen: 256},
			{Name: "role", Type: "string", Required: true, MaxLen: 64,
				Enum: []string{"viewer", "editor", "admin"}},
			{Name: "resource", Type: "string", Required: true, MaxLen: 256},
		},
		Rationale: "Irreversible despite revocation being one call away: revoking " +
			"stops future reads, it does not un-copy what was read in between.",
	},
	{
		Name: "rotate_credentials", Domain: "identity",
		Description:   "Rotate a stored secret.",
		Reversibility: RevIrreversible, Radius: RadiusCritical,
		Capability: "iam:admin", MaxPerSession: 1,
		Params: []Param{
			{Name: "secret_name", Type: "string", Required: true, MaxLen: 256},
		},
		Rationale: "Every consumer of the old value breaks at once, and the old " +
			"value is gone. A correct action with an outage-shaped failure mode.",
	},

	// ----------------------------------------------------------------- deploy
	{
		Name: "deploy_service", Domain: "deploy",
		Description:   "Deploy a service version to an environment.",
		Reversibility: RevIrreversible, Radius: RadiusCritical,
		Capability: "deploy:write", MaxPerSession: 1,
		Params: []Param{
			{Name: "service", Type: "string", Required: true, MaxLen: 128},
			{Name: "version", Type: "string", Required: true, MaxLen: 64},
			{Name: "environment", Type: "string", Required: true, MaxLen: 32,
				Enum: []string{"dev", "staging", "production"}},
		},
		Rationale: "Rollback restores the binary, not the rows a migration " +
			"rewrote, so the deploy itself is graded irreversible.",
	},

	// ---------------------------------------------------------------- support
	{
		Name: "create_ticket", Domain: "support",
		Description:   "Open a support ticket.",
		Reversibility: RevCompensable, Radius: RadiusOrg,
		Capability: "ticket:write", MaxPerSession: 10,
		Undo: "close the ticket as created in error",
		Params: []Param{
			{Name: "title", Type: "string", Required: true, MaxLen: 512},
			{Name: "body", Type: "string", Required: true, MaxLen: 65536, Payload: true},
			{Name: "assignee", Type: "string", MaxLen: 128},
		},
		Rationale: "Cheap to undo; the cost of getting it wrong is a colleague's " +
			"attention, which is why it is governed but not gated.",
	},
}

var (
	builtinOnce sync.Once
	builtin     *Catalog
	builtinErr  error
)

// DefaultCatalog returns the built-in tool catalog.
//
// It is validated on first use rather than in an init function so that a
// grading mistake surfaces as an error the caller can report with context,
// instead of as a panic during package initialisation with no request to
// attach it to.
func DefaultCatalog() (*Catalog, error) {
	builtinOnce.Do(func() { builtin, builtinErr = NewCatalog(builtinTools) })
	return builtin, builtinErr
}

// MustDefaultCatalog is DefaultCatalog for tests and command-line tools.
func MustDefaultCatalog() *Catalog {
	c, err := DefaultCatalog()
	if err != nil {
		panic(err)
	}
	return c
}
