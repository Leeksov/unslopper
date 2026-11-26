# Direct-state jump-table proof audit

Set `UNSLOP_IDENTITY_AUDIT=1` and
`UNSLOP_IDENTITY_AUDIT_FILE=/absolute/path/to/new-results.jsonl` before IDA
loads the plugin. The file must not exist, and its parent directory must be trusted.
The plugin creates it exclusively; an existing file or final-path symlink is
rejected without enabling the normal optimizer. This selects a dedicated audit-only plugin context. The
normal Unslopper optimizer and Hex-Rays lifecycle callbacks are not installed
in this mode. Its optblock handler reads the `MMAT_GLBOPT1` microcode array,
writes a JSONL record, and returns zero without editing the MBA or IDB.
Only plugin actions 1 (disable), 2 (enable), 3 (status), and 4 (per-function
audit status) are available. Action 4 always reports zero plugin CFG edges.
The audit writes the JSONL file as an external artifact; it does not save
changes to the IDB.

The detector requires one register-selected `m_jtbl`, exact case keys, and at
least two distinct case targets with paths back to that dispatcher. It
accepts a direct selector register or one width-checked `mov`, `low`, or
zero-extension. It requires each reachable dispatcher context to resolve to
a mapped key. Unknown selectors, unsupported exits, inconsistent successors,
and context growth limits reject the proof. Tables over 128 keys are rejected.
A conventional switch or a candidate with unresolved state is not counted as
proved CFF.

Each JSONL line is one event written to the exclusively owned file with
`schema: 2`, a per-context `run_id`, monotonically increasing `sequence`,
function EA, SHA-256 stored by
IDA for the input, status, and optional case and context rows. A successful
row has `cases` entries `[state, target_block, target_ea]` and
`dispatch_contexts` entries
`[context_id, state, next_context_id, target_block, target_ea]`.
`next_context_id` is `-1` for the exit sink. A failed file write or callback exception is reported by plugin actions 3
and 4, disables further auditing in that plugin context, and is not followed
by a second write. An incomplete last line is possible after
a partial I/O failure; the failure is explicit in IDA output.
The handler records only the **first** `MMAT_GLBOPT1` audit result for each
function in one IDA plugin session. Repeated F5 calls do not duplicate a
function's row. Start a fresh IDA process with a new output file for an
independent second pass.

The rows express static state-to-target conclusions in one microcode snapshot.
They are not runtime observations and do not prove full functional
equivalence. The file's SHA-256 comes from IDA's IDB metadata; if the original
input file is no longer available, independently rehashing it is impossible.
Microcode block serials and context IDs may change between optimizer runs;
physical target EAs are the stable comparison field.

The older experimental identity rewrite cloned blocks after a detached trial.
IDA SDK 9.5 exposes no supported atomic live `mba_t` replacement or rollback
for that edit. The audit-only implementation has no identity emitter or
`copy_block` path. Existing optional affine rewriting is available only in
normal plugin mode and is not invoked by this audit context.
