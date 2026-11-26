# Direct-state jump-table proof audit

Set `UNSLOP_IDENTITY_AUDIT=1` and
`UNSLOP_IDENTITY_AUDIT_FILE=/absolute/path/to/results-base` before IDA
loads the plugin. This is a base path in a trusted writable directory. Each
plugin context writes a distinct file named `<base>.<run_id>.jsonl`, and prints
the exact path in IDA Output. The plugin checks that this derived file is
absent before creating it; this is not an OS-atomic exclusive-create guarantee.
The trusted parent directory must not be writable by an adversary. Failure to
create the output never enables the normal optimizer. This setting selects a
dedicated audit-only plugin context. The normal Unslopper optimizer and
Hex-Rays lifecycle callbacks are not installed in this mode. Its optblock
handler reads the `MMAT_GLBOPT1` microcode array,
writes a JSONL record, and returns zero without editing the MBA or IDB.
Only plugin actions 1 (disable), 2 (enable), 3 (status), and 4 (per-function
audit status) are available. Action 4 always reports zero plugin CFG edges.
The audit writes the JSONL file as an external artifact; it does not save
changes to the IDB.

The detector requires one register-selected `m_jtbl`, exact case keys, and at
least two distinct case targets with paths back to that dispatcher. It
accepts a direct selector register or one width-checked `mov`, `low`, or
zero-extension. Hex-Rays stores jump-table labels as signed `sval_t` values;
the audit accepts a negative label only when it fits the selector's signed
width, then compares its width-limited bit pattern. Positive labels must fit
the unsigned width. Two distinct labels that collapse to one bit pattern are
rejected, even if they name the same target. Zero-extended selectors also
require the resulting key to fit the source width. The audit requires each
reachable dispatcher context to resolve to
a mapped key. Unknown selectors, unsupported exits, inconsistent successors,
and context growth limits reject the proof. Tables over 128 keys are rejected.
A conventional switch or a candidate with unresolved state is not counted as
proved CFF.

Each JSONL line is one event written to its per-context file with
`schema: 2`, a per-context `run_id`, monotonically increasing `sequence`,
function EA, SHA-256 stored by
IDA for the input, status, and optional case and context rows. A successful
row has `cases` entries `[state, target_block, target_ea]` and
`dispatch_contexts` entries
`[context_id, state, next_context_id, target_block, target_ea]`.
`next_context_id` is `-1` for the exit sink. A failed file write or callback
exception is reported by plugin actions 3 and 4, disables further auditing
in that plugin context, and is not followed
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

## Exact-sample validation

The `libloader` ARM64 IDB records input SHA-256
`aa4ba77dc142c944b64fdbd8d3fb83a38b7e7200b13cb79422dc9da88cf10970`.
The original input file was unavailable for a fresh hash. A fixed list of
502 **heuristic** direct-state candidates was audited in two independent
audit-only contexts. Each context produced one record per candidate. Both
agreed on all statuses and normalized state-to-target EAs: 465 `proved`;
30 unknown selectors, 2 selector-width failures, 4 case-budget failures,
and 1 multiple-dispatcher failure. Four fixture functions produced
byte-identical OFF and audit-only F5 output from copies of the same IDB.
Plugin action 4 reported zero CFG edge edits for all 502 functions.

The signed-case revision was then tested on the same SHA in a fresh
audit-only IDA process. Its 529-address set comprised the original 502 and
27 disjoint high-goto structural leads (21 direct-state switches and six
state jump tables). All 529 F5 calls succeeded and each address produced one
audit row. The result was **482 `proved` maps**: all 465 previously proved
maps kept identical normalized `state → target EA` pairs; 17 of the 27
additional leads were proved. The 47 remaining rows were 33 unknown or
unmapped selectors, seven without a qualifying identity dispatcher, five
over the 128-case budget, and two with multiple candidate dispatchers.
The two old selector-width failures advanced to an unknown-selector result
and a multiple-dispatcher result, respectively; neither was counted as
proved. Three newly proved high-goto fixtures had byte-identical OFF and
audit-only F5 text on copies of the same saved IDB. This is a read-only
state-map gain, not automatic unflattening.

These results establish bounded static state-map coverage for this exact
microcode snapshot. They do not establish all-path functional equivalence,
runtime reachability, complete flattening removal, or cross-build coverage.
See the [coverage matrix](coverage_matrix.md) for the scoped result.

The older experimental identity rewrite cloned blocks after a detached trial.
IDA SDK 9.5 exposes no supported atomic live `mba_t` replacement or rollback
for that edit. The audit-only implementation has no identity emitter or
`copy_block` path. Existing optional affine rewriting is available only in
normal plugin mode and is not invoked by this audit context.
