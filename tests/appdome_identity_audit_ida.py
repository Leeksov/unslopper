"""Read-only audit fixture, run in a disposable IDA 9.5 libloader IDB.

Start IDA with UNSLOP_IDENTITY_AUDIT=1 and a fresh absolute
UNSLOP_IDENTITY_AUDIT_FILE. Compare OFF/ON F5 text separately with an OFF
instance; this script checks only audit-mode evidence and per-EA dedup.
"""

import json
import os
from pathlib import Path

import ida_hexrays
import ida_nalt

EXPECTED_SHA256 = "aa4ba77dc142c944b64fdbd8d3fb83a38b7e7200b13cb79422dc9da88cf10970"
FIXTURES = (0x23B6BC, 0x1A4778, 0x63290, 0x8B30)

assert os.environ.get("UNSLOP_IDENTITY_AUDIT") == "1"
assert ida_nalt.retrieve_input_file_sha256().hex() == EXPECTED_SHA256
path = Path(os.environ["UNSLOP_IDENTITY_AUDIT_FILE"])
assert path.is_file(), "audit-only plugin must exclusively create a new file at init"
assert path.stat().st_size == 0, "use a fresh output file for this fixture"
for _ in range(2):
    for ea in FIXTURES:
        ida_hexrays.mark_cfunc_dirty(ea, False)
        assert ida_hexrays.decompile(ea) is not None, hex(ea)
with path.open("rb") as handle:
    new_events = [json.loads(line) for line in handle if line.strip()]
assert len(new_events) == len(FIXTURES)
assert {e["entry_ea"] for e in new_events} == set(FIXTURES)
assert sorted(e["sequence"] for e in new_events) == list(range(1, len(FIXTURES) + 1))
assert all(e["schema"] == 2 and e["sample_sha256"] == EXPECTED_SHA256
           and e["status"] == "proved" for e in new_events)
assert len({e["run_id"] for e in new_events}) == 1
for event in new_events:
    cases = {state: (block, target_ea)
             for state, block, target_ea in event["cases"]}
    assert len(cases) >= 4
    assert len(event["dispatch_contexts"]) >= 2
    for _, state, _, target_block, target_ea in event["dispatch_contexts"]:
        assert cases[state] == (target_block, target_ea)
print("identity audit: %d new unique fixture events, no duplicate F5 rows" % len(new_events))
