#pragma once
// FairPlay VM dispatch-table resolver (one-shot IDA action).
//
// fairplayd.H2 virtualizes control flow through a large jump/handler LUT
// (`jpt_100006B1C`, 0x101039F20 .. 0x1010A0B50 in the shipped build: 52,614
// eight-byte slots, ~44,700 unique __text targets). IDA applies the chained-
// fixup relocations, so each slot already reads back as its resolved target
// via get_qword -- no rebase math is needed for THIS table (that is only the
// separate biased-pointer LUT at 0x1010A0B50).
//
// This pass walks the table, ensures every resolved target is a defined
// function so the VM handlers become navigable, names the table, and reports
// coverage. It never guesses a target: a slot is used only when its value is
// mapped and lands in an executable segment.
//
// Bounds default to the shipped fairplayd build and can be overridden with
// UNSLOP_FP_LUT_START / UNSLOP_FP_LUT_END (hex ea). Returns the number of
// handler functions newly created, or -1 if no plausible table was found.
#include <hexrays.hpp>

namespace unslop {

int fairplay_resolve_vm_table();

} // namespace unslop
