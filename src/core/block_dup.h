#pragma once
//
// CFG-surgery primitives for the D-810-style unflattening driver.
//
// These are faithful C++ ports of D-810's cfg_utils.py helpers
// (docs/ref_d810_cfg_utils.py): the successor/predecessor bookkeeping is
// identical to the proven Python, so a mutated block always leaves the
// succset/predset graph and the block-type/goto flags in a verifier-consistent
// state. Unlike the Python helpers we do NOT call mba->verify() inside each
// primitive (the plugin owns exactly one authoritative verify per function);
// callers may opt into per-step verification through UNSLOP_VERIFY_STEPS.
//
// Block insertion (insert_nop_blk / duplicate_block) uses mba->copy_block,
// which RENUMBERS every serial >= the insertion point. Any DispatcherInfo the
// driver still relies on must be kept consistent across such a renumber:
// di_shift_up_from() applies the same +1 shift to every serial stored in a
// DispatcherInfo. Callers must invoke it immediately after an insertion.
//
#include <hexrays.hpp>
#include "unslop_types.h"

namespace unslop {

// Append a fresh `goto target` to `blk` (porting insert_goto_instruction).
// When nop_previous is true the current tail is first turned into a nop
// (used when replacing an m_ijmp / lowered select tail).
void insert_goto_instruction(mblock_t *blk, int target, bool nop_previous);

// Retarget a 1-way block's single successor to `new_succ`, rewriting or adding
// the terminating goto and fixing both succset/predset. Returns false when the
// block is not 1-way or the change is unsafe (e.g. a pre-CALLS call tail).
bool change_1way_block_successor(mblock_t *blk, int new_succ);

// Retarget the CONDITIONAL (taken) edge of a 2-way (jcnd) block to `new_succ`,
// leaving the fallthrough edge intact. Returns false when the block is not
// 2-way.
bool change_2way_block_conditional_successor(mblock_t *blk, int new_succ);

// Insert a fresh 1-way nop block immediately after `blk` (at blk->serial + 1)
// that falls through to whatever now sits at that serial. Returns the new
// block, or nullptr on failure. RENUMBERS serials >= blk->serial + 1: the
// caller must di_shift_up_from(di, blk->serial + 1) afterward if it keeps a di.
mblock_t *insert_nop_blk(mblock_t *blk);

// Guarantee that `child` is reached from `father` by an UNCONDITIONAL (1-way)
// edge, splitting a conditional father through a new 1-way nop block when
// necessary (porting ensure_child_has_an_unconditional_father). Returns the
// number of blocks inserted (0 or 1). On a nonzero return serials were
// renumbered; see insert_nop_blk. `inserted_at` (when non-null) receives the
// serial the new block was inserted at, for di bookkeeping.
int ensure_child_has_an_unconditional_father(mblock_t *father, mblock_t *child,
                                             int *inserted_at);

// Clone `block_to_duplicate` at the end of the array (serial mba->qty - 1) so
// each reaching history can own a private copy. Returns the duplicate, or
// nullptr on failure. The clone is wired to the same successor(s) as the
// original. RENUMBERS (the copy is appended, so only the trailing sink shifts);
// callers keep di consistent via di_shift_up_from with the returned serial.
mblock_t *duplicate_block(mblock_t *block_to_duplicate);

// Apply the +1 serial renumber caused by inserting a block at serial `at` to
// every serial stored inside `di` (block_idx, dispatcher_blocks, state_map
// targets, block_state keys). Idempotent per insertion; call exactly once per
// insert_nop_blk / copy_block done at `at`.
void di_shift_up_from(DispatcherInfo *di, int at);

} // namespace unslop
