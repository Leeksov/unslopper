#pragma once
// Microcode simplification helpers: MBA (mixed boolean-arithmetic) identity
// reduction, affine bitvector reduction, and opaque-predicate elimination.
#include <hexrays.hpp>

namespace unslop {

// Apply MBA identity rewrite rules to every instruction in `blk`. Returns the
// number of instructions changed.
int simplify_mba_block(mblock_t *blk);

// Attempt an affine (linear-over-bitvector) reduction of a single instruction
// in place. Returns true if `ins` was simplified.
bool try_affine_simplify(minsn_t *ins);

// Remove always-true / always-false (opaque) predicates across the whole
// microcode array, folding the dead branch. Returns the number removed.
int eliminate_opaque_predicates(mba_t *mba);

} // namespace unslop
