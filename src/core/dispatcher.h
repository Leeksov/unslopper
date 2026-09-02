#pragma once
// Generic flattening-dispatcher detection over one microcode array. Combines
// three strategies (max-predecessor block, jump-table, and a state-variable
// heuristic) into a single DispatcherInfo.
#include <hexrays.hpp>
#include <map>
#include <cstdint>
#include "unslop_types.h"

namespace unslop {

// Detect the dispatcher in `mba` and populate `out`. Returns true on success
// (out->valid is also set). Tries max-preds, then jump-table, then the
// state-var heuristic; out->detection_strategy records which one fired.
// `regmap` is the shared register-constant map built once per function.
bool detect_dispatcher(mba_t *mba, DispatcherInfo *out,
                       const std::map<mreg_t, uint64_t> &regmap);

// Serial of the block with the most predecessors (the classic dispatcher
// shape), or -1 if none qualifies.
int find_max_pred_block(mba_t *mba);

// Identify the state variable compared inside the dispatcher block `disp_serial`
// and record it in `out` (out->state_var / out->state_reg). Returns true if a
// state variable was found. `regmap` is the shared register-constant map.
bool find_state_var(mba_t *mba, int disp_serial, DispatcherInfo *out,
                    const std::map<mreg_t, uint64_t> &regmap);

// Walk the dispatcher comparisons and fill out->state_map / out->state_consts /
// out->bst_pivots from the recovered state-constant -> target-block edges.
// `regmap` is the shared register-constant map built once per function.
void build_state_map(mba_t *mba, DispatcherInfo *di,
                     const std::map<mreg_t, uint64_t> &regmap);

// ── Shared state-dispatcher discriminators ───────────────────────────
// Used by BOTH the register-BST seed check (dispatcher.cpp) and the
// DexProtector profile gate (profiles/dexprotector.cpp) so a lone
// xor+condjump or a natural compare-cascade / cleanup join is never mistaken
// for a genuine flattened state dispatcher.

// The register compared against the most DISTINCT constants across the whole
// microcode array, that count, and the block where they converge. This is
// find_state_var's reg->consts counting lifted out for reuse.
struct StateFingerprint
{
  mreg_t sel_reg = mreg_t(-1);   // register compared against the most consts
  size_t distinct = 0;           // number of distinct constants it is tested vs
  int    converge_blk = -1;      // block where that maximum was observed
};

// Populate *out with the whole-array fingerprint. Returns true when any
// register-vs-constant comparison was found (converge_blk >= 0).
bool state_dispatcher_fingerprint(mba_t *mba,
                                  const std::map<mreg_t, uint64_t> &rm,
                                  StateFingerprint *out);

// A max-pred seed block is a JOIN/CLEANUP sink (return/goto funnel, C++
// destructor epilogue, or a convergence point with no state compare) rather
// than a real fan-out dispatcher. Returns true when the block should be
// REJECTED as a sink. A block is a sink if it has <2 successors (pure
// return/goto funnel) OR its body is dominated by >=4 calls to one callee
// (destructor epilogue). When `require_state_compare` is true it is ALSO a
// sink unless it compares selector `sel` against >=2 distinct constants -
// correct for the DexProtector convergence block (the richest-compare block),
// but NOT for a register-BST tree ENTRY, which legitimately compares only one
// pivot in its own block (the tree fans the remaining pivots across its
// successors), so the register-BST seed check passes false.
bool is_convergence_sink(mba_t *mba, int serial, mreg_t sel,
                         const std::map<mreg_t, uint64_t> &rm,
                         bool require_state_compare = true);

} // namespace unslop
