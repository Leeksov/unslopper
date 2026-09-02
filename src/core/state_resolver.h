#pragma once
// State-value resolution: given a block that jumps back to the dispatcher,
// determine which state constant it installs, then forward that mapping across
// every relevant block so the CFG rewriter knows each block's successor state.
#include <hexrays.hpp>
#include <set>
#include <map>
#include <cstdint>
#include "unslop_types.h"

namespace unslop {

// Resolve the state value that block `serial` writes into `state_reg` before
// branching to the dispatcher, using `regmap` (register -> known const) as the
// starting environment and `disp_blocks` to bound the search. On success stores
// the resolved constant in *out and returns true.
bool resolve_state_in_block(mba_t *mba,
                            int serial,
                            mreg_t state_reg,
                            const std::map<mreg_t, uint64_t> &regmap,
                            const std::set<int> &disp_blocks,
                            uint64_t *out);

// Compute, for every non-dispatcher block that feeds the dispatcher, the state
// constant it installs into `state_reg`. Results land in *out (block serial ->
// state value).
void forward_state_map(mba_t *mba,
                       mreg_t state_reg,
                       const std::set<int> &disp_blocks,
                       const std::map<mreg_t, uint64_t> &regmap,
                       std::map<int, uint64_t> *out);

} // namespace unslop
