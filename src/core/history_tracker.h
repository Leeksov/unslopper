#pragma once
//
// Backward history emulator for the Unslopper deflattener.
//
// Ported in spirit from D-810's MopTracker / MopHistory
// (docs/ref_d810_tracker.py): given a dispatcher-predecessor ("father") block
// that installs the next flattening state, recover the EXACT state value(s) it
// feeds the dispatcher, handling conditional (two-way) installs.
//
// Unlike D-810 we do not rebuild the microcode path object graph; we walk the
// single-predecessor chain backward, then constant-fold FORWARD over the
// reconstructed straight-line instruction stream (this is exactly what
// MopHistory._execute_microcode does under the hood). The tracker is purely
// analytical: it reads the mba but never mutates it.
//
// The state carrier is whichever of the three DispatcherInfo carriers is set:
//   * register            -> di.sel_state_reg  (+/- 1 sub-register neighbours)
//   * ldx/stx memory slot -> di.sel_state_sel (selector) + di.sel_state_addr
//   * stack-variable slot -> di.sel_state_sel  (a mop_S matched whole)
//
#include <hexrays.hpp>
#include <cstdint>
#include <vector>
#include "unslop_types.h"

namespace unslop {

// Result of resolving the state value a father block feeds the dispatcher.
//
// Interpretation for the driver:
//   resolved && !conditional && values.size()==1
//        -> the father installs exactly ONE state (values[0]). Rewrite its
//           dispatcher edge to that state's target directly.
//   resolved && conditional
//        -> the father is a two-way select: on `cond` true it installs
//           cond_true_val, otherwise cond_false_val (also mirrored in
//           values = {cond_false_val, cond_true_val}). Split the edge.
//   !resolved && values.size() > 1
//        -> ambiguous: several reaching predecessors install DIFFERENT states
//           (the candidate set). The driver should duplicate to disambiguate.
//   !resolved && values.empty()
//        -> nothing could be determined; leave the father as residue.
struct StateResolution
{
  std::vector<uint64_t> values;      // resolved value(s) / candidate set
  bool     resolved     = false;     // a definite outcome was reached
  bool     conditional  = false;     // two-way (jcnd) select between two states
  mop_t    cond;                     // condition operand of the select (jcnd.l)
  uint64_t cond_true_val  = 0;       // state installed when cond is true
  uint64_t cond_false_val = 0;       // state installed when cond is false
};

// Resolve the state value written to the state carrier at the end of `father`,
// walking backward across single-predecessor chains up to `max_depth` blocks.
// Handles direct `mov #K`, simple constant arithmetic, ldx/stx and stack-slot
// carriers, and two-way (jcnd) conditional installs. Conservative: any unknown
// leaves the result unresolved rather than guessing.
StateResolution resolve_father_state(mba_t *mba,
                                     mblock_t *father,
                                     const DispatcherInfo &di,
                                     int max_depth = 32);

// Enumerate the set of state values that can reach the dispatcher out of
// `father` (deduplicated). Used by the duplication decision: a size > 1 result
// means the father is fed several distinct states and must be split/duplicated
// before its dispatcher edge can be rewritten. Empty means unresolved.
std::vector<uint64_t> possible_state_values(mba_t *mba,
                                            mblock_t *father,
                                            const DispatcherInfo &di,
                                            int max_depth = 32);

} // namespace unslop
