#pragma once
// CFG rewriting: redirect dispatcher-bound gotos to their true targets and
// drive the whole deflattening pass over one microcode array.
#include <hexrays.hpp>
#include <map>
#include <cstdint>
#include "unslop_types.h"

namespace unslop {

class Profile; // forward decl (defined in profile.h)

// Retarget the goto/branch in `blk` from block `old_target` to `new_target`,
// keeping succset/predset and the dirty flags consistent. Returns true if the
// edge was changed.
bool change_goto_target(mblock_t *blk, int old_target, int new_target);

// Main deflatten driver for one mba_t: resolves states via the recovered
// dispatcher `di` (optionally guided by `profile`), rewrites the flattened CFG
// into direct edges, and returns the number of changes made. `regmap` is the
// shared register-constant map built once per function.
int rewrite_cfg(mba_t *mba, DispatcherInfo *di, Profile *profile,
                const std::map<mreg_t, uint64_t> &regmap);

} // namespace unslop
