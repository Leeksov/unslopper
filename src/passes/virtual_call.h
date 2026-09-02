#pragma once
// Virtual / indirect call devirtualization: resolve obfuscated indirect calls
// (icall/ijmp through computed targets, dispatch tables, register-indirect
// thunks) into direct calls where the target is statically recoverable.
#include <hexrays.hpp>

namespace unslop {

// Devirtualize indirect calls across the whole microcode array `mba`.
// Returns the number of changes made (0 if nothing matched).
int devirtualize_calls(mba_t *mba);

} // namespace unslop
