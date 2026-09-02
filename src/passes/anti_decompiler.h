#pragma once
// Anti-decompiler / anti-disassembly resolution at the microcode level.
// Removes decompiler-defeating constructs (bogus flow, junk instructions,
// stack-frame poisoning, exception-based obfuscation) so Hex-Rays can lift
// the function cleanly.
#include <hexrays.hpp>

namespace unslop {

// Resolve anti-decompiler constructs across the whole microcode array `mba`.
// Returns the number of changes made (0 if nothing matched).
int resolve_anti_decompiler(mba_t *mba);

} // namespace unslop
