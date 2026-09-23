#pragma once

#include <hexrays.hpp>

namespace unslop {

struct CoreALDDiagnostics {
  int markers = 0;
  int proven = 0;
  int changed = 0;
  int rejected = 0;
};

// Apply a native-instruction proof produced by tools/coreald_sbox.py to the
// GENERATED microcode for the corresponding AND Wn,Wn,#0xff. Neither machine
// bytes nor IDA CFG edges are patched. Unmarked/changed sites are untouched.
int restore_coreald_sboxes(mba_t *mba, CoreALDDiagnostics *diagnostics = nullptr);

} // namespace unslop
