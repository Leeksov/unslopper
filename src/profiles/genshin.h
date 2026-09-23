#pragma once

#include <pro.h>

namespace unslop {

struct GenshinReport
{
  int sites = 0;
  int changed = 0;
  int already_folded = 0;
  ea_t function_start = BADADDR;
  qstring error;
};

// Manifest-driven, native-stage CFG recovery. The offline generator proves
// relocated targets and branch encodings; this profile rechecks the current
// IDB before optionally patching *only* its BR instructions and xrefs.
bool run_genshin_manifest(const char *path, bool apply, GenshinReport *report);

} // namespace unslop
