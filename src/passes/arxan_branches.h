#pragma once
#include <hexrays.hpp>
#include <gdl.hpp>
namespace unslop {
struct ArxanDiagnostics {
  int verified=0, reachable_added=0, matched=0, changed=0, ownership_rejected=0, entry_rejected=0, missing_block=0;
};
// Make already-existing, proven target blocks available to microcode generation.
int expand_arxan_reachability(const qflow_chart_ea_t *fc, mba_t *mba, bitset_t *reachable);
// Automatic GENERATED-stage recovery; no annotations or IDB byte patches.
int restore_arxan_branches(mba_t *mba, ArxanDiagnostics *diagnostics=nullptr);
}
