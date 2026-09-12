#pragma once
#include <hexrays.hpp>
#include <string>
namespace unslop
{
// Bounded, all-or-nothing specialization of stack jump-table/equality CFF.
struct StackJtblDiagnostics {
  std::string reason="not_attempted";
  int cases=0,contexts=0;
};
int unflatten_stack_jtbl(mba_t *mba,StackJtblDiagnostics *diagnostics=nullptr);
} // namespace unslop
