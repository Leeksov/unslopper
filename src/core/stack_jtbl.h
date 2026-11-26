#pragma once
#include <hexrays.hpp>
#include <string>
#include <vector>
namespace unslop
{
// Bounded, all-or-nothing specialization of stack jump-table/equality CFF.
struct StackJtblDiagnostics {
  std::string reason="not_attempted";
  int cases=0,contexts=0;
};
int unflatten_stack_jtbl(mba_t *mba,StackJtblDiagnostics *diagnostics=nullptr);
// Opt-in, all-or-nothing register-affine jump-table context expansion.
int unflatten_affine_context_jtbl(mba_t *mba, StackJtblDiagnostics *diagnostics=nullptr);
struct IdentityAuditCase { uint64_t state; int target_block; ea_t target_ea; };
struct IdentityAuditContext {
  int context_id;
  uint64_t state;
  int next_context_id;
  int target_block;
  ea_t target_ea;
};
struct IdentityAuditResult {
  std::string reason="not_attempted";
  int dispatcher_block=-1;
  ea_t dispatcher_ea=BADADDR;
  int contexts=0;
  std::vector<IdentityAuditCase> cases;
  std::vector<IdentityAuditContext> dispatch_contexts;
};
// Pure analysis: no MBA or IDB mutations.
IdentityAuditResult audit_identity_jtbl(mba_t *mba);
bool affine_context_trial_active();
} // namespace unslop
