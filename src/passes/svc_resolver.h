#pragma once
// Supervisor-call (svc / syscall) resolution: recover the syscall being
// invoked from the immediate/register state at each svc site and annotate or
// rewrite it so the call becomes legible in the decompiler output.
#include <hexrays.hpp>
#include <map>
#include <cstdint>

namespace unslop {

// Resolve supervisor calls across the whole microcode array `mba`.
// Returns the number of changes made (0 if nothing matched). `regs` is the
// shared register-constant map built once per function.
int resolve_svcs(mba_t *mba, const std::map<mreg_t, uint64_t> &regs);

} // namespace unslop
