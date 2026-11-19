#pragma once

namespace unslop {

// Read-only, sample-gated audit of ARM32 Thumb Promon dispatcher evidence.
// Returns the number of validated dispatcher hubs; never changes the IDB.
int audit_promon_thumb_native();

} // namespace unslop
