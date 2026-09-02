#pragma once
// Semantic-diffusion folding: collapse value computations that have been
// spread ("diffused") across many microcode instructions and blocks back
// into their canonical form, undoing MBA-style expression scattering.
#include <hexrays.hpp>

namespace unslop {

// Fold semantic-diffusion patterns across the whole microcode array `mba`.
// Returns the number of changes made (0 if nothing matched).
int fold_semantic_diffusion(mba_t *mba);

} // namespace unslop
