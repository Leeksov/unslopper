#include "../src/core/affine_context_gate.h"

static_assert(unslop::affine_store_keeps_register_facts(false),
              "ordinary memory store must preserve register facts");
static_assert(!unslop::affine_store_keeps_register_facts(true),
              "nested call in store operand must invalidate register facts");

static_assert(unslop::affine_trial_completed(0, 6, 6),
              "completed GLBOPT2 trial should be accepted");
static_assert(!unslop::affine_trial_completed(-33, 6, 6),
              "MERR_STOP does not prove downstream completion");
static_assert(!unslop::affine_trial_completed(0, 5, 6),
              "success before required maturity is insufficient");

int main() { return 0; }
