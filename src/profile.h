#pragma once
// Abstract Profile interface for the Unslopper deflattener. A Profile models one
// protector family: it decides whether a given microcode array looks like its
// target (detect), refines the recovered dispatcher (configure), maps raw
// state values to canonical ones (transform_state), and performs family-
// specific cleanup after the CFG has been rewritten (post_process).
#include <hexrays.hpp>
#include <vector>
#include <map>
#include <cstdint>
#include "unslop_types.h"

namespace unslop {

class Profile
{
public:
  virtual ~Profile() {}

  // Human-readable name, e.g. "OLLVM".
  virtual const char *name() const = 0;

  // Which family this profile models.
  virtual ProfileKind kind() const = 0;

  // Cheap structural check: does this protector match the given microcode?
  // `regmap` is the shared register-constant map built once per function.
  virtual bool detect(mba_t *mba,
                      const std::map<mreg_t, uint64_t> &regmap) = 0;

  // Fill / refine the DispatcherInfo (state keys, pivots, register pool, ...).
  // Returns true if a usable dispatcher configuration was produced. `regmap`
  // is the shared register-constant map built once per function.
  virtual bool configure(mba_t *mba,
                         DispatcherInfo *di,
                         const std::map<mreg_t, uint64_t> &regmap) = 0;

  // Map a raw encoded state value to its canonical form. Default: identity.
  // e.g. DexProtector: (raw ^ xor_key) + add_key.
  virtual uint64_t transform_state(uint64_t raw) { return raw; }

  // Family-specific cleanup after CFG rewriting (opaque predicates, MBA, ...).
  // Returns the number of additional changes made.
  virtual int post_process(mba_t *mba, int changes) { return 0; }
};

// Concrete-profile factories. Each is defined in its own profile TU; the
// registry (all_profiles) wires them together.
Profile *make_ollvm();
Profile *make_promon();
Profile *make_dexprotector();
Profile *make_mvg();

// Registry of every profile instance, in detection-priority order. Defined in
// the registry / plugin TU. Callers do not own the returned pointers.
std::vector<Profile*> all_profiles();

} // namespace unslop
