#pragma once
// Self-proving "makeOpaque" / MBA simplification layer.
//
// This is a family-agnostic microcode cleanup pass that collapses the opaque
// algebraic wrappers used by Apple's FairPlay `makeOpaque` framework and by the
// Arxan/branding-stripped MBA branch obfuscator (Pokemon GO NianticLabsPlugin).
// Unlike the CFF profiles, it does NOT need a flattening dispatcher: the
// obfuscated handlers are not flattened, they are opaqued, so this runs on
// every function.
//
// Every rule here is SELF-PROVING: it rewrites an instruction only when the
// algebraic identity is proven to hold for all inputs (verified S-box
// permutation tables read from the IDB, modular-inverse affine round-trips,
// always-true residue predicates). It never guesses. This is what makes it
// safe to run unconditionally without corrupting microcode.
//
// Rules:
//   * S-box constant chains   x ^ outer[inner[x] ^ c]  ->  const
//       (both tables read from the IDB and verified constant for all 256 x)
//   * MBA subtraction         (x ^ ~c) + ((2*x) & ~(2*c+1)) + 1  ->  x - c
//   * Affine add round-trip   (x*a + b)*inv(a) + rb   ->  x
//   * Affine xor round-trip   inv(a) * (a * (x ^ c)) ^ c  ->  x
//   * Opaque square predicate (x*x) % 4 in {0,1}  ->  1  (always true)
//
// The complementary identities `(x^y)+2*(x&y) -> x+y`, `(x|y)-(x&y) -> x^y`,
// selector folds, etc. already live in mba_simplify.cpp and cover the bulk of
// Arxan's per-branch MBA; this layer adds the constructions those rules miss.
#include <hexrays.hpp>

namespace unslop {

// Apply every self-proving opaque/MBA rule to all sub-instructions of every
// block in `mba`. Returns the number of instructions rewritten. Marks affected
// block lists dirty; the caller is responsible for the final verify()/
// mark_chains_dirty() (func() does one strict verify per function).
int simplify_opaque_mba(mba_t *mba);

} // namespace unslop
