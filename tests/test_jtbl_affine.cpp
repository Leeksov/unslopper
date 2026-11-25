#include "../src/core/jtbl_affine.h"

#include <cstdint>
#include <map>

int main()
{
  // Synthetic 84-case switch: case = (raw - offset) modulo 2^32.
  constexpr uint32_t offset = 0x5A20B310u;
  std::map<uint64_t, int> cases;
  for ( uint32_t i = 0; i < 84; ++i )
    cases.emplace(i, int(i + 10));
  std::map<uint64_t, int> raw;
  if ( !unslop::invert_jtbl_cases(cases, 0, -int64_t(offset), &raw)
    || raw.size() != cases.size()
    || raw.at(offset) != 10
    || raw.at(offset + 0x41u) != 10 + 0x41 )
    return 1;
  for ( const auto &entry : raw )
  {
    uint32_t selector = uint32_t(uint32_t(entry.first) - offset);
    if ( cases.at(selector) != entry.second )
      return 2;
  }

  // Verify wraparound and XOR+ADD inversion at the machine-word width.
  const std::map<uint64_t, int> wrapped = {{0, 1}, {1, 2}, {4, 3}};
  if ( !unslop::invert_jtbl_cases(wrapped, 0, 5, &raw)
    || raw.at(0xFFFFFFFBu) != 1
    || raw.at(0xFFFFFFFCu) != 2
    || raw.at(0xFFFFFFFFu) != 3 )
    return 3;
  if ( !unslop::invert_jtbl_cases(wrapped, 0x12345678u, 5, &raw) )
    return 4;
  for ( const auto &entry : raw )
  {
    uint32_t selector = uint32_t((uint32_t(entry.first) ^ 0x12345678u) + 5u);
    if ( wrapped.at(selector) != entry.second )
      return 5;
  }

  // Invalid width must fail without exposing a partially built map.
  const auto saved = raw;
  const std::map<uint64_t, int> too_wide = {{0, 1}, {0x100000000ull, 2}};
  if ( unslop::invert_jtbl_cases(too_wide, 0, 0, &raw) || raw != saved )
    return 6;
  if ( unslop::invert_jtbl_cases(wrapped, 0x100000000ull, 0, &raw)
    || raw != saved )
    return 7;

  using I = unslop::JtblInstruction;
  if ( !unslop::pure_jtbl_shape({I::ExactAffineSelector, I::Branch}, true, false)
    || !unslop::pure_jtbl_shape({I::Nop, I::Branch}, false, false) )
    return 8;
  // A side-effectful move, duplicate selector definition, or live-out
  // selector must veto direct-edge rewriting even when the affine map is exact.
  if ( unslop::pure_jtbl_shape({I::ExactAffineSelector, I::Other, I::Branch},
                               true, false)
    || unslop::pure_jtbl_shape({I::ExactAffineSelector,
                                 I::ExactAffineSelector, I::Branch}, true, false)
    || unslop::pure_jtbl_shape({I::ExactAffineSelector, I::Branch}, true, true) )
    return 9;
  return 0;
}
