#pragma once

// A jump-table case is the transformed selector, while case blocks install
// the raw state. Keep the inversion in one pure, testable place so callers do
// not accidentally treat case indices as raw state constants.
#include <cstdint>
#include <map>
#include <vector>

namespace unslop {

enum class JtblInstruction
{
  Nop,
  ExactAffineSelector,
  Branch,
  Other,
};

inline bool pure_jtbl_shape(const std::vector<JtblInstruction> &body,
                            bool affine, bool selector_live_out)
{
  if ( body.empty() || body.back() != JtblInstruction::Branch
    || selector_live_out )
    return false;
  int selector_defs = 0;
  for ( size_t i = 0; i < body.size(); ++i )
  {
    switch ( body[i] )
    {
      case JtblInstruction::Nop: break;
      case JtblInstruction::ExactAffineSelector: ++selector_defs; break;
      case JtblInstruction::Branch:
        if ( i + 1 != body.size() ) return false;
        break;
      case JtblInstruction::Other: return false;
    }
  }
  return selector_defs == (affine ? 1 : 0);
}

inline bool invert_jtbl_cases(const std::map<uint64_t, int> &cases,
                              uint64_t xor_key, int64_t add,
                              std::map<uint64_t, int> *raw_cases)
{
  if ( raw_cases == nullptr || cases.size() < 2 || xor_key > 0xFFFFFFFFull )
    return false;

  std::map<uint64_t, int> result;
  for ( const auto &entry : cases )
  {
    if ( entry.first > 0xFFFFFFFFull )
      return false;
    const uint32_t raw = (uint32_t(entry.first) - uint32_t(add))
                       ^ uint32_t(xor_key);
    if ( !result.emplace(uint64_t(raw), entry.second).second )
      return false;
  }
  raw_cases->swap(result);
  return true;
}

} // namespace unslop
