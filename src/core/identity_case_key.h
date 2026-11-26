#pragma once

#include <cstdint>
#include <map>
#include <optional>

namespace unslop
{
// Hex-Rays may store a negative case label as a signed int64 even when the
// m_jtbl selector is narrower. Accept only labels representable in the
// selector's signed or unsigned width, then compare their bit patterns.
// A nonzero zero_extend_source_bytes means the selector came from m_xdu.
inline std::optional<uint64_t> identity_case_key(
    int64_t label,
    int selector_bytes,
    int zero_extend_source_bytes = 0)
{
  if (selector_bytes < 1 || selector_bytes > 8
      || zero_extend_source_bytes < 0
      || zero_extend_source_bytes >= selector_bytes)
    return {};
  const int bits = selector_bytes * 8;
  const uint64_t selector_mask = selector_bytes == 8
      ? ~uint64_t(0)
      : (uint64_t(1) << bits) - 1;
  if (selector_bytes < 8)
  {
    const int64_t signed_min = -(int64_t(1) << (bits - 1));
    if (label < signed_min
        || (label >= 0 && uint64_t(label) > selector_mask))
      return {};
  }
  const uint64_t key = uint64_t(label) & selector_mask;
  if (zero_extend_source_bytes != 0)
  {
    const uint64_t source_mask = (uint64_t(1)
        << (zero_extend_source_bytes * 8)) - 1;
    if (key > source_mask)
      return {};
  }
  return key;
}

enum class IdentityCaseInsert
{
  ok,
  outside_width,
  conflicting_target,
  aliased_label,
};

// Keep both maps unchanged on every rejection. In particular, -1 and
// 0xffffffff are two spellings of the same 32-bit key, not two proven cases.
inline IdentityCaseInsert insert_identity_case(
    int64_t label,
    int target,
    int selector_bytes,
    int zero_extend_source_bytes,
    std::map<uint64_t, int> &cases,
    std::map<uint64_t, int64_t> &origins)
{
  const auto key = identity_case_key(label, selector_bytes, zero_extend_source_bytes);
  if (!key)
    return IdentityCaseInsert::outside_width;
  const auto old = cases.find(*key);
  if (old != cases.end() && old->second != target)
    return IdentityCaseInsert::conflicting_target;
  const auto origin = origins.find(*key);
  if (origin != origins.end() && origin->second != label)
    return IdentityCaseInsert::aliased_label;
  cases[*key] = target;
  origins[*key] = label;
  return IdentityCaseInsert::ok;
}
} // namespace unslop
