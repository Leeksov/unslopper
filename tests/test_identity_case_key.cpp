#include "../src/core/identity_case_key.h"

#include <cstdint>
#include <limits>
#include <map>

int main()
{
  using unslop::identity_case_key;
  if (identity_case_key(-1, 4) != 0xFFFFFFFFull
      || identity_case_key(INT32_MIN, 4) != 0x80000000ull
      || identity_case_key(0xFFFFFFFFll, 4) != 0xFFFFFFFFull
      || identity_case_key(-128, 1) != 0x80ull
      || identity_case_key(255, 1) != 0xFFull)
    return 1;
  if (identity_case_key(int64_t(INT32_MIN) - 1, 4)
      || identity_case_key(0x100000000ll, 4)
      || identity_case_key(-129, 1)
      || identity_case_key(256, 1))
    return 2;
  // The same bit pattern can have signed and unsigned spelling. The caller
  // must reject distinct labels that collide after canonicalization.
  if (identity_case_key(-1, 4) != identity_case_key(0xFFFFFFFFll, 4))
    return 3;
  std::map<uint64_t, int> cases;
  std::map<uint64_t, int64_t> origins;
  using unslop::IdentityCaseInsert;
  using unslop::insert_identity_case;
  if (insert_identity_case(-1, 10, 4, 0, cases, origins)
        != IdentityCaseInsert::ok
      || insert_identity_case(-1, 10, 4, 0, cases, origins)
        != IdentityCaseInsert::ok)
    return 7;
  const auto saved_cases = cases;
  const auto saved_origins = origins;
  if (insert_identity_case(0xFFFFFFFFll, 10, 4, 0, cases, origins)
        != IdentityCaseInsert::aliased_label
      || insert_identity_case(-1, 11, 4, 0, cases, origins)
        != IdentityCaseInsert::conflicting_target
      || insert_identity_case(0x100000000ll, 10, 4, 0, cases, origins)
        != IdentityCaseInsert::outside_width
      || cases != saved_cases || origins != saved_origins)
    return 8;
  if (identity_case_key(255, 4, 1) != 255
      || identity_case_key(-1, 4, 1)
      || identity_case_key(256, 4, 1)
      || identity_case_key(0x10000, 4, 2))
    return 4;
  if (identity_case_key(std::numeric_limits<int64_t>::min(), 8)
        != 0x8000000000000000ull
      || identity_case_key(-1, 8) != 0xFFFFFFFFFFFFFFFFull)
    return 5;
  if (identity_case_key(0, 0) || identity_case_key(0, 9)
      || identity_case_key(0, 4, 4) || identity_case_key(0, 4, -1))
    return 6;
  return 0;
}
