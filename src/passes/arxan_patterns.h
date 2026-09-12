#pragma once
#include <cstdint>
#include <functional>

namespace unslop { namespace arxan {
enum class Pattern { zero_mask, multiply_one, cancelled_offset };
struct Image {
  uint64_t text_start = 0, text_end = 0;
  std::function<bool(uint64_t, uint32_t *)> read_word;
  std::function<bool(uint64_t, uint64_t)> readonly;
};
struct Proof {
  uint64_t start = 0, site = 0, target = 0;
  Pattern pattern = Pattern::zero_mask;
};
// Local raw-instruction proof. No mutable pointer slots or inferred values.
bool match(const Image &image, uint64_t site, Proof *proof);
const char *name(Pattern pattern);
} }
