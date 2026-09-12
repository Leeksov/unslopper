#include "arxan_patterns.h"
#include <array>

namespace unslop { namespace arxan {
namespace {
constexpr uint32_t br8 = 0xd61f0100, br9 = 0xd61f0120;
bool code_word(const Image &im, uint64_t ea, uint32_t *word)
{
  return (ea & 3) == 0 && ea >= im.text_start && ea < im.text_end
      && im.text_end - ea >= 4 && im.read_word(ea, word);
}
bool is(const Image &im, uint64_t ea, uint32_t expected)
{
  uint32_t word;
  return code_word(im, ea, &word) && word == expected;
}
bool adr(const Image &im, uint64_t ea, unsigned reg, uint64_t *target)
{
  uint32_t word;
  if (!code_word(im, ea, &word) || (word & 0x9f00001f) != (0x10000000u | reg))
    return false;
  uint32_t imm = ((word >> 5) & 0x7ffff) * 4 + ((word >> 29) & 3);
  int64_t delta = (imm & (1u << 20)) ? int64_t(imm) - (1LL << 21) : imm;
  *target = ea + uint64_t(delta);
  return true;
}
bool finish(const Image &im, uint64_t start, uint64_t site, uint64_t target,
            Pattern pattern, Proof *proof)
{
  if ((target & 3) || target < im.text_start || target >= im.text_end
      || im.text_end - target < 4 || target == site)
    return false;
  *proof = {start, site, target, pattern};
  return true;
}
}

const char *name(Pattern pattern)
{
  switch (pattern) {
    case Pattern::zero_mask: return "zero_mask_constant";
    case Pattern::multiply_one: return "multiply_one";
    case Pattern::cancelled_offset: return "cancelled_address_offset";
  }
  return "unknown";
}

bool match(const Image &im, uint64_t site, Proof *proof)
{
  uint32_t last;
  if (proof == nullptr || !im.read_word || !im.readonly || !code_word(im, site, &last))
    return false;
  if (last == br8) {
    for (uint64_t distance : {32u, 40u}) {
      if (site < distance) continue;
      uint64_t start = site - distance, proof_start = start, target;
      uint32_t store, load;
      if (!code_word(im, start, &store) || !code_word(im, start+4, &load)) continue;
      bool scaled = (store & 0xffc0001f) == 0xf900001f
                 && (load & 0xffc0001f) == 0xf940000b;
      bool unscaled = (store & 0xffe00c1f) == 0xf800001f
                   && (load & 0xffe00c1f) == 0xf840000b;
      if (!(scaled || unscaled) || (store & 0x003fffe0) != (load & 0x003fffe0)) continue;
      unsigned base = (store >> 5) & 31;
      if (base != 29 && base != 31) {
        uint32_t previous;
        if (base != 8 || start < 4 || !code_word(im, start-4, &previous)) continue;
        uint32_t op = previous & 0xff80001f;
        unsigned from = (previous >> 5) & 31;
        if ((op != 0x91000008 && op != 0xd1000008) || (from != 29 && from != 31)) continue;
        proof_start -= 4;
      }
      if (!adr(im, start+8, 8, &target)) continue;
      uint64_t tail = start+12;
      if (distance == 40) {
        uint32_t relative;
        if (!is(im, tail, 0xb9800109) || !is(im, tail+4, 0x8b080128)
            || !im.readonly(target, 4) || !im.read_word(target, &relative)) continue;
        int64_t displacement = (relative & 0x80000000u)
          ? int64_t(relative) - (1LL << 32) : relative;
        target += uint64_t(displacement);
        tail += 8;
      }
      const std::array<uint32_t, 6> expected = {
        0x8a0b0109, 0xd280004a, 0x9b0a7d29, 0xca0b0108, 0x8b090108, br8};
      bool matches = true;
      for (unsigned i=0; i<expected.size(); ++i)
        if (!is(im, tail+4*i, expected[i])) { matches=false; break; }
      if (matches && finish(im, proof_start, site, target, Pattern::zero_mask, proof)) return true;
    }
    uint64_t target;
    if (site >= 12 && is(im, site-12, 0xd2800028) && is(im, site-4, 0x9b087d28)
        && adr(im, site-8, 9, &target))
      return finish(im, site-12, site, target, Pattern::multiply_one, proof);
  } else if (last == br9 && site >= 24) {
    uint64_t start=site-24, target;
    const std::array<uint32_t, 6> expected = {
      0xcb0b0129, 0xd10023ff, 0x14000002, 0xcb0b0129, 0x8b0b0129, br9};
    if (!adr(im, start, 9, &target) || target != site+4 || !is(im, target, 0x910023ff)) return false;
    for (unsigned i=0; i<expected.size(); ++i)
      if (!is(im, start+4*(i+1), expected[i])) return false;
    return finish(im, start, site, target, Pattern::cancelled_offset, proof);
  }
  return false;
}
} }
