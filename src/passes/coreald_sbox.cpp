#include "coreald_sbox.h"

#include <bytes.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <segment.hpp>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace unslop {
namespace {

constexpr const char *marker_prefix = "UNSLOPPER_COREALD_SBOX:";
constexpr uint64_t fnv_offset = 0xCBF29CE484222325ULL;
constexpr uint64_t fnv_prime = 0x100000001B3ULL;

struct Marker {
  ea_t start = BADADDR;
  ea_t inner = BADADDR;
  ea_t outer = BADADDR;
  uint8_t xor_byte = 0;
  uint8_t constant = 0;
  ea_t inner_slot = 0;
  ea_t outer_slot = 0;
  uint64_t fingerprint = 0;
};

bool parse_hex(const std::string &token, uint64_t *value)
{
  if ( token.size() < 3 || token[0] != '0' || token[1] != 'x' )
    return false;
  errno = 0;
  char *end = nullptr;
  unsigned long long parsed = strtoull(token.c_str(), &end, 0);
  if ( errno != 0 || end == token.c_str() || *end != '\0' )
    return false;
  *value = uint64_t(parsed);
  return true;
}

bool parse_marker_line(const std::string &line, Marker *out)
{
  std::istringstream stream(line);
  std::string prefix, fields[8], extra;
  if ( !(stream >> prefix) || prefix != marker_prefix )
    return false;
  for ( auto &field : fields )
    if ( !(stream >> field) )
      return false;
  if ( stream >> extra )
    return false;
  uint64_t values[8];
  for ( int i = 0; i < 8; ++i )
    if ( !parse_hex(fields[i], &values[i]) )
      return false;
  if ( values[3] > 255 || values[4] > 255 )
    return false;
  out->start = ea_t(values[0]);
  out->inner = ea_t(values[1]);
  out->outer = ea_t(values[2]);
  out->xor_byte = uint8_t(values[3]);
  out->constant = uint8_t(values[4]);
  out->inner_slot = ea_t(values[5]);
  out->outer_slot = ea_t(values[6]);
  out->fingerprint = values[7];
  return true;
}

bool find_marker(ea_t ea, Marker *out)
{
  qstring comment;
  if ( get_cmt(&comment, ea, false) <= 0 )
    return false;
  std::istringstream lines(comment.c_str());
  std::string line;
  int count = 0;
  while ( std::getline(lines, line) )
    if ( line.rfind(marker_prefix, 0) == 0 )
    {
      Marker candidate;
      if ( !parse_marker_line(line, &candidate) )
        return false;
      *out = candidate;
      ++count;
    }
  return count == 1;
}

bool readonly_bytes(ea_t ea, size_t size)
{
  segment_t *segment = getseg(ea);
  return segment != nullptr && ea < segment->end_ea
      && size <= size_t(segment->end_ea - ea)
      && (segment->perm & SEGPERM_WRITE) == 0;
}

bool permutation(const std::array<uint8_t, 256> &table)
{
  std::array<bool, 256> seen{};
  for ( uint8_t byte : table )
  {
    if ( seen[byte] )
      return false;
    seen[byte] = true;
  }
  return true;
}

bool validate_proof(ea_t site, const Marker &marker)
{
  if ( marker.start == BADADDR || marker.start > site || site - marker.start > 0x60
       || (marker.start & 3) != 0 || (site & 3) != 0 )
    return false;
  func_t *first = get_func(marker.start), *last = get_func(site);
  segment_t *code = getseg(site);
  if ( first == nullptr || last == nullptr || first->start_ea != last->start_ea
       || code == nullptr || (code->perm & SEGPERM_EXEC) == 0
       || getseg(marker.start) != code || site + 4 > code->end_ea )
    return false;
  // AND Wn,Wn,#0xff: the only variable bits are Rn[9:5] and Rd[4:0].
  uint32_t word = get_dword(site);
  if ( (word & ~uint32_t(0x3ff)) != 0x12001C00u
       || ((word >> 5) & 31) != (word & 31) )
    return false;

  std::array<uint8_t, 256> inner{}, outer{};
  if ( !readonly_bytes(marker.inner, inner.size())
       || !readonly_bytes(marker.outer, outer.size())
       || get_bytes(inner.data(), inner.size(), marker.inner) != inner.size()
       || get_bytes(outer.data(), outer.size(), marker.outer) != outer.size()
       || !permutation(inner) || !permutation(outer) )
    return false;
  for ( int x = 0; x < 256; ++x )
    if ( uint8_t(x ^ outer[inner[x] ^ marker.xor_byte]) != marker.constant )
      return false;

  // Indirect table bases are read-only chained shared-cache rebases in the
  // examined CoreALD build. Reject authenticated/bind forms and changed slots.
  if ( (marker.inner_slot == 0) != (marker.outer_slot == 0) )
    return false;
  std::array<uint8_t, 8> inner_slot_bytes{}, outer_slot_bytes{};
  if ( marker.inner_slot != 0 )
  {
    if ( !readonly_bytes(marker.inner_slot, 8)
         || !readonly_bytes(marker.outer_slot, 8)
         || get_bytes(inner_slot_bytes.data(), 8, marker.inner_slot) != 8
         || get_bytes(outer_slot_bytes.data(), 8, marker.outer_slot) != 8 )
      return false;
    auto slot_raw = [](const std::array<uint8_t, 8> &bytes) {
      uint64_t raw = 0;
      for ( unsigned i = 0; i < 8; ++i ) raw |= uint64_t(bytes[i]) << (8 * i);
      return raw;
    };
    auto valid_rebase = [&](uint64_t raw, ea_t table) {
      if ( raw >> 63 || ((raw >> 34) & 0xff) || ((raw >> 42) & 0x3ff) )
        return false;
      uint64_t target = 0x180000000ULL + (raw & ((1ULL << 34) - 1));
      return target >= table && target - table <= 16;
    };
    if ( !valid_rebase(slot_raw(inner_slot_bytes), marker.inner)
         || !valid_rebase(slot_raw(outer_slot_bytes), marker.outer) )
      return false;
  }

  std::vector<uint8_t> instructions(size_t(site - marker.start + 4));
  if ( get_bytes(instructions.data(), instructions.size(), marker.start)
       != instructions.size() )
    return false;
  uint64_t hash = fnv_offset;
  auto feed = [&](uint8_t byte) { hash = (hash ^ byte) * fnv_prime; };
  for ( uint8_t byte : instructions ) feed(byte);
  for ( uint8_t byte : inner ) feed(byte);
  for ( uint8_t byte : outer ) feed(byte);
  if ( marker.inner_slot != 0 )
  {
    for ( uint8_t byte : inner_slot_bytes ) feed(byte);
    for ( uint8_t byte : outer_slot_bytes ) feed(byte);
  }
  for ( uint64_t value : { uint64_t(marker.start), uint64_t(site),
                           uint64_t(marker.inner), uint64_t(marker.outer),
                           uint64_t(marker.xor_byte), uint64_t(marker.constant),
                           uint64_t(marker.inner_slot), uint64_t(marker.outer_slot) } )
    for ( unsigned i = 0; i < 8; ++i ) feed(uint8_t(value >> (8 * i)));
  return hash == marker.fingerprint;
}

} // namespace

int restore_coreald_sboxes(mba_t *mba, CoreALDDiagnostics *diagnostics)
{
  CoreALDDiagnostics local;
  auto &d = diagnostics != nullptr ? *diagnostics : local;
  if ( mba == nullptr || mba->maturity > MMAT_GENERATED
       || PH.id != PLFM_ARM || !inf_is_64bit() )
    return 0;

  // At GENERATED one native AND may lower to several micro-instructions, but
  // exactly one must be m_and with a 32-bit result before we change anything.
  std::map<ea_t, int> ands_per_ea;
  for ( int block_no = 0; block_no < mba->qty; ++block_no )
  {
    mblock_t *block = mba->get_mblock(block_no);
    if ( block == nullptr ) continue;
    for ( minsn_t *ins = block->head; ins != nullptr; ins = ins->next )
      if ( ins->opcode == m_and && ins->ea != BADADDR )
        ++ands_per_ea[ins->ea];
  }
  for ( int block_no = 0; block_no < mba->qty; ++block_no )
  {
    mblock_t *block = mba->get_mblock(block_no);
    if ( block == nullptr ) continue;
    for ( minsn_t *ins = block->head; ins != nullptr; ins = ins->next )
    {
      if ( ins->opcode != m_and || ins->d.size != 4 || ins->ea == BADADDR
           || ands_per_ea[ins->ea] != 1 )
        continue;
      Marker marker;
      if ( !find_marker(ins->ea, &marker) )
        continue;
      ++d.markers;
      if ( !validate_proof(ins->ea, marker) )
      {
        ++d.rejected;
        continue;
      }
      ++d.proven;
      ins->opcode = m_mov;
      ins->l.make_number(marker.constant, 4, ins->ea);
      ins->r.erase();
      block->mark_lists_dirty();
      ++d.changed;
    }
  }
  return d.changed;
}

} // namespace unslop
