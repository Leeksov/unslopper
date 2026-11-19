#include "promon_thumb_audit.h"

#include <bytes.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <nalt.hpp>
#include <segregs.hpp>
#include <xref.hpp>

#include <array>
#include <cstdint>
#include <cstring>

namespace unslop {
namespace {

// Valu 10.5.3, armeabi-v7a, reconstructed code+data ELF. These are offsets
// from the image base, not transferable function signatures. A different
// build must be researched independently before its control-flow edges are
// interpreted. The audit never rewrites microcode or the database.
constexpr std::array<uchar, 32> sample_sha256 = {{
  0x77,0x6e,0x99,0xe7,0xb6,0x0b,0xf9,0x80,
  0x3f,0x7e,0xd5,0x9a,0xfc,0x46,0x90,0x7e,
  0x6a,0x3e,0x8d,0x3c,0x9a,0x19,0x8a,0x9b,
  0x4e,0xc1,0x01,0x67,0x5d,0x04,0x06,0xb0,
}};

struct HubSite
{
  ea_t hub_offset;
  ea_t predecessor_offset;
  uint64_t hub_fnv64;
  uint64_t predecessor_fnv64;
  int min_incoming;
  uint32_t example_state;
};

constexpr HubSite hub_sites[] = {
  {0x465654, 0x466504, 0x0B34F7E32F2234D1ull,
   0xB7C4D4BF7CD51286ull, 20, 0x18555161},
  {0x1F92EA, 0x1FA1D8, 0x32F3575B7801472Aull,
   0xEAB260691F023B09ull, 20, 0x32094048},
};

// Byte anchors for the decoded indirect-call helper and one producer.
constexpr ea_t call_helper_offset = 0x451E40;
constexpr ea_t call_producer_offset = 0x4657E8;
constexpr uint64_t call_helper_fnv64 = 0x90A3968796FE47D7ull;
constexpr uint64_t call_producer_fnv64 = 0xF4D1011491654268ull;

uint64_t fnv64(ea_t ea, size_t size)
{
  if ( size > 64 )
    return 0;
  std::array<uchar, 64> bytes{};
  if ( get_bytes(bytes.data(), size, ea) != ssize_t(size) )
    return 0;
  uint64_t h = 0xCBF29CE484222325ull;
  for ( size_t i = 0; i < size; ++i )
    h = (h ^ bytes[i]) * 0x100000001B3ull;
  return h;
}

int incoming_code_xrefs(ea_t target, ea_t predecessor, size_t pred_size,
                        bool *has_predecessor)
{
  int count = 0;
  *has_predecessor = false;
  xrefblk_t x;
  for ( bool ok = x.first_to(target, XREF_CODE); ok; ok = x.next_to() )
  {
    if ( !x.iscode )
      continue;
    if ( x.type != fl_JN && x.type != fl_JF && x.type != fl_F )
      continue;
    ++count;
    if ( x.from >= predecessor && x.from < predecessor + pred_size )
      *has_predecessor = true;
  }
  return count;
}

bool is_thumb(ea_t ea, int thumb_reg)
{
  return thumb_reg >= 0 && get_sreg(ea, thumb_reg) == 1;
}

} // namespace

int audit_promon_thumb_native()
{
  qstring enabled;
  if ( !qgetenv("UNSLOP_PROMON_THUMB_AUDIT", &enabled) || enabled != "1" )
  {
    msg("[unslop-promon32] read-only audit disabled; set UNSLOP_PROMON_THUMB_AUDIT=1\n");
    return 0;
  }

  if ( inf_get_procname() != "ARM" || inf_is_64bit() )
  {
    msg("[unslop-promon32] rejected: requires 32-bit ARM database\n");
    return 0;
  }
  std::array<uchar, 32> actual_hash{};
  if ( !retrieve_input_file_sha256(actual_hash.data())
    || std::memcmp(actual_hash.data(), sample_sha256.data(), actual_hash.size()) != 0 )
  {
    msg("[unslop-promon32] rejected: input SHA-256 is not the audited Valu image\n");
    return 0;
  }

  const ea_t base = get_imagebase();
  const int thumb_reg = str2reg("T");
  int accepted = 0;
  for ( const HubSite &s : hub_sites )
  {
    const ea_t hub = base + s.hub_offset;
    const ea_t pred = base + s.predecessor_offset;
    const bool bytes_ok = fnv64(hub, 64) == s.hub_fnv64
                       && fnv64(pred, 24) == s.predecessor_fnv64;
    const bool mode_ok = is_thumb(hub, thumb_reg) && is_thumb(pred, thumb_reg);
    bool predecessor_edge = false;
    const int incoming = incoming_code_xrefs(hub, pred, 24, &predecessor_edge);
    const bool graph_ok = incoming >= s.min_incoming && predecessor_edge;
    func_t *owner = get_func(hub);
    if ( bytes_ok && mode_ok && graph_ok )
      ++accepted;
    msg("[unslop-promon32] hub=0x%llx owner=0x%llx incoming=%d "
        "example_state=0x%08x bytes=%d thumb=%d backedge=%d %s\n",
        (unsigned long long)hub,
        (unsigned long long)(owner != nullptr ? owner->start_ea : BADADDR),
        incoming, unsigned(s.example_state), int(bytes_ok), int(mode_ok),
        int(predecessor_edge),
        bytes_ok && mode_ok && graph_ok ? "candidate" : "rejected");
  }

  const ea_t helper = base + call_helper_offset;
  const ea_t producer = base + call_producer_offset;
  const bool encoded_call_anchor = is_thumb(helper, thumb_reg)
    && is_thumb(producer, thumb_reg)
    && fnv64(helper, 64) == call_helper_fnv64
    && fnv64(producer, 48) == call_producer_fnv64;
  msg("[unslop-promon32] encoded-call descriptor XOR anchor=0x%llx "
      "producer=0x%llx matched=%d; no target resolution or IDB changes\n",
      (unsigned long long)helper, (unsigned long long)producer,
      int(encoded_call_anchor));
  msg("[unslop-promon32] audited %d/%d CFF hubs; report only, no CFG rewrite\n",
      accepted, int(sizeof(hub_sites) / sizeof(hub_sites[0])));
  return accepted;
}

} // namespace unslop
