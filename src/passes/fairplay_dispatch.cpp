#include "fairplay_dispatch.h"
#include "unslop_log.h"

#include <kernwin.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <set>

namespace unslop {

// Default LUT bounds for the shipped fairplayd.H2 build.
static const ea_t FP_LUT_START = 0x101039f20;
static const ea_t FP_LUT_END   = 0x1010a0b50;

// True if `ea` lies in an executable segment.
static bool in_exec_seg(ea_t ea)
{
  segment_t *s = getseg(ea);
  return s != nullptr && (s->perm & SEGPERM_EXEC) != 0;
}

static ea_t env_ea(const char *var, ea_t def)
{
  qstring v;
  if ( qgetenv(var, &v) && !v.empty() )
  {
    ea_t e = ea_t(strtoull(v.c_str(), nullptr, 0));
    if ( e != 0 )
      return e;
  }
  return def;
}

int fairplay_resolve_vm_table()
{
  ea_t start = env_ea("UNSLOP_FP_LUT_START", FP_LUT_START);
  ea_t end   = env_ea("UNSLOP_FP_LUT_END",   FP_LUT_END);
  if ( end <= start || !is_mapped(start) )
  {
    msg("[unslop/fp] no dispatch LUT at %a..%a (set UNSLOP_FP_LUT_START/END)\n",
        start, end);
    return -1;
  }

  // Sanity gate: the first slots must look like executable-segment pointers,
  // otherwise this is not the FairPlay dispatch table and we refuse to touch
  // anything. Require a clear majority of a small prefix to be __text pointers.
  int probe = 0, hits = 0;
  for ( ea_t slot = start; slot < end && probe < 64; slot += 8, ++probe )
  {
    ea_t tgt = ea_t(get_qword(slot));
    if ( is_mapped(tgt) && in_exec_seg(tgt) )
      ++hits;
  }
  if ( probe == 0 || hits * 2 < probe )
  {
    msg("[unslop/fp] %a does not look like a handler LUT (%d/%d exec ptrs); "
        "refusing.\n", start, hits, probe);
    return -1;
  }

  uint64_t slots = 0, resolved = 0, created = 0;
  std::set<ea_t> unique;
  for ( ea_t slot = start; slot < end; slot += 8 )
  {
    ++slots;
    ea_t tgt = ea_t(get_qword(slot));
    if ( !is_mapped(tgt) || !in_exec_seg(tgt) )
      continue;                       // unresolved / past-end garbage slot
    ++resolved;
    unique.insert(tgt);
    func_t *f = get_func(tgt);
    if ( f == nullptr )
    {
      if ( add_func(tgt) )            // surface a previously-undefined handler
        ++created;
    }
    else if ( f->start_ea != tgt )
    {
      // tgt is inside a function but not its head -- a tail-called VM chunk.
      // Leave IDA's model alone; just record it as a unique target.
    }
  }

  // Name the table head so the dispatch site reads clearly.
  if ( get_name(start).empty() )
    set_name(start, "fairplay_vm_dispatch_lut", SN_NOWARN | SN_FORCE);

  msg("[unslop/fp] VM dispatch LUT %a..%a: %llu slots, %llu resolved, "
      "%llu unique targets, %llu new handler func(s)\n",
      start, end, (uint64_t)slots, (uint64_t)resolved,
      (uint64_t)unique.size(), (uint64_t)created);
  DLOG(L_INFO, "fairplay VM table: %llu/%llu resolved, %llu unique, %llu created",
       (uint64_t)resolved, (uint64_t)slots, (uint64_t)unique.size(),
       (uint64_t)created);
  return int(created);
}

} // namespace unslop
