#include "verified_jump.h"
#include <bytes.hpp>
#include <xref.hpp>
#include <funcs.hpp>
#include <cstdlib>
#include <cerrno>
#include <cstring>
namespace unslop {
int restore_verified_jumps(mba_t *mba)
{
  if ( mba == nullptr || mba->maturity > MMAT_GENERATED )
    return 0;
  func_t *fn = get_func(mba->entry_ea);
  if ( fn == nullptr )
    return 0;
  const char prefix[] = "UNSLOPPER_VERIFIED_JUMP: ";
  int changed = 0;
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *b = mba->get_mblock(i);
    minsn_t *t = b->tail;
    if ( t == nullptr || t->opcode != m_ijmp || t->ea == BADADDR )
      continue;
    qstring comment;
    if ( get_cmt(&comment, t->ea, false) <= 0
      || strncmp(comment.c_str(), prefix, sizeof(prefix)-1) != 0 )
      continue;
    const char *number = comment.c_str() + sizeof(prefix)-1;
    char *end = nullptr;
    errno = 0;
    unsigned long long parsed = strtoull(number, &end, 0);
    if ( errno != 0 || end == number || *end != '\0' )
      continue;
    ea_t target = ea_t(parsed);
    if ( target == BADADDR || target == t->ea || !func_contains(fn, target) )
      continue;
    // Require one and only one analyst-added jump destination.
    int count = 0;
    bool matches = false;
    xrefblk_t xb;
    for ( bool ok = xb.first_from(t->ea, XREF_FAR); ok; ok = xb.next_from() )
      if ( xb.iscode && xb.user && (xb.type == fl_JN || xb.type == fl_JF) )
      {
        ++count;
        matches = xb.to == target;
      }
    if ( count != 1 || !matches )
      continue;
    bool has_block = false;
    for ( int j = 0; j < mba->qty; ++j )
      if ( j != i && mba->get_mblock(j)->start == target )
        has_block = true;
    if ( !has_block )
      continue;
    // GENERATED branches use EA operands, not block serials. Hex-Rays will
    // build/optimize the graph after this event; do not edit stale succsets.
    t->opcode = m_goto;
    t->l.make_gvar(target);
    t->r.erase();
    t->d.erase();
    ++changed;
  }
  return changed;
}
}
