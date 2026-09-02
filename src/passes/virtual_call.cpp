#include "virtual_call.h"
#include "microcode_utils.h"

#include <bytes.hpp>
#include <segment.hpp>
#include <funcs.hpp>

namespace unslop {

//--------------------------------------------------------------------------
// OLLVM-22 "vcall" (virtual call) pass devirtualization.
//
// The vcall pass rewrites a direct call `f(...)` into an indirect call that
// looks the target up through a synthetic, read-only vtable:
//
//     ldx  ds, (VTABLE + idx*ptrsize), tmp   ; load the function pointer
//     icall {ds, tmp}, <callinfo>            ; call through it
//
// When the vtable slot lives in a non-writable segment and holds a valid
// function entry, the whole indirection is statically recoverable: we read
// the pointer out of the IDB and rewrite the m_icall into a direct m_call.
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
// Find the instruction in `blk` that last defines register `reg` strictly
// before instruction `before`. Returns nullptr if none.
//--------------------------------------------------------------------------
static minsn_t *find_reg_def(mblock_t *blk, const minsn_t *before, mreg_t reg)
{
  minsn_t *last = nullptr;
  for ( minsn_t *m = blk->head; m != nullptr && m != before; m = m->next )
  {
    if ( m->d.t == mop_r && m->d.r == reg )
      last = m;
  }
  return last;
}

//--------------------------------------------------------------------------
// Given the operand that carries an icall's target value, walk back through
// register moves to the m_ldx that originally produced it. Bounded hop count
// so we never loop on pathological chains.
//--------------------------------------------------------------------------
static const minsn_t *trace_to_ldx(mblock_t *blk, const minsn_t *icall,
                                    const mop_t *target)
{
  const minsn_t *cur = nullptr;
  const minsn_t *ctx = icall; // instruction the current value is used at

  if ( target->t == mop_d )
    cur = target->d;
  else if ( target->t == mop_r )
    cur = find_reg_def(blk, icall, target->r);

  for ( int hop = 0; cur != nullptr && hop < 8; ++hop )
  {
    if ( cur->opcode == m_ldx )
      return cur;
    if ( cur->opcode != m_mov )
      break;
    // Follow the source of the move one level deeper.
    if ( cur->l.t == mop_d )
    {
      cur = cur->l.d;
    }
    else if ( cur->l.t == mop_r )
    {
      const minsn_t *def = find_reg_def(blk, ctx, cur->l.r);
      ctx = cur;
      cur = def;
    }
    else
    {
      break;
    }
  }
  return nullptr;
}

//--------------------------------------------------------------------------
// Fold an address expression operand into an absolute linear address.
// Handles global operands, immediates, and add/sub/mul trees combining them
// (e.g. VTABLE_BASE + index*ptrsize with a constant index).
//--------------------------------------------------------------------------
static bool eval_addr(const mop_t *m, uint64_t *out, int depth = 0)
{
  if ( m == nullptr || depth > 8 )
    return false;

  switch ( m->t )
  {
    case mop_n:
      *out = num_val(m, 0);
      return true;

    case mop_v: // global variable: its linear address
      *out = (uint64_t)m->g;
      return true;

    case mop_a: // address of an operand (&global)
      if ( m->a != nullptr && m->a->t == mop_v )
      {
        *out = (uint64_t)m->a->g;
        return true;
      }
      return false;

    case mop_d:
    {
      const minsn_t *ins = m->d;
      if ( ins == nullptr )
        return false;
      uint64_t lv = 0, rv = 0;
      switch ( ins->opcode )
      {
        case m_add:
          if ( eval_addr(&ins->l, &lv, depth + 1)
            && eval_addr(&ins->r, &rv, depth + 1) )
          {
            *out = lv + rv;
            return true;
          }
          return false;
        case m_sub:
          if ( eval_addr(&ins->l, &lv, depth + 1)
            && eval_addr(&ins->r, &rv, depth + 1) )
          {
            *out = lv - rv;
            return true;
          }
          return false;
        case m_mul:
          if ( eval_addr(&ins->l, &lv, depth + 1)
            && eval_addr(&ins->r, &rv, depth + 1) )
          {
            *out = lv * rv;
            return true;
          }
          return false;
        case m_mov:
          return eval_addr(&ins->l, out, depth + 1);
        default:
          return false;
      }
    }

    default:
      return false;
  }
}

//--------------------------------------------------------------------------
// Read a pointer-sized value out of the IDB, honoring the load width used by
// the ldx that produced it.
//--------------------------------------------------------------------------
static uint64_t read_ptr(ea_t addr, int load_size)
{
  if ( load_size == 4 )
    return (uint64_t)get_dword(addr);
  return (uint64_t)get_qword(addr);
}

//--------------------------------------------------------------------------
// Attempt to devirtualize a single m_icall in `blk`. Returns true if the
// instruction was rewritten into a direct m_call.
//--------------------------------------------------------------------------
static bool devirtualize_one(mblock_t *blk, minsn_t *ic)
{
  // Locate the ldx that loaded the call target from the vtable slot.
  const minsn_t *ldx = trace_to_ldx(blk, ic, &ic->r);
  if ( ldx == nullptr )
    return false;

  // Fold the load address to an absolute linear address.
  uint64_t slot = 0;
  if ( !eval_addr(&ldx->r, &slot) )
    return false;
  ea_t slot_ea = (ea_t)slot;

  // The vtable slot must live in a loaded, non-writable segment.
  if ( !is_mapped(slot_ea) || !is_loaded(slot_ea) )
    return false;
  segment_t *seg = getseg(slot_ea);
  if ( seg == nullptr || (seg->perm & SEGPERM_WRITE) != 0 )
    return false;

  // Read the stored pointer and check it names a real function entry.
  int load_size = ldx->d.size;
  if ( load_size != 4 && load_size != 8 )
    load_size = 8;
  uint64_t raw = read_ptr(slot_ea, load_size);
  if ( raw == 0 )
    return false;
  ea_t target = (ea_t)raw;
  if ( target == BADADDR )
    return false;
  if ( get_func_start(target) != target ) // must be a genuine function entry
    return false;

  // Rewrite: icall {sel, off}, callinfo  ->  call <target>, callinfo.
  ic->opcode = m_call;
  ic->l.make_gvar(target); // erases previous contents, sets mop_v(target)
  ic->r.erase();           // drop the now-unused off operand
  if ( ic->d.t == mop_f && ic->d.f != nullptr )
    ic->d.f->callee = target; // let Hex-Rays display the resolved callee
  return true;
}

//--------------------------------------------------------------------------
// Public entry point: devirtualize resolvable indirect calls across `mba`.
//--------------------------------------------------------------------------
int devirtualize_calls(mba_t *mba)
{
  if ( mba == nullptr )
    return 0;

  int changes = 0;
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    if ( blk == nullptr )
      continue;
    bool blk_changed = false;
    for ( minsn_t *m = blk->head; m != nullptr; m = m->next )
    {
      if ( m->opcode != m_icall )
        continue;
      if ( devirtualize_one(blk, m) )
      {
        ++changes;
        blk_changed = true;
      }
    }
    if ( blk_changed )
      blk->mark_lists_dirty();
  }

  // The caller does a single mark_chains_dirty() and one verify(true) after
  // all passes; per-block mark_lists_dirty() above keeps edits consistent.
  return changes;
}

} // namespace unslop
