#include "semantic_diffusion.h"
#include "microcode_utils.h"

#include <vector>
#include <cstdint>

namespace unslop {

//--------------------------------------------------------------------------
// OLLVM-22 Semantic Diffusion (volatile-slot masking) + Anti-Optimization
// Shield (volatile barriers).
//
// The obfuscator blocks value propagation by round-tripping a live value
// through a volatile stack slot: it stores the value into the slot and then
// immediately reads it back, sometimes XOR-masking with a constant K on the
// store and unmasking with the same K on the load. The native optimizer keeps
// the load/store because the slot is `volatile`.
//
// We work at MMAT_LVARS-level microcode where stack accesses appear as movs
// to/from a mop_S operand (also handling the m_stx/m_ldx forms). Within a
// single block we track, for every stack slot, its single reaching definition
// and (when representable) the simple source operand that produced it. When we
// later see a load of that slot with no intervening writer, we know the slot
// has exactly one reaching definition at that point (any predecessor value is
// killed by the in-block store), so we may safely rewrite:
//
//   store  mov  x        -> S      ;  load  mov  S -> y   ==>  mov  x -> y
//   store  xor  x, K     -> S      ;  load  xor  S, K -> y ==>  mov  x -> y
//   store  mov  x        -> S      ;  load  xor  S, K -> y ==>  xor  x, K -> y
//
// A rewritten load whose source equals its destination is a pure volatile
// barrier and is turned into a nop.
//
// Conservative guards:
//  * store and load live in the same block; the store dominates the load with
//    no intervening writer to the slot -> exactly one reaching definition;
//  * the propagated source operand must be simple (const/reg/stack) and must
//    not be clobbered between the store and the load;
//  * calls and un-pinnable memory stores clear all tracking (may alias).
//--------------------------------------------------------------------------

namespace {

// A simple operand can be safely copied and propagated forward: it holds no
// subinstruction and its value is a plain constant, register, or stack slot.
inline bool is_simple_operand(const mop_t *m)
{
  return m != nullptr && (m->t == mop_n || m->t == mop_r || m->t == mop_S);
}

// Byte range [off, off+size) of a stack operand. size<=0 => unknown (BADSIZE).
inline bool slot_range(const mop_t *m, int64_t *off, int *size)
{
  if ( m == nullptr || m->t != mop_S || m->s == nullptr )
    return false;
  *off = m->s->off;
  *size = m->size;
  return true;
}

// True if two byte ranges overlap. Unknown sizes are treated as overlapping.
inline bool ranges_overlap(int64_t o1, int s1, int64_t o2, int s2)
{
  if ( s1 <= 0 || s2 <= 0 )
    return o1 == o2 ? true : true; // unknown extent: assume aliasing
  return o1 < o2 + s2 && o2 < o1 + s1;
}

// One tracked reaching definition of a stack slot inside a block.
struct store_def_t
{
  int64_t  off = 0;         // slot offset
  int      size = 0;        // slot size in bytes
  mop_t    src;             // simple source value (valid only if src_ok)
  bool     src_ok = false;  // src is representable and still live
  bool     masked = false;  // value stored is (src ^ mask)
  uint64_t mask = 0;        // K when masked
};

class slot_tracker_t
{
  std::vector<store_def_t> defs;

public:
  void clear() { defs.clear(); }

  // Find the active definition covering exactly [off,size) (same slot & size).
  store_def_t *find_exact(int64_t off, int size)
  {
    for ( store_def_t &d : defs )
      if ( d.off == off && d.size == size )
        return &d;
    return nullptr;
  }

  // A write to memory range [off,size): kill overlapping defs, and invalidate
  // any def whose source aliases the written range.
  void on_slot_write(int64_t off, int size)
  {
    for ( size_t i = 0; i < defs.size(); )
    {
      if ( ranges_overlap(defs[i].off, defs[i].size, off, size) )
      {
        defs.erase(defs.begin() + i);
        continue;
      }
      // Source invalidation: a stack-slot source overlapping the write.
      store_def_t &d = defs[i];
      if ( d.src_ok && d.src.t == mop_S && d.src.s != nullptr
        && ranges_overlap(d.src.s->off, d.src.size, off, size) )
      {
        d.src_ok = false;
      }
      ++i;
    }
  }

  // A write to register r: invalidate any def whose source is that register.
  void on_reg_write(mreg_t r)
  {
    for ( store_def_t &d : defs )
      if ( d.src_ok && d.src.t == mop_r && d.src.r == r )
        d.src_ok = false;
  }

  // Register or replace the definition of a slot.
  void set_def(const store_def_t &nd)
  {
    for ( store_def_t &d : defs )
    {
      if ( d.off == nd.off && d.size == nd.size )
      {
        d = nd;
        return;
      }
    }
    defs.push_back(nd);
  }
};

// Describe a load of a stack slot into a register (dst is always ins->d).
struct load_info_t
{
  bool         ok = false;
  const mop_t *slot = nullptr;
  bool         masked = false;
  uint64_t     mask = 0;
};

// Recognize a slot load. Only called when the destination is NOT a stack slot
// (so masked stores, whose d is a mop_S, are never mistaken for loads).
load_info_t detect_load(const minsn_t *ins)
{
  load_info_t li;
  switch ( ins->opcode )
  {
    case m_mov:
      if ( ins->l.t == mop_S )
      {
        li.ok = true;
        li.slot = &ins->l;
      }
      break;

    case m_ldx: // ldx {l=sel, r=off}, d  -> the address offset is r
      if ( ins->r.t == mop_S )
      {
        li.ok = true;
        li.slot = &ins->r;
      }
      break;

    case m_xor: // masked load: slot ^ K -> d
      if ( ins->l.t == mop_S && is_num(&ins->r) )
      {
        li.ok = true;
        li.slot = &ins->l;
        li.masked = true;
        li.mask = num_val(&ins->r);
      }
      else if ( ins->r.t == mop_S && is_num(&ins->l) )
      {
        li.ok = true;
        li.slot = &ins->r;
        li.masked = true;
        li.mask = num_val(&ins->l);
      }
      break;

    default:
      break;
  }
  return li;
}

// Build a store definition from an instruction whose destination is a stack
// slot. Always fills off/size; src_ok is set only for representable values.
store_def_t detect_store(const minsn_t *ins)
{
  store_def_t d;
  d.off = ins->d.s->off;
  d.size = ins->d.size;

  switch ( ins->opcode )
  {
    case m_mov:
    case m_stx: // stx l, {r=sel, d=off}: value l stored at stack offset d
      if ( is_simple_operand(&ins->l) )
      {
        d.src = ins->l;
        d.src_ok = true;
      }
      break;

    case m_xor: // masked store: (x ^ K) -> S
      if ( is_num(&ins->r) && is_simple_operand(&ins->l) )
      {
        d.src = ins->l;
        d.src_ok = true;
        d.masked = true;
        d.mask = num_val(&ins->r);
      }
      else if ( is_num(&ins->l) && is_simple_operand(&ins->r) )
      {
        d.src = ins->r;
        d.src_ok = true;
        d.masked = true;
        d.mask = num_val(&ins->l);
      }
      break;

    default:
      break; // opaque value: recorded as an (invalidating) definition only
  }
  return d;
}

// Turn a matched load into `mov src -> d` (round-trip / mask cancellation) or
// `xor src, K -> d` (unmasked store folded through a masking load). Returns 1.
int rewrite_load(minsn_t *ins, const mop_t &src, bool emit_xor, uint64_t k)
{
  mop_t nsrc = src; // deep copy before mutating the instruction

  if ( emit_xor )
  {
    ins->opcode = m_xor;
    ins->l = nsrc;
    ins->r.make_number(k, ins->d.size, ins->ea);
    // ins->d (destination) preserved
  }
  else
  {
    ins->opcode = m_mov;
    ins->l = nsrc;
    ins->r.erase();
    // ins->d (destination) preserved
  }
  return 1;
}

// Apply an instruction's write/clobber effects to the tracker, and register a
// new definition if the instruction stores to a stack slot.
void apply_effects(minsn_t *ins, slot_tracker_t *trk)
{
  mcode_t op = ins->opcode;

  // Calls clobber registers and memory arbitrarily.
  if ( op == m_call || op == m_icall )
  {
    trk->clear();
    return;
  }

  // Store to memory.
  if ( op == m_stx )
  {
    if ( ins->d.t == mop_S && ins->d.s != nullptr )
    {
      trk->on_slot_write(ins->d.s->off, ins->d.size);
      trk->set_def(detect_store(ins));
    }
    else
    {
      trk->clear(); // store to an unpinnable address: may alias any slot
    }
    return;
  }

  // A value-producing instruction writes its destination operand.
  if ( ins->d.t == mop_S && ins->d.s != nullptr )
  {
    trk->on_slot_write(ins->d.s->off, ins->d.size);
    trk->set_def(detect_store(ins));
  }
  else if ( ins->d.t == mop_r )
  {
    trk->on_reg_write(ins->d.r);
  }
}

// Process one block: eliminate volatile-slot round trips. Returns #changes.
int fold_block(mblock_t *blk)
{
  int changes = 0;
  slot_tracker_t trk;

  for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    // A load candidate never writes a stack slot (that would be a store).
    if ( ins->d.t != mop_S )
    {
      load_info_t li = detect_load(ins);
      if ( li.ok && li.slot->s != nullptr )
      {
        int64_t off = li.slot->s->off;
        int lsize = li.slot->size;
        store_def_t *def = trk.find_exact(off, lsize);
        if ( def != nullptr && def->src_ok )
        {
          bool did = false;
          if ( !li.masked && !def->masked )
          {
            // Pure round trip: store x -> S ; load S -> y  =>  mov x -> y
            rewrite_load(ins, def->src, false, 0);
            did = true;
          }
          else if ( li.masked && def->masked && li.mask == def->mask )
          {
            // Mask cancellation: (x^K)->S ; (S^K)->y  =>  mov x -> y
            rewrite_load(ins, def->src, false, 0);
            did = true;
          }
          else if ( li.masked && !def->masked )
          {
            // Store plain x, load masks: fold through as xor x, K -> y.
            rewrite_load(ins, def->src, true, li.mask);
            did = true;
          }
          // (masked store + plain load leaves x^K in the slot: not a simple
          // operand, so we leave it untouched.)

          if ( did )
          {
            ++changes;
            // A plain `mov src -> dst` with identical operands is a pure
            // volatile barrier: drop it entirely.
            if ( ins->opcode == m_mov
              && ((ins->l.t == mop_r && ins->d.t == mop_r && ins->l == ins->d)
               || (ins->l.t == mop_S && ins->d.t == mop_S && ins->l == ins->d)) )
            {
              blk->make_nop(ins);
              // make_nop cleared the destination; no further effects to apply.
              continue;
            }
          }
        }
      }
    }

    apply_effects(ins, &trk);
  }

  if ( changes > 0 )
    blk->mark_lists_dirty();
  return changes;
}

} // anonymous namespace

int fold_semantic_diffusion(mba_t *mba)
{
  if ( mba == nullptr )
    return 0;

  int changes = 0;
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    if ( blk != nullptr )
      changes += fold_block(blk);
  }

  // The caller does a single mark_chains_dirty() and one verify(true) after
  // all passes; per-block mark_lists_dirty() above keeps edits consistent.
  return changes;
}

} // namespace unslop
