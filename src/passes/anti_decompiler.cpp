// Anti-decompiler / anti-disassembly resolution at the microcode level.
//
// Target: the OLLVM-22 "anti-decompiler" (adec) post-hardening pass. See
//   docs/ollvm22_user.md ("Anti-decompiler (adec) tuning", techniques:
//   asmGadgets, indirectBr, deadDecoy, stackPollution, callTrampoline,
//   aliasConfusion, fakeLoop, rdtscStretch, constLaunder).
//
// This TU removes the microcode-visible constructs, always conservatively:
// every rewrite is proven from constants / single definitions, never guessed.
// The techniques handled here:
//
//   indirectBr   - an m_ijmp / m_goto whose target operand provably resolves
//                  (via backward const/reg trace inside the block) to the
//                  start address of a single block -> rewritten to a direct
//                  m_goto, with succset/predset fixed (vds11 CFG-edit pattern).
//   deadDecoy /  - conditional branches guarded by an opaque predicate that
//   fakeLoop       folds to a constant -> the taken edge is kept and the dead
//                  edge dropped (delegated to eliminate_opaque_predicates()).
//   aliasConfusion - ptr->int->ptr round-trip cast chains that reduce to
//                  identity (low(xdu/xds(x)) with matching size, or a nested
//                  identity mov) -> replaced by the original operand.
//   constLaunder - a register that provably holds a constant at a use site
//                  (local forward constant propagation) -> the use is replaced
//                  by the immediate.
//
// verify(true) is performed by the caller after this returns.
#include "anti_decompiler.h"
#include "microcode_utils.h"
#include "mba_simplify.h"

#include <map>
#include <vector>

namespace unslop {

//--------------------------------------------------------------------------
// Small classification helpers.
//--------------------------------------------------------------------------

// A control-transfer / call opcode: we never touch its operands during the
// value-level constant propagation below (indirectBr handles jumps separately).
static bool is_control_or_call(mcode_t op)
{
  if ( op == m_goto || op == m_ijmp || op == m_jtbl
    || op == m_call || op == m_icall || op == m_ret )
  {
    return true;
  }
  // conditional jumps m_jcnd .. m_jle
  return op == m_jcnd || (op >= m_jnz && op <= m_jle);
}

// Locate the block whose start address equals `addr`, or -1.
static int find_block_by_start(mba_t *mba, ea_t addr)
{
  if ( addr == BADADDR )
    return -1;
  for ( int i = 0; i < mba->qty; ++i )
  {
    const mblock_t *b = mba->get_mblock(i);
    if ( b->start == addr )
      return i;
  }
  return -1;
}

//--------------------------------------------------------------------------
// Local (single-block) constant environment.
//
// A running reg -> known-constant map, updated instruction by instruction.
// Only movs from an immediate, or copies of an already-known-constant
// register, are tracked; any other definition of a register clears it. This
// makes every lookup a *proven* fact about the register's value at that point.
//--------------------------------------------------------------------------

// Apply the effect of `ins` on the constant environment `env`.
static void step_env(const minsn_t *ins, std::map<mreg_t, uint64_t> *env)
{
  if ( ins->d.t != mop_r )
    return;
  mreg_t reg = ins->d.r;
  if ( ins->opcode == m_mov )
  {
    if ( is_num(&ins->l) )
    {
      (*env)[reg] = num_val(&ins->l);
      return;
    }
    if ( ins->l.t == mop_r )
    {
      auto it = env->find(ins->l.r);
      if ( it != env->end() )
      {
        (*env)[reg] = it->second;
        return;
      }
    }
  }
  // Any other definition makes the register's value unknown.
  env->erase(reg);
}

// If `m` is a register whose constant value is known in `env`, return true and
// store the value; else false.
static bool reg_const(const mop_t *m, const std::map<mreg_t, uint64_t> &env,
                      uint64_t *out)
{
  if ( m == nullptr || m->t != mop_r )
    return false;
  auto it = env.find(m->r);
  if ( it == env.end() )
    return false;
  *out = it->second;
  return true;
}

//--------------------------------------------------------------------------
// aliasConfusion: fold provable identity cast / move round-trips.
//
//   low_s( xdu(x) )  ==  x   when size(x) == s   (widen then narrow back)
//   low_s( xds(x) )  ==  x   when size(x) == s
//   mov( x )         ==  x   when a value is wrapped in a no-op nested move
//
// Only fired when the produced size matches the inner source size, so the
// transform is a bit-exact identity.
//--------------------------------------------------------------------------

static int fold_identity_casts(mop_t *m);

// Try to reduce the operand `m` (which embeds a subinstruction) to an inner
// operand. Returns 1 if `m` was replaced.
static int reduce_operand(mop_t *m)
{
  if ( m->t != mop_d || m->d == nullptr )
    return 0;
  minsn_t *sub = m->d;

  // low(xdu/xds(x)) -> x, when the narrowed result is the same width as x.
  if ( sub->opcode == m_low
    && sub->l.t == mop_d && sub->l.d != nullptr )
  {
    minsn_t *inner = sub->l.d;
    if ( (inner->opcode == m_xdu || inner->opcode == m_xds)
      && inner->l.size == m->size
      && inner->l.size != 0 )
    {
      mop_t x = inner->l;   // deep copy before we overwrite *m (frees sub)
      *m = x;
      return 1;
    }
  }

  // A nested no-op move: the operand is exactly the value of the move source.
  if ( sub->opcode == m_mov
    && sub->l.size == m->size
    && sub->l.size != 0 )
  {
    mop_t x = sub->l;       // deep copy before we overwrite *m
    *m = x;
    return 1;
  }

  return 0;
}

// Recurse into an operand's subtree, folding identity casts bottom-up.
static int fold_identity_casts(mop_t *m)
{
  if ( m == nullptr || m->t != mop_d || m->d == nullptr )
    return 0;
  int cnt = 0;
  minsn_t *sub = m->d;
  cnt += fold_identity_casts(&sub->l);
  cnt += fold_identity_casts(&sub->r);
  cnt += fold_identity_casts(&sub->d);
  cnt += reduce_operand(m);
  return cnt;
}

//--------------------------------------------------------------------------
// indirectBr: resolve a computed jump to a single constant block.
//--------------------------------------------------------------------------

// Rewrite `blk`'s tail into a direct `goto new_target`, repairing the CFG.
// Assumes new_target is a valid block index != blk->serial.
static void rewrite_to_direct_goto(mba_t *mba, mblock_t *blk, int new_target)
{
  minsn_t *tail = blk->tail;

  // Snapshot the current successors so we can drop the stale ones.
  std::vector<int> old_succs;
  int ns = blk->nsucc();
  for ( int i = 0; i < ns; ++i )
    old_succs.push_back(blk->succ(i));

  // Rewrite the terminator.
  tail->opcode = m_goto;
  tail->l.make_blkref(new_target);
  tail->r.erase();
  tail->d.erase();

  // Detach us from every old successor except the surviving target.
  for ( size_t i = 0; i < old_succs.size(); ++i )
  {
    int s = old_succs[i];
    if ( s == new_target )
      continue;
    blk->succset.del(s);
    mblock_t *ob = mba->get_mblock(s);
    ob->predset.del(blk->serial);
    if ( ob->serial != mba->qty - 1 )
      ob->mark_lists_dirty();
  }

  // Ensure the single edge to new_target exists in both directions.
  if ( !blk->succset.has(new_target) )
    blk->succset.push_back(new_target);
  mblock_t *nb = mba->get_mblock(new_target);
  if ( !nb->predset.has(blk->serial) )
  {
    nb->predset.push_back(blk->serial);
    if ( nb->serial != mba->qty - 1 )
      nb->mark_lists_dirty();
  }

  blk->mark_lists_dirty();
}

// Try to resolve one block's indirect terminator. Returns 1 if rewritten.
static int resolve_indirect_terminator(mba_t *mba, mblock_t *blk)
{
  minsn_t *tail = blk->tail;
  if ( tail == nullptr )
    return 0;

  // Select the operand that names the jump destination.
  //   m_ijmp {r=sel, d=off}  -> destination is in `d`
  //   m_goto  l              -> destination is in `l` (already direct if mop_b)
  const mop_t *tgt = nullptr;
  if ( tail->opcode == m_ijmp )
    tgt = &tail->d;
  else if ( tail->opcode == m_goto && tail->l.t != mop_b )
    tgt = &tail->l;
  else
    return 0;

  if ( tgt == nullptr )
    return 0;

  // Backward const/reg trace within this block up to the terminator.
  uint64_t addr = 0;
  bool have = false;
  if ( is_num(tgt) )
  {
    addr = num_val(tgt);
    have = true;
  }
  else if ( tgt->t == mop_r )
  {
    std::map<mreg_t, uint64_t> env;
    for ( minsn_t *ins = blk->head; ins != nullptr && ins != tail; ins = ins->next )
      step_env(ins, &env);
    have = reg_const(tgt, env, &addr);
  }
  if ( !have )
    return 0;

  int target = find_block_by_start(mba, ea_t(addr));
  if ( target < 0 || target == blk->serial )
    return 0;

  rewrite_to_direct_goto(mba, blk, target);
  return 1;
}

//--------------------------------------------------------------------------
// constLaunder: replace register uses that provably hold a constant with the
// immediate. Local forward constant propagation guarantees the value at the
// use site. Control-transfer / call operands are left untouched (jumps are the
// indirectBr path; calls may depend on the register identity).
//--------------------------------------------------------------------------

// Replace `m` with its proven constant, preserving the operand size.
static bool launder_operand(mop_t *m, const std::map<mreg_t, uint64_t> &env,
                            ea_t ea)
{
  uint64_t v = 0;
  if ( !reg_const(m, env, &v) )
    return false;
  int sz = m->size;
  if ( sz != 1 && sz != 2 && sz != 4 && sz != 8 )
    return false;
  m->make_number(v, sz, ea);
  return true;
}

// Run constLaunder + aliasConfusion folding over one block. Returns #changes.
static int process_block_values(mblock_t *blk)
{
  int changes = 0;
  std::map<mreg_t, uint64_t> env;

  for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    // aliasConfusion: identity cast / move round-trips inside every operand.
    changes += fold_identity_casts(&ins->l);
    changes += fold_identity_casts(&ins->r);
    changes += fold_identity_casts(&ins->d);

    // constLaunder: substitute known-constant register sources. Never rewrite
    // the operands of a control transfer or call.
    if ( !is_control_or_call(ins->opcode) )
    {
      if ( ins->l.t == mop_r && launder_operand(&ins->l, env, ins->ea) )
        ++changes;
      if ( ins->r.t == mop_r && launder_operand(&ins->r, env, ins->ea) )
        ++changes;
    }

    // Advance the constant environment past this instruction.
    step_env(ins, &env);
  }

  if ( changes > 0 )
    blk->mark_lists_dirty();
  return changes;
}

//--------------------------------------------------------------------------
// Public entry.
//--------------------------------------------------------------------------

int resolve_anti_decompiler(mba_t *mba)
{
  if ( mba == nullptr || mba->qty <= 0 )
    return 0;

  int changes = 0;

  // 1) deadDecoy / fakeLoop: fold opaque-predicate branches to their taken
  //    edge and drop the dead edge. This helper repairs the CFG per changed
  //    block via mark_lists_dirty(); the caller verifies once at the end.
  changes += eliminate_opaque_predicates(mba);

  // 2) indirectBr: rewrite provably-single-target computed jumps to direct
  //    gotos and repair the CFG edges.
  for ( int i = 0; i < mba->qty; ++i )
    changes += resolve_indirect_terminator(mba, mba->get_mblock(i));

  // 3) aliasConfusion + constLaunder: value-level folds that preserve types
  //    and sizes (no CFG change).
  for ( int i = 0; i < mba->qty; ++i )
    changes += process_block_values(mba->get_mblock(i));

  // The caller does a single mark_chains_dirty() and one verify(true) after
  // all passes; per-block mark_lists_dirty() keeps the CFG edits consistent.
  return changes;
}

} // namespace unslop
