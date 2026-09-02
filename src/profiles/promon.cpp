// Promon SHIELD profile for the Unslopper deflattener.
//
// Ported from the promon-research CFF deobfuscators:
//   tools/cff_deobfuscator.py        (register-pool + BST dispatch, CSEL aliases)
//   tweak/promon_cff_deobfuscator.py (BST pivots vs real states, opaque preds
//                                     via dword_9AD844 / dword_9AD848)
//
// Promon's OLLVM-derived CFF scheme, as seen at the ARM64 / microcode level:
//   - The prologue loads all state constants into a pool of callee-saved
//     registers (many `mov #const, reg` near the entry).
//   - The dispatcher is a high-predecessor block feeding a binary-search-tree
//     of comparisons: interior nodes are range compares (B.LE / B.GT, i.e.
//     m_jle / m_jg / m_jl / m_jge) whose compared value is only a *pivot*, and
//     leaves are equality compares (B.EQ, i.e. m_jz) whose value is a *real*
//     state that maps to a handler block.
//   - Off-by-one BST pivots: the value N-1 is used as a partition pivot while
//     N is the real state, so pivots must be separated from states.
//   - Opaque predicates built on dword_9AD844 / dword_9AD848 (x*(x-1)%2==0,
//     always TRUE) select predetermined CSEL branches; these are folded away in
//     post_process via unslop::eliminate_opaque_predicates.

#include <hexrays.hpp>
#include <map>
#include <set>
#include <vector>
#include <cstdint>

#include "profile.h"
#include "unslop_types.h"
#include "microcode_utils.h"
#include "mba_simplify.h"

namespace unslop {

//--------------------------------------------------------------------------
// Local helpers
//--------------------------------------------------------------------------

// True if the block looks like a dispatcher / BST-interior comparison block:
// it ends in (or contains) a conditional jump and performs no calls. Handler
// blocks contain calls or terminate by branching back to the dispatcher, so
// this keeps the tree walk confined to the comparison skeleton.
static bool looks_like_dispatch(const mblock_t *blk)
{
  if ( blk == nullptr )
    return false;
  bool has_cond = false;
  for ( const minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    if ( ins->opcode == m_call || ins->opcode == m_icall )
      return false;
    if ( is_cond_jump(ins->opcode) )
      has_cond = true;
  }
  return has_cond;
}

// Serial of the block with the most predecessors (the classic flattening
// dispatcher shape), or -1 if none has at least `min_preds` predecessors.
static int max_pred_block(mba_t *mba, int min_preds)
{
  int best = -1;
  int best_preds = min_preds - 1;
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    int np = blk->npred();
    if ( np > best_preds )
    {
      best_preds = np;
      best = i;
    }
  }
  return best;
}

// From one conditional-jump instruction, recover the constant it compares the
// state variable against. The compared value is either an immediate operand or
// a register whose constant is known from the register pool. The *other*
// operand (a register not carrying a pool constant) is taken to be the state
// variable. Returns true and fills *cval (and *statereg, when identifiable).
static bool get_cmp_const(const minsn_t *ins,
                          const std::map<mreg_t, uint64_t> &pool,
                          uint64_t *cval,
                          mreg_t *statereg)
{
  const mop_t *ops[2] = { &ins->l, &ins->r };
  for ( int i = 0; i < 2; ++i )
  {
    const mop_t *c = ops[i];       // candidate constant operand
    const mop_t *o = ops[1 - i];   // the other operand -> state var
    uint64_t v;
    if ( is_num(c) )
    {
      v = num_val(c);
    }
    else if ( is_reg(c) )
    {
      auto it = pool.find(c->r);
      if ( it == pool.end() )
        continue;
      v = it->second;
    }
    else
    {
      continue;
    }
    *cval = v;
    if ( is_reg(o) )
      *statereg = o->r;
    return true;
  }
  return false;
}

// The successor serial of `blk` that is not `taken` (the fall-through edge of a
// two-way conditional jump), or -1 if there is no distinct other successor.
static int other_succ(const mblock_t *blk, int taken)
{
  for ( int k = 0; k < blk->nsucc(); ++k )
  {
    int s = blk->succset[k];
    if ( s != taken )
      return s;
  }
  return -1;
}

//--------------------------------------------------------------------------
// Promon profile
//--------------------------------------------------------------------------

class PromonProfile : public Profile
{
public:
  const char *name() const override { return "promon"; }
  ProfileKind kind() const override { return ProfileKind::PROMON; }

  bool detect(mba_t *mba,
              const std::map<mreg_t, uint64_t> &regmap) override;
  bool configure(mba_t *mba, DispatcherInfo *di,
                 const std::map<mreg_t, uint64_t> &regmap) override;

  // Promon state values are plain constants held in the register pool; there
  // is no XOR/ADD encoding, so the mapping is identity.
  uint64_t transform_state(uint64_t raw) override { return raw; }

  // Fold the dword_9AD844 / dword_9AD848 opaque predicates that gate the CSEL
  // state transitions once the flattened CFG has been rewritten.
  int post_process(mba_t *mba, int changes) override
  {
    return eliminate_opaque_predicates(mba);
  }

private:
  // The prologue register-constant pool: register -> loaded state constant.
  std::map<mreg_t, uint64_t> reg_pool;
};

//--------------------------------------------------------------------------
bool PromonProfile::detect(mba_t *mba,
                           const std::map<mreg_t, uint64_t> &regmap)
{
  if ( mba == nullptr || mba->qty <= 0 )
    return false;

  // (1) Register pool: the prologue loads many constants into registers. The
  //     caller supplies it as the shared map built once per function (FIX 2).
  if ( (int)regmap.size() < 4 )
    return false;

  // (2) A high-predecessor dispatcher block must exist.
  int head = max_pred_block(mba, 3);
  if ( head < 0 )
    return false;

  // (3) A BST comparison tree: range compares (B.LE / B.GT => m_jle / m_jg /
  //     m_jl / m_jge) forming interior nodes, plus equality leaves (B.EQ =>
  //     m_jz / m_jnz). Require at least one range compare and a chain of
  //     comparisons overall.
  int range = 0;
  int eq = 0;
  for ( int i = 0; i < mba->qty; ++i )
  {
    for ( minsn_t *ins = mba->get_mblock(i)->head; ins != nullptr; ins = ins->next )
    {
      switch ( ins->opcode )
      {
        case m_jz:
        case m_jnz:
          ++eq;
          break;
        case m_jg:
        case m_jge:
        case m_jl:
        case m_jle:
          ++range;
          break;
        default:
          break;
      }
    }
  }

  return range >= 1 && (range + eq) >= 3;
}

//--------------------------------------------------------------------------
bool PromonProfile::configure(mba_t *mba, DispatcherInfo *di,
                              const std::map<mreg_t, uint64_t> &regmap)
{
  if ( mba == nullptr || di == nullptr )
    return false;

  // Prologue register-constant pool (kept as a member so the profile can
  // resolve register-form pivots throughout). Sourced from the shared map
  // built once per function (FIX 2).
  reg_pool = regmap;

  // Locate the dispatcher head if not already known.
  int head = di->block_idx;
  if ( head < 0 )
    head = max_pred_block(mba, 3);
  if ( head < 0 )
    return false;
  di->block_idx = head;

  // Walk the dispatcher / BST-interior blocks, classifying each compared value
  // as a real state (equality) or a BST pivot (range partition).
  std::set<int> visited;
  std::vector<int> work;
  work.push_back(head);

  while ( !work.empty() )
  {
    int s = work.back();
    work.pop_back();
    if ( !visited.insert(s).second )
      continue;
    mblock_t *blk = mba->get_mblock(s);
    if ( blk == nullptr )
      continue;
    di->dispatcher_blocks.insert(s);

    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( !is_cond_jump(ins->opcode) )
        continue;

      uint64_t cval = 0;
      mreg_t sr = mreg_t(-1);
      if ( !get_cmp_const(ins, reg_pool, &cval, &sr) )
        continue;

      // Record the state variable (register that is compared, not the pooled
      // constant) the first time we identify it.
      if ( sr != mreg_t(-1) && di->state_reg == mreg_t(-1) )
      {
        di->state_reg = sr;
        di->state_var = mop_t(sr, 4);
      }

      int taken = is_blkref(&ins->d) ? ins->d.b : -1;

      switch ( ins->opcode )
      {
        case m_jz:
          // Equality (B.EQ) leaf: cval is a real state, taken branch is its
          // handler.
          di->state_consts.insert(cval);
          if ( taken >= 0 )
            di->state_map[cval] = taken;
          break;

        case m_jnz:
          // Not-equal (B.NE): cval is still a real state, but the *handler* is
          // the fall-through edge (the taken branch is the "keep searching"
          // path back toward the dispatcher).
          {
            di->state_consts.insert(cval);
            int ft = other_succ(blk, taken);
            if ( ft >= 0 )
              di->state_map[cval] = ft;
          }
          break;

        case m_jg:
        case m_jge:
        case m_jl:
        case m_jle:
          // Range compare (B.LE / B.GT / ...): cval is a BST partition pivot,
          // not a real state. Descend into both subtrees.
          di->bst_pivots.insert(cval);
          if ( taken >= 0 && !visited.count(taken) )
            work.push_back(taken);
          {
            int ft = other_succ(blk, taken);
            if ( ft >= 0 && !visited.count(ft) )
              work.push_back(ft);
          }
          break;

        default:
          break;
      }
    }

    // Continue through comparison-only successors so linear equality chains and
    // BST fall-throughs are fully traversed; handler blocks (which contain
    // calls) are skipped by looks_like_dispatch.
    for ( int k = 0; k < blk->nsucc(); ++k )
    {
      int su = blk->succset[k];
      if ( !visited.count(su) && looks_like_dispatch(mba->get_mblock(su)) )
        work.push_back(su);
    }
  }

  di->detection_strategy = 1;   // max-preds derived dispatcher
  di->valid = !di->state_map.empty();
  return di->valid;
}

//--------------------------------------------------------------------------
Profile *make_promon()
{
  return new PromonProfile();
}

} // namespace unslop
