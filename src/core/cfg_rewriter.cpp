// CFG rewriting: redirect dispatcher-bound gotos to their true targets, erase
// the now-dead state machine, and prune the unreachable dispatcher so Hex-Rays
// re-structures clean if/while instead of a switch over a state variable.
//
// Recipe follows Rolles' HexRaysDeob (docs/ref_hexraysdeob_unflattener.cpp):
//   * collect edge Replace()s and state-store erasures BEFORE mutating,
//     then apply them together (DeferredGraphModifier + m_DeferredErasures),
//   * make_nop() the state-var stores after the edges are rewritten,
//   * PruneUnreachable() once the dispatcher's incoming edges are gone.
// D-810's mba_deep_cleaning informs the dead-block pruning.
//
// change_goto_target is the original per-edge primitive (ported from
// appdome-research/scripts/cff_deflat.py::_change_goto_target).
#include "cfg_rewriter.h"
#include "state_resolver.h"
#include "history_tracker.h"
#include "block_dup.h"
#include "dispatcher.h"
#include "profile.h"
#include "microcode_utils.h"
#include "unslop_log.h"

#include <vector>
#include <set>
#include <deque>
#include <cstdlib>

namespace unslop {

//-------------------------------------------------------------------------
// Redirect a 1-way block's m_goto from `old_target` to `new_target`, keeping
// the successor / predecessor lists and the block dirty-flags consistent so the
// Hex-Rays verifier accepts the change. Returns true if the edge was rewritten.
bool change_goto_target(mblock_t *blk, int old_target, int new_target)
{
  if ( blk == nullptr )
    return false;

  mba_t *mba = blk->mba;
  minsn_t *tail = blk->tail;
  if ( tail == nullptr )
    return false;

  // Only rewrite a genuine one-way goto that targets `old_target`.
  if ( tail->opcode != m_goto || tail->l.t != mop_b )
    return false;
  if ( tail->l.b != old_target )
    return false;

  // A no-op or self-edge would only confuse the verifier.
  if ( new_target == old_target || new_target == blk->serial )
    return false;

  // 1. Rewrite the goto instruction operand.
  tail->l.make_blkref(new_target);

  // 2. Update this block's successor list (single successor for a 1-way block).
  blk->succset.del(old_target);
  blk->succset.push_back(new_target);
  blk->mark_lists_dirty();

  // 3. Drop us from the old target's predecessor list.
  mblock_t *old_blk = mba->get_mblock(old_target);
  old_blk->predset.del(blk->serial);
  if ( old_blk->serial != mba->qty - 1 )
    old_blk->mark_lists_dirty();

  // 4. Add us to the new target's predecessor list.
  mblock_t *new_blk = mba->get_mblock(new_target);
  new_blk->predset.push_back(blk->serial);
  if ( new_blk->serial != mba->qty - 1 )
    new_blk->mark_lists_dirty();

  return true;
}

//-------------------------------------------------------------------------
namespace {

// One planned edge rewrite plus the exact (block-local) state-store
// instructions to erase once the edge has been applied. Nothing is mutated
// until the whole plan is collected, mirroring HexRaysDeob's deferred model.
struct PlannedEdge
{
  int from = -1;                    // block whose goto we retarget
  int old_target = -1;              // dispatcher block it currently jumps to
  int to = -1;                      // resolved real target block
  std::vector<minsn_t *> stores;    // `mov #K, state_reg` machinery in `from`
};

} // anonymous namespace

//=========================================================================
//  D-810-style multi-pass unflattening driver (emulated / XOR-BST path).
//
//  Ported in spirit from docs/ref_d810_generic.py
//  (GenericDispatcherUnflatteningRule.remove_flattening) and
//  docs/ref_d810_cfg_utils.py. Runs at GLBOPT so Hex-Rays' structurer can
//  turn the resulting direct edges into if/while.
//
//  The register (non-emulated) path keeps the original single-pass rewriter
//  below unchanged; rewrite_cfg early-returns into this driver when the
//  emulated-BST resolver produced an exact per-block state map.
//=========================================================================
namespace {

// Insertion-based conditional-split / duplication are the only mutations that
// renumber serials (via copy_block). They are OPT-IN (UNSLOP_DUP=1): correctness
// first. The non-insertion phases (single-value edge rewrite + dead-store nop +
// reachability prune) only ever rewrite an existing goto to a target that the
// SAME validated BST resolver produced, so every edge they emit is correct by
// construction. The insertion phases add blocks and re-thread the fallthrough
// graph, a composition that must be validated on-device before it is trusted to
// never emit a wrong-but-verifiable edge; until then it stays behind the flag.
bool insertion_ops_enabled()
{
  qstring env;
  return qgetenv("UNSLOP_DUP", &env) && atoi(env.c_str()) != 0;
}

// Is `ins` a store of a CONSTANT into the emulated memory/stack state carrier?
// Register carriers are excluded on purpose: di.sel_state_reg aliases the BST
// selector register, which case blocks legitimately reuse, so nopping there
// would corrupt real computation (see unslop_types.h). Only constant stores to
// a dedicated memory/stack slot are provably dead once the tree is pruned.
bool is_emu_const_carrier_store(const DispatcherInfo &di, const minsn_t *ins)
{
  if ( ins == nullptr || di.sel_state_reg != mreg_t(-1) )
    return false;

  if ( !di.sel_state_addr.empty() )
  {
    // stx #imm, <sel>, <addr>
    return ins->opcode == m_stx
        && is_num(&ins->l)
        && mop_equal(&ins->r, &di.sel_state_sel)
        && mop_equal(&ins->d, &di.sel_state_addr);
  }
  if ( !di.sel_state_sel.empty() )
  {
    // mov #imm, %stackvar
    return ins->opcode == m_mov
        && is_num(&ins->l)
        && mop_equal(&ins->d, &di.sel_state_sel);
  }
  return false;
}

// Resolve the SINGLE raw state a father installs. Tries the exact per-block map
// from BST emulation first, then falls back to backward history emulation
// (history_tracker) so relative installs and single-value predecessor chains
// resolve too. Returns false for conditional / ambiguous / unknown fathers.
bool father_single_state(mba_t *mba, mblock_t *father, const DispatcherInfo &di,
                         uint64_t *out)
{
  std::map<int, uint64_t>::const_iterator it = di.block_state.find(father->serial);
  if ( it != di.block_state.end() )
  {
    *out = it->second;
    return true;
  }
  StateResolution r = resolve_father_state(mba, father, di);
  if ( r.resolved && !r.conditional && r.values.size() == 1 )
  {
    *out = r.values[0];
    return true;
  }
  return false;
}

// Map a raw state K to a real (non-dispatcher, in-range, non-self) target
// block serial via di.state_map. Returns -1 when unusable.
int target_for_state(mba_t *mba, const DispatcherInfo &di, uint64_t K,
                     int self_serial)
{
  std::map<uint64_t, int>::const_iterator sit = di.state_map.find(K);
  if ( sit == di.state_map.end() )
    return -1;
  int real = sit->second;
  if ( real < 0 || real >= mba->qty )
    return -1;
  if ( real == di.block_idx || real == self_serial )
    return -1;
  return real;
}

// True if the block ends in `goto <dispatcher block>`.
bool gotos_dispatcher(mba_t *mba, const DispatcherInfo &di, int serial)
{
  mblock_t *blk = mba->get_mblock(serial);
  minsn_t *tail = blk->tail;
  return tail != nullptr
      && tail->opcode == m_goto
      && tail->l.t == mop_b
      && di.dispatcher_blocks.count(tail->l.b) != 0;
}

// Every predecessor is itself a dispatcher-internal block => this is a
// dispatcher-internal trampoline carrying no real successor state; skip it.
bool all_preds_dispatcher(mba_t *mba, const DispatcherInfo &di, mblock_t *blk)
{
  int np = blk->npred();
  if ( np == 0 )
    return false;
  for ( int j = 0; j < np; ++j )
    if ( di.dispatcher_blocks.count(blk->pred(j)) == 0 )
      return false;
  return true;
}

// update_blk_successor (ref_d810_cfg_utils.py:204): retarget whichever edge of
// `blk` currently points at `old_succ` to `new_succ`. Fallthrough edges of a
// 2-way block cannot be retargeted in place and are left alone.
int update_blk_successor(mblock_t *blk, int old_succ, int new_succ)
{
  if ( blk->nsucc() == 1 )
    return change_1way_block_successor(blk, new_succ) ? 1 : 0;
  if ( blk->nsucc() == 2 )
  {
    if ( old_succ == blk->serial + 1 )
      return 0;                          // fallthrough: can't move in place
    return change_2way_block_conditional_successor(blk, new_succ) ? 1 : 0;
  }
  return 0;
}

// PRUNE + deep-clean (iterative). Collapses simple goto blocks into their
// fathers (mba_remove_simple_goto_blocks) and removes every block unreachable
// from entry (block 0). Removal renumbers serials, so we never consult `di`
// here; reachability is recomputed each round. Never removes block 0 or the
// exit sink. Returns the number of edges collapsed + blocks removed.
int prune_and_clean(mba_t *mba)
{
  int total = 0;
  int guard = 0;
  bool again = true;
  while ( again && guard++ < 128 )
  {
    again = false;

    // 1. Collapse simple 1-insn goto blocks by pulling their target up into
    //    every father. DISABLED: at GLBOPT this predecessor rewiring triggers
    //    Hex-Rays INTERR 51919. Hex-Rays does its own goto-collapse anyway; we
    //    only need reachability-based removal (step 2 below), which is safe.
    for ( int i = 0; false && i < mba->qty; ++i )
    {
      mblock_t *blk = mba->get_mblock(i);
      if ( blk == nullptr || !blk->is_simple_goto_block() )
        continue;
      if ( i == 0 || i == mba->qty - 1 )
        continue;
      int dst = blk->tail->l.b;
      if ( dst == i || dst < 0 || dst >= mba->qty )
        continue;

      std::vector<int> preds;
      for ( int j = 0; j < blk->npred(); ++j )
        preds.push_back(blk->pred(j));
      for ( int p : preds )
      {
        mblock_t *pf = mba->get_mblock(p);
        if ( pf == nullptr )
          continue;
        mblock_t *tb = mba->get_mblock(dst);
        if ( tb->predset.has(p) )         // would duplicate an edge
          continue;
        int n = update_blk_successor(pf, i, dst);
        if ( n > 0 )
        {
          total += n;
          again = true;
        }
      }
    }

    // 2. Reachability prune from block 0 over succset.
    int n = mba->qty;
    std::vector<char> reachable(n, 0);
    std::vector<int> stack;
    reachable[0] = 1;
    stack.push_back(0);
    while ( !stack.empty() )
    {
      int s = stack.back();
      stack.pop_back();
      mblock_t *blk = mba->get_mblock(s);
      if ( blk == nullptr )
        continue;
      for ( int j = 0; j < blk->nsucc(); ++j )
      {
        int su = blk->succ(j);
        if ( su >= 0 && su < n && !reachable[su] )
        {
          reachable[su] = 1;
          stack.push_back(su);
        }
      }
    }

    std::vector<int> dead;
    for ( int s = 1; s < n - 1; ++s )
      if ( !reachable[s] )
        dead.push_back(s);

    // Do NOT call mba->remove_block() here: at GLBOPT it throws INTERR 51919
    // on some shapes (verified on AppDome register-BST functions). Hex-Rays
    // removes unreachable blocks itself during its own optimization once our
    // rewrites make the dispatcher unreachable, so manual removal is both
    // unnecessary and unsafe. We only COUNT the dead blocks for reporting.
    if ( !dead.empty() )
      DLOG(L_TRACE, "%d unreachable blocks left for Hex-Rays DCE", int(dead.size()));
  }
  return total;
}

// Step-verify helper (UNSLOP_VERIFY_STEPS): verify after a risky phase so a
// corruption can be attributed to the exact step. Inert in normal mode.
void step_verify_emu(mba_t *mba, const char *step)
{
  if ( !verify_steps_enabled() )
    return;
  try
  {
    mba->verify(true);
    DLOG(L_TRACE, "verify OK after %s", step);
  }
  catch ( ... )
  {
    DLOG(L_ERROR, "verify FAILED after %s", step);
    dump_mba_to_file(mba, step);
  }
}

} // anonymous namespace

//-------------------------------------------------------------------------
// Emulated-BST multi-pass driver. Returns total changes (edges + splits + dups
// + pruned). Does NOT verify / mark_chains_dirty (plugin owns those).
int rewrite_cfg_emulated(mba_t *mba, DispatcherInfo *di)
{
  int total = 0;
  const int MAX_PASSES = 16;
  const int MAX_DUP_PASSES = 200;
  bool do_insertion = insertion_ops_enabled();

  // ── Resolution loop (single-value + conditional-split + duplication). No
  //    block REMOVAL happens here so serials only ever shift UP via inserts,
  //    which di_shift_up_from tracks; di.state_map / block_state stay valid. ──
  for ( int pass = 0; pass < MAX_PASSES; ++pass )
  {
    int changes = 0;
    std::vector<std::pair<int, minsn_t *>> erasures;   // (block serial, insn)

    // ---- PHASE A: single-value fathers (no insertion). ----
    for ( int i = 0; i < mba->qty; ++i )
    {
      if ( di->dispatcher_blocks.count(i) != 0 )
        continue;
      if ( !gotos_dispatcher(mba, *di, i) )
        continue;
      mblock_t *blk = mba->get_mblock(i);
      if ( all_preds_dispatcher(mba, *di, blk) )
        continue;

      uint64_t K = 0;
      if ( !father_single_state(mba, blk, *di, &K) )
      {
        if ( log_enabled(L_DEBUG) )
        {
          std::vector<uint64_t> cand = possible_state_values(mba, blk, *di);
          DLOG(L_DEBUG, "A-skip blk %d: not single-state (npred=%d candidates=%d)",
               i, blk->npred(), int(cand.size()));
        }
        continue;                        // deferred to PHASE B / C
      }
      int real = target_for_state(mba, *di, K, i);
      if ( real < 0 )
      {
        DLOG(L_DEBUG, "A-skip blk %d: state 0x%llx has no target", i, (unsigned long long)K);
        continue;
      }
      mblock_t *tb = mba->get_mblock(real);
      if ( tb->predset.has(i) )
      {
        DLOG(L_DEBUG, "A-skip blk %d: target %d already pred (dup edge)", i, real);
        continue;                        // duplicate edge -> skip
      }

      int old_target = blk->tail->l.b;
      if ( change_goto_target(blk, old_target, real) )
      {
        ++changes;
        DLOG(L_DEBUG, "A: blk %d -> state 0x%llx -> target %d",
             i, (unsigned long long)K, real);
        if ( verify_steps_enabled() )
        {
          try { mba->verify(true); }
          catch ( ... )
          {
            DLOG(L_ERROR, "A-edge blk %d -> target %d CORRUPTED mba", i, real);
          }
        }
        for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
          if ( is_emu_const_carrier_store(*di, ins) )
            erasures.emplace_back(i, ins);
      }
    }
    step_verify_emu(mba, "edges");

    // ---- PHASE B: conditional (jcnd) fathers whose two edges install two
    //      distinct states. Handles the in-block lowered-select case that
    //      PHASE A skips (father does not end in goto). Needs a fresh goto
    //      block for the fallthrough target => renumbers => di bookkeeping. ----
    if ( do_insertion )
    {
      for ( int i = 0; i < mba->qty; ++i )
      {
        if ( di->dispatcher_blocks.count(i) != 0 )
          continue;
        mblock_t *father = mba->get_mblock(i);
        minsn_t *tail = father->tail;
        if ( tail == nullptr || tail->opcode != m_jcnd || tail->d.t != mop_b )
          continue;
        if ( father->nsucc() != 2 )
          continue;

        // Both successors must lead into the dispatcher (directly or via a
        // simple goto), otherwise this is an ordinary conditional, not a
        // flattening select.
        int taken = tail->d.b;
        int fall  = father->serial + 1;
        bool taken_disp = di->dispatcher_blocks.count(taken) != 0
                       || gotos_dispatcher(mba, *di, taken);
        bool fall_disp  = di->dispatcher_blocks.count(fall) != 0
                       || gotos_dispatcher(mba, *di, fall);
        if ( !taken_disp || !fall_disp )
          continue;

        StateResolution r = resolve_father_state(mba, father, *di);
        if ( !r.resolved || !r.conditional )
          continue;
        int t_target = target_for_state(mba, *di, r.cond_true_val, i);
        int f_target = target_for_state(mba, *di, r.cond_false_val, i);
        if ( t_target < 0 || f_target < 0 || t_target == f_target )
          continue;

        // Retarget the taken edge directly to t_target (no insertion).
        mblock_t *tb = mba->get_mblock(t_target);
        if ( !tb->predset.has(i) )
        {
          if ( !change_2way_block_conditional_successor(father, t_target) )
            continue;
        }

        // The fallthrough must reach f_target. Insert a fresh 1-way goto block
        // right after the father; the fallthrough lands on it and it gotos
        // f_target. insert_nop_blk renumbers serials >= father->serial+1.
        int at = father->serial + 1;
        mblock_t *nf = insert_nop_blk(father);
        if ( nf == nullptr )
          continue;
        di_shift_up_from(di, at);
        if ( f_target >= at )
          ++f_target;                    // apply the same shift to our target
        change_1way_block_successor(nf, f_target);

        ++changes;
        DLOG(L_DEBUG, "B: split father %d -> taken %d / fall %d",
             i, t_target, f_target);
      }
      step_verify_emu(mba, "cond_split");
    }

    // ---- PHASE C: duplication for ambiguous fathers (>1 candidate state from
    //      distinct histories). Clone the father so each reaching history owns
    //      a private copy that resolves to one state next pass. Bounded. ----
    if ( do_insertion )
    {
      int dup_passes = 0;
      for ( int i = 0; i < mba->qty && dup_passes < MAX_DUP_PASSES; ++i )
      {
        if ( di->dispatcher_blocks.count(i) != 0 )
          continue;
        if ( !gotos_dispatcher(mba, *di, i) )
          continue;
        mblock_t *blk = mba->get_mblock(i);
        if ( all_preds_dispatcher(mba, *di, blk) )
          continue;

        // Ambiguous (known candidate set) OR a MERGE point (>=2 preds where
        // single-state resolution failed and the tracker cannot even enumerate
        // candidates, because two case-paths converge here before the goto).
        // Both are fixed by giving each incoming history a private copy so the
        // resolution point is pushed back toward the single-history case body
        // (D-810 ensure_child_has_an_unconditional_father). Bounded by the
        // outer pass count + MAX_DUP_PASSES so a truly unresolvable father just
        // stops duplicating and is left as residue.
        if ( blk->npred() < 2 )
          continue;                      // need >=2 preds to split histories
        std::vector<uint64_t> vals = possible_state_values(mba, blk, *di);
        if ( vals.size() >= 2 )
        {
          // Known ambiguous: only split when every candidate maps to a target,
          // otherwise duplication cannot finish and would only bloat the graph.
          bool all_mapped = true;
          for ( uint64_t v : vals )
            if ( target_for_state(mba, *di, v, i) < 0 )
            {
              all_mapped = false;
              break;
            }
          if ( !all_mapped )
            continue;
        }
        else if ( !vals.empty() )
        {
          // Exactly one candidate but single-state resolution failed: not a
          // clean merge; leave it rather than risk a wrong split.
          continue;
        }
        // else vals.empty() && npred>=2: a merge point -> duplicate to expose
        // the per-predecessor histories; each copy resolves in a later pass.

        // Give the father a private copy per predecessor beyond the first, so
        // each incoming history reaches its own single-state block. The clone
        // is appended at qty-1 and the trailing sink shifts up.
        std::vector<int> preds;
        for ( int j = 0; j < blk->npred(); ++j )
          preds.push_back(blk->pred(j));

        bool duplicated = false;
        for ( size_t pi = 1; pi < preds.size(); ++pi )
        {
          int at = mba->qty - 1;         // copy_block insertion serial
          mblock_t *dup = duplicate_block(blk);
          if ( dup == nullptr )
            break;
          di_shift_up_from(di, at);
          // Rewire predecessor `preds[pi]` from `blk` to the fresh copy.
          int p = preds[pi] >= at ? preds[pi] + 1 : preds[pi];
          int blk_serial = i >= at ? i + 1 : i;
          mblock_t *pf = mba->get_mblock(p);
          if ( pf != nullptr )
            update_blk_successor(pf, blk_serial, dup->serial);
          duplicated = true;
          ++dup_passes;
        }
        if ( duplicated )
        {
          ++changes;
          DLOG(L_DEBUG, "C: duplicated ambiguous father %d (%d candidates)",
               i, int(vals.size()));
        }
      }
      step_verify_emu(mba, "duplicate");
    }

    // ---- PHASE D: erase dead constant state stores in rewired fathers. ----
    for ( const std::pair<int, minsn_t *> &e : erasures )
    {
      mblock_t *blk = mba->get_mblock(e.first);
      if ( blk != nullptr )
      {
        blk->make_nop(e.second);
        DLOG(L_TRACE, "D: erased const state store in blk %d", e.first);
      }
    }

    total += changes;
    if ( changes == 0 )
      break;                             // fixed point reached
  }

  // DIAGNOSTIC: before pruning, report who still points at the dispatcher
  //    entry so a non-pruned dispatcher (pruned=0) can be explained.
  if ( log_enabled(L_DEBUG) && di->block_idx >= 0 && di->block_idx < mba->qty )
  {
    mblock_t *de = mba->get_mblock(di->block_idx);
    DLOG(L_DEBUG, "PRE-PRUNE: dispatcher entry blk %d has %d predecessors",
         di->block_idx, de->npred());
    for ( int j = 0; j < de->npred(); ++j )
    {
      int p = de->pred(j);
      mblock_t *pf = mba->get_mblock(p);
      const char *tk = "?";
      if ( pf != nullptr && pf->tail != nullptr )
      {
        int op = pf->tail->opcode;
        tk = (op == m_goto) ? "goto" : (op == m_jcnd) ? "jcnd"
           : (op == m_ijmp) ? "ijmp" : "other";
      }
      bool isdisp = di->dispatcher_blocks.count(p) != 0;
      DLOG(L_DEBUG, "  pred blk %d tail=%s disp_internal=%d gotos_disp=%d",
           p, tk, isdisp ? 1 : 0, gotos_dispatcher(mba, *di, p) ? 1 : 0);
    }
  }

  // ── PHASE E: prune the now-unreachable dispatcher + tree + dead trampolines
  //    and collapse simple gotos. Runs after resolution; needs no di. ──
  int before_prune = mba->qty;
  total += prune_and_clean(mba);
  DLOG(L_DEBUG, "PRUNE removed %d blocks (%d -> %d)",
       before_prune - mba->qty, before_prune, mba->qty);
  step_verify_emu(mba, "prune");

  return total;
}

//-------------------------------------------------------------------------
// Full structural unflatten driver for one mba_t. Returns the number of edges
// rewritten plus blocks removed. Does NOT call verify() or mark_chains_dirty()
// (run_pipeline in plugin.cpp owns exactly one of each).
int rewrite_cfg(mba_t *mba, DispatcherInfo *di, Profile *profile,
                const std::map<mreg_t, uint64_t> &regmap)
{
  // The emulated-BST resolver carries an exact per-block state map and a
  // memory/stack state carrier: hand it to the D-810-style multi-pass driver
  // so Hex-Rays restructures clean if/while at GLBOPT. The register path keeps
  // the original single-pass rewriter below.
  if ( di != nullptr && di->emulated )
    return rewrite_cfg_emulated(mba, di);

  if ( mba == nullptr || di == nullptr )
    return 0;
  if ( mba->qty < 6 )
    return 0;

  int disp = di->block_idx;
  if ( disp < 0 )
    return 0;

  // We need a usable state variable and at least two decoded state edges.
  mreg_t state_reg = di->state_reg;
  if ( di->state_map.size() < 2 )
    return 0;

  const std::set<int> &disp_blocks = di->dispatcher_blocks;

  // Register ids the resolver treats as "the state var" (state_reg +/- 1 for
  // ARM64 sub-register aliasing). Used only to recognise state-store movs.
  auto is_state_reg = [&](mreg_t r) -> bool
  {
    return r == state_reg
        || r == mreg_t(state_reg - 1)
        || r == mreg_t(state_reg + 1);
  };

  // Forward dataflow: precompute the installed state for every goto-to-dispatcher
  // block once, as a fallback for blocks where local resolution fails. The
  // emulated-BST path already carries an exact per-block state map (di->block_
  // state), so the register-based dataflow is skipped for it.
  std::map<int, uint64_t> fwd_map;
  if ( !di->emulated )
    forward_state_map(mba, state_reg, disp_blocks, regmap, &fwd_map);

  // ---------------------------------------------------------------------
  // PHASE 1: RESOLVE + COLLECT (no mutation yet).
  //
  // For every real block ending in `m_goto dispatcher`, resolve the state it
  // installs and look up its true target. Blocks that do not uniquely resolve
  // are SKIPPED (left intact) - never rewritten to a guessed target.
  //
  // PHASE 2 (conditional split) is folded into this same walk implicitly: the
  // OLLVM/CFF if-statement shape at MMAT_LOCOPT is a conditional block whose two
  // successors are *trampolines* (`mov #K, sv; goto disp`). Each trampoline is a
  // unique-resolving one-way goto handled here; once both are redirected to
  // their real targets the parent block naturally ends in a real jcc -> t /
  // fallthrough -> f, so Hex-Rays reconstructs the if without any instruction
  // surgery. See the DELIBERATE SKIP note below for the in-block CSEL case.
  // ---------------------------------------------------------------------
  std::vector<PlannedEdge> planned;
  int unresolved = 0;

  for ( int i = 0; i < mba->qty; ++i )
  {
    // Never touch the dispatcher's own blocks.
    if ( disp_blocks.find(i) != disp_blocks.end() )
      continue;

    mblock_t *blk = mba->get_mblock(i);
    minsn_t *tail = blk->tail;
    if ( tail == nullptr || tail->opcode != m_goto || tail->l.t != mop_b )
    {
      // DELIBERATE SKIP: a block ending in a conditional (m_jcnd / jcc) that
      // selects between two states *inside itself* (a lowered CSEL) cannot be
      // rewritten without synthesising a verifier-safe jcc from lowered
      // microcode; per the correctness-first rule we leave it intact rather
      // than emit a wrong target. The common if-shape is handled via its
      // trampolines above, so this only defers genuinely in-block selects.
      continue;
    }

    int goto_target = tail->l.b;
    // Only rewrite blocks that jump into the dispatcher.
    if ( disp_blocks.find(goto_target) == disp_blocks.end() )
      continue;

    // Skip dispatcher-internal trampolines: blocks whose every predecessor is
    // itself part of the dispatcher (they carry no real successor state).
    bool all_preds_disp = true;
    int npred = blk->npred();
    for ( int j = 0; j < npred; ++j )
    {
      if ( disp_blocks.find(blk->pred(j)) == disp_blocks.end() )
      {
        all_preds_disp = false;
        break;
      }
    }
    if ( all_preds_disp && npred > 0 )
      continue;

    // Resolve the raw state constant this block installs.
    uint64_t tv = 0;
    bool have_tv = false;
    if ( di->emulated )
    {
      // The emulated-BST path resolved every case block up front and keyed the
      // state map by the RAW K (the transform was applied inside the emulator),
      // so we look up block_state[i] directly and do NOT re-apply any transform.
      std::map<int, uint64_t>::const_iterator bit = di->block_state.find(i);
      if ( bit != di->block_state.end() )
      {
        tv = bit->second;
        have_tv = true;
      }
    }
    else
    {
      // Local propagation first, then the precomputed forward dataflow map.
      have_tv = resolve_state_in_block(mba, i, state_reg, regmap,
                                       disp_blocks, &tv);
      if ( !have_tv )
      {
        std::map<int, uint64_t>::const_iterator it = fwd_map.find(i);
        if ( it != fwd_map.end() )
        {
          tv = it->second;
          have_tv = true;
        }
      }
      // Let the profile map the raw encoded value to its canonical form
      // (identity for the generic case). Never applied on the emulated path.
      if ( have_tv && profile != nullptr )
        tv = profile->transform_state(tv);
    }

    if ( !have_tv )
    {
      ++unresolved;   // ambiguous / conditional -> leave intact (residue)
      DLOG(L_DEBUG, "blk %d unresolved (state resolution failed)", i);
      continue;
    }

    // Look up the real target block for this state.
    std::map<uint64_t, int>::const_iterator sit = di->state_map.find(tv);
    if ( sit == di->state_map.end() )
    {
      ++unresolved;
      DLOG(L_DEBUG, "blk %d unresolved (state=0x%llx not in state_map)",
           i, (unsigned long long)tv);
      continue;
    }

    int real = sit->second;
    if ( real < 0 || real >= mba->qty )
    {
      DLOG(L_DEBUG, "blk %d skipped (target %d out of range)", i, real);
      continue;
    }
    // Never redirect back into the dispatcher entry itself.
    if ( real == disp )
    {
      DLOG(L_DEBUG, "blk %d skipped (target is dispatcher entry)", i);
      continue;
    }
    // Do not create a self-edge.
    if ( real == i )
    {
      DLOG(L_DEBUG, "blk %d skipped (self-edge)", i);
      continue;
    }

    // Safety: skip if the target already lists us as a predecessor, which would
    // create a duplicate edge and make the verifier reject the microcode.
    mblock_t *target_blk = mba->get_mblock(real);
    if ( target_blk->predset.has(i) )
    {
      DLOG(L_DEBUG, "blk %d skipped (duplicate edge to %d)", i, real);
      continue;
    }

    // Collect the block-local state-store machinery to erase after the edge is
    // applied. We only erase `mov #imm, state_reg` (the state constant install):
    // a numeric-source mov into the state register is unambiguously dispatcher
    // machinery, whereas a register-source mov could be real computation, so we
    // leave those (they become dead once the dispatcher is pruned and Hex-Rays
    // DCE removes them). This keeps erasure correctness-safe.
    //
    // The emulated-BST path never erases here: its state carrier is a memory
    // slot or stack variable (not `state_reg`), and `state_reg` there aliases
    // the tree's SELECTOR register (e.g. x8), which case blocks legitimately
    // reuse for real computation - nopping a `mov #imm, x8` would corrupt them.
    // The state stores go dead once the tree is pruned, so DCE removes them.
    PlannedEdge pe;
    pe.from = i;
    pe.old_target = goto_target;
    pe.to = real;
    for ( minsn_t *ins = blk->head; !di->emulated && ins != nullptr; ins = ins->next )
    {
      if ( ins->opcode == m_mov
        && ins->d.t == mop_r
        && is_state_reg(ins->d.r)
        && is_num(&ins->l) )
      {
        pe.stores.push_back(ins);
      }
    }
    DLOG(L_DEBUG, "blk %d goto disp %d -> state=0x%llx target=%d (stores=%d)",
         i, goto_target, (unsigned long long)tv, real, int(pe.stores.size()));
    planned.push_back(pe);
  }

  // Step-verify diagnostic: when UNSLOP_VERIFY_STEPS is set, run the full
  // verifier after each mutation phase so a corruption can be attributed to the
  // exact step (edge apply / store erase / prune) that introduced it. On the
  // first failure we also dump the microcode. In normal mode this is inert (the
  // plugin still does its single final verify).
  bool dumped_once = false;
  auto step_verify = [&](const char *step_name)
  {
    if ( !verify_steps_enabled() )
      return;
    try
    {
      mba->verify(true);
      DLOG(L_TRACE, "verify OK after %s", step_name);
    }
    catch ( ... )
    {
      DLOG(L_ERROR, "verify FAILED after %s", step_name);
      if ( !dumped_once )
      {
        dumped_once = true;
        dump_mba_to_file(mba, step_name);
      }
    }
  };

  // ---------------------------------------------------------------------
  // PHASE 3: APPLY edges.
  // ---------------------------------------------------------------------
  int changes = 0;
  std::vector<std::pair<int, minsn_t *>> erasures; // (block serial, insn)

  for ( const PlannedEdge &pe : planned )
  {
    mblock_t *blk = mba->get_mblock(pe.from);
    if ( change_goto_target(blk, pe.old_target, pe.to) )
    {
      ++changes;
      // Only erase the state machinery for edges we actually rewrote; a block
      // whose edge still points at the dispatcher still needs its state store.
      for ( minsn_t *ins : pe.stores )
        erasures.emplace_back(pe.from, ins);
    }
  }
  step_verify("apply_edges");

  // ---------------------------------------------------------------------
  // PHASE 4: ERASE dead state machinery.
  //
  // Removing the `mov #K, state_reg` stores is what lets Hex-Rays stop emitting
  // the switch. make_nop() also marks the owning block's lists dirty. Serials
  // are still stable here (no block has been removed yet), so pe.from is valid.
  // ---------------------------------------------------------------------
  for ( const std::pair<int, minsn_t *> &e : erasures )
  {
    mblock_t *blk = mba->get_mblock(e.first);
    if ( blk != nullptr )
    {
      blk->make_nop(e.second);
      DLOG(L_TRACE, "erased state store in blk %d", e.first);
    }
  }
  step_verify("nop_stores");

  // ---------------------------------------------------------------------
  // PHASE 5: PRUNE unreachable blocks.
  //
  // With the dispatcher's incoming edges rewritten away, the dispatcher entry,
  // its comparison-chain blocks and now-dead trampolines are unreachable from
  // the entry (block 0). Compute reachability over succset from serial 0, then
  // remove the unreachable blocks. remove_block() renumbers serials of blocks
  // ABOVE the removed one, so we remove in DESCENDING serial order and re-fetch
  // by serial each time: serials below an already-removed block are unchanged,
  // keeping every pending serial valid. Reachability is computed once - removing
  // unreachable blocks can never change the reachable/unreachable status of any
  // remaining block. We never remove block 0 or the last block (the exit sink),
  // and re-check bounds after every removal.
  // ---------------------------------------------------------------------
  if ( changes > 0 && mba->qty > 1 )
  {
    int n = mba->qty;
    std::vector<char> reachable(n, 0);
    std::vector<int> stack;
    if ( n > 0 )
    {
      reachable[0] = 1;
      stack.push_back(0);
    }
    while ( !stack.empty() )
    {
      int s = stack.back();
      stack.pop_back();
      mblock_t *blk = mba->get_mblock(s);
      if ( blk == nullptr )
        continue;
      int ns = blk->nsucc();
      for ( int j = 0; j < ns; ++j )
      {
        int su = blk->succ(j);
        if ( su >= 0 && su < n && !reachable[su] )
        {
          reachable[su] = 1;
          stack.push_back(su);
        }
      }
    }

    // Collect unreachable serials, excluding entry (0) and exit (last block).
    std::vector<int> dead;
    for ( int s = 1; s < n - 1; ++s )
    {
      if ( !reachable[s] )
        dead.push_back(s);
    }

    // Remove highest serial first so lower serials stay valid across renumbers.
    for ( int k = int(dead.size()) - 1; k >= 0; --k )
    {
      int s = dead[k];
      if ( s <= 0 || s >= mba->qty )   // defensive after each renumber
        continue;
      if ( s == mba->qty - 1 )         // never remove the current last block
        continue;
      mblock_t *blk = mba->get_mblock(s);
      if ( blk == nullptr )
        continue;
      mba->remove_block(blk);
      ++changes;
      DLOG(L_TRACE, "pruned unreachable blk %d", s);
    }
    step_verify("prune");
  }

  // The caller (run_pipeline) performs a single mark_chains_dirty() and one
  // verify() after all passes have run, so this pass does neither.

  return changes;
}

} // namespace unslop
