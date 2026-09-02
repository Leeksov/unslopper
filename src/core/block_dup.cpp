// CFG-surgery primitives for the D-810-style unflattening driver.
// See block_dup.h for the design contract. Ported from D-810 cfg_utils.py.

#include "block_dup.h"
#include "unslop_log.h"

#include <map>
#include <set>
#include <vector>

namespace unslop {

//-------------------------------------------------------------------------
void insert_goto_instruction(mblock_t *blk, int target, bool nop_previous)
{
  if ( blk == nullptr )
    return;

  // Build the goto by cloning an existing insn (for a valid ea) or minting one.
  minsn_t *goto_ins = (blk->tail != nullptr) ? new minsn_t(*blk->tail)
                                             : new minsn_t(blk->start);

  if ( nop_previous && blk->tail != nullptr )
    blk->make_nop(blk->tail);

  // Insert after the current tail so the goto becomes the new tail.
  minsn_t *ins = blk->insert_into_block(goto_ins, blk->tail);

  // Nop the freshly inserted insn before repurposing it (avoids verifier 52123).
  blk->make_nop(ins);
  ins->opcode = m_goto;
  ins->l = mop_t();
  ins->l.make_blkref(target);
}

//-------------------------------------------------------------------------
bool change_1way_block_successor(mblock_t *blk, int new_succ)
{
  if ( blk == nullptr || blk->nsucc() != 1 )
    return false;

  mba_t *mba = blk->mba;
  int prev = blk->succset[0];
  if ( prev == new_succ )
    return false;                       // already there; nothing to do

  mblock_t *prev_succ = mba->get_mblock(prev);
  minsn_t *tail = blk->tail;

  if ( tail == nullptr )
  {
    insert_goto_instruction(blk, new_succ, false);
  }
  else if ( tail->opcode == m_goto )
  {
    tail->l.make_blkref(new_succ);
  }
  else if ( tail->opcode == m_ijmp )
  {
    insert_goto_instruction(blk, new_succ, true);
  }
  else if ( tail->opcode == m_call || tail->opcode == m_icall )
  {
    // A goto after a call is only legal once calls are materialised. The
    // driver runs at GLBOPT so this holds, but stay safe if it does not.
    if ( mba->maturity < MMAT_CALLS )
      return false;
    insert_goto_instruction(blk, new_succ, false);
  }
  else
  {
    insert_goto_instruction(blk, new_succ, false);
  }

  blk->type = BLT_1WAY;
  blk->flags |= MBL_GOTO;

  // Bookkeeping: swap our single successor, fix both predsets.
  blk->succset.del(prev);
  blk->succset.push_back(new_succ);
  blk->mark_lists_dirty();

  prev_succ->predset.del(blk->serial);
  if ( prev_succ->serial != mba->qty - 1 )
    prev_succ->mark_lists_dirty();

  mblock_t *nb = mba->get_mblock(new_succ);
  if ( !nb->predset.has(blk->serial) )
    nb->predset.push_back(blk->serial);
  if ( nb->serial != mba->qty - 1 )
    nb->mark_lists_dirty();

  return true;
}

//-------------------------------------------------------------------------
bool change_2way_block_conditional_successor(mblock_t *blk, int new_succ)
{
  if ( blk == nullptr || blk->nsucc() != 2 )
    return false;
  minsn_t *tail = blk->tail;
  if ( tail == nullptr || tail->d.t != mop_b )
    return false;

  mba_t *mba = blk->mba;
  int prev = tail->d.b;                 // current conditional (taken) target
  if ( prev == new_succ )
    return false;

  mblock_t *prev_succ = mba->get_mblock(prev);

  tail->d = mop_t();
  tail->d.make_blkref(new_succ);

  blk->succset.del(prev);
  blk->succset.push_back(new_succ);
  blk->mark_lists_dirty();

  prev_succ->predset.del(blk->serial);
  if ( prev_succ->serial != mba->qty - 1 )
    prev_succ->mark_lists_dirty();

  mblock_t *nb = mba->get_mblock(new_succ);
  if ( !nb->predset.has(blk->serial) )
    nb->predset.push_back(blk->serial);
  if ( nb->serial != mba->qty - 1 )
    nb->mark_lists_dirty();

  return true;
}

//-------------------------------------------------------------------------
mblock_t *insert_nop_blk(mblock_t *blk)
{
  if ( blk == nullptr )
    return nullptr;
  mba_t *mba = blk->mba;

  // copy_block inserts at blk->serial + 1 and renumbers everything above it.
  mblock_t *nop = mba->copy_block(blk, blk->serial + 1);
  if ( nop == nullptr )
    return nullptr;

  for ( minsn_t *cur = nop->head; cur != nullptr; cur = cur->next )
    nop->make_nop(cur);

  nop->type = BLT_1WAY;

  // The clone inherited blk's successors; drop them all, then fall through to
  // the block now sitting immediately after us.
  std::vector<int> prev;
  for ( int i = 0; i < nop->nsucc(); ++i )
    prev.push_back(nop->succset[i]);
  for ( int s : prev )
  {
    nop->succset.del(s);
    mblock_t *ps = mba->get_mblock(s);
    ps->predset.del(nop->serial);
    if ( ps->serial != mba->qty - 1 )
      ps->mark_lists_dirty();
  }

  int fall = nop->serial + 1;
  nop->succset.push_back(fall);
  nop->mark_lists_dirty();

  mblock_t *ns = mba->get_mblock(fall);
  if ( !ns->predset.has(nop->serial) )
    ns->predset.push_back(nop->serial);
  if ( ns->serial != mba->qty - 1 )
    ns->mark_lists_dirty();

  return nop;
}

//-------------------------------------------------------------------------
int ensure_child_has_an_unconditional_father(mblock_t *father, mblock_t *child,
                                             int *inserted_at)
{
  if ( father == nullptr || child == nullptr )
    return 0;
  mba_t *mba = father->mba;
  if ( father->nsucc() == 1 )
    return 0;                            // already unconditional -> nothing to do
  if ( father->tail == nullptr || father->tail->d.t != mop_b )
    return 0;

  int child_serial = child->serial;

  if ( father->tail->d.b == child_serial )
  {
    // `child` is the conditional (taken) target: interpose a new 1-way father
    // appended near the end of the array (does not disturb father's serial).
    mblock_t *last = mba->get_mblock(mba->qty - 2);
    int at = last->serial + 1;
    mblock_t *nf = insert_nop_blk(last);
    if ( nf == nullptr )
      return 0;
    if ( inserted_at != nullptr )
      *inserted_at = at;
    change_1way_block_successor(nf, child_serial >= at ? child_serial + 1
                                                       : child_serial);
    change_2way_block_conditional_successor(father, nf->serial);
  }
  else
  {
    // `child` is the fallthrough (default) target: interpose a new 1-way father
    // right after `father` so the fallthrough lands on it, and it gotos child.
    int at = father->serial + 1;
    mblock_t *nf = insert_nop_blk(father);
    if ( nf == nullptr )
      return 0;
    if ( inserted_at != nullptr )
      *inserted_at = at;
    change_1way_block_successor(nf, child_serial >= at ? child_serial + 1
                                                       : child_serial);
  }
  return 1;
}

//-------------------------------------------------------------------------
mblock_t *duplicate_block(mblock_t *block_to_duplicate)
{
  if ( block_to_duplicate == nullptr )
    return nullptr;
  mba_t *mba = block_to_duplicate->mba;

  // Append the clone as the new last real block (serial mba->qty - 1, before
  // the exit sink). copy_block renumbers the trailing sink up by one.
  mblock_t *dup = mba->copy_block(block_to_duplicate, mba->qty - 1);
  if ( dup == nullptr )
    return nullptr;

  minsn_t *tail = block_to_duplicate->tail;
  if ( tail != nullptr && is_mcode_jcond(tail->opcode) )
  {
    // Conditional clone keeps its taken edge; give it a private fallthrough
    // that gotos the original's fallthrough successor.
    mblock_t *dflt = insert_nop_blk(dup);
    if ( dflt != nullptr )
      change_1way_block_successor(dflt, block_to_duplicate->serial + 1);
  }
  else if ( dup->nsucc() == 1 )
  {
    change_1way_block_successor(dup, block_to_duplicate->succset[0]);
  }
  return dup;
}

//-------------------------------------------------------------------------
void di_shift_up_from(DispatcherInfo *di, int at)
{
  if ( di == nullptr )
    return;

  if ( di->block_idx >= at )
    di->block_idx += 1;

  std::set<int> nb;
  for ( int s : di->dispatcher_blocks )
    nb.insert(s >= at ? s + 1 : s);
  di->dispatcher_blocks.swap(nb);

  for ( auto &kv : di->state_map )
  {
    if ( kv.second >= at )
      kv.second += 1;
  }

  std::map<int, uint64_t> nbs;
  for ( const auto &kv : di->block_state )
    nbs[kv.first >= at ? kv.first + 1 : kv.first] = kv.second;
  di->block_state.swap(nbs);
}

} // namespace unslop
