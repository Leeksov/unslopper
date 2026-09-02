// MVG profile for the Unslopper deflattener.
//
// MVG's "strong_cff" control-flow flattening (as reversed in
// mvg-research/mvg_full_microcode_unflattener.py) is a manifest-driven,
// jump-table dispatcher over an ARM64 Mach-O. The dispatcher tail is an
// m_jtbl whose selector is an *identity*-transformed 32-bit (w) register
// loaded from a stack slot: the case value read from the switch table is
// the canonical state directly (selector_transform.kind == "identity" in
// every audited manifest), so there is no state re-encoding to undo.
//
// The full Python tool is manifest- and SHA-gated (6399 lines of immutable
// constant-cell / provenance machinery). We keep only the essentials here:
//
//   detect()        SHA-256 gate on the audited input, OR the structural
//                   strong_cff shape (jtbl selector loaded from a stack slot
//                   through identity-preserving ops).
//   configure()     recover the jump table: fill di->state_map from the
//                   m_jtbl mcases (case value -> target block). Prefers the
//                   generic Strategy-2 recovery, then fills directly from the
//                   mcases so the map is always exact.
//   transform_state identity (per the manifest selector_transform).
//   post_process()  run simplify_mba_block over every block to clean up the
//                   index arithmetic the table lowering leaves behind.

#include "profile.h"
#include "microcode_utils.h"
#include "dispatcher.h"
#include "mba_simplify.h"

#include <nalt.hpp>

#include <cstdint>
#include <cstring>
#include <string>

namespace unslop {

// SHA-256 of the single audited MVG input this profile was reversed against.
static const char *EXPECTED_SHA256 =
    "4ac5c23838e4c87bc33f72f92f3456787f14aa1c3668bd56d021d85051fe7705";

// Read the input file's SHA-256 and format it as a lowercase hex string.
// Returns false if IDA has no recorded hash.
static bool input_sha256_hex(std::string *out)
{
  uchar hash[32];
  if ( !retrieve_input_file_sha256(hash) )
    return false;

  static const char *digits = "0123456789abcdef";
  out->clear();
  out->reserve(64);
  for ( int i = 0; i < 32; ++i )
  {
    out->push_back(digits[(hash[i] >> 4) & 0xF]);
    out->push_back(digits[hash[i] & 0xF]);
  }
  return true;
}

// Follow single-source identity-preserving subinstructions (mov/low/xdu/xds)
// down to their leaf operand. These are the transforms MVG places between the
// stack slot and the jump-table selector, and they do not alter the value's
// canonical identity.
static const mop_t *strip_identity(const mop_t *m)
{
  int guard = 0;
  while ( m != nullptr
       && m->t == mop_d
       && m->d != nullptr
       && guard++ < 8 )
  {
    mcode_t op = m->d->opcode;
    if ( op == m_mov || op == m_low || op == m_xdu || op == m_xds )
      m = &m->d->l;
    else
      break;
  }
  return m;
}

// True if register `reg` is (transitively, through identity ops) defined
// inside `blk` before instruction `before` by a load from a stack slot.
static bool reg_from_stack(
        mblock_t *blk,
        const minsn_t *before,
        mreg_t reg,
        int depth)
{
  if ( blk == nullptr || depth > 6 )
    return false;

  // Locate the last definition of `reg` prior to `before` in this block.
  const minsn_t *def = nullptr;
  for ( const minsn_t *ins = blk->head;
        ins != nullptr && ins != before;
        ins = ins->next )
  {
    if ( ins->d.t == mop_r && ins->d.r == reg )
      def = ins;
  }
  if ( def == nullptr )
    return false;

  // A memory load (m_ldx {l=sel, r=off}) is how a stack slot reaches a
  // register on ARM64 once Hex-Rays has not folded it into an mop_S.
  if ( def->opcode == m_ldx )
    return true;

  if ( def->opcode == m_mov
    || def->opcode == m_low
    || def->opcode == m_xdu
    || def->opcode == m_xds )
  {
    const mop_t *src = strip_identity(&def->l);
    if ( src == nullptr )
      return false;
    if ( src->t == mop_S )                  // direct stack variable
      return true;
    if ( src->t == mop_r )                  // chase one more link
      return reg_from_stack(blk, def, src->r, depth + 1);
  }
  return false;
}

// If `blk`'s tail is an m_jtbl whose selector is an identity-transformed
// value ultimately loaded from a stack slot, return that tail; else nullptr.
static minsn_t *jtbl_stack_selector_tail(mblock_t *blk)
{
  if ( blk == nullptr )
    return nullptr;
  minsn_t *tail = blk->tail;
  if ( tail == nullptr || tail->opcode != m_jtbl )
    return nullptr;

  const mop_t *sel = strip_identity(&tail->l);
  if ( sel == nullptr )
    return nullptr;

  // Selector read straight off the stack.
  if ( sel->t == mop_S )
    return tail;

  // Selector held in a (w-)register that was loaded from the stack.
  if ( sel->t == mop_r && reg_from_stack(blk, tail, sel->r, 0) )
    return tail;

  return nullptr;
}

// Populate di->state_map / state_consts directly from an m_jtbl's mcases:
// each case value is the canonical state (identity selector), each target is
// the block it dispatches to. Returns the number of edges recorded.
static int fill_state_map_from_jtbl(const minsn_t *jtbl, DispatcherInfo *di)
{
  if ( jtbl == nullptr || jtbl->r.t != mop_c || jtbl->r.c == nullptr )
    return 0;

  const mcases_t *cs = jtbl->r.c;
  int added = 0;
  size_t n = cs->size();
  for ( size_t i = 0; i < n; ++i )
  {
    int tgt = cs->targets[i];
    const svalvec_t &vals = cs->values[i];
    for ( size_t j = 0; j < vals.size(); ++j )
    {
      uint64_t state = uint64_t(vals[j]) & 0xFFFFFFFFull;
      di->state_map[state] = tgt;
      di->state_consts.insert(state);
      ++added;
    }
  }
  return added;
}

class MvgProfile : public Profile
{
public:
  const char *name() const override { return "mvg"; }
  ProfileKind kind() const override { return ProfileKind::MVG; }

  bool detect(mba_t *mba, const std::map<mreg_t, uint64_t> &regmap) override
  {
    qnotused(regmap);
    if ( mba == nullptr )
      return false;

    // 1. SHA-256 gate on the audited input file.
    std::string sha;
    if ( input_sha256_hex(&sha) && sha == EXPECTED_SHA256 )
      return true;

    // 2. Structural fallback: an MVG strong_cff jump-table dispatcher whose
    //    selector is an identity-transformed register/value loaded from a
    //    stack slot.
    for ( int i = 0; i < mba->qty; ++i )
    {
      if ( jtbl_stack_selector_tail(mba->get_mblock(i)) != nullptr )
        return true;
    }
    return false;
  }

  // Recover the dispatcher's jump table into di->state_map. We first let the
  // generic detector run (its Strategy 2 targets exactly this m_jtbl shape),
  // then fill the map directly from the mcases so it is always exact and
  // complete regardless of which generic strategy fired.
  bool configure(mba_t *mba, DispatcherInfo *di,
                 const std::map<mreg_t, uint64_t> &regmap) override
  {
    if ( mba == nullptr || di == nullptr )
      return false;

    // Generic recovery (max-preds -> jump-table -> state-var heuristic).
    detect_dispatcher(mba, di, regmap);

    // Locate the strong_cff jtbl dispatcher and fill the state map exactly.
    for ( int i = 0; i < mba->qty; ++i )
    {
      mblock_t *blk = mba->get_mblock(i);
      minsn_t *tail = jtbl_stack_selector_tail(blk);
      if ( tail == nullptr )
        continue;

      di->block_idx = blk->serial;
      di->detection_strategy = 2;          // jump-table
      di->dispatcher_blocks.insert(blk->serial);

      // Record the selector operand / register.
      const mop_t *sel = strip_identity(&tail->l);
      if ( sel != nullptr )
      {
        di->state_var = *sel;
        di->state_reg = (sel->t == mop_r) ? sel->r : mreg_t(-1);
      }

      fill_state_map_from_jtbl(tail, di);
      break;
    }

    di->valid = !di->state_map.empty();
    return di->valid;
  }

  // MVG's selector transform is identity in every audited manifest: the case
  // value pulled from the table is the canonical state.
  uint64_t transform_state(uint64_t raw) override { return raw; }

  // Clean up the index arithmetic the table lowering leaves behind by running
  // the MBA simplifier over every block. Returns the extra change count.
  int post_process(mba_t *mba, int changes) override
  {
    qnotused(changes);
    if ( mba == nullptr )
      return 0;

    int n = 0;
    for ( int i = 0; i < mba->qty; ++i )
      n += simplify_mba_block(mba->get_mblock(i));
    return n;
  }
};

Profile *make_mvg()
{
  return new MvgProfile();
}

} // namespace unslop
