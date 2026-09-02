// DexProtector profile for the Unslopper deflattener.
//
// DexProtector (ios_runtime.framework) flattens control flow with a dispatcher
// whose distinguishing feature is a state transform applied *before* the
// comparison chain:
//
//     LDR  Wd, [SP, #state_offset]     ; load state
//     EOR  Wd, Wd, Wkey                ; state ^ XOR_KEY
//     ADD  Wd, Wd, Wadd                ; + ADD_KEY   (optional)
//     CMP  Wd, #const1                 ; binary-search dispatch tree
//     B.EQ block_1
//     ...
//
// At the microcode level this surfaces as an m_xor of the state operand against
// a constant key, optionally followed by an m_add of another constant, and then
// a conditional-jump comparison chain (m_jz / m_jnz / ...). The XOR/ADD keys may
// be immediates or may live in registers preloaded in the prologue; in the
// latter case we resolve them through the whole-array register-const map.
//
// Ported from dexprotector-research/tools/unflatten.py
// (CFFAnalyzer.detect_cff / resolve_successor) and unflatten2.py
// (analyze_cff / resolve_state):
//     dispatch_value = ((state ^ xor_key) + add_key) & 0xFFFFFFFF

#include "profile.h"
#include "microcode_utils.h"
#include "dispatcher.h"
#include "unslop_log.h"

#include <map>

namespace unslop {

namespace {

// Resolve a mop to a constant value: either a direct immediate, or a register
// whose constant value is known from the prologue register map.
bool resolve_const(const mop_t *m,
                   const std::map<mreg_t, uint64_t> &regmap,
                   uint64_t *out)
{
  if ( is_num(m) )
  {
    *out = num_val(m);
    return true;
  }
  if ( is_reg(m) )
  {
    std::map<mreg_t, uint64_t>::const_iterator it = regmap.find(m->r);
    if ( it != regmap.end() )
    {
      *out = it->second;
      return true;
    }
  }
  return false;
}

// Given the two source operands of an m_xor, decide which one is the constant
// key (the other being the running state value). Prefer a resolvable operand;
// r is checked first since DexProtector emits `EOR Wd, Wstate, Wkey`.
bool xor_key_operand(const minsn_t *ins,
                     const std::map<mreg_t, uint64_t> &regmap,
                     uint64_t *out)
{
  if ( resolve_const(&ins->r, regmap, out) )
    return true;
  if ( resolve_const(&ins->l, regmap, out) )
    return true;
  return false;
}

} // namespace

class DexProtectorProfile : public Profile
{
public:
  const char *name() const override { return "dexprotector"; }

  ProfileKind kind() const override { return ProfileKind::DEXPROTECTOR; }

  bool detect(mba_t *mba, const std::map<mreg_t, uint64_t> &regmap) override
  {
    return find_keys(mba, regmap);
  }

  bool configure(mba_t *mba, DispatcherInfo *di,
                 const std::map<mreg_t, uint64_t> &regmap) override
  {
    qnotused(di);
    // Record xor_key / add_key into members; usable only if a key was found.
    return find_keys(mba, regmap);
  }

  // (raw ^ xor_key) + add_key, masked to 32 bits, matching resolve_state().
  uint64_t transform_state(uint64_t raw) override
  {
    return ((raw ^ xor_key_) + add_key_) & 0xFFFFFFFFull;
  }

  int post_process(mba_t *mba, int changes) override
  {
    qnotused(mba);
    qnotused(changes);
    return 0;
  }

private:
  // Scan the whole microcode array for the DexProtector dispatcher signature:
  // an m_xor of the state operand against a constant key, optionally followed by
  // an m_add of another constant, and then a conditional comparison chain in the
  // same block. Records the recovered keys in xor_key_ / add_key_.
  bool find_keys(mba_t *mba, const std::map<mreg_t, uint64_t> &regmap)
  {
    found_ = false;
    xor_key_ = 0;
    add_key_ = 0;
    if ( mba == nullptr )
      return false;

    // A genuine DexProtector CFF dispatcher transforms a state value into a
    // selector that is compared against a LARGE set of distinct constants
    // (dozens) converging on one fan-out block. A lone `x ^ const` feeding a
    // handful of compares is an ordinary source switch / parser branch, not a
    // flattened region. Fingerprint the whole array ONCE so the per-xor gate
    // below can require a real multi-constant state dispatcher.
    static const size_t kMinDispatcherConsts = 12;   // above the semantic-switch
                                                     // ceiling (max 10 observed)
    StateFingerprint fp;
    bool have_fp = state_dispatcher_fingerprint(mba, regmap, &fp);

    for ( int bi = 0; bi < mba->qty; ++bi )
    {
      mblock_t *blk = mba->get_mblock(bi);
      if ( blk == nullptr )
        continue;

      for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
      {
        if ( ins->opcode != m_xor )
          continue;

        uint64_t key = 0;
        if ( !xor_key_operand(ins, regmap, &key) )
          continue;

        // Walk forward in this block: capture an optional constant m_add, and
        // require the transform to feed a conditional comparison chain.
        uint64_t add = 0;
        bool have_add = false;
        bool have_compare = false;
        for ( minsn_t *nx = ins->next; nx != nullptr; nx = nx->next )
        {
          if ( !have_add && nx->opcode == m_add )
          {
            uint64_t av = 0;
            if ( resolve_const(&nx->r, regmap, &av)
              || resolve_const(&nx->l, regmap, &av) )
            {
              add = av;
              have_add = true;
              continue;
            }
          }
          if ( is_cond_jump(nx->opcode) )
          {
            have_compare = true;
            break;
          }
        }

        if ( !have_compare )
          continue;

        // ── Dispatcher gate: reject a stray hash/checksum/cleanup xor that is
        //    not actually the flattening selector. ──
        // 1. The xor result must land in a register (the selector), and that
        //    register must be the one the dispatcher tree compares (allowing
        //    ARM64 sub-register aliasing).
        if ( ins->d.t != mop_r )
          continue;
        if ( !have_fp )
          continue;
        mreg_t d = ins->d.r;
        if ( d != fp.sel_reg
          && d != mreg_t(fp.sel_reg - 1)
          && d != mreg_t(fp.sel_reg + 1) )
          continue;
        // 2. Require a real multi-constant state dispatcher, not a lone
        //    xor + branch (source switches top out at ~10 distinct consts).
        if ( fp.distinct < kMinDispatcherConsts )
          continue;
        // 3. Reject a convergence sink (cleanup/return join, destructor
        //    epilogue) masquerading as the dispatcher head.
        if ( is_convergence_sink(mba, fp.converge_blk, fp.sel_reg, regmap) )
          continue;

        DLOG(L_INFO,
             "dexprotector dispatcher: sel_reg=%d distinct=%d converge_blk=%d",
             int(fp.sel_reg), int(fp.distinct), fp.converge_blk);
        xor_key_ = key & 0xFFFFFFFFull;
        add_key_ = add & 0xFFFFFFFFull;
        found_ = true;
        return true;
      }
    }
    return false;
  }

  uint64_t xor_key_ = 0;
  uint64_t add_key_ = 0;
  bool found_ = false;
};

Profile *make_dexprotector()
{
  return new DexProtectorProfile();
}

} // namespace unslop
