// Backward history emulator for the Unslopper deflattener. See history_tracker.h.
//
// Strategy (per resolve_father_state):
//   1. Conditional-install probe: if `father` ends in a jcnd whose two
//      successors each forward a single, DIFFERENT constant state to the
//      dispatcher, report a two-way select (conditional=true).
//   2. Otherwise resolve the carrier value flowing out of `father` via
//      resolve_carrier_out: emulate the block straight-line; if the carrier is
//      installed absolutely, done; else fetch the incoming carrier value from
//      the predecessor chain (single-pred followed directly, multi-pred unioned)
//      and re-emulate so relative updates (state ^= K, state += 1, ...) fold.
//
// All arithmetic is constant folding over a small optional-valued environment.
// Anything not understood collapses to "unknown", which propagates to
// resolved=false — never to a wrong value.

#include "history_tracker.h"
#include "microcode_utils.h"
#include "unslop_log.h"

#include <algorithm>
#include <optional>
#include <set>

namespace unslop {
namespace {

// State constants are 32-bit raw K (matching dispatcher.cpp block_installed_state).
constexpr uint64_t STATE_MASK = 0xFFFFFFFFull;

// Bounds guarding the recursion / fan-out (correctness-first: stop early).
constexpr int MAX_PRED_FANOUT = 8;
constexpr int MAX_VISIT_VALUES = 16;

bool mops_eq(const mop_t *a, const mop_t *b)
{
  return a != nullptr && b != nullptr && a->equal_mops(*b, EQ_IGNSIZE);
}

// ── carrier identity ────────────────────────────────────────────────────────

// Is `ins` a store INTO the state carrier described by di? If so, *val_mop
// points at the stored value operand.
bool is_carrier_store(const DispatcherInfo &di, const minsn_t *ins,
                      const mop_t **val_mop)
{
  if ( ins == nullptr )
    return false;

  if ( di.sel_state_reg != mreg_t(-1) )
  {
    // Register carrier: mov <val>, state_reg (accept +/-1 sub-reg neighbours).
    if ( ins->opcode == m_mov && ins->d.t == mop_r )
    {
      mreg_t r = ins->d.r;
      if ( r == di.sel_state_reg
        || r == mreg_t(di.sel_state_reg - 1)
        || r == mreg_t(di.sel_state_reg + 1) )
      {
        *val_mop = &ins->l;
        return true;
      }
    }
    return false;
  }

  if ( !di.sel_state_addr.empty() )
  {
    // ldx/stx memory carrier: stx <val>, <sel>, <addr>.
    if ( ins->opcode == m_stx
      && mops_eq(&ins->r, &di.sel_state_sel)
      && mops_eq(&ins->d, &di.sel_state_addr) )
    {
      *val_mop = &ins->l;
      return true;
    }
    return false;
  }

  if ( !di.sel_state_sel.empty() )
  {
    // Stack-variable carrier: mov <val>, %stackvar (d is the mop_S itself).
    if ( ins->opcode == m_mov && mops_eq(&ins->d, &di.sel_state_sel) )
    {
      *val_mop = &ins->l;
      return true;
    }
    return false;
  }

  return false;
}

// Is `ins` a load FROM the state carrier into a register? If so *dst_reg is set.
bool is_carrier_load(const DispatcherInfo &di, const minsn_t *ins, mreg_t *dst_reg)
{
  if ( ins == nullptr || ins->d.t != mop_r )
    return false;

  if ( !di.sel_state_addr.empty() )
  {
    // ldx <sel>, <addr>, dst
    if ( ins->opcode == m_ldx
      && mops_eq(&ins->l, &di.sel_state_sel)
      && mops_eq(&ins->r, &di.sel_state_addr) )
    {
      *dst_reg = ins->d.r;
      return true;
    }
    return false;
  }

  if ( di.sel_state_reg == mreg_t(-1) && !di.sel_state_sel.empty() )
  {
    // mov %stackvar, dst
    if ( ins->opcode == m_mov && mops_eq(&ins->l, &di.sel_state_sel) )
    {
      *dst_reg = ins->d.r;
      return true;
    }
  }
  return false;
}

// ── constant-folding environment ─────────────────────────────────────────────

struct Env
{
  std::map<mreg_t, uint64_t> regs;      // known register values
  bool     carrier_mem_known = false;   // for memory/stack carriers
  uint64_t carrier_mem_val   = 0;
};

std::optional<uint64_t> eval_mop(const DispatcherInfo &di, const Env &env,
                                 const mop_t *m, int depth);

std::optional<uint64_t> eval_insn(const DispatcherInfo &di, const Env &env,
                                  const minsn_t *ins, int depth)
{
  if ( ins == nullptr || depth <= 0 )
    return std::nullopt;

  switch ( ins->opcode )
  {
    // Pass-through / width changes: value flows unchanged for our purposes.
    case m_mov:
    case m_low:
    case m_xdu:
    case m_xds:
    case m_f2f:
      return eval_mop(di, env, &ins->l, depth - 1);

    case m_neg:
    {
      auto v = eval_mop(di, env, &ins->l, depth - 1);
      if ( v ) return uint64_t(0) - *v;
      return std::nullopt;
    }
    case m_bnot:
    {
      auto v = eval_mop(di, env, &ins->l, depth - 1);
      if ( v ) return ~*v;
      return std::nullopt;
    }
    case m_lnot:
    {
      auto v = eval_mop(di, env, &ins->l, depth - 1);
      if ( v ) return uint64_t(*v == 0 ? 1 : 0);
      return std::nullopt;
    }

    // Binary constant folding.
    case m_add: case m_sub: case m_mul:
    case m_or:  case m_and: case m_xor:
    case m_shl: case m_shr: case m_sar:
    {
      auto l = eval_mop(di, env, &ins->l, depth - 1);
      auto r = eval_mop(di, env, &ins->r, depth - 1);
      if ( !l || !r )
        return std::nullopt;
      uint64_t a = *l, b = *r;
      switch ( ins->opcode )
      {
        case m_add: return a + b;
        case m_sub: return a - b;
        case m_mul: return a * b;
        case m_or:  return a | b;
        case m_and: return a & b;
        case m_xor: return a ^ b;
        case m_shl: return a << (b & 63);
        case m_shr: return a >> (b & 63);
        case m_sar: return uint64_t(s32(a) >> (b & 31)); // 32-bit arithmetic
        default:    return std::nullopt;
      }
    }

    default:
      return std::nullopt;
  }
}

std::optional<uint64_t> eval_mop(const DispatcherInfo &di, const Env &env,
                                 const mop_t *m, int depth)
{
  if ( m == nullptr || depth <= 0 )
    return std::nullopt;

  switch ( m->t )
  {
    case mop_n:
      return num_val(m);

    case mop_r:
    {
      auto it = env.regs.find(m->r);
      if ( it != env.regs.end() )
        return it->second;
      return std::nullopt;
    }

    case mop_d:
      return eval_insn(di, env, m->d, depth);

    case mop_S:
      // A stack-slot read resolves only if it is the (stack) carrier itself.
      if ( di.sel_state_reg == mreg_t(-1)
        && !di.sel_state_sel.empty()
        && mops_eq(m, &di.sel_state_sel)
        && env.carrier_mem_known )
      {
        return env.carrier_mem_val;
      }
      return std::nullopt;

    default:
      return std::nullopt;
  }
}

// Store `v` (masked) into the carrier slot of `env`.
void set_carrier(const DispatcherInfo &di, Env &env, uint64_t v)
{
  v &= STATE_MASK;
  if ( di.sel_state_reg != mreg_t(-1) )
    env.regs[di.sel_state_reg] = v;
  else
  {
    env.carrier_mem_known = true;
    env.carrier_mem_val = v;
  }
}

// Read the carrier's current value from `env`, if known.
std::optional<uint64_t> read_carrier(const DispatcherInfo &di, const Env &env)
{
  if ( di.sel_state_reg != mreg_t(-1) )
  {
    const mreg_t cands[3] = {
      di.sel_state_reg,
      mreg_t(di.sel_state_reg - 1),
      mreg_t(di.sel_state_reg + 1),
    };
    for ( mreg_t r : cands )
    {
      auto it = env.regs.find(r);
      if ( it != env.regs.end() )
        return it->second & STATE_MASK;
    }
    return std::nullopt;
  }
  if ( env.carrier_mem_known )
    return env.carrier_mem_val & STATE_MASK;
  return std::nullopt;
}

// Emulate one block's straight-line body (excluding its terminating jump/goto)
// over `env`, folding constants. Register defs with an unknown RHS clear that
// register so a stale value is never reused.
void emulate_block_body(const DispatcherInfo &di, mblock_t *blk, Env &env)
{
  for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    // Store into the carrier (register mov, stx, or stack mov).
    const mop_t *valmop = nullptr;
    if ( is_carrier_store(di, ins, &valmop) )
    {
      auto v = eval_mop(di, env, valmop, 32);
      if ( v )
        set_carrier(di, env, *v);
      else if ( di.sel_state_reg == mreg_t(-1) )
        env.carrier_mem_known = false;    // memory carrier now unknown
      else
        env.regs.erase(di.sel_state_reg); // register carrier now unknown
      continue;
    }

    // Load from the carrier into a register.
    mreg_t ldreg = mreg_t(-1);
    if ( is_carrier_load(di, ins, &ldreg) )
    {
      if ( di.sel_state_reg == mreg_t(-1) && env.carrier_mem_known )
        env.regs[ldreg] = env.carrier_mem_val;
      else
        env.regs.erase(ldreg);
      continue;
    }

    // A call may clobber registers; drop reg knowledge conservatively but keep
    // any memory-carrier value (explicit stores are unaffected).
    if ( ins->opcode == m_call || ins->opcode == m_icall )
    {
      env.regs.clear();
      continue;
    }

    // Generic register definition: fold the RHS.
    if ( ins->d.t == mop_r )
    {
      // Treat the instruction's result as (opcode applied to its operands).
      // eval_insn expects the defining minsn; build it by evaluating this ins.
      auto v = eval_insn(di, env, ins, 32);
      if ( v )
        env.regs[ins->d.r] = *v;
      else
        env.regs.erase(ins->d.r);
    }
  }
}

// ── recursive carrier resolution ─────────────────────────────────────────────

struct CarrierVals
{
  bool known = false;                // at least one value determined
  std::vector<uint64_t> vals;        // deduplicated candidate value(s)
};

void add_val(CarrierVals *cv, uint64_t v)
{
  v &= STATE_MASK;
  if ( std::find(cv->vals.begin(), cv->vals.end(), v) == cv->vals.end() )
    cv->vals.push_back(v);
  cv->known = true;
}

// Resolve the carrier value flowing OUT of block `serial` (as it branches to
// its successor). `visited` is copied per branch to bound loops.
CarrierVals resolve_carrier_out(mba_t *mba, const DispatcherInfo &di,
                                int serial, int depth, std::set<int> visited)
{
  CarrierVals out;
  if ( depth <= 0 || serial < 0 || serial >= mba->qty || visited.count(serial) )
    return out;
  visited.insert(serial);

  mblock_t *blk = mba->get_mblock(serial);

  // Pass 1: emulate with the incoming carrier UNKNOWN. If the block installs
  // the carrier absolutely (mov #K / stx #K, independent of the old value) the
  // result is known without consulting predecessors.
  {
    Env env;
    emulate_block_body(di, blk, env);
    auto v = read_carrier(di, env);
    if ( v )
    {
      add_val(&out, *v);
      DLOG(L_TRACE, "carrier_out blk %d absolute -> 0x%llx",
           serial, (unsigned long long)*v);
      return out;
    }
  }

  // Pass 2: the block leaves the carrier as whatever entered it (possibly after
  // a relative update). Fetch the incoming value(s) from predecessors.
  if ( blk->npred() == 0 )
    return out;

  int nfan = std::min(blk->npred(), MAX_PRED_FANOUT);
  std::vector<uint64_t> incoming;
  for ( int j = 0; j < nfan; ++j )
  {
    CarrierVals pv = resolve_carrier_out(mba, di, blk->pred(j), depth - 1, visited);
    if ( !pv.known )
      return CarrierVals{};   // any unknown predecessor -> whole result unknown
    for ( uint64_t v : pv.vals )
      if ( std::find(incoming.begin(), incoming.end(), v) == incoming.end() )
        incoming.push_back(v);
  }
  if ( incoming.empty() || incoming.size() > MAX_VISIT_VALUES )
    return out;

  // Re-emulate the block once per incoming value so relative updates fold.
  for ( uint64_t inv : incoming )
  {
    Env env;
    set_carrier(di, env, inv);
    emulate_block_body(di, blk, env);
    auto v = read_carrier(di, env);
    if ( !v )
      return CarrierVals{};   // block turns a known input into an unknown
    add_val(&out, *v);
  }
  DLOG(L_TRACE, "carrier_out blk %d -> %d value(s) via %d pred(s)",
       serial, int(out.vals.size()), nfan);
  return out;
}

// Try to read the single constant state a successor forwards to the dispatcher.
std::optional<uint64_t> single_state_out(mba_t *mba, const DispatcherInfo &di,
                                         int serial, int depth)
{
  CarrierVals cv = resolve_carrier_out(mba, di, serial, depth, std::set<int>());
  if ( cv.known && cv.vals.size() == 1 )
    return cv.vals[0];
  return std::nullopt;
}

} // anonymous namespace

StateResolution resolve_father_state(mba_t *mba, mblock_t *father,
                                     const DispatcherInfo &di, int max_depth)
{
  StateResolution res;
  if ( mba == nullptr || father == nullptr )
    return res;

  // 1. Conditional (two-way) install: father ends in jcnd, each edge forwards a
  //    distinct single constant state to the dispatcher.
  minsn_t *tail = father->tail;
  if ( tail != nullptr && tail->opcode == m_jcnd && tail->d.t == mop_b )
  {
    int true_blk  = tail->d.b;          // taken when the condition holds
    int false_blk = father->serial + 1; // fallthrough
    std::optional<uint64_t> tv = single_state_out(mba, di, true_blk, max_depth);
    std::optional<uint64_t> fv = single_state_out(mba, di, false_blk, max_depth);
    if ( tv && fv && *tv != *fv )
    {
      res.resolved       = true;
      res.conditional    = true;
      res.cond           = tail->l;
      res.cond_true_val  = *tv;
      res.cond_false_val = *fv;
      res.values.push_back(*fv);
      res.values.push_back(*tv);
      DLOG(L_TRACE,
           "father %d conditional: true(blk %d)=0x%llx false(blk %d)=0x%llx",
           father->serial, true_blk, (unsigned long long)*tv,
           false_blk, (unsigned long long)*fv);
      return res;
    }
  }

  // 2. Unconditional: resolve the carrier value flowing out of the father.
  CarrierVals cv = resolve_carrier_out(mba, di, father->serial, max_depth,
                                       std::set<int>());
  if ( cv.known && cv.vals.size() == 1 )
  {
    res.resolved = true;
    res.values   = cv.vals;
    DLOG(L_TRACE, "father %d resolved -> 0x%llx",
         father->serial, (unsigned long long)cv.vals[0]);
  }
  else
  {
    res.resolved = false;
    res.values   = cv.vals;   // candidate set (>1) or empty (unknown)
    DLOG(L_TRACE, "father %d unresolved (%d candidate value(s))",
         father->serial, int(cv.vals.size()));
  }
  return res;
}

std::vector<uint64_t> possible_state_values(mba_t *mba, mblock_t *father,
                                            const DispatcherInfo &di,
                                            int max_depth)
{
  std::vector<uint64_t> out;
  if ( mba == nullptr || father == nullptr )
    return out;

  StateResolution r = resolve_father_state(mba, father, di, max_depth);
  if ( r.conditional )
  {
    out.push_back(r.cond_false_val);
    if ( r.cond_true_val != r.cond_false_val )
      out.push_back(r.cond_true_val);
    return out;
  }
  return r.values;
}

std::vector<uint64_t> state_values_via_pred(mba_t *mba, mblock_t *blk,
                                            int pred_serial,
                                            const DispatcherInfo &di,
                                            int max_depth)
{
  std::vector<uint64_t> out;
  if ( mba == nullptr || blk == nullptr )
    return out;
  if ( pred_serial < 0 || pred_serial >= mba->qty )
    return out;

  // Pass 1: does `blk` install the carrier ABSOLUTELY (independent of the value
  // that flowed in)? Then the predecessor is irrelevant and the state is exact.
  {
    Env env;
    emulate_block_body(di, blk, env);
    auto v = read_carrier(di, env);
    if ( v )
    {
      out.push_back(*v & STATE_MASK);
      return out;
    }
  }

  // Pass 2: the block leaves / relatively-updates the carrier. Fetch the
  // value(s) flowing OUT of the chosen predecessor only, then re-emulate `blk`
  // once per incoming value so relative updates fold. Any unknown collapses the
  // whole result to empty (never a guess).
  CarrierVals in = resolve_carrier_out(mba, di, pred_serial, max_depth,
                                       std::set<int>());
  if ( !in.known || in.vals.empty() || in.vals.size() > MAX_VISIT_VALUES )
    return out;

  std::set<uint64_t> seen;
  for ( uint64_t inv : in.vals )
  {
    Env env;
    set_carrier(di, env, inv);
    emulate_block_body(di, blk, env);
    auto v = read_carrier(di, env);
    if ( !v )
      return std::vector<uint64_t>();   // block turns a known input into unknown
    uint64_t k = *v & STATE_MASK;
    if ( seen.insert(k).second )
      out.push_back(k);
  }
  return out;
}

} // namespace unslop
