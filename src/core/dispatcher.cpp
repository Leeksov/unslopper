// Generic flattening-dispatcher detection over one microcode array.
//
// Ported from appdome-research/scripts/cff_deflat.py:
//   _find_dispatcher  -> find_max_pred_block   (Strategy 1 seed)
//   _find_state_var   -> find_state_var
//   _build_state_map  -> build_state_map
// plus a jump-table seed (Strategy 2) and a whole-array state-var scan
// (Strategy 3) that reuse the same state_var / state_map machinery.
#include "dispatcher.h"
#include "microcode_utils.h"
#include "unslop_log.h"
#include "jtbl_affine.h"

#include <algorithm>
#include <deque>
#include <set>
#include <map>
#include <utility>
#include <vector>

namespace unslop {

// ── local helpers ────────────────────────────────────────────────────

// The Python _CMP_OPS set: every conditional/table branch opcode. In the
// microcode enum these are contiguous m_jcnd(0x2A) .. m_jtbl(0x35).
static inline bool is_cmp_op(mcode_t op)
{
  return op >= m_jcnd && op <= m_jtbl;
}

// Resolve an operand to a constant, either a literal or a register whose
// last `mov #const, reg` we recorded in `rm`. Returns true and writes *out
// on success. Mirrors _resolve_const / the inline reg_map lookups in Python.
static bool resolve_const(const mop_t *op,
                          const std::map<mreg_t, uint64_t> &rm,
                          uint64_t *out)
{
  if ( is_num(op) )
  {
    *out = num_val(op);
    return true;
  }
  if ( op != nullptr && op->t == mop_r )
  {
    auto it = rm.find(op->r);
    if ( it != rm.end() )
    {
      *out = it->second;
      return true;
    }
  }
  return false;
}

// ── Shared state-dispatcher discriminators ───────────────────────────
// (declared in dispatcher.h; reused by the register-BST seed check below and
//  by the DexProtector profile gate). Both reuse the exact reg->consts idea
//  from find_state_var: is_cmp_op + resolve_const on {l,r}/{r,l} pairs.

bool state_dispatcher_fingerprint(mba_t *mba,
                                  const std::map<mreg_t, uint64_t> &rm,
                                  StateFingerprint *out)
{
  StateFingerprint best;
  if ( mba != nullptr )
  {
    for ( int i = 0; i < mba->qty; ++i )
    {
      mblock_t *b = mba->get_mblock(i);
      if ( b == nullptr )
        continue;
      std::map<mreg_t, std::set<uint64_t>> cmp;
      for ( minsn_t *ins = b->head; ins != nullptr; ins = ins->next )
      {
        if ( !is_cmp_op(ins->opcode) )
          continue;
        const mop_t *pr[2][2] = { { &ins->l, &ins->r }, { &ins->r, &ins->l } };
        for ( int p = 0; p < 2; ++p )
        {
          if ( pr[p][0]->t != mop_r )
            continue;
          uint64_t c;
          if ( resolve_const(pr[p][1], rm, &c) )
            cmp[pr[p][0]->r].insert(c);
        }
      }
      for ( const auto &kv : cmp )
      {
        if ( kv.second.size() > best.distinct )
        {
          best.distinct = kv.second.size();
          best.sel_reg = kv.first;
          best.converge_blk = i;
        }
      }
    }
  }
  if ( out != nullptr )
    *out = best;
  return best.converge_blk >= 0;
}

bool is_convergence_sink(mba_t *mba, int serial, mreg_t sel,
                         const std::map<mreg_t, uint64_t> &rm,
                         bool require_state_compare)
{
  if ( mba == nullptr || serial < 0 || serial >= mba->qty )
    return true;
  mblock_t *b = mba->get_mblock(serial);
  if ( b == nullptr )
    return true;
  if ( b->nsucc() < 2 )                    // pure return / goto funnel
    return true;

  // C++ destructor / cleanup epilogue: a block whose body is dominated by
  // >=4 calls to the SAME callee is a teardown join, not a dispatcher.
  std::vector<const mop_t *> callees;
  for ( minsn_t *ins = b->head; ins != nullptr; ins = ins->next )
    if ( ins->opcode == m_call || ins->opcode == m_icall )
      callees.push_back(&ins->l);
  for ( size_t i = 0; i < callees.size(); ++i )
  {
    int same = 1;
    for ( size_t j = i + 1; j < callees.size(); ++j )
      if ( callees[i]->equal_mops(*callees[j], EQ_IGNSIZE) )
        ++same;
    if ( same >= 4 )
      return true;
  }

  // Real fan-out dispatcher: the selector is compared against >=2 distinct
  // constants in this very block. Anything less is a sink (a loop header
  // comparing an index vs a length, or a convergence point with no
  // state-variable compare, clears fewer than two). Skipped for a register-BST
  // ENTRY, which compares only one pivot in its own block.
  if ( !require_state_compare )
    return false;
  std::set<uint64_t> cs;
  for ( minsn_t *ins = b->head; ins != nullptr; ins = ins->next )
  {
    if ( !is_cmp_op(ins->opcode) )
      continue;
    const mop_t *o[2] = { &ins->l, &ins->r };
    for ( int k = 0; k < 2; ++k )
    {
      if ( o[k]->t == mop_r && o[k]->r == sel )
      {
        uint64_t c;
        if ( resolve_const(o[k ^ 1], rm, &c) )
          cs.insert(c);
      }
    }
  }
  return cs.size() < 2;
}

// ── Strategy 1 seed: block with the most predecessors ────────────────
// Port of _find_dispatcher.

int find_max_pred_block(mba_t *mba)
{
  int best = -1;
  int mp = 3;
  for ( int i = 0; i < mba->qty; ++i )
  {
    int np = mba->get_mblock(i)->npred();
    if ( np > mp )
    {
      best = i;
      mp = np;
    }
  }
  return best;
}

// ── State variable + dispatcher-block recovery ───────────────────────
// Port of _find_state_var. Populates out->state_var, out->state_reg,
// out->dispatcher_blocks (the "real_disp" set) and out->state_consts
// (the "assigned_states" set). Returns true when a state variable with at
// least three distinct compared constants is found.

bool find_state_var(mba_t *mba, int disp_serial, DispatcherInfo *out,
                    const std::map<mreg_t, uint64_t> &reg_map)
{
  if ( disp_serial < 0 || disp_serial >= mba->qty )
    return false;

  // Step 1a: registers compared against constants inside the ENTRY block.
  // Checked first so we prefer the true state var over a copy register.
  std::map<mreg_t, std::set<uint64_t>> entry_cmp_regs;
  {
    mblock_t *entry = mba->get_mblock(disp_serial);
    for ( minsn_t *ins = entry->head; ins != nullptr; ins = ins->next )
    {
      if ( !is_cmp_op(ins->opcode) )
        continue;
      const mop_t *pairs[2][2] = { { &ins->l, &ins->r }, { &ins->r, &ins->l } };
      for ( int p = 0; p < 2; ++p )
      {
        const mop_t *sv_op = pairs[p][0];
        const mop_t *cv_op = pairs[p][1];
        if ( sv_op->t != mop_r )
          continue;
        uint64_t c;
        if ( resolve_const(cv_op, reg_map, &c) )
          entry_cmp_regs[sv_op->r].insert(c);
      }
    }
  }

  // Step 1b: BFS the dispatcher tree, collecting every reg->consts pairing
  // and the set of dispatcher blocks. Only descend into small successors
  // (<= 6 instructions), exactly as the Python does.
  std::map<mreg_t, std::set<uint64_t>> var_info;
  std::set<int> disp_blks;
  std::deque<int> queue;
  queue.push_back(disp_serial);
  while ( !queue.empty() )
  {
    int s = queue.front();
    queue.pop_front();
    if ( disp_blks.count(s) )
      continue;
    disp_blks.insert(s);

    mblock_t *blk = mba->get_mblock(s);
    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( !is_cmp_op(ins->opcode) )
        continue;
      const mop_t *pairs[2][2] = { { &ins->l, &ins->r }, { &ins->r, &ins->l } };
      for ( int p = 0; p < 2; ++p )
      {
        const mop_t *sv_op = pairs[p][0];
        const mop_t *cv_op = pairs[p][1];
        if ( sv_op->t != mop_r )
          continue;
        uint64_t c;
        if ( resolve_const(cv_op, reg_map, &c) )
          var_info[sv_op->r].insert(c);
      }
    }

    for ( int j = 0; j < blk->nsucc(); ++j )
    {
      int succ = blk->succ(j);
      if ( !disp_blks.count(succ) && insn_count(mba->get_mblock(succ)) <= 6 )
        queue.push_back(succ);
    }
  }

  if ( var_info.empty() )
    return false;

  // Pick the state register: prefer the entry-block winner, but fall back to
  // the tree-wide winner if the entry pick has fewer than three constants.
  auto argmax = [](const std::map<mreg_t, std::set<uint64_t>> &m) -> mreg_t
  {
    mreg_t k = mreg_t(-1);
    size_t best = 0;
    for ( const auto &kv : m )
    {
      if ( k == mreg_t(-1) || kv.second.size() > best )
      {
        k = kv.first;
        best = kv.second.size();
      }
    }
    return k;
  };

  mreg_t best = mreg_t(-1);
  if ( !entry_cmp_regs.empty() )
    best = argmax(entry_cmp_regs);
  if ( best == mreg_t(-1)
    || var_info.find(best) == var_info.end()
    || var_info[best].size() < 3 )
  {
    best = argmax(var_info);
  }
  if ( var_info[best].size() < 3 )
    return false;

  mreg_t sv_reg = best;

  // Step 2: state values from equality comparisons (JZ/JNZ) against sv_reg,
  // plus constants moved directly into sv_reg (or its adjacent regs) in the
  // flat, non-dispatcher blocks.
  std::set<uint64_t> eq_states;
  for ( int s : disp_blks )
  {
    mblock_t *blk = mba->get_mblock(s);
    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( ins->opcode != m_jz && ins->opcode != m_jnz )
        continue;
      const mop_t *pairs[2][2] = { { &ins->l, &ins->r }, { &ins->r, &ins->l } };
      for ( int p = 0; p < 2; ++p )
      {
        const mop_t *sv_op = pairs[p][0];
        const mop_t *cv_op = pairs[p][1];
        if ( sv_op->t == mop_r && sv_op->r == sv_reg )
        {
          uint64_t c;
          if ( resolve_const(cv_op, reg_map, &c) )
            eq_states.insert(c);
        }
      }
    }
  }
  for ( int i = 0; i < mba->qty; ++i )
  {
    if ( disp_blks.count(i) )
      continue;
    mblock_t *blk = mba->get_mblock(i);
    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( ins->opcode == m_mov && is_num(&ins->l) && ins->d.t == mop_r )
      {
        mreg_t r = ins->d.r;
        if ( r == sv_reg || r == sv_reg - 1 || r == sv_reg + 1 )
          eq_states.insert(num_val(&ins->l));
      }
    }
  }

  // Step 3: restrict dispatcher blocks to those that actually contain a
  // comparison of sv_reg (drop pure goto trampolines).
  std::set<int> real_disp;
  for ( int s : disp_blks )
  {
    mblock_t *blk = mba->get_mblock(s);
    bool has_sv_cmp = false;
    for ( minsn_t *ins = blk->head; ins != nullptr && !has_sv_cmp; ins = ins->next )
    {
      if ( !is_cmp_op(ins->opcode) )
        continue;
      const mop_t *ops[2] = { &ins->l, &ins->r };
      for ( int o = 0; o < 2; ++o )
        if ( ops[o]->t == mop_r && ops[o]->r == sv_reg )
          has_sv_cmp = true;
    }
    if ( has_sv_cmp )
      real_disp.insert(s);
  }

  out->state_var.make_reg(sv_reg, 4);
  out->state_reg = sv_reg;
  out->dispatcher_blocks = real_disp;
  out->state_consts = ( eq_states.size() >= 3 ) ? eq_states : var_info[best];
  return true;
}

// ── State-map walker ─────────────────────────────────────────────────
// Port of _build_state_map's nested _follow_goto / _walk closures.

namespace {

struct StateMapWalker
{
  mba_t *mba;
  const mop_t *sv;
  std::map<mreg_t, uint64_t> reg_map;
  const std::set<int> *disp_nodes;
  std::map<uint64_t, int> *sm;

  bool resolve_c(const mop_t *op, uint64_t *out) const
  {
    return resolve_const(op, reg_map, out);
  }

  // Constant compared against the state var in this instruction, if any.
  bool sv_const(const minsn_t *ins, uint64_t *out) const
  {
    const mop_t *pairs[2][2] = { { &ins->l, &ins->r }, { &ins->r, &ins->l } };
    for ( int p = 0; p < 2; ++p )
    {
      if ( mop_equal(pairs[p][0], sv) )
        return resolve_c(pairs[p][1], out);
    }
    return false;
  }

  // Follow pure goto blocks through to a real state entry.
  int follow_goto(int serial, int depth = 0) const
  {
    if ( depth > 10 || serial < 0 || serial >= mba->qty )
      return serial;
    mblock_t *b = mba->get_mblock(serial);
    if ( insn_count(b) == 1
      && b->head->opcode == m_goto
      && b->head->l.t == mop_b )
    {
      return follow_goto(b->head->l.b, depth + 1);
    }
    return serial;
  }

  void walk(int serial, const std::set<uint64_t> &possible,
            std::set<int> &visited, int depth = 0)
  {
    if ( visited.count(serial) || serial < 0 || serial >= mba->qty
      || depth > 50 || visited.size() > 500 )
      return;
    visited.insert(serial);

    mblock_t *blk = mba->get_mblock(serial);
    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( !is_cmp_op(ins->opcode) || ins->d.t != mop_b )
        continue;
      uint64_t c;
      if ( !sv_const(ins, &c) )
        continue;

      int target = ins->d.b;
      int ft = serial + 1;
      for ( int j = 0; j < blk->nsucc(); ++j )
      {
        int s = blk->succ(j);
        if ( s != target ) { ft = s; break; }
      }

      if ( ins->opcode == m_jz )
      {
        (*sm)[c] = follow_goto(target);
        std::set<uint64_t> remaining = possible;
        remaining.erase(c);
        if ( remaining.size() == 1 )
          (*sm)[*remaining.begin()] = follow_goto(ft);
        else
          walk(ft, remaining, visited, depth + 1);
      }
      else if ( ins->opcode == m_jnz )
      {
        (*sm)[c] = follow_goto(ft);
        std::set<uint64_t> remaining = possible;
        remaining.erase(c);
        if ( remaining.size() == 1 )
          (*sm)[*remaining.begin()] = follow_goto(target);
        else
          walk(target, remaining, visited, depth + 1);
      }
      else
      {
        // Range comparison (signed jg/jge/jl/jle or unsigned ja/jae/jb/jbe).
        int64_t cs = s32(c);
        std::set<uint64_t> t_set, f_set;
        bool handled = true;
        mcode_t op = ins->opcode;
        if ( op == m_jg || op == m_ja )
        {
          for ( uint64_t v : possible )
            (s32(v) > cs ? t_set : f_set).insert(v);
        }
        else if ( op == m_jge || op == m_jae )
        {
          for ( uint64_t v : possible )
            (s32(v) >= cs ? t_set : f_set).insert(v);
        }
        else if ( op == m_jl || op == m_jb )
        {
          for ( uint64_t v : possible )
            (s32(v) < cs ? t_set : f_set).insert(v);
        }
        else if ( op == m_jle || op == m_jbe )
        {
          for ( uint64_t v : possible )
            (s32(v) <= cs ? t_set : f_set).insert(v);
        }
        else
        {
          handled = false;
        }
        if ( !handled )
          return;

        if ( t_set.size() == 1 )
          (*sm)[*t_set.begin()] = follow_goto(target);
        else if ( t_set.size() > 1 )
          walk(target, t_set, visited, depth + 1);

        if ( f_set.size() == 1 )
          (*sm)[*f_set.begin()] = follow_goto(ft);
        else if ( f_set.size() > 1 )
          walk(ft, f_set, visited, depth + 1);
      }
      return;
    }

    // No sv-conditional found: follow a goto trampoline.
    if ( blk->head != nullptr
      && blk->head->opcode == m_goto
      && blk->head->l.t == mop_b )
    {
      int target = blk->head->l.b;
      if ( possible.size() == 1 )
        (*sm)[*possible.begin()] = follow_goto(target);
      else if ( possible.size() > 1 )
        walk(target, possible, visited, depth + 1);
    }
  }
};

} // anonymous namespace

void build_state_map(mba_t *mba, DispatcherInfo *di,
                     const std::map<mreg_t, uint64_t> &regmap)
{
  di->state_map.clear();

  StateMapWalker w;
  w.mba = mba;
  w.sv = &di->state_var;
  w.disp_nodes = &di->dispatcher_blocks;
  w.sm = &di->state_map;
  w.reg_map = regmap;   // shared map built once per function (FIX 2)

  std::set<int> visited_walk;
  for ( int entry : di->dispatcher_blocks ) // std::set iterates sorted
  {
    if ( !visited_walk.count(entry) )
      w.walk(entry, di->state_consts, visited_walk);
  }

  DLOG(L_DEBUG, "state_map built: %d entries (state_consts=%d)",
       int(di->state_map.size()), int(di->state_consts.size()));
}

// ── Strategy 4: XOR-keyed binary-search-tree dispatcher (emulated) ────
//
// DexProtector (and OLLVM range-dispatch) do not compare the raw state
// variable against equality constants. They transform the state once at the
// dispatcher entry
//     t = ((state ^ KEY) + ADD)          [signed 32-bit]
// and route t through a binary-search tree of signed/unsigned inequality (and
// occasional equality) comparisons against threshold pivots. Each case block
// re-installs a raw constant K into the state slot and jumps back to the tree.
//
// The equality-only build_state_map is nearly empty for this shape, so we
// instead EMULATE the tree once per candidate K: apply the transform to K,
// then walk the comparison nodes following the taken / fallthrough successor
// until we leave the tree into a real block. That block is K's target. This
// mirrors ref_d810_generic.py::emulate_dispatcher_with_father_history and the
// standalone EmulationEngine.emulate_dispatcher (Unicorn walk of the tree).

namespace {

// Recursively search a mop's subinstruction tree for the first minsn whose
// opcode is `op`. Returns nullptr if none. (mop_d wraps a nested minsn_t.)
static const minsn_t *search_subinsn(const mop_t *m, mcode_t op)
{
  if ( m == nullptr || m->t != mop_d || m->d == nullptr )
    return nullptr;
  const minsn_t *ins = m->d;
  if ( ins->opcode == op )
    return ins;
  const minsn_t *r;
  if ( (r = search_subinsn(&ins->l, op)) != nullptr ) return r;
  if ( (r = search_subinsn(&ins->r, op)) != nullptr ) return r;
  if ( (r = search_subinsn(&ins->d, op)) != nullptr ) return r;
  return nullptr;
}

// True if `target` appears anywhere within mop `m`'s subinstruction tree.
static bool subtree_contains(const mop_t *m, const minsn_t *target)
{
  if ( m == nullptr || m->t != mop_d || m->d == nullptr )
    return false;
  if ( m->d == target )
    return true;
  return subtree_contains(&m->d->l, target)
      || subtree_contains(&m->d->r, target)
      || subtree_contains(&m->d->d, target);
}

// Find the m_add / m_sub that applies the +ADD/-SUB of the selector transform:
// the one whose operand subtree CONTAINS the xor node `xr` (i.e. an ancestor of
// the xor). This deliberately ignores an m_add buried inside the state load's
// address expression (e.g. the (x19+0x18) of an ldx), which is a descendant of
// the xor, not an ancestor. Returns the node and sets *is_sub.
static const minsn_t *find_xform_addsub(const mop_t *m, const minsn_t *xr,
                                        bool *is_sub)
{
  if ( m == nullptr || m->t != mop_d || m->d == nullptr )
    return nullptr;
  const minsn_t *i = m->d;
  if ( (i->opcode == m_add || i->opcode == m_sub)
    && (subtree_contains(&i->l, xr) || subtree_contains(&i->r, xr)) )
  {
    *is_sub = (i->opcode == m_sub);
    return i;
  }
  const minsn_t *r;
  if ( (r = find_xform_addsub(&i->l, xr, is_sub)) != nullptr ) return r;
  if ( (r = find_xform_addsub(&i->r, xr, is_sub)) != nullptr ) return r;
  if ( (r = find_xform_addsub(&i->d, xr, is_sub)) != nullptr ) return r;
  return nullptr;
}

// From an m_xor/m_add/m_sub minsn, pick the operand that resolves to a constant
// (the key) and hand back the OTHER operand (the running value). r is checked
// first because the protectors emit `op value, #const`.
static bool split_binop_const(const minsn_t *ins,
                              const std::map<mreg_t, uint64_t> &rm,
                              uint64_t *cst, const mop_t **other)
{
  if ( resolve_const(&ins->r, rm, cst) ) { *other = &ins->l; return true; }
  if ( resolve_const(&ins->l, rm, cst) ) { *other = &ins->r; return true; }
  return false;
}

// The set of direct conditional-compare opcodes the tree uses (jz..jle). jcnd
// carries its condition as a nested mop_d and is not part of this direct form.
static inline bool is_tree_cond(mcode_t op)
{
  return op == m_jz || op == m_jnz
      || op >= m_jae && op <= m_jle;   // jae,jb,ja,jbe,jg,jge,jl,jle
}

// Tail conditional of a block, if it is a direct compare with a block target.
static const minsn_t *tail_cond(const mblock_t *blk)
{
  const minsn_t *last = nullptr;
  for ( const minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    if ( is_tree_cond(ins->opcode) && ins->d.t == mop_b )
      last = ins;
  }
  return last;
}

// Is `serial` a comparison node of the tree: it ends in a direct conditional
// one of whose operands is the compared selector register `sel`.
static bool is_cmp_node(mba_t *mba, int serial, mreg_t sel)
{
  if ( serial < 0 || serial >= mba->qty )
    return false;
  const minsn_t *c = tail_cond(mba->get_mblock(serial));
  if ( c == nullptr )
    return false;
  if ( c->l.t == mop_r && c->l.r == sel ) return true;
  if ( c->r.t == mop_r && c->r.r == sel ) return true;
  return false;
}

// Follow a chain of single-instruction goto trampolines to the block they
// ultimately land in.
static int follow_goto_chain(mba_t *mba, int serial, int depth = 0)
{
  if ( depth > 16 || serial < 0 || serial >= mba->qty )
    return serial;
  mblock_t *b = mba->get_mblock(serial);
  if ( b->head != nullptr
    && b->head->next == nullptr
    && b->head->opcode == m_goto
    && b->head->l.t == mop_b )
  {
    return follow_goto_chain(mba, b->head->l.b, depth + 1);
  }
  return serial;
}

// Evaluate `lv <op> rv` for a tree conditional. Signed ops use signed 32-bit,
// unsigned ops unsigned 32-bit, equality masked 32-bit.
static bool eval_tree_cond(mcode_t op, uint64_t lv, uint64_t rv)
{
  uint32_t lu = uint32_t(lv), ru = uint32_t(rv);
  int64_t ls = s32(lv), rs = s32(rv);
  switch ( op )
  {
    case m_jz:  return lu == ru;
    case m_jnz: return lu != ru;
    case m_jg:  return ls >  rs;
    case m_jge: return ls >= rs;
    case m_jl:  return ls <  rs;
    case m_jle: return ls <= rs;
    case m_ja:  return lu >  ru;
    case m_jae: return lu >= ru;
    case m_jb:  return lu <  ru;
    case m_jbe: return lu <= ru;
    default:    return false;
  }
}

// Walk the tree from `entry` for one candidate raw state K. Returns the serial
// of the real (non-tree) block K dispatches to, or -1 if the walk cannot be
// resolved uniquely (bounded to 64 steps to defeat loops).
static int emulate_tree(mba_t *mba, const DispatcherInfo *di,
                        const std::set<int> &tree_nodes,
                        const std::map<mreg_t, uint64_t> &rm, uint64_t K)
{
  uint64_t t = K;
  if ( di->sel_has_transform )
    t = uint64_t(uint32_t((K ^ di->sel_xor_key) + di->sel_add));
  t &= 0xFFFFFFFFull;

  int cur = di->block_idx;
  for ( int step = 0; step <= 64; ++step )
  {
    mblock_t *blk = mba->get_mblock(cur);
    const minsn_t *c = tail_cond(blk);
    if ( c == nullptr )
      return -1;

    // Substitute t for the selector operand, resolve the other as the pivot.
    uint64_t lv = 0, rv = 0;
    bool ok = true;
    if ( c->l.t == mop_r && c->l.r == di->sel_reg_cmp )
      lv = t;
    else if ( !resolve_const(&c->l, rm, &lv) )
      ok = false;
    if ( c->r.t == mop_r && c->r.r == di->sel_reg_cmp )
      rv = t;
    else if ( ok && !resolve_const(&c->r, rm, &rv) )
      ok = false;
    if ( !ok )
      return -1;

    bool taken = eval_tree_cond(c->opcode, lv, rv);
    int target = c->d.b;
    int ft = target;
    for ( int j = 0; j < blk->nsucc(); ++j )
    {
      int s = blk->succ(j);
      if ( s != target ) { ft = s; break; }
    }

    int nxt = follow_goto_chain(mba, taken ? target : ft);
    if ( tree_nodes.count(nxt) != 0 )
    {
      cur = nxt;
      continue;
    }
    return nxt; // left the tree -> real target
  }
  return -1;
}

// Structural operand match for the memory-state slot (selector + address).
static bool same_mop(const mop_t *a, const mop_t *b)
{
  if ( a == nullptr || b == nullptr )
    return false;
  return a->equal_mops(*b, EQ_IGNSIZE);
}

} // anonymous namespace

// Detect the selector transform  t = ((state ^ KEY) + ADD)  at the dispatcher
// entry block and record it (sel_xor_key / sel_add / sel_reg_cmp and the state
// location) into `di`. Handles both the nested-compound form
//   xdu (( [state] ^ #KEY ) + #ADD), sel      (DexProtector at LOCOPT)
// and the flat multi-instruction form
//   xor state, #KEY, t ; add t, #ADD, t.
// Returns true when a transform was found. KEY/ADD may be immediates or
// prologue-loaded registers (resolved through `regmap`).
bool detect_selector_transform(mba_t *mba, int entry,
                               const std::map<mreg_t, uint64_t> &regmap,
                               DispatcherInfo *di)
{
  if ( entry < 0 || entry >= mba->qty )
    return false;
  mblock_t *blk = mba->get_mblock(entry);

  // The transform must feed the register the entry's tail conditional compares:
  // that anchors "the selector" and rejects unrelated xors in the block.
  const minsn_t *ec = tail_cond(blk);
  if ( ec == nullptr )
    return false;

  for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    if ( ins->d.t != mop_r )
      continue; // the transform result must land in a register (the selector)

    // Only consider the instruction whose destination the tail conditional
    // actually compares (allowing for register sub-size aliasing).
    bool feeds_cmp =
        (ec->l.t == mop_r && ec->l.r == ins->d.r)
     || (ec->r.t == mop_r && ec->r.r == ins->d.r);
    if ( !feeds_cmp )
      continue;

    // Find the XOR node: the instruction itself, or nested in its sources.
    const minsn_t *xr = nullptr;
    if ( ins->opcode == m_xor )
      xr = ins;
    if ( xr == nullptr ) xr = search_subinsn(&ins->l, m_xor);
    if ( xr == nullptr ) xr = search_subinsn(&ins->r, m_xor);
    if ( xr == nullptr )
      continue;

    uint64_t key = 0;
    const mop_t *state_leaf = nullptr;
    if ( !split_binop_const(xr, regmap, &key, &state_leaf) )
      continue;

    // Optional +ADD / -SUB with a constant applied to the xor result. Nested
    // form: an add/sub that is an ANCESTOR of the xor node (never the address
    // add inside the state load). Flat form: a following instruction on sel.
    int64_t add = 0;
    bool is_sub = false;
    const minsn_t *ad = nullptr;
    if ( xr != ins )
    {
      // Nested compound: search the instruction's sources for the ancestor.
      ad = find_xform_addsub(&ins->l, xr, &is_sub);
      if ( ad == nullptr )
        ad = find_xform_addsub(&ins->r, xr, &is_sub);
    }
    else
    {
      // Flat form (`xor state,#K,sel`): look ahead for `add/sub sel, #C`.
      for ( minsn_t *nx = ins->next; nx != nullptr; nx = nx->next )
      {
        if ( nx->d.t == mop_r && nx->d.r == ins->d.r
          && (nx->opcode == m_add || nx->opcode == m_sub) )
        {
          ad = nx;
          is_sub = (nx->opcode == m_sub);
          break;
        }
        if ( is_tree_cond(nx->opcode) )
          break;
      }
    }
    uint64_t addc = 0;
    const mop_t *dummy = nullptr;
    if ( ad != nullptr && split_binop_const(ad, regmap, &addc, &dummy) )
      add = is_sub ? -int64_t(int32_t(uint32_t(addc)))
                   :  int64_t(int32_t(uint32_t(addc)));

    di->sel_has_transform = true;
    di->sel_xor_key = key & 0xFFFFFFFFull;
    di->sel_add = add;
    di->sel_reg_cmp = ins->d.r;

    // Classify the state location from the XOR's non-const leaf.
    if ( state_leaf != nullptr && state_leaf->t == mop_r )
    {
      di->sel_mem_state = false;
      di->sel_state_reg = state_leaf->r;
    }
    else if ( state_leaf != nullptr && state_leaf->t == mop_d
           && state_leaf->d != nullptr && state_leaf->d->opcode == m_ldx )
    {
      di->sel_mem_state = true;
      di->sel_state_sel = state_leaf->d->l;   // e.g. cs
      di->sel_state_addr = state_leaf->d->r;   // e.g. (x19+0x18)
    }
    else if ( state_leaf != nullptr && state_leaf->t == mop_S )
    {
      di->sel_mem_state = true;
      di->sel_state_sel = *state_leaf;         // stack-var form: match whole mop
    }
    else
    {
      // Unknown state carrier - keep the transform for logging but the
      // per-block resolution below will find nothing, so bail.
      di->sel_has_transform = false;
      return false;
    }

    DLOG(L_INFO,
         "transform: (sv ^ 0x%llX) + %lld  sel_reg=%d state=%s",
         (unsigned long long)di->sel_xor_key, (long long)di->sel_add,
         int(di->sel_reg_cmp), di->sel_mem_state ? "mem" : "reg");
    return true;
  }
  return false;
}

// Recover, for one block, the raw state constant it stores into the state slot
// (register or memory), following simple within-block const propagation. The
// LAST such store wins. Returns true and writes *out on success.
static bool block_installed_state(mba_t *mba, int serial,
                                  const DispatcherInfo *di,
                                  const std::map<mreg_t, uint64_t> &regmap,
                                  uint64_t *out)
{
  mblock_t *blk = mba->get_mblock(serial);
  std::map<mreg_t, uint64_t> local;
  bool have = false;
  uint64_t last = 0;

  // Resolve the value operand of a store: a direct immediate, or a register
  // whose block-local `mov #imm, reg` we already saw.
  auto store_val = [&](const mop_t *v, uint64_t *out_v) -> bool
  {
    if ( is_num(v) ) { *out_v = num_val(v); return true; }
    if ( v->t == mop_r )
    {
      auto it = local.find(v->r);
      if ( it != local.end() ) { *out_v = it->second; return true; }
    }
    return false;
  };

  for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    // Track block-local `mov #imm, reg` so a `mov #K,r; store r` pair resolves.
    if ( ins->opcode == m_mov && is_num(&ins->l) && ins->d.t == mop_r )
      local[ins->d.r] = num_val(&ins->l);

    uint64_t v = 0;
    if ( di->sel_state_reg != mreg_t(-1) )
    {
      // Register carrier: `mov #K, state_reg` (accept sub-register neighbours).
      if ( ins->opcode == m_mov && is_num(&ins->l) && ins->d.t == mop_r )
      {
        mreg_t r = ins->d.r;
        if ( (r == di->sel_state_reg
           || r == mreg_t(di->sel_state_reg - 1)
           || r == mreg_t(di->sel_state_reg + 1)) )
        {
          last = num_val(&ins->l); have = true;
        }
      }
    }
    else if ( !di->sel_state_addr.empty() )
    {
      // ldx/stx memory carrier: `stx value, selector, address`.
      if ( ins->opcode == m_stx
        && same_mop(&ins->r, &di->sel_state_sel)
        && same_mop(&ins->d, &di->sel_state_addr)
        && store_val(&ins->l, &v) )
      {
        last = v; have = true;
      }
    }
    else if ( !di->sel_state_sel.empty() )
    {
      // Stack-variable carrier: `mov #K, %stackvar` (d is the mop_S itself).
      if ( ins->opcode == m_mov
        && same_mop(&ins->d, &di->sel_state_sel)
        && store_val(&ins->l, &v) )
      {
        last = v; have = true;
      }
    }
  }
  if ( have && out != nullptr )
    *out = last & 0xFFFFFFFFull;
  return have;
}

// Build the state map by emulating the XOR-keyed BST. Requires that
// detect_selector_transform has populated di->sel_*. Fills di->dispatcher_blocks
// with the tree's comparison nodes, di->block_state (block -> raw K) and
// di->state_map (raw K -> real target block). Sets di->emulated.
void build_state_map_emulated(mba_t *mba, DispatcherInfo *di,
                              const std::map<mreg_t, uint64_t> &regmap)
{
  di->state_map.clear();
  di->block_state.clear();
  di->dispatcher_blocks.clear();

  // 1. BFS the comparison-node tree from the entry (staying on sel_reg_cmp
  //    compares, hopping goto trampolines).
  std::set<int> tree_nodes;
  std::deque<int> queue;
  queue.push_back(di->block_idx);
  while ( !queue.empty() )
  {
    int s = queue.front();
    queue.pop_front();
    if ( tree_nodes.count(s) != 0 || !is_cmp_node(mba, s, di->sel_reg_cmp) )
      continue;
    tree_nodes.insert(s);
    mblock_t *b = mba->get_mblock(s);
    for ( int j = 0; j < b->nsucc(); ++j )
    {
      int t = follow_goto_chain(mba, b->succ(j));
      if ( tree_nodes.count(t) == 0 && is_cmp_node(mba, t, di->sel_reg_cmp) )
        queue.push_back(t);
    }
  }
  di->dispatcher_blocks = tree_nodes;
  DLOG(L_INFO, "emulated-BST: %d comparison nodes", int(tree_nodes.size()));

  // 2. Per-block raw state constants (case exits + prologue initial state).
  std::set<uint64_t> candidates;
  for ( int i = 0; i < mba->qty; ++i )
  {
    if ( tree_nodes.count(i) != 0 )
      continue;
    uint64_t k = 0;
    if ( block_installed_state(mba, i, di, regmap, &k) )
    {
      di->block_state[i] = k;
      candidates.insert(k);
      di->state_consts.insert(k);
    }
  }

  // 3. Emulate the tree once per candidate raw K.
  int resolved = 0;
  for ( uint64_t K : candidates )
  {
    int tgt = emulate_tree(mba, di, tree_nodes, regmap, K);
    if ( tgt >= 0 && tgt < mba->qty && tree_nodes.count(tgt) == 0 )
    {
      di->state_map[K] = tgt;
      ++resolved;
      DLOG(L_DEBUG, "state 0x%llX -> blk %d via BST",
           (unsigned long long)K, tgt);
    }
  }
  di->emulated = true;
  DLOG(L_INFO, "emulated-BST: %d/%d candidate states resolved (%d blocks store state)",
       resolved, int(candidates.size()), int(di->block_state.size()));
}

// Strategy 4 driver: max-predecessor entry + selector transform + emulated tree.
// Count how many blocks reachable from `entry` (hopping goto trampolines) are
// comparison nodes on register `sel`. A real BST selector recurs across nodes.
static int count_tree_nodes_for(mba_t *mba, int entry, mreg_t sel)
{
  std::set<int> seen;
  std::vector<int> q;
  q.push_back(entry);
  while ( !q.empty() )
  {
    int s = q.back(); q.pop_back();
    if ( s < 0 || s >= mba->qty || seen.count(s) != 0 )
      continue;
    if ( !is_cmp_node(mba, s, sel) )
      continue;
    seen.insert(s);
    mblock_t *b = mba->get_mblock(s);
    for ( int j = 0; j < b->nsucc(); ++j )
      q.push_back(follow_goto_chain(mba, b->succ(j)));
  }
  return int(seen.size());
}

// Register-BST dispatcher with NO xor transform (AppDome / Promon family):
// the entry compares a runtime state register against per-node thresholds
// (immediates or prologue-pool registers). Treat it as an identity transform
// (key=0, add=0) so the emulated resolver + D-810 driver apply. Picks, of the
// entry conditional's register operands, the one that recurs as the compared
// register across the tree (>=2 nodes).
static bool detect_register_bst(mba_t *mba, int entry,
                                const std::map<mreg_t, uint64_t> &regmap,
                                DispatcherInfo *di)
{
  if ( entry < 0 || entry >= mba->qty )
    return false;
  const minsn_t *ec = tail_cond(mba->get_mblock(entry));
  if ( ec == nullptr || !is_tree_cond(ec->opcode) )
    return false;

  mreg_t best = mreg_t(-1);
  int best_n = 1;                     // require >=2 tree nodes
  const mop_t *ops[2] = { &ec->l, &ec->r };
  for ( int i = 0; i < 2; ++i )
  {
    if ( ops[i]->t != mop_r )
      continue;
    int n = count_tree_nodes_for(mba, entry, ops[i]->r);
    if ( n > best_n )
    {
      best_n = n;
      best = ops[i]->r;
    }
  }
  if ( best == mreg_t(-1) )
    return false;

  // Reject a max-pred seed that is really a convergence / cleanup sink (a
  // return/goto funnel, a C++ destructor epilogue, or a join with no genuine
  // multi-constant state compare). find_max_pred_block latches onto these on
  // clean functions, producing the register-BST false positives that explode
  // the goto count when rewritten.
  if ( is_convergence_sink(mba, entry, best, regmap, /*require_state_compare=*/false) )
  {
    DLOG(L_INFO, "register-BST reject: seed blk %d is a convergence sink", entry);
    return false;
  }

  di->sel_has_transform = true;       // identity: key=0, add=0
  di->sel_xor_key = 0;
  di->sel_add = 0;
  di->sel_reg_cmp = best;
  di->sel_mem_state = false;
  di->sel_state_reg = best;           // state carrier == the compared register
  DLOG(L_INFO, "identity register-BST: sel_reg=%d (%d nodes, no transform)",
       int(best), best_n);
  return true;
}

static bool detect_emulated_dispatcher(mba_t *mba, DispatcherInfo *out,
                                       const std::map<mreg_t, uint64_t> &regmap)
{
  int entry = find_max_pred_block(mba);
  if ( entry < 0 )
    return false;

  DispatcherInfo di;
  di.block_idx = entry;
  bool regbst_ok = false;
  {
    static int rb = -1;
    if ( rb < 0 )
    {
      qstring ev;
      // Default ON: the register-BST detector feeds the CRASH-SAFE emulated
      // rewriter (di.emulated=true -> rewrite_cfg_emulated at GLBOPT), which is
      // how AppDome/Promon (iOS and Android) register-magic-BST dispatchers get
      // deflattened. It is additive - only tried when detect_selector_transform
      // did not already match - and each rewrite is strict-verified. Opt out
      // with UNSLOP_REGBST=0.
      rb = (qgetenv("UNSLOP_REGBST", &ev) && atoi(ev.c_str()) == 0) ? 0 : 1;
    }
    regbst_ok = (rb != 0);
  }
  bool via_selector = detect_selector_transform(mba, entry, regmap, &di);
  bool via_regbst   = false;
  if ( !via_selector )
    via_regbst = regbst_ok && detect_register_bst(mba, entry, regmap, &di);
  if ( !via_selector && !via_regbst )
    return false;
  if ( di.sel_reg_cmp == mreg_t(-1) )
    return false;

  build_state_map_emulated(mba, &di, regmap);
  if ( di.state_map.size() < 2 )
    return false;

  // Register-BST safety pre-filter. A genuine magic-BST resolves at least as
  // many distinct states as its comparison tree has nodes (nodes/states ~0.7-
  // 0.8); a false positive - find_max_pred_block latched onto a natural
  // compare-cascade or convergence sink - has MORE comparison nodes than
  // resolvable states (ratio >= 1.21) and its rewrite INFLATES gotos. The
  // threshold sits in the clean gap (genuine ceiling 0.81, FP floor 1.21).
  // Gated to the register-BST path only: the selector-transform path is the
  // already-validated default and must stay byte-identical.
  if ( via_regbst && di.dispatcher_blocks.size() > di.state_map.size() )
  {
    DLOG(L_INFO,
         "register-BST reject: %d tree nodes > %d states (compare-cascade FP)",
         int(di.dispatcher_blocks.size()), int(di.state_map.size()));
    return false;
  }

  // The register the tree compares is the selector; the raw state carrier is
  // recorded separately (state_reg is used by the CFG rewriter's fallback).
  di.state_reg = di.sel_mem_state ? di.sel_reg_cmp : di.sel_state_reg;
  di.state_var.make_reg(di.sel_reg_cmp, 4);
  di.detection_strategy = 4;
  di.valid = true;
  *out = di;
  return true;
}

// ── Strategy 2: jump table ───────────────────────────────────────────
// A block whose tail is m_jtbl carries an mcases_t (values -> targets); a
// block ending in m_ijmp is an indirect table jump. Treat the mcases as the
// state map directly.

// Trace the jump-table selector register back to the state carrier the case
// blocks actually write. The selector is loaded just before the jtbl from a
// memory slot (ldx), a stack var (mov %stkvar), or copied from another reg.
// Sets di's carrier fields (sel_state_reg / sel_state_sel / sel_state_addr) to
// that source so block_installed_state can find the per-case installs. Returns
// true if a concrete carrier was identified.
static bool match_affine_jtbl_def(const minsn_t *def, mreg_t *raw_reg,
                                  int64_t *add)
{
  if ( def == nullptr || raw_reg == nullptr || add == nullptr )
    return false;
  const minsn_t *expr = def;
  if ( def->opcode == m_xdu && def->l.t == mop_d && def->l.d != nullptr
    && def->l.size == 4 && def->d.size == 8 )
    expr = def->l.d;
  if ( (expr->opcode != m_sub && expr->opcode != m_add)
    || expr->l.t != mop_r || expr->l.size != 4
    || !is_num(&expr->r) || expr->r.size != 4 )
    return false;
  const uint32_t c = uint32_t(num_val(&expr->r));
  *raw_reg = expr->l.r;
  *add = expr->opcode == m_sub ? -int64_t(c) : int64_t(c);
  return true;
}

static bool trace_jtbl_carrier(mba_t *mba, int jtbl_serial, mreg_t selreg,
                               DispatcherInfo *di)
{
  int cur = jtbl_serial;
  mreg_t want = selreg;
  for ( int hops = 0; hops < 8 && cur >= 0 && cur < mba->qty; ++hops )
  {
    mblock_t *blk = mba->get_mblock(cur);
    // Scan this block backward for the definition of `want`.
    const minsn_t *def = nullptr;
    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
      if ( ins->d.t == mop_r && ins->d.r == want )
        def = ins;                     // keep the LAST def before the tail
    if ( def != nullptr )
    {
      // Appdome-style switches may index the table with a zero-extended
      // 32-bit affine selector, e.g. xdu(state - #C) -> selector. The case
      // blocks install the *raw* state, not the zero-based table index. Only
      // accept the exact, anchored expression feeding this jtbl selector.
      mreg_t raw_reg = mreg_t(-1);
      int64_t add = 0;
      if ( match_affine_jtbl_def(def, &raw_reg, &add) )
      {
        di->sel_state_reg = raw_reg;
        di->sel_state_sel = mop_t();
        di->sel_state_addr = mop_t();
        di->sel_mem_state = false;
        di->sel_xor_key = 0;
        di->sel_add = add;
        di->jtbl_affine_proven = true;
        DLOG(L_INFO, "jump-table affine selector: state_reg=%d add=%lld",
             int(di->sel_state_reg), (long long)di->sel_add);
        return true;
      }
      // ldx sel,addr -> want : memory carrier.
      if ( def->opcode == m_ldx )
      {
        di->sel_mem_state = true;
        di->sel_state_reg = mreg_t(-1);
        di->sel_state_sel = def->l;    // selector (e.g. cs)
        di->sel_state_addr = def->r;   // address (e.g. x19+off)
        return true;
      }
      // mov %stkvar -> want : stack carrier.
      if ( def->opcode == m_mov && def->l.t == mop_S )
      {
        di->sel_mem_state = true;
        di->sel_state_reg = mreg_t(-1);
        di->sel_state_sel = def->l;    // the mop_S itself
        di->sel_state_addr = mop_t();  // empty
        return true;
      }
      // mov otherreg -> want : follow the copy.
      if ( def->opcode == m_mov && def->l.t == mop_r )
      {
        want = def->l.r;
        continue;                      // re-scan same block for the new reg
      }
      // mov #imm -> want : constant, not a carrier. Give up.
      if ( def->opcode == m_mov && is_num(&def->l) )
        return false;
      return false;                    // unknown def shape
    }
    // Not defined here: follow a single predecessor.
    if ( blk->npred() != 1 )
      return false;
    cur = blk->pred(0);
  }
  return false;
}

// Replacing a goto-to-jtbl with a direct case edge skips every instruction
// in the dispatcher block. That is valid only when the block is a pure branch
// (or computes an otherwise-dead selector). In particular, Appdome-style
// dispatchers can update ordinary live registers *after* computing the switch
// index; an exact state map does not make those writes safe to skip.
static bool pure_jtbl_dispatcher(mba_t *mba, int serial,
                                 const DispatcherInfo &di)
{
  if ( mba == nullptr || serial < 0 || serial >= mba->qty )
    return false;
  mblock_t *blk = mba->get_mblock(serial);
  if ( blk == nullptr || blk->tail == nullptr || blk->tail->opcode != m_jtbl )
    return false;
  if ( blk->tail->l.t != mop_r && blk->tail->l.t != mop_S )
    return false;

  std::vector<JtblInstruction> shape;
  for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    if ( ins == blk->tail )
    {
      shape.push_back(JtblInstruction::Branch);
      continue;
    }
    if ( ins->opcode == m_nop )
    {
      shape.push_back(JtblInstruction::Nop);
      continue;
    }
    mreg_t raw_reg = mreg_t(-1);
    int64_t add = 0;
    if ( di.jtbl_affine_proven
      && ins->d.t == mop_r && ins->d.r == di.sel_reg_cmp
      && match_affine_jtbl_def(ins, &raw_reg, &add)
      && raw_reg == di.sel_state_reg && add == di.sel_add )
    {
      shape.push_back(JtblInstruction::ExactAffineSelector);
      continue;
    }
    shape.push_back(JtblInstruction::Other);
  }
  if ( !pure_jtbl_shape(shape, di.jtbl_affine_proven, false) )
    return false;
  if ( !di.jtbl_affine_proven )
    return true; // the jtbl is the block's only non-NOP instruction

  // The affine selector computation is skipped on a direct edge. Its result
  // must not be read outside the dispatcher, including inside nested mops.
  if ( blk->tail->l.t != mop_r || blk->tail->l.r != di.sel_reg_cmp
    || blk->tail->l.size <= 0 || blk->tail->l.size > 8 )
    return false;
  for ( int b = 0; b < mba->qty; ++b )
  {
    if ( b == serial )
      continue;
    mblock_t *other = mba->get_mblock(b);
    if ( other == nullptr )
      return false;
    for ( minsn_t *ins = other->head; ins != nullptr; ins = ins->next )
    {
      mlist_t uses = other->build_use_list(*ins, MAY_ACCESS);
      for ( int byte = 0; byte < blk->tail->l.size; ++byte )
        if ( uses.has(mreg_t(di.sel_reg_cmp + byte)) )
          return false;
    }
  }
  return true;
}

static bool detect_jump_table(mba_t *mba, DispatcherInfo *out,
                              const std::map<mreg_t, uint64_t> &regmap)
{
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    minsn_t *tail = blk->tail;
    if ( tail == nullptr )
      continue;
    if ( tail->opcode != m_jtbl && tail->opcode != m_ijmp )
      continue;

    // The cases live in the mop_c operand. For m_jtbl it is the r operand;
    // scan l/r/d defensively in case a maturity stores it elsewhere.
    const mcases_t *cases = nullptr;
    const mop_t *ops[3] = { &tail->r, &tail->l, &tail->d };
    for ( int o = 0; o < 3; ++o )
    {
      if ( ops[o]->t == mop_c && ops[o]->c != nullptr )
      {
        cases = ops[o]->c;
        break;
      }
    }
    if ( cases == nullptr || cases->empty() )
      continue;

    std::map<uint64_t, int> sm;
    size_t n = cases->size();
    for ( size_t k = 0; k < n; ++k )
    {
      int target = cases->targets[k];
      if ( target < 0 || target >= mba->qty )
        continue;
      const svalvec_t &vals = cases->values[k];
      for ( size_t v = 0; v < vals.size(); ++v )
      {
        uint64_t sc = uint64_t(vals[v]);
        sm[sc] = target;
        out->state_consts.insert(sc);
      }
    }

    if ( sm.size() < 2 )
      continue;

    out->block_idx = i;
    out->dispatcher_blocks.insert(i);
    out->state_map = sm;
    // The switch selector operand, when it is a register/stack slot.
    if ( tail->l.t == mop_r )
    {
      out->state_var.make_reg(tail->l.r, 4);
      out->state_reg = tail->l.r;
    }
    else
    {
      out->state_var = tail->l;
    }

    // Bridge to the D-810 emulated driver: a jump-table CFF is unflattened the
    // same way as a BST one -- each case block installs the next state constant
    // and loops back to the jtbl; we rewrite that back-edge to the case target
    // directly and prune the jtbl. Populate the per-block state map and mark the
    // dispatcher emulated so rewrite_cfg_emulated (GLBOPT, prune, duplication)
    // handles it instead of the legacy path.
    // Set up the state carrier so block_installed_state can find per-case
    // installs. The selector may be a register (trace it back to its mem/stack
    // source) OR, at GLBOPT, a stack slot (mop_S) directly.
    bool carrier_ok = false;
    if ( out->state_reg != mreg_t(-1) )
    {
      out->sel_has_transform = true;   // identity: the jtbl value IS the state
      out->sel_xor_key = 0;
      out->sel_add = 0;
      out->sel_reg_cmp = out->state_reg;
      out->sel_mem_state = false;
      out->sel_state_reg = out->state_reg;
      out->sel_state_sel = mop_t();
      out->sel_state_addr = mop_t();
      trace_jtbl_carrier(mba, i, out->state_reg, out);
      carrier_ok = true;
    }
    else if ( out->state_var.t == mop_S )
    {
      // Stack-slot selector (common at GLBOPT): the case blocks write the next
      // state directly to this stack var.
      out->sel_has_transform = true;
      out->sel_xor_key = 0;
      out->sel_add = 0;
      out->sel_reg_cmp = mreg_t(-1);
      out->sel_mem_state = true;
      out->sel_state_reg = mreg_t(-1);
      out->sel_state_sel = out->state_var;   // the mop_S itself
      out->sel_state_addr = mop_t();
      carrier_ok = true;
    }
    if ( carrier_ok )
    {
      // The m_jtbl cases are selector values. The emulated rewriter instead
      // consumes the raw constants installed by case blocks, so invert the
      // proven 32-bit selector transform before building its state map.
      std::map<uint64_t, int> raw_map;
      const bool raw_map_ok = invert_jtbl_cases(
          sm, out->sel_xor_key, out->sel_add, &raw_map);
      out->block_state.clear();
      int installs = 0;
      for ( int b = 0; raw_map_ok && b < mba->qty; ++b )
      {
        if ( b == i )
          continue;                    // skip the jtbl block itself
        uint64_t k = 0;
        if ( block_installed_state(mba, b, out, regmap, &k)
          && raw_map.count(k) != 0 )
        {
          out->block_state[b] = k;
          ++installs;
        }
      }
      static int rb2 = -1;
      if ( rb2 < 0 )
      {
        qstring ev;
        // Default ON (see the register-BST note above): bridge a jump-table CFF
        // to the crash-safe emulated driver. Opt out with UNSLOP_REGBST=0.
        rb2 = (qgetenv("UNSLOP_REGBST", &ev) && atoi(ev.c_str()) == 0) ? 0 : 1;
      }
      const bool pure = pure_jtbl_dispatcher(mba, i, *out);
      if ( rb2 != 0 && raw_map_ok && installs >= 2 && pure )
      {
        out->state_map = std::move(raw_map);
        out->state_consts.clear();
        for ( const auto &entry : out->state_map )
          out->state_consts.insert(entry.first);
        out->emulated = true;
        DLOG(L_INFO, "jump-table bridged to emulated driver: %d installs, %d cases",
             installs, int(out->state_map.size()));
      }
      else
      {
        out->block_state.clear();
        if ( !pure )
          DLOG(L_INFO, "jump-table state map is audit-only: dispatcher has "
                       "unproven side effects or live selector");
      }
    }
    return true;
  }
  return false;
}

// ── Strategy 3: whole-array state-variable heuristic ─────────────────
// No single high-fan-in block: find the block that compares one register
// against the most distinct constants (>= 3) and seed find_state_var there.

static int find_state_var_block(mba_t *mba,
                                const std::map<mreg_t, uint64_t> &reg_map)
{
  int best_block = -1;
  size_t best_count = 2; // need at least 3 distinct constants

  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    std::map<mreg_t, std::set<uint64_t>> cmp_regs;
    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( !is_cmp_op(ins->opcode) )
        continue;
      const mop_t *pairs[2][2] = { { &ins->l, &ins->r }, { &ins->r, &ins->l } };
      for ( int p = 0; p < 2; ++p )
      {
        const mop_t *sv_op = pairs[p][0];
        const mop_t *cv_op = pairs[p][1];
        if ( sv_op->t != mop_r )
          continue;
        uint64_t c;
        if ( resolve_const(cv_op, reg_map, &c) )
          cmp_regs[sv_op->r].insert(c);
      }
    }
    for ( const auto &kv : cmp_regs )
    {
      if ( kv.second.size() > best_count )
      {
        best_count = kv.second.size();
        best_block = i;
      }
    }
  }
  return best_block;
}

// ── Top-level detection ──────────────────────────────────────────────

bool detect_dispatcher(mba_t *mba, DispatcherInfo *out,
                       const std::map<mreg_t, uint64_t> &regmap)
{
  if ( out == nullptr )
    return false;
  *out = DispatcherInfo();
  if ( mba == nullptr || mba->qty < 6 )
    return false;

  // Strategy 4 (tried first, but only fires when a selector transform is
  // present): XOR-keyed binary-search-tree dispatcher, resolved by emulation.
  // DexProtector and OLLVM range-dispatch land here; functions without the
  // transform fall through untouched to the classic strategies below.
  {
    DispatcherInfo di;
    if ( detect_emulated_dispatcher(mba, &di, regmap) )
    {
      DLOG(L_DEBUG, "strategy 4 (emulated-BST) fired at block %d", di.block_idx);
      *out = di;
      return true;
    }
  }

  // Strategy 1: classic max-predecessor dispatcher.
  int disp = find_max_pred_block(mba);
  if ( disp >= 0 )
  {
    DispatcherInfo di;
    di.block_idx = disp;
    if ( find_state_var(mba, disp, &di, regmap) )
    {
      build_state_map(mba, &di, regmap);
      if ( di.state_map.size() >= 2 )
      {
        di.detection_strategy = 1;
        di.valid = true;
        DLOG(L_DEBUG, "strategy 1 (max-preds) fired at block %d", disp);
        *out = di;
        return true;
      }
    }
  }

  // Strategy 2: jump table (mcases).
  {
    DispatcherInfo di;
    if ( detect_jump_table(mba, &di, regmap) )
    {
      di.detection_strategy = 2;
      di.valid = true;
      DLOG(L_DEBUG, "strategy 2 (jump-table) fired at block %d", di.block_idx);
      *out = di;
      return true;
    }
  }

  // Strategy 3: state-variable heuristic across all blocks.
  int sv_block = find_state_var_block(mba, regmap);
  if ( sv_block >= 0 )
  {
    DispatcherInfo di;
    di.block_idx = sv_block;
    if ( find_state_var(mba, sv_block, &di, regmap) )
    {
      build_state_map(mba, &di, regmap);
      if ( di.state_map.size() >= 2 )
      {
        di.detection_strategy = 3;
        di.valid = true;
        DLOG(L_DEBUG, "strategy 3 (state-var heuristic) fired at block %d",
             sv_block);
        *out = di;
        return true;
      }
    }
  }

  return false;
}

} // namespace unslop
