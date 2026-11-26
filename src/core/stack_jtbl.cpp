#include "stack_jtbl.h"
#include "affine_context_gate.h"
#include "block_dup.h"
#include "unslop_log.h"
#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <vector>

namespace unslop
{
static thread_local bool g_affine_context_trial_active = false;
bool affine_context_trial_active() { return g_affine_context_trial_active; }
namespace
{
// Values are local scalars, never file-backed globals. Width is part of the
// identity; overlapping writes invalidate older facts rather than aliasing
// neighbouring microregisters by a heuristic.
struct Var
{
  int kind = 0, size = 0;
  uint64_t off = 0;
  bool operator==(const Var &b) const { return kind == b.kind && size == b.size && off == b.off; }
  bool operator<(const Var &b) const
  {
    return std::tie(kind, off, size) < std::tie(b.kind, b.off, b.size);
  }
};
using Vars = std::set<Var>;
using Env = std::map<Var, uint64_t>;
std::optional<Var> variable(const mop_t &m)
{
  if (m.size < 1 || m.size > 8)
    return {};
  if (m.t == mop_r)
    return Var{1, m.size, uint64_t(m.r)};
  if (m.t == mop_S && m.s)
    return Var{2, m.size, uint64_t(m.s->off)};
  return {};
}
bool overlaps(const Var &a, const Var &b)
{
  return a.kind == b.kind && a.off < b.off + b.size && b.off < a.off + a.size;
}
uint64_t mask(int size) { return size >= 8 ? ~uint64_t(0) : (uint64_t(1) << (size * 8)) - 1; }
bool call_in(const mop_t &m);
bool call_in(const minsn_t &i)
{
  return i.opcode == m_call || i.opcode == m_icall || call_in(i.l) || call_in(i.r) || call_in(i.d);
}
bool call_in(const mop_t &m) { return m.t == mop_d && m.d && call_in(*m.d); }
bool pure(mcode_t op)
{
  switch (op)
  {
  case m_mov:
  case m_low:
  case m_xdu:
  case m_xds:
  case m_neg:
  case m_bnot:
  case m_lnot:
  case m_add:
  case m_sub:
  case m_mul:
  case m_or:
  case m_and:
  case m_xor:
  case m_shl:
  case m_shr:
  case m_sar:
    return true;
  case m_setz:
  case m_setnz:
  case m_setb:
  case m_setbe:
  case m_seta:
  case m_setae:
    return true;
  default:
    return false;
  }
}
void uses(const mop_t &m, Vars &v)
{
  auto x = variable(m);
  if (x)
    v.insert(*x);
  else if (m.t == mop_d && m.d && pure(m.d->opcode))
  {
    uses(m.d->l, v);
    uses(m.d->r, v);
  }
}
std::optional<uint64_t> value(const mop_t &, const Env &, int);
// Exact byte coverage, needed for e.g. a one-byte boolean definition followed
// by `(w8.4 & 1)`. Unknown upper bytes must NOT become zero by assumption.
std::optional<uint64_t> masked_value(const mop_t &m, const Env &env, uint64_t wanted)
{
  auto v = variable(m);
  if (!v)
    return {};
  uint64_t bits = 0, known = 0;
  for (auto &kv : env)
  {
    if (!overlaps(*v, kv.first))
      continue;
    uint64_t lo = std::max(v->off, kv.first.off);
    uint64_t hi = std::min(v->off + v->size, kv.first.off + kv.first.size);
    for (uint64_t p = lo; p < hi; ++p)
    {
      int shift = int(p - v->off) * 8;
      known |= uint64_t(255) << shift;
      bits |= ((kv.second >> ((p - kv.first.off) * 8)) & 255) << shift;
    }
  }
  return (known & wanted) == wanted ? std::optional<uint64_t>(bits & wanted) : std::nullopt;
}
std::optional<uint64_t> evaluate(const minsn_t &i, const Env &env, int depth, int width)
{
  if (depth <= 0 || !pure(i.opcode))
    return {};
  if (i.opcode == m_and)
  {
    auto b = value(i.r, env, depth - 1);
    if (b)
    {
      auto a = masked_value(i.l, env, *b);
      if (a)
        return *a & mask(width);
    }
    auto a = value(i.l, env, depth - 1);
    if (a)
    {
      auto b2 = masked_value(i.r, env, *a);
      if (b2)
        return *b2 & mask(width);
    }
  }
  auto a = value(i.l, env, depth - 1);
  if (!a)
    return {};
  uint64_t r = 0;
  switch (i.opcode)
  {
  case m_mov:
  case m_low:
  case m_xdu:
    r = *a;
    break;
  case m_xds:
  {
    int n = i.l.size * 8;
    if (n < 1 || n > 64)
      return {};
    uint64_t sign = uint64_t(1) << (n - 1);
    r = (*a ^ sign) - sign;
    break;
  }
  case m_neg:
    r = 0 - *a;
    break;
  case m_bnot:
    r = ~*a;
    break;
  case m_lnot:
    r = !*a;
    break;
  default:
  {
    auto b = value(i.r, env, depth - 1);
    if (!b)
      return {};
    switch (i.opcode)
    {
    case m_add:
      r = *a + *b;
      break;
    case m_sub:
      r = *a - *b;
      break;
    case m_mul:
      r = *a * *b;
      break;
    case m_and:
      r = *a & *b;
      break;
    case m_or:
      r = *a | *b;
      break;
    case m_xor:
      r = *a ^ *b;
      break;
    case m_setz:
      r = *a == *b;
      break;
    case m_setnz:
      r = *a != *b;
      break;
    case m_setb:
      r = *a < *b;
      break;
    case m_setbe:
      r = *a <= *b;
      break;
    case m_seta:
      r = *a > *b;
      break;
    case m_setae:
      r = *a >= *b;
      break;
    case m_shl:
      if (*b >= uint64_t(width * 8))
        return {};
      r = *a << *b;
      break;
    case m_shr:
      if (*b >= uint64_t(i.l.size * 8))
        return {};
      r = *a >> *b;
      break;
    case m_sar:
    {
      if (*b >= uint64_t(i.l.size * 8))
        return {};
      uint64_t sign = uint64_t(1) << (i.l.size * 8 - 1);
      r = uint64_t(int64_t((*a ^ sign) - sign) >> *b);
      break;
    }
    default:
      return {};
    }
  }
  }
  return r & mask(width);
}
std::optional<uint64_t> value(const mop_t &m, const Env &env, int depth)
{
  if (depth <= 0 || m.size < 1 || m.size > 8)
    return {};
  if (m.t == mop_n)
    return m.nnn->value & mask(m.size);
  auto v = variable(m);
  if (v)
    return masked_value(m, env, mask(m.size));
  if (m.t == mop_d && m.d)
    return evaluate(*m.d, env, depth - 1, m.size);
  return {};
}
// The established stack-state planner treats indirect stores as a full fact
// barrier. The opt-in register-state planner may preserve only register facts
// across m_stx: memory writes cannot modify a microregister, but may alias any
// stack slot. Keep the old stack-state behavior unchanged by default.
bool barrier(const minsn_t &i) { return call_in(i) || i.opcode == m_stx || i.opcode == m_ext; }
Vars transfer_need(mblock_t *b, Vars need, bool preserve_reg_across_stx = false)
{
  for (auto i = b->tail; i; i = i->prev)
  {
    if (preserve_reg_across_stx && i->opcode == m_stx
      && affine_store_keeps_register_facts(call_in(*i)))
    {
      for (auto it = need.begin(); it != need.end();)
        it = it->kind == 2 ? need.erase(it) : std::next(it);
      continue; // i.d is the STORE ADDRESS, not a register definition
    }
    auto d = variable(i->d);
    bool demanded = d && need.count(*d);
    if (d)
      for (auto it = need.begin(); it != need.end();)
      {
        if (overlaps(*d, *it))
          it = need.erase(it);
        else
          ++it;
      }
    if (barrier(*i))
      need.clear();
    if (demanded && pure(i->opcode) && !barrier(*i))
    {
      uses(i->l, need);
      uses(i->r, need);
    }
  }
  return need;
}
void run_body(mblock_t *b, Env &env, bool preserve_reg_across_stx = false)
{
  for (auto i = b->head; i; i = i->next)
  {
    if (preserve_reg_across_stx && i->opcode == m_stx
      && affine_store_keeps_register_facts(call_in(*i)))
    {
      for (auto it = env.begin(); it != env.end();)
        it = it->first.kind == 2 ? env.erase(it) : std::next(it);
      continue; // preserve registers; i.d is the memory address operand
    }
    if (barrier(*i))
      env.clear();
    auto d = variable(i->d);
    if (!d)
      continue;
    auto result = evaluate(*i, env, 32, d->size);
    for (auto it = env.begin(); it != env.end();)
    {
      if (overlaps(*d, it->first))
        it = env.erase(it);
      else
        ++it;
    }
    if (result)
      env[*d] = *result;
  }
}
struct Key
{
  int block;
  Env env;
  bool operator<(const Key &b) const
  {
    if (block != b.block)
      return block < b.block;
    return env < b.env;
  }
};
struct Node
{
  Key key;
  std::vector<int> succ;
  bool dispatch = false;
  bool ordinary_jtbl = false;
  int parent = -1; // first discovered predecessor context (diagnostic only)
  std::optional<uint64_t> selector;
};
void goto_only(mblock_t *b, int dst, bool replace_tail)
{
  insert_goto_instruction(b, dst, replace_tail);
  b->type = BLT_1WAY;
  b->flags |= MBL_GOTO;
  b->succset.clear();
  b->succset.push_back(dst);
  b->mark_lists_dirty();
}
} // namespace

int unflatten_stack_jtbl(mba_t *mba,StackJtblDiagnostics *diagnostics)
{
  auto reject=[&](const char *why){if(diagnostics)diagnostics->reason=why;return 0;};
  qstring disabled;
  if (qgetenv("UNSLOP_NO_STACK_JTBL", &disabled) && disabled == "1")
    return reject("disabled");
  if (mba->maturity != MMAT_GLBOPT1)
    return reject("deferred_until_glbopt1");
  const int original = mba->qty;
  if (original < 6 || original > 2000)
    return reject("input_block_limit");
  int disp = -1;
  Var carrier;
  std::set<int> equality_dispatchers;
  std::map<uint64_t, int> cases;
  for (int b = 1; b < original - 1; ++b)
  {
    auto blk = mba->get_mblock(b);
    auto t = blk->tail;
    if (!t || t->opcode != m_jtbl)
      continue;
    auto v = variable(t->l);
    if (!v || v->kind != 2 || t->r.t != mop_c || !t->r.c)
      return reject("unsupported_selector");
    if (disp != -1)
      return reject("multiple_dispatchers"); // no cross-dispatcher inference
    // Hex-Rays can retain the range-check flags before a switch. They are
    // copied verbatim, including when a case uses those flags later.
    for (auto i = blk->head; i && i != t; i = i->next)
    {
      auto d = variable(i->d);
      if (barrier(*i) || (d && overlaps(*d, *v)))
        return reject("dispatcher_side_effect_or_carrier_write");
    }
    bool has_default = false;
    for (int j = 0; j < int(t->r.c->size()); ++j)
    {
      auto &vals = t->r.c->values[j];
      int target = t->r.c->targets[j];
      if (vals.empty())
      {
        has_default = true;
        continue;
      }
      for (auto n : vals)
        cases[uint64_t(n) & mask(v->size)] = target;
    }
    if (!has_default || cases.size() < 4 || blk->npred() < 3)
      return reject("not_cff_shape");
    disp = b;
    carrier = *v;
  }
  if (disp < 0)
  {
    // BShield/OLLVM also lowers a 64-bit stack state to a chain of equality
    // branches. Reuse the exact-width context planner, never the 32-bit BST
    // arithmetic. Only pure compare blocks may become dispatch boundaries.
    std::map<Var, std::vector<int>> groups;
    for (int b = 1; b < original - 1; ++b)
    {
      auto blk = mba->get_mblock(b);
      auto t = blk->tail;
      if (!t || (t->opcode != m_jz && t->opcode != m_jnz)
          || t->r.t != mop_n || t->d.t != mop_b || blk->nsucc() != 2)
        continue;
      auto v = variable(t->l);
      if (!v || v->kind != 2 || (v->size != 4 && v->size != 8)
          || t->r.size != v->size)
        continue;
      bool clean = true;
      for (auto i = blk->head; i && i != t; i = i->next)
        if (i->opcode != m_nop) clean = false;
      if (clean) groups[*v].push_back(b);
    }
    for (const auto &group : groups)
    {
      std::set<uint64_t> constants;
      int head = -1;
      for (int b : group.second)
      {
        auto blk = mba->get_mblock(b);
        uint64_t k = blk->tail->r.nnn->value & mask(group.first.size);
        constants.insert(k);
        if (blk->npred() >= 3) head = b;
      }
      if (head < 0 || constants.size() < 4) continue;
      if (disp >= 0) return reject("multiple_equality_carriers");
      disp = head;
      carrier = group.first;
      equality_dispatchers.insert(group.second.begin(), group.second.end());
      for (auto k : constants) cases[k] = -1; // inventory only; branch locally
    }
    if (disp < 0) return reject("no_stack_dispatcher");
  }
  auto is_dispatch = [&](int b) {
    return equality_dispatchers.empty() ? b == disp : equality_dispatchers.count(b) != 0;
  };
  if(diagnostics)diagnostics->cases=int(cases.size());
  // Demand only the scalar data feeding the next dispatcher, not application
  // predicates/counters. This merges payload contexts instead of unrolling
  // real loops. The dispatcher is a liveness boundary.
  std::vector<Vars> need(original);
  for (int b = 1; b < original - 1; ++b)
    if (is_dispatch(b)) need[b].insert(carrier);
  bool changed = true;
  int iter = 0;
  for (; changed && iter < original * 2; ++iter)
  {
    changed = false;
    for (int b = original - 2; b > 0; --b)
    {
      if (is_dispatch(b))
        continue;
      Vars n;
      auto blk = mba->get_mblock(b);
      for (int j = 0; j < blk->nsucc(); ++j)
      {
        int s = blk->succ(j);
        n.insert(need[s].begin(), need[s].end());
      }
      n = transfer_need(blk, n);
      if (n != need[b])
      {
        need[b] = n;
        changed = true;
      }
    }
  }
  if (changed)
    return reject("demand_did_not_converge");
  // Pure planning: an unknown reachable selector, unsupported terminator or
  // growth cap leaves the entire original graph untouched.
  std::vector<Node> nodes;
  std::map<Key, int> seen;
  auto intern = [&](int block, const Env &env)
  {
    if (block == original - 1)
      return -1;
    Key key{block, {}};
    for (auto &v : need[block])
      for (auto &kv : env)
        if (overlaps(v, kv.first))
          key.env.insert(kv);
    auto old = seen.find(key);
    if (old != seen.end())
      return old->second;
    int id = int(nodes.size());
    seen.emplace(key, id);
    nodes.push_back({key, {}, is_dispatch(block)});
    return id;
  };
  if (mba->get_mblock(0)->nsucc() != 1 || mba->get_mblock(0)->succ(0) != 1)
    return reject("unsupported_entry");
  intern(1, {});
  int dispatches = 0;
  for (size_t i = 0; i < nodes.size(); ++i)
  {
    if (nodes.size() > 4096 || nodes.size() > size_t(original * 16))
    {
      DLOG(L_INFO, "stack-jtbl: context budget exceeded");
      return reject("context_budget");
    }
    int b = nodes[i].key.block;
    auto blk = mba->get_mblock(b);
    Env env = nodes[i].key.env;
    run_body(blk, env);
    std::vector<int> succ;
    if (is_dispatch(b))
    {
      auto v = env.find(carrier);
      if (v == env.end() || (equality_dispatchers.empty() && !cases.count(v->second)))
      {
        DLOG(L_INFO, "stack-jtbl: unresolved selector in context %d (%d nodes)", int(i),
             int(nodes.size()));
        for (size_t k = 0; k < nodes.size() && k < 24; ++k)
          DLOG(L_INFO, "  context %d original block %d facts %d", int(k), nodes[k].key.block,
               int(nodes[k].key.env.size()));
        return reject("unknown_or_unmapped_selector");
      }
      if (equality_dispatchers.empty())
        succ.push_back(intern(cases.at(v->second), env));
      else
      {
        auto t = blk->tail;
        bool eq = v->second == (t->r.nnn->value & mask(carrier.size));
        bool taken = t->opcode == m_jz ? eq : !eq;
        succ.push_back(intern(taken ? t->d.b : b + 1, env));
      }
      ++dispatches;
    }
    else if (blk->nsucc() == 2)
    {
      auto t = blk->tail;
      if (!t || !is_mcode_jcond(t->opcode) || t->d.t != mop_b)
        return reject("unsupported_conditional_exit");
      succ.push_back(intern(t->d.b, env));
      succ.push_back(intern(b + 1, env));
    }
    else if (blk->nsucc() == 1)
    {
      if (blk->tail && (blk->tail->opcode == m_ijmp || blk->tail->opcode == m_jtbl))
        return reject("unresolved_indirect_exit");
      succ.push_back(intern(blk->succ(0), env));
    }
    else if (blk->nsucc() != 0)
      return reject("unsupported_successor_count");
    nodes[i].succ = succ;
  }
  if (dispatches < 2)
    return reject("insufficient_dispatch_contexts");
  if(diagnostics)diagnostics->contexts=int(nodes.size());
  DLOG(L_INFO, "stack-jtbl: fully proved %d dispatch contexts; %d original blocks -> %d contexts",
       dispatches, original, int(nodes.size()));
  auto emit = [&](mba_t *mba)
  {
    // Keep originals until Hex-Rays' DCE; no remove_block at GLBOPT. Each
    // conditional receives a physical fallthrough trampoline. Rebuild all
    // predecessor lists after emission, including the untouched original graph.
    auto exit = mba->get_mblock(original - 1);
    std::vector<mblock_t *> clones, bridges;
    for (auto &n : nodes)
    {
      auto c = mba->copy_block(mba->get_mblock(n.key.block), mba->qty - 1, CPBLK_MINREF);
      clones.push_back(c);
      mblock_t *bridge = nullptr;
      if (n.succ.size() == 2)
      {
        bridge = mba->copy_block(c, mba->qty - 1, CPBLK_MINREF);
        for (auto j = bridge->head; j; j = j->next)
          bridge->make_nop(j);
      }
      bridges.push_back(bridge);
    }
    auto serial = [&](int id) { return id < 0 ? exit->serial : clones[id]->serial; };
    for (size_t i = 0; i < nodes.size(); ++i)
    {
      auto c = clones[i];
      auto &n = nodes[i];
      c->predset.clear();
      c->succset.clear();
      if (n.succ.size() == 2)
      {
        c->tail->d.make_blkref(serial(n.succ[0]));
        c->succset.push_back(bridges[i]->serial);
        c->succset.push_back(serial(n.succ[0]));
        goto_only(bridges[i], serial(n.succ[1]), false);
      }
      else if (n.succ.size() == 1)
      {
        bool replace = c->tail && (c->tail->opcode == m_jtbl || c->tail->opcode == m_goto || n.dispatch);
        goto_only(c, serial(n.succ[0]), replace);
      }
      c->mark_lists_dirty();
    }
    auto entry = mba->get_mblock(1);
    for (auto i = entry->head; i; i = i->next)
      entry->make_nop(i);
    goto_only(entry, clones[0]->serial, false);
    for (int i = 0; i < mba->qty; ++i)
      mba->get_mblock(i)->predset.clear();
    for (int i = 0; i < mba->qty; ++i)
    {
      auto b = mba->get_mblock(i);
      for (int j = 0; j < b->nsucc(); ++j)
      {
        auto s = mba->get_mblock(b->succ(j));
        if (!s->predset.has(i))
          s->predset.push_back(i);
      }
    }
    mba->mark_chains_dirty();
    mba->verify(true);
  };
  // Validate the exact edit on a detached snapshot first. A verifier refusal
  // must never leave a partially edited live array for the next optimizer.
  try
  {
    bytevec_t serialized;
    mba->serialize(&serialized);
    std::unique_ptr<mba_t> trial(mba_t::deserialize(serialized.begin(), serialized.size()));
    if (!trial)
      return reject("trial_deserialization_failed");
    emit(trial.get());
  }
  catch (...)
  {
    DLOG(L_WARN, "stack-jtbl: trial graph rejected; original kept intact");
    return reject("trial_verifier_rejected");
  }
  emit(mba);
  dump_mba_to_file(mba, "stack_jtbl_emitted");
  if(diagnostics)diagnostics->reason="complete";
  return dispatches;
}

// Experimental register-affine variant of the all-or-nothing context planner.
// Unlike a father->case edge shortcut, cloned dispatcher contexts execute the
// full original dispatcher body, including every register/memory side effect.
// A second ordinary switch is preserved as a switch with context-local targets.
int unflatten_affine_context_jtbl(mba_t *mba, StackJtblDiagnostics *diagnostics)
{
  if (g_affine_context_trial_active)
    return 0;
  auto reject = [&](const char *why) {
    if (diagnostics) diagnostics->reason = why;
    DLOG(L_INFO, "affine-context rejected: %s", why);
    return 0;
  };
  qstring enabled;
  if (!qgetenv("UNSLOP_AFFINE_CONTEXT", &enabled) || enabled != "1")
    return reject("disabled");
  if (mba == nullptr || mba->maturity != MMAT_GLBOPT1)
    return reject("deferred_until_glbopt1");
  const int original = mba->qty;
  if (original < 6 || original > 1000)
    return reject("input_block_limit");

  int disp = -1;
  Var raw_state, branch_selector;
  std::map<uint64_t, int> cases;
  for (int b = 1; b < original - 1; ++b)
  {
    mblock_t *blk = mba->get_mblock(b);
    minsn_t *tail = blk->tail;
    if (tail == nullptr || tail->opcode != m_jtbl || blk->npred() < 3)
      continue;
    if (tail->l.t != mop_r || tail->l.size != 8
      || tail->r.t != mop_c || tail->r.c == nullptr)
      continue;
    const auto selector = variable(tail->l);
    if (!selector)
      continue;
    const minsn_t *definition = nullptr;
    for (minsn_t *ins = blk->head; ins != tail; ins = ins->next)
    {
      if (ins == nullptr)
        return reject("malformed_dispatcher_body");
      const auto dst = variable(ins->d);
      if (dst && overlaps(*dst, *selector))
        definition = ins; // LAST overlapping selector definition wins
    }
    if (definition == nullptr || definition->opcode != m_xdu
      || definition->d.t != mop_r || definition->d.r != tail->l.r
      || definition->l.t != mop_d || definition->l.d == nullptr)
      continue;
    const minsn_t &arith = *definition->l.d;
    if ((arith.opcode != m_sub && arith.opcode != m_add)
      || arith.l.t != mop_r || arith.l.size != 4
      || arith.r.t != mop_n || arith.r.size != 4
      || arith.d.size != 4)
      continue;
    if (disp != -1)
      return reject("multiple_affine_dispatchers");

    std::map<uint64_t, int> candidate_cases;
    bool has_default = false;
    for (int j = 0; j < int(tail->r.c->size()); ++j)
    {
      const int target = tail->r.c->targets[j];
      if (target < 0 || target >= original)
        return reject("invalid_case_target");
      const auto &vals = tail->r.c->values[j];
      if (vals.empty()) { has_default = true; continue; }
      for (auto n : vals)
      {
        const uint64_t key = uint64_t(n);
        if (key > 0xFFFFFFFFull)
          return reject("case_outside_32bit_selector");
        auto old = candidate_cases.find(key);
        if (old != candidate_cases.end() && old->second != target)
          return reject("conflicting_case_target");
        candidate_cases[key] = target;
      }
    }
    if (!has_default || candidate_cases.size() < 4)
      continue;
    // Larger affine tables are expensive to trial and have not produced a
    // verified recovery in this corpus. Reject before context construction
    // or any detached optimizer work; 128 still exceeds every edited fixture.
    disp = b;
    raw_state = *variable(arith.l);
    branch_selector = *selector;
    cases = std::move(candidate_cases);
    DLOG(L_INFO, "affine-context: dispatcher %d raw-reg=%llu selector-reg=%llu cases=%d",
         disp, (unsigned long long)raw_state.off,
         (unsigned long long)branch_selector.off, int(cases.size()));
  }
  if (disp < 0)
    return reject("no_affine_dispatcher");
  if (diagnostics) diagnostics->cases = int(cases.size());

  // Project only facts that can influence the next raw-state input. The
  // selector temporary is computed inside the dispatcher from that input.
  std::vector<Vars> need(original);
  need[disp].insert(raw_state);
  bool changed = true;
  for (int iter = 0; changed && iter < original * 2; ++iter)
  {
    changed = false;
    for (int b = original - 2; b > 0; --b)
    {
      if (b == disp)
        continue;
      Vars n;
      mblock_t *blk = mba->get_mblock(b);
      for (int j = 0; j < blk->nsucc(); ++j)
      {
        const int s = blk->succ(j);
        if (s < 0 || s >= original)
          return reject("invalid_successor");
        n.insert(need[s].begin(), need[s].end());
      }
      n = transfer_need(blk, n, true);
      if (n != need[b]) { need[b] = std::move(n); changed = true; }
    }
  }
  if (changed)
    return reject("demand_did_not_converge");

  std::vector<Node> nodes;
  std::map<Key, int> seen;
  int active_parent = -1;
  auto intern = [&](int block, const Env &env)
  {
    if (block == original - 1)
      return -1;
    Key key{block, {}};
    for (const auto &v : need[block])
      for (const auto &kv : env)
        if (overlaps(v, kv.first)) key.env.insert(kv);
    const auto old = seen.find(key);
    if (old != seen.end()) return old->second;
    const int id = int(nodes.size());
    seen.emplace(key, id);
    nodes.push_back({key, {}, block == disp, false, active_parent});
    return id;
  };
  if (mba->get_mblock(0)->nsucc() != 1 || mba->get_mblock(0)->succ(0) != 1)
    return reject("unsupported_entry");
  intern(1, {});
  int dispatches = 0;
  for (size_t i = 0; i < nodes.size(); ++i)
  {
    if (nodes.size() > 2048 || nodes.size() > size_t(original * 12))
      return reject("context_budget");
    active_parent = int(i);
    const int b = nodes[i].key.block;
    mblock_t *blk = mba->get_mblock(b);
    Env env = nodes[i].key.env;
    run_body(blk, env, true);
    std::vector<int> succ;
    if (b == disp)
    {
      const auto case_value = masked_value(blk->tail->l, env, mask(branch_selector.size));
      if (!case_value || cases.count(*case_value) == 0)
      {
        DLOG(L_INFO, "affine-context: unresolved selector at context %d block %d",
             int(i), b);
        for (int p = int(i), depth = 0; p >= 0 && depth < 24; p = nodes[p].parent, ++depth)
        {
          const Node &ancestor = nodes[p];
          DLOG(L_INFO, "  path[%d] context=%d original_block=%d facts=%d",
               depth, p, ancestor.key.block, int(ancestor.key.env.size()));
          for (const auto &fact : ancestor.key.env)
            DLOG(L_INFO, "    fact kind=%d off=%llu width=%d value=0x%llx",
                 fact.first.kind, (unsigned long long)fact.first.off,
                 fact.first.size, (unsigned long long)fact.second);
        }
        return reject("unknown_or_unmapped_selector");
      }
      succ.push_back(intern(cases.at(*case_value), env));
      ++dispatches;
    }
    else if (blk->tail && blk->tail->opcode == m_jtbl)
    {
      const mcases_t *table = blk->tail->r.t == mop_c ? blk->tail->r.c : nullptr;
      if (table == nullptr || table->size() < 2 || table->size() > 64)
        return reject("unsupported_ordinary_jtbl");
      std::set<int> table_targets;
      for (int j = 0; j < int(table->size()); ++j)
      {
        const int target = table->targets[j];
        if (target < 0 || target >= original)
          return reject("invalid_ordinary_case_target");
        table_targets.insert(target);
        succ.push_back(intern(target, env));
      }
      if (table_targets.size() != size_t(blk->nsucc()))
        return reject("ordinary_case_successor_mismatch");
      for (int j = 0; j < blk->nsucc(); ++j)
        if (table_targets.count(blk->succ(j)) == 0)
          return reject("ordinary_case_successor_mismatch");
      nodes[i].ordinary_jtbl = true;
    }
    else if (blk->nsucc() == 2)
    {
      minsn_t *t = blk->tail;
      if (t == nullptr || !is_mcode_jcond(t->opcode) || t->d.t != mop_b)
        return reject("unsupported_conditional_exit");
      succ.push_back(intern(t->d.b, env));
      succ.push_back(intern(b + 1, env));
    }
    else if (blk->nsucc() == 1)
    {
      if (blk->tail && blk->tail->opcode == m_ijmp)
        return reject("unresolved_indirect_exit");
      succ.push_back(intern(blk->succ(0), env));
    }
    else if (blk->nsucc() != 0)
      return reject("unsupported_successor_count");
    nodes[i].succ = std::move(succ);
  }
  if (dispatches < 2)
    return reject("insufficient_dispatch_contexts");
  if (diagnostics) diagnostics->contexts = int(nodes.size());
  DLOG(L_INFO, "affine-context: proved %d dispatches across %d contexts",
       dispatches, int(nodes.size()));

  auto emit = [&](mba_t *work)
  {
    mblock_t *exit = work->get_mblock(original - 1);
    std::vector<mblock_t *> clones, bridges;
    for (const Node &n : nodes)
    {
      mblock_t *c = work->copy_block(work->get_mblock(n.key.block), work->qty - 1,
                                    CPBLK_MINREF);
      if (c == nullptr) throw 1;
      clones.push_back(c);
      mblock_t *bridge = nullptr;
      if (n.succ.size() == 2 && !n.ordinary_jtbl)
      {
        bridge = work->copy_block(c, work->qty - 1, CPBLK_MINREF);
        if (bridge == nullptr) throw 1;
        for (minsn_t *j = bridge->head; j; j = j->next)
          bridge->make_nop(j);
      }
      bridges.push_back(bridge);
    }
    auto serial = [&](int id) { return id < 0 ? exit->serial : clones[id]->serial; };
    for (size_t i = 0; i < nodes.size(); ++i)
    {
      mblock_t *c = clones[i];
      const Node &n = nodes[i];
      c->predset.clear();
      c->succset.clear();
      if (n.ordinary_jtbl)
      {
        if (c->tail == nullptr || c->tail->opcode != m_jtbl
          || c->tail->r.t != mop_c || c->tail->r.c == nullptr
          || c->tail->r.c->size() != n.succ.size()) throw 1;
        const mblock_t *source = work->get_mblock(n.key.block);
        if (source->tail == nullptr || source->tail->r.t != mop_c
          || source->tail->r.c == nullptr || source->tail->r.c == c->tail->r.c)
          throw 1; // copy_block must not alias the original case table
        const std::vector<int> original_targets(
            source->tail->r.c->targets.begin(), source->tail->r.c->targets.end());
        for (size_t j = 0; j < n.succ.size(); ++j)
        {
          const int dst = serial(n.succ[j]);
          c->tail->r.c->targets[j] = dst;
          if (!c->succset.has(dst)) c->succset.push_back(dst);
        }
        if (source->tail->r.c->targets.size() != original_targets.size()) throw 1;
        for (size_t j = 0; j < original_targets.size(); ++j)
          if (source->tail->r.c->targets[j] != original_targets[j]) throw 1;
      }
      else if (n.succ.size() == 2)
      {
        c->tail->d.make_blkref(serial(n.succ[0]));
        c->succset.push_back(bridges[i]->serial);
        c->succset.push_back(serial(n.succ[0]));
        goto_only(bridges[i], serial(n.succ[1]), false);
      }
      else if (n.succ.size() == 1)
      {
        const bool replace = c->tail &&
          (c->tail->opcode == m_jtbl || c->tail->opcode == m_goto || n.dispatch);
        goto_only(c, serial(n.succ[0]), replace);
      }
      c->mark_lists_dirty();
    }
    mblock_t *entry = work->get_mblock(1);
    for (minsn_t *i = entry->head; i; i = i->next) entry->make_nop(i);
    goto_only(entry, clones[0]->serial, false);
    for (int i = 0; i < work->qty; ++i) work->get_mblock(i)->predset.clear();
    for (int i = 0; i < work->qty; ++i)
    {
      mblock_t *b = work->get_mblock(i);
      for (int j = 0; j < b->nsucc(); ++j)
      {
        mblock_t *s = work->get_mblock(b->succ(j));
        if (!s->predset.has(i)) s->predset.push_back(i);
      }
    }
    work->mark_chains_dirty();
    work->verify(true);
  };
  const ea_t original_dispatcher_ea = mba->get_mblock(disp)->start;
  auto reachable_dispatcher = [&](mba_t *work)
  {
    std::vector<char> reached(work->qty, 0);
    std::vector<int> queue{0};
    reached[0] = 1;
    for (size_t qi = 0; qi < queue.size(); ++qi)
    {
      const int b = queue[qi];
      mblock_t *blk = work->get_mblock(b);
      if (blk->start == original_dispatcher_ea && blk->tail
        && blk->tail->opcode == m_jtbl)
        return true;
      for (int j = 0; j < blk->nsucc(); ++j)
      {
        const int s = blk->succ(j);
        if (s < 0 || s >= work->qty)
          return true; // malformed graph is not an acceptable rewrite
        if (!reached[s]) { reached[s] = 1; queue.push_back(s); }
      }
    }
    return false;
  };
  try
  {
    bytevec_t serialized;
    mba->serialize(&serialized);
    std::unique_ptr<mba_t> trial(mba_t::deserialize(serialized.begin(), serialized.size()));
    if (!trial) return reject("trial_deserialization_failed");
    emit(trial.get());
    if (reachable_dispatcher(trial.get()))
      return reject("residual_dispatcher_reachable_before_opt");
    // Diagnostic only: ask Hex-Rays to continue global optimization on the
    // detached rewritten array. A normal verifier does not catch INTERR 50342
    // later at GLBOPT3 in the observed libloader build.
    g_affine_context_trial_active = true;
    DLOG(L_INFO, "affine-context: downstream trial begin maturity=%d qty=%d",
         int(trial->maturity), trial->qty);
    const merror_t later = trial->optimize_global();
    g_affine_context_trial_active = false;
    DLOG(L_INFO, "affine-context: downstream trial return=%d maturity=%d qty=%d",
         int(later), int(trial->maturity), trial->qty);
    if (!affine_trial_completed(int(later), int(trial->maturity),
                                int(MMAT_GLBOPT2)))
      return reject("trial_downstream_optimizer_rejected");
    trial->verify(true);
    if (reachable_dispatcher(trial.get()))
      return reject("residual_dispatcher_reachable_after_opt");
  }
  catch (...)
  {
    g_affine_context_trial_active = false;
    DLOG(L_WARN, "affine-context: detached trial rejected");
    return reject("trial_verifier_rejected");
  }
  QASSERT(59992, (emit(mba), true));
  if (diagnostics) diagnostics->reason = "complete";
  return dispatches;
}
// Bounded, read-only state-map proof for direct-register jump tables. This is
// intentionally separate from the affine emitter above: no edit operation is
// reachable from this function.
IdentityAuditResult audit_identity_jtbl(mba_t *mba)
{
  IdentityAuditResult out;
  auto reject = [&](const char *reason) {
    out.reason = reason;
    out.cases.clear();
    out.dispatch_contexts.clear();
    return out;
  };
  if (mba == nullptr || mba->maturity != MMAT_GLBOPT1)
    return reject("wrong_maturity");
  const int original = mba->qty;
  if (original < 6 || original > 1000)
    return reject("input_block_limit");

  int disp = -1;
  Var raw_state, branch_selector;
  std::map<uint64_t, int> cases;
  for (int b = 1; b < original - 1; ++b)
  {
    mblock_t *blk = mba->get_mblock(b);
    minsn_t *tail = blk->tail;
    if (tail == nullptr || tail->opcode != m_jtbl || blk->npred() < 3
      || tail->l.t != mop_r || (tail->l.size != 4 && tail->l.size != 8)
      || tail->r.t != mop_c || tail->r.c == nullptr)
      continue;
    const auto selector = variable(tail->l);
    if (!selector)
      continue;
    const minsn_t *definition = nullptr;
    for (minsn_t *ins = blk->head; ins != tail; ins = ins->next)
    {
      if (ins == nullptr)
        return reject("malformed_dispatcher_body");
      const auto dst = variable(ins->d);
      if (dst && overlaps(*dst, *selector))
        definition = ins;
    }
    Var candidate_raw;
    if (definition == nullptr)
      candidate_raw = *selector;
    else
    {
      if (definition->d.t != mop_r || definition->d.r != tail->l.r
        || definition->d.size != tail->l.size || definition->l.t != mop_r)
        continue;
      const int input_size = definition->l.size;
      const int output_size = definition->d.size;
      const bool transparent =
        (definition->opcode == m_mov && input_size == output_size)
        || (definition->opcode == m_low && input_size >= output_size)
        || (definition->opcode == m_xdu && input_size < output_size);
      if (!transparent)
        continue;
      const auto source = variable(definition->l);
      if (!source)
        continue;
      candidate_raw = *source;
    }
    std::map<uint64_t, int> candidate_cases;
    for (int j = 0; j < int(tail->r.c->size()); ++j)
    {
      const int target = tail->r.c->targets[j];
      if (target < 0 || target >= original)
        return reject("invalid_case_target");
      for (auto n : tail->r.c->values[j])
      {
        const uint64_t key = uint64_t(n);
        if (key > mask(tail->l.size)
          || (definition != nullptr && definition->opcode == m_xdu
              && key > mask(candidate_raw.size)))
          return reject("case_outside_selector_width");
        const auto old = candidate_cases.find(key);
        if (old != candidate_cases.end() && old->second != target)
          return reject("conflicting_case_target");
        candidate_cases[key] = target;
        if (candidate_cases.size() > 128)
        {
          out.dispatcher_block = b;
          out.dispatcher_ea = blk->start;
          return reject("case_budget");
        }
      }
    }
    if (candidate_cases.size() < 4)
      continue;
    // A conventional switch may also use a register. Require two distinct
    // case targets with paths back to this very dispatcher.
    std::set<int> feedback_targets;
    for (const auto &kv : candidate_cases)
    {
      const int first = kv.second;
      if (feedback_targets.count(first))
        continue;
      std::vector<char> visited(original, 0);
      std::vector<int> queue{first};
      visited[first] = 1;
      for (size_t qi = 0; qi < queue.size(); ++qi)
      {
        const int cur = queue[qi];
        if (cur == b) { feedback_targets.insert(first); break; }
        if (cur == original - 1) continue;
        const mblock_t *next = mba->get_mblock(cur);
        for (int si = 0; si < next->nsucc(); ++si)
        {
          const int dst = next->succ(si);
          if (dst < 0 || dst >= original)
            return reject("invalid_feedback_successor");
          if (!visited[dst]) { visited[dst] = 1; queue.push_back(dst); }
        }
      }
    }
    if (feedback_targets.size() < 2)
      continue;
    if (disp != -1)
      return reject("multiple_candidate_dispatchers");
    disp = b;
    out.dispatcher_block = b;
    out.dispatcher_ea = blk->start;
    if (candidate_cases.size() > 128)
      return reject("case_budget");
    raw_state = candidate_raw;
    branch_selector = *selector;
    cases = std::move(candidate_cases);
  }
  if (disp < 0)
    return reject("no_identity_dispatcher");

  std::vector<Vars> need(original);
  need[disp].insert(raw_state);
  bool changed = true;
  for (int iter = 0; changed && iter < original * 2; ++iter)
  {
    changed = false;
    for (int b = original - 2; b > 0; --b)
    {
      if (b == disp) continue;
      Vars n;
      mblock_t *blk = mba->get_mblock(b);
      for (int j = 0; j < blk->nsucc(); ++j)
      {
        const int s = blk->succ(j);
        if (s < 0 || s >= original)
          return reject("invalid_successor");
        n.insert(need[s].begin(), need[s].end());
      }
      n = transfer_need(blk, n, true);
      if (n != need[b]) { need[b] = std::move(n); changed = true; }
    }
  }
  if (changed)
    return reject("demand_did_not_converge");

  std::vector<Node> nodes;
  std::map<Key, int> seen;
  int active_parent = -1;
  auto intern = [&](int block, const Env &env)
  {
    if (block == original - 1)
      return -1;
    Key key{block, {}};
    for (const auto &v : need[block])
      for (const auto &kv : env)
        if (overlaps(v, kv.first)) key.env.insert(kv);
    const auto old = seen.find(key);
    if (old != seen.end()) return old->second;
    const int id = int(nodes.size());
    seen.emplace(key, id);
    nodes.push_back({key, {}, block == disp, false, active_parent});
    return id;
  };
  if (mba->get_mblock(0)->nsucc() != 1 || mba->get_mblock(0)->succ(0) != 1)
    return reject("unsupported_entry");
  intern(1, {});
  int dispatches = 0;
  for (size_t i = 0; i < nodes.size(); ++i)
  {
    if (nodes.size() > 2048 || nodes.size() > size_t(original * 12))
      return reject("context_budget");
    active_parent = int(i);
    const int b = nodes[i].key.block;
    mblock_t *blk = mba->get_mblock(b);
    Env env = nodes[i].key.env;
    run_body(blk, env, true);
    std::vector<int> succ;
    if (b == disp)
    {
      const auto value = masked_value(blk->tail->l, env, mask(branch_selector.size));
      if (!value || cases.count(*value) == 0)
        return reject("unknown_or_unmapped_selector");
      succ.push_back(intern(cases.at(*value), env));
      nodes[i].selector = *value;
      ++dispatches;
    }
    else if (blk->tail && blk->tail->opcode == m_jtbl)
    {
      const mcases_t *table = blk->tail->r.t == mop_c ? blk->tail->r.c : nullptr;
      if (table == nullptr || table->size() < 2 || table->size() > 64)
        return reject("unsupported_ordinary_jtbl");
      std::set<int> table_targets;
      for (int j = 0; j < int(table->size()); ++j)
      {
        const int target = table->targets[j];
        if (target < 0 || target >= original)
          return reject("invalid_ordinary_case_target");
        table_targets.insert(target);
        succ.push_back(intern(target, env));
      }
      if (table_targets.size() != size_t(blk->nsucc()))
        return reject("ordinary_case_successor_mismatch");
      for (int j = 0; j < blk->nsucc(); ++j)
        if (table_targets.count(blk->succ(j)) == 0)
          return reject("ordinary_case_successor_mismatch");
      nodes[i].ordinary_jtbl = true;
    }
    else if (blk->nsucc() == 2)
    {
      const minsn_t *t = blk->tail;
      if (t == nullptr || !is_mcode_jcond(t->opcode) || t->d.t != mop_b
        || t->d.b < 0 || t->d.b >= original || b + 1 >= original)
        return reject("unsupported_conditional_exit");
      const int first = blk->succ(0), second = blk->succ(1);
      if (t->d.b == b + 1
        || !((first == t->d.b && second == b + 1)
          || (second == t->d.b && first == b + 1)))
        return reject("conditional_successor_mismatch");
      succ.push_back(intern(t->d.b, env));
      succ.push_back(intern(b + 1, env));
    }
    else if (blk->nsucc() == 1)
    {
      if (blk->tail && blk->tail->opcode == m_ijmp)
        return reject("unresolved_indirect_exit");
      const int dst = blk->succ(0);
      if (dst < 0 || dst >= original)
        return reject("invalid_successor");
      succ.push_back(intern(dst, env));
    }
    else if (blk->nsucc() != 0)
      return reject("unsupported_successor_count");
    nodes[i].succ = std::move(succ);
  }
  if (dispatches < 2)
    return reject("insufficient_dispatch_contexts");
  out.reason = "proved";
  out.contexts = int(nodes.size());
  for (const auto &kv : cases)
    out.cases.push_back({kv.first, kv.second, mba->get_mblock(kv.second)->start});
  for (size_t i = 0; i < nodes.size(); ++i)
  {
    const Node &n = nodes[i];
    if (!n.dispatch)
      continue;
    if (!n.selector || n.succ.size() != 1)
      return reject("malformed_proved_context");
    const int next_context = n.succ[0];
    const int target_block = next_context < 0
      ? original - 1 : nodes[next_context].key.block;
    out.dispatch_contexts.push_back({int(i), *n.selector, next_context,
                                     target_block, mba->get_mblock(target_block)->start});
  }
  return out;
}
} // namespace unslop
