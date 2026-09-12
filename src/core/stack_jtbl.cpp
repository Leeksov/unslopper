#include "stack_jtbl.h"
#include "block_dup.h"
#include "unslop_log.h"
#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <vector>

namespace unslop
{
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
// Calls/indirect writes are barriers. This deliberately rejects contexts
// whose proof would require alias assumptions or a process-memory snapshot.
bool barrier(const minsn_t &i) { return call_in(i) || i.opcode == m_stx || i.opcode == m_ext; }
Vars transfer_need(mblock_t *b, Vars need)
{
  for (auto i = b->tail; i; i = i->prev)
  {
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
void run_body(mblock_t *b, Env &env)
{
  for (auto i = b->head; i; i = i->next)
  {
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
} // namespace unslop
