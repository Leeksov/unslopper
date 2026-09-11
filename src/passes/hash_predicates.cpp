#include "hash_predicates.h"
#include <bytes.hpp>
#include <cstring>
#include <nalt.hpp>

namespace unslop
{
namespace
{
#include "ixguard_fnv_recipe.inc"
constexpr uint64_t seed_value = 0xc8dba56f43099739ULL;
constexpr ea_t helper_rva = 0x193e78, seed_rva = 0x2425fe8;
bool model_matches()
{
  unsigned char actual[sizeof(fnv_code)];
  ea_t base = get_imagebase();
  return get_bytes(actual, sizeof(actual), base + helper_rva) == sizeof(actual) &&
         std::memcmp(actual, fnv_code, sizeof(actual)) == 0 &&
         get_qword(base + seed_rva) == seed_value;
}
uint64_t fnv(uint32_t flag, uint32_t salt)
{
  uint64_t bits = (uint64_t(flag) << 32) | salt, h = 0xcbf29ce484222325ULL;
  for (int i = 0; i < 8; ++i)
    h = (h ^ ((bits >> (i * 8)) & 255)) * 0x100000001b3ULL;
  return h;
}
bool boolean(const mop_t &v, int depth = 12)
{
  if (depth <= 0)
    return false;
  if (v.t == mop_n)
    return v.nnn->value <= 1;
  if (v.t != mop_d || !v.d)
    return false;
  const auto &i = *v.d;
  switch (i.opcode)
  {
  case m_setz:
  case m_setnz:
  case m_seta:
  case m_setae:
  case m_setb:
  case m_setbe:
  case m_setg:
  case m_setge:
  case m_setl:
  case m_setle:
  case m_lnot:
    return true;
  case m_mov:
  case m_low:
  case m_xdu:
    return boolean(i.l, depth - 1);
  case m_and:
    if ((i.l.t == mop_n && i.l.nnn->value <= 1) || (i.r.t == mop_n && i.r.nnn->value <= 1))
      return true;
    return boolean(i.l, depth - 1) && boolean(i.r, depth - 1);
  case m_or:
  case m_xor:
    return boolean(i.l, depth - 1) && boolean(i.r, depth - 1);
  default:
    return false;
  }
}
bool boolean_at(const mop_t &v, mblock_t *blk, const minsn_t *before, int depth = 12)
{
  if (boolean(v))
    return true;
  if (depth <= 0 || (v.t != mop_r && v.t != mop_S))
    return false;
  for (auto p = before->prev; p; p = p->prev)
  {
    if (p->d == v)
    {
      if (p->opcode == m_mov || p->opcode == m_xdu || p->opcode == m_low)
        return boolean_at(p->l, blk, p, depth - 1);
      switch (p->opcode)
      {
      case m_setz:
      case m_setnz:
      case m_setb:
      case m_setbe:
      case m_seta:
      case m_setae:
      case m_setg:
      case m_setge:
      case m_setl:
      case m_setle:
      case m_lnot:
        return true;
      default:
        return false;
      }
    }
    if (p->d.t == v.t)
    {
      if (v.t == mop_r && p->d.r < v.r + v.size && v.r < p->d.r + p->d.size)
        return false;
      if (v.t == mop_S && p->d.s && v.s && p->d.s->off < v.s->off + v.size &&
          v.s->off < p->d.s->off + p->d.size)
        return false;
    }
    if (p->has_side_effects(true))
      return false;
  }
  return false;
}
int visit(minsn_t *i, mblock_t *blk, const minsn_t *root, bool snapshot, bool valid, int &matched,
          std::string &reason)
{
  if (!i)
    return 0;
  int n = 0;
  if (i->l.t == mop_d)
    n += visit(i->l.d, blk, root, snapshot, valid, matched, reason);
  if (i->r.t == mop_d)
    n += visit(i->r.d, blk, root, snapshot, valid, matched, reason);
  if (i->d.t == mop_d)
    n += visit(i->d.d, blk, root, snapshot, valid, matched, reason);
  if (i->opcode != m_jz && i->opcode != m_jnz && i->opcode != m_setz && i->opcode != m_setnz)
    return n;
  mop_t *call = &i->l, *constant = &i->r;
  if (call->t == mop_n)
    std::swap(call, constant);
  if (call->t != mop_d || !call->d || constant->t != mop_n || constant->size != 8)
    return n;
  auto c = call->d;
  if (c->opcode != m_call || c->l.t != mop_v || c->l.g != get_imagebase() + helper_rva ||
      c->d.t != mop_f || !c->d.f || c->d.f->args.size() != 2)
    return n;
  ++matched;
  if (!valid)
  {
    reason = "recipe_bytes_or_seed_mismatch";
    return n;
  }
  if (!snapshot)
  {
    reason = "fixed_seed_snapshot_required";
    return n;
  }
  auto &flag = c->d.f->args[0];
  auto &salt = c->d.f->args[1];
  if (flag.size != 4 || salt.size != 4 || salt.t != mop_n || !boolean_at(flag, blk, root))
  {
    reason = "boolean_domain_or_constant_salt_not_proven";
    return n;
  }
  uint64_t a = fnv(0, uint32_t(salt.nnn->value)), b = fnv(1, uint32_t(salt.nnn->value));
  if (a == b || (constant->nnn->value != a && constant->nnn->value != b))
  {
    reason = "comparison_not_a_unique_boolean_hash";
    return n;
  }
  uint64_t wanted = constant->nnn->value == a ? 0 : 1;
  mop_t replacement = flag;
  i->l = replacement;
  i->r.make_number(wanted, 4, i->ea);
  reason = "folded_under_audited_fixed_seed_snapshot";
  return n + 1;
}
} // namespace
int simplify_hash_predicates(mba_t *mba, bool snapshot, int *matched, std::string *reason)
{
  int count = 0, seen = 0;
  bool valid = model_matches();
  std::string why = "no_recipe_call_comparison";
  for (int b = 0; b < mba->qty; ++b)
  {
    auto blk = mba->get_mblock(b);
    int n = 0;
    for (auto i = blk->head; i; i = i->next)
      n += visit(i, blk, i, snapshot, valid, seen, why);
    if (n)
      blk->mark_lists_dirty();
    count += n;
  }
  if (count)
    mba->mark_chains_dirty();
  *matched = seen;
  *reason = why;
  return count;
}
} // namespace unslop
