#include "ixguard_mba.h"

namespace unslop
{
namespace
{
const minsn_t *op(const mop_t &m, mcode_t code)
{
  return m.t == mop_d && m.d && m.d->opcode == code ? m.d : nullptr;
}
bool imm(const mop_t &m, uint64_t n) { return m.t == mop_n && m.nnn->value == n; }
const mop_t *twice(const mop_t &m)
{
  if (auto p = op(m, m_mul))
  {
    if (imm(p->l, 2))
      return &p->r;
    if (imm(p->r, 2))
      return &p->l;
  }
  if (auto p = op(m, m_shl))
    if (imm(p->r, 1))
      return &p->l;
  return nullptr;
}
bool same_value(const mop_t &a, const mop_t &b)
{
  if (a.t != b.t || a.size != b.size)
    return false;
  if (a.valnum && b.valnum && a.valnum != b.valnum)
    return false;
  if (a.t == mop_v)
    return a.g == b.g && a.valnum && a.valnum == b.valnum;
  if (a.t == mop_d && a.d && b.d)
    return a.d->opcode == b.d->opcode && same_value(a.d->l, b.d->l) && same_value(a.d->r, b.d->r);
  return a == b;
}
bool pair(const minsn_t *a, const minsn_t *b)
{
  return a && b &&
         ((same_value(a->l, b->l) && same_value(a->r, b->r)) ||
          (same_value(a->l, b->r) && same_value(a->r, b->l)));
}
// Match only uniform-width, side-effect-free value trees. In particular, do
// not remove repeated calls or indirect/possibly faulting memory reads.
bool safe(const mop_t &m, int width)
{
  if (m.size != width || m.has_side_effects(true))
    return false;
  if (m.t == mop_r || m.t == mop_S || m.t == mop_n)
    return true;
  if (m.t == mop_v)
    return m.valnum != 0;
  if (m.t != mop_d || !m.d)
    return false;
  switch (m.d->opcode)
  {
  case m_neg:
  case m_bnot:
    return safe(m.d->l, width);
  case m_add:
  case m_sub:
  case m_xor:
  case m_or:
  case m_and:
  case m_mul:
    return safe(m.d->l, width) && safe(m.d->r, width);
  default:
    return false;
  }
}
void rewrite(minsn_t *i, mcode_t code, const mop_t &a, const mop_t &b)
{
  mop_t ca = a, cb = b;
  i->opcode = code;
  i->l = ca;
  i->r = cb;
}
int node(minsn_t *i)
{
  if (!i)
    return 0;
  int n = 0;
  if (i->l.t == mop_d)
    n += node(i->l.d);
  if (i->r.t == mop_d)
    n += node(i->r.d);
  if (i->d.t == mop_d)
    n += node(i->d.d);
  int w = i->l.size;
  if ((w != 1 && w != 2 && w != 4 && w != 8) || i->r.size != w)
    return n;
  const minsn_t *a = nullptr, *b = nullptr;
  mcode_t code = m_nop;
  if (i->opcode == m_sub)
  {
    auto t = twice(i->l);
    a = t ? op(*t, m_or) : nullptr;
    b = op(i->r, m_xor);
    if (pair(a, b))
      code = m_add; // 2*(a|b)-(a^b) == a+b
  }
  if (i->opcode == m_add)
  {
    a = op(i->l, m_or);
    b = op(i->r, m_and);
    if (!pair(a, b))
    {
      a = op(i->r, m_or);
      b = op(i->l, m_and);
    }
    if (pair(a, b))
      code = m_add; // (a|b)+(a&b) == a+b
    if (code == m_nop)
    {
      auto t = twice(i->r);
      a = op(i->l, m_xor);
      b = t ? op(*t, m_and) : nullptr;
      if (!pair(a, b))
      {
        t = twice(i->l);
        a = op(i->r, m_xor);
        b = t ? op(*t, m_and) : nullptr;
      }
      if (pair(a, b))
        code = m_add;
    }
  }
  if (code != m_nop && a->l.size == w && a->r.size == w && safe(a->l, w) && safe(a->r, w))
  {
    rewrite(i, code, a->l, a->r);
    return n + 1;
  }
  return n;
}
} // namespace
int simplify_ixguard_mba(mba_t *mba)
{
  int changes = 0;
  for (int b = 0; b < mba->qty; ++b)
  {
    auto blk = mba->get_mblock(b);
    int n = 0;
    for (auto i = blk->head; i; i = i->next)
      n += node(i);
    if (n)
      blk->mark_lists_dirty();
    changes += n;
  }
  if (changes)
    mba->mark_chains_dirty();
  return changes;
}
} // namespace unslop
