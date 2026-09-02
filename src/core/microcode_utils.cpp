#include "microcode_utils.h"

namespace unslop {

bool is_num(const mop_t *m)
{
  return m != nullptr && m->t == mop_n;
}

uint64_t num_val(const mop_t *m, uint64_t def)
{
  if ( !is_num(m) || m->nnn == nullptr )
    return def;
  return m->nnn->value;
}

bool mop_equal(const mop_t *a, const mop_t *b)
{
  if ( a == nullptr || b == nullptr || a->t != b->t )
    return false;
  if ( a->t == mop_r )
    return a->r == b->r;
  if ( a->t == mop_S )
    return a->s != nullptr && b->s != nullptr && a->s->off == b->s->off;
  if ( a->t == mop_n )
    return num_val(a) == num_val(b);
  return false;
}

int insn_count(const mblock_t *blk)
{
  int n = 0;
  for ( const minsn_t *i = blk->head; i != nullptr; i = i->next )
    ++n;
  return n;
}

bool is_cond_jump(mcode_t op)
{
  return op >= m_jcnd && op <= m_jle;
}

int64_t s32(uint64_t v)
{
  v &= 0xFFFFFFFFull;
  return v >= 0x80000000ull ? int64_t(v) - 0x100000000ll : int64_t(v);
}

void build_reg_const_map(mba_t *mba, std::map<mreg_t, uint64_t> *out)
{
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( ins->opcode == m_mov && is_num(&ins->l) && ins->d.t == mop_r )
        (*out)[ins->d.r] = num_val(&ins->l);
    }
  }
}

} // namespace unslop
