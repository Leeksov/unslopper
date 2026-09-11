#include "mba_simplify.h"
#include "microcode_utils.h"

#include <cstdint>

namespace unslop {

//--------------------------------------------------------------------------
// Small numeric helpers.
//--------------------------------------------------------------------------

// Return `s` if it is a valid microcode operand byte size (1,2,4,8), else 0.
static int good_size(int s)
{
  return (s == 1 || s == 2 || s == 4 || s == 8) ? s : 0;
}

// Pick a sensible destination size for a folded constant.
static int pick_size(const minsn_t *ins)
{
  int s = good_size(ins->d.size);
  if ( s == 0 )
    s = good_size(ins->l.size);
  if ( s == 0 )
    s = good_size(ins->r.size);
  return s == 0 ? 4 : s;
}

static uint64_t size_mask(int size)
{
  if ( size <= 0 || size >= 8 )
    return ~uint64_t(0);
  return (uint64_t(1) << (size * 8)) - 1;
}

static int64_t sign_ext(uint64_t v, int size)
{
  if ( size <= 0 || size >= 8 )
    return int64_t(v);
  uint64_t m = uint64_t(1) << (size * 8 - 1);
  v &= size_mask(size);
  return int64_t((v ^ m) - m);
}

//--------------------------------------------------------------------------
// Constant evaluation over the microcode expression tree.
//--------------------------------------------------------------------------

static bool eval_insn_const(const minsn_t *ins, uint64_t *out);

// True if the operand resolves to a compile-time constant; value stored in out.
static bool eval_const(const mop_t *m, uint64_t *out)
{
  if ( m == nullptr )
    return false;
  if ( m->t == mop_n )
  {
    *out = num_val(m);
    return true;
  }
  if ( m->t == mop_d && m->d != nullptr )
    return eval_insn_const(m->d, out);
  return false;
}

// Evaluate an instruction to a constant if all of its inputs are constant.
static bool eval_insn_const(const minsn_t *ins, uint64_t *out)
{
  if ( ins == nullptr )
    return false;
  uint64_t a = 0;
  uint64_t b = 0;
  switch ( ins->opcode )
  {
    case m_mov:
      return eval_const(&ins->l, out);
    case m_neg:
      if ( eval_const(&ins->l, &a) ) { *out = uint64_t(-int64_t(a)); return true; }
      return false;
    case m_bnot:
      if ( eval_const(&ins->l, &a) ) { *out = ~a; return true; }
      return false;
    case m_lnot:
      if ( eval_const(&ins->l, &a) ) { *out = (a == 0) ? 1 : 0; return true; }
      return false;
    case m_add:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) ) { *out = a + b; return true; }
      return false;
    case m_sub:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) ) { *out = a - b; return true; }
      return false;
    case m_mul:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) ) { *out = a * b; return true; }
      return false;
    case m_or:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) ) { *out = a | b; return true; }
      return false;
    case m_and:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) ) { *out = a & b; return true; }
      return false;
    case m_xor:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) ) { *out = a ^ b; return true; }
      return false;
    case m_shl:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) ) { *out = a << (b & 63); return true; }
      return false;
    case m_shr:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) ) { *out = a >> (b & 63); return true; }
      return false;
    case m_sar:
      if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b) )
      {
        *out = uint64_t(sign_ext(a, ins->l.size) >> (b & 63));
        return true;
      }
      return false;
    default:
      return false;
  }
}

// Evaluate a relational operator (used both by set* and jXX opcodes).
static bool eval_compare(mcode_t op, uint64_t a, uint64_t b, int size, bool *res)
{
  uint64_t ua = a & size_mask(size);
  uint64_t ub = b & size_mask(size);
  int64_t sa = sign_ext(a, size);
  int64_t sb = sign_ext(b, size);
  switch ( op )
  {
    case m_jz:   case m_setz:  *res = (ua == ub); return true;
    case m_jnz:  case m_setnz: *res = (ua != ub); return true;
    case m_jae:  case m_setae: *res = (ua >= ub); return true;
    case m_jb:   case m_setb:  *res = (ua <  ub); return true;
    case m_ja:   case m_seta:  *res = (ua >  ub); return true;
    case m_jbe:  case m_setbe: *res = (ua <= ub); return true;
    case m_jg:   case m_setg:  *res = (sa >  sb); return true;
    case m_jge:  case m_setge: *res = (sa >= sb); return true;
    case m_jl:   case m_setl:  *res = (sa <  sb); return true;
    case m_jle:  case m_setle: *res = (sa <= sb); return true;
    default:
      return false;
  }
}

// Prove the outcome of a conditional jump. Returns true if the branch outcome
// is a constant; *taken set to 1 if the jump is taken, 0 if it falls through.
static bool eval_condition(const minsn_t *ins, int *taken)
{
  mcode_t op = ins->opcode;
  if ( op == m_jcnd )
  {
    const mop_t *c = &ins->l;
    if ( is_num(c) )
    {
      *taken = num_val(c) != 0 ? 1 : 0;
      return true;
    }
    if ( c->t == mop_d && c->d != nullptr )
    {
      const minsn_t *sub = c->d;
      uint64_t a = 0;
      uint64_t b = 0;
      bool res = false;
      // A comparison subinstruction with two constant operands.
      if ( eval_const(&sub->l, &a) && eval_const(&sub->r, &b)
        && eval_compare(sub->opcode, a, b, sub->l.size, &res) )
      {
        *taken = res ? 1 : 0;
        return true;
      }
      // Or an arithmetic subexpression that folds to a constant boolean.
      uint64_t v = 0;
      if ( eval_insn_const(sub, &v) )
      {
        *taken = v != 0 ? 1 : 0;
        return true;
      }
    }
    return false;
  }
  if ( op >= m_jnz && op <= m_jle )
  {
    uint64_t a = 0;
    uint64_t b = 0;
    bool res = false;
    if ( eval_const(&ins->l, &a) && eval_const(&ins->r, &b)
      && eval_compare(op, a, b, ins->l.size, &res) )
    {
      *taken = res ? 1 : 0;
      return true;
    }
    return false;
  }
  return false;
}

//--------------------------------------------------------------------------
// MBA identity matching.
//--------------------------------------------------------------------------

// If `m` embeds a subinstruction with opcode `op`, return it, else nullptr.
static const minsn_t *as_insn(const mop_t *m, mcode_t op)
{
  if ( m != nullptr && m->t == mop_d && m->d != nullptr && m->d->opcode == op )
    return m->d;
  return nullptr;
}

// True if two binary instructions operate on the same (unordered) operand pair.
static bool same_pair(const minsn_t *a, const minsn_t *b)
{
  return (a->l == b->l && a->r == b->r)
      || (a->l == b->r && a->r == b->l);
}

// Rewrite `ins` in place to `op x, y` (keeping its destination). x and y are
// deep-copied up front so the assignments cannot alias freed subinstructions.
static void rewrite_binop(minsn_t *ins, mcode_t op, const mop_t &x, const mop_t &y)
{
  mop_t nx = x;
  mop_t ny = y;
  ins->opcode = op;
  ins->l = nx;
  ins->r = ny;
}

// Rewrite `ins` in place to a unary `op x` (m_neg / m_bnot / m_mov), keeping
// the destination. x is copied up front to avoid aliasing a freed subtree.
static void rewrite_unop(minsn_t *ins, mcode_t op, const mop_t &x)
{
  mop_t nx = x;
  ins->opcode = op;
  ins->l = nx;
  ins->r.erase();
}

// True if `m` is an immediate whose sign-extended value equals `want`.
static bool is_const_val(const mop_t *m, int64_t want)
{
  if ( !is_num(m) )
    return false;
  return sign_ext(num_val(m), m->size) == want;
}

// Inner operand of a unary m_neg subtree (i.e. the x of -x), or nullptr.
static const mop_t *neg_operand(const mop_t *m)
{
  const minsn_t *n = as_insn(m, m_neg);
  return n != nullptr ? &n->l : nullptr;
}

// Inner operand of a unary m_bnot subtree (i.e. the x of ~x), or nullptr.
static const mop_t *bnot_operand(const mop_t *m)
{
  const minsn_t *n = as_insn(m, m_bnot);
  return n != nullptr ? &n->l : nullptr;
}

// If `m` is `k * y` (or `y * k`) with k a constant, return &y, else nullptr.
static const mop_t *mul_by_operand(const mop_t *m, int64_t k)
{
  const minsn_t *mul = as_insn(m, m_mul);
  if ( mul == nullptr )
    return nullptr;
  if ( is_const_val(&mul->l, k) )
    return &mul->r;
  if ( is_const_val(&mul->r, k) )
    return &mul->l;
  return nullptr;
}

// If exactly one operand of binary `bin` is a subinstruction with opcode `op`,
// return it via *sub and the OTHER operand via *other. Tries both orders.
static bool split_one(const minsn_t *bin, mcode_t op,
                      const minsn_t **sub, const mop_t **other)
{
  const minsn_t *s = as_insn(&bin->l, op);
  if ( s != nullptr ) { *sub = s; *other = &bin->r; return true; }
  s = as_insn(&bin->r, op);
  if ( s != nullptr ) { *sub = s; *other = &bin->l; return true; }
  return false;
}

// Decompose a binary insn shaped like `X op ~Y` into plain=X and notinner=Y.
static bool split_with_not(const minsn_t *bin, mop_t *plain, mop_t *notinner)
{
  const minsn_t *nb = nullptr;
  const mop_t *oth = nullptr;
  if ( !split_one(bin, m_bnot, &nb, &oth) )
    return false;
  *plain = *oth;
  *notinner = nb->l;
  return true;
}

// Apply the classic MBA identities to a single node. Returns 1 if it changed.
static int try_mba_identity(minsn_t *ins)
{
  switch ( ins->opcode )
  {
    case m_add:
    {
      // (x|y) + (x&y)  =>  x + y
      const minsn_t *orI  = as_insn(&ins->l, m_or);
      const minsn_t *andI = as_insn(&ins->r, m_and);
      if ( orI == nullptr || andI == nullptr )
      {
        orI  = as_insn(&ins->r, m_or);
        andI = as_insn(&ins->l, m_and);
      }
      if ( orI != nullptr && andI != nullptr && same_pair(orI, andI) )
      {
        rewrite_binop(ins, m_add, orI->l, orI->r);
        return 1;
      }

      // (x^y) + 2*(x&y)  =>  x + y
      const minsn_t *xorI = as_insn(&ins->l, m_xor);
      const minsn_t *mulI = as_insn(&ins->r, m_mul);
      if ( xorI == nullptr || mulI == nullptr )
      {
        xorI = as_insn(&ins->r, m_xor);
        mulI = as_insn(&ins->l, m_mul);
      }
      if ( xorI != nullptr && mulI != nullptr )
      {
        const minsn_t *andI2 = nullptr;
        if ( is_num(&mulI->l) && num_val(&mulI->l) == 2 )
          andI2 = as_insn(&mulI->r, m_and);
        else if ( is_num(&mulI->r) && num_val(&mulI->r) == 2 )
          andI2 = as_insn(&mulI->l, m_and);
        if ( andI2 != nullptr && same_pair(xorI, andI2) )
        {
          rewrite_binop(ins, m_add, xorI->l, xorI->r);
          return 1;
        }
      }

      // a + (-b)  =>  a - b   ;   (-a) + b  =>  b - a
      {
        const mop_t *nb = neg_operand(&ins->r);
        if ( nb != nullptr )
        {
          rewrite_binop(ins, m_sub, ins->l, *nb);
          return 1;
        }
        const mop_t *na = neg_operand(&ins->l);
        if ( na != nullptr )
        {
          rewrite_binop(ins, m_sub, ins->r, *na);
          return 1;
        }
      }

      // (a+b+1) + ~(a&b)  =>  a | b
      {
        const minsn_t *nb = nullptr;
        const mop_t *oth = nullptr;
        if ( split_one(ins, m_bnot, &nb, &oth) )
        {
          const minsn_t *andI3 = as_insn(&nb->l, m_and);
          const minsn_t *addTop = as_insn(oth, m_add);
          if ( andI3 != nullptr && addTop != nullptr )
          {
            const minsn_t *innerAdd = nullptr;
            if ( is_const_val(&addTop->r, 1) )
              innerAdd = as_insn(&addTop->l, m_add);
            else if ( is_const_val(&addTop->l, 1) )
              innerAdd = as_insn(&addTop->r, m_add);
            if ( innerAdd != nullptr && same_pair(innerAdd, andI3) )
            {
              rewrite_binop(ins, m_or, andI3->l, andI3->r);
              return 1;
            }
          }
        }
      }

      // patterns carrying a literal +1:  ~x+1 => -x ,  (a+~b)+1 => a-b
      {
        const mop_t *rest = nullptr;
        if ( is_const_val(&ins->r, 1) )
          rest = &ins->l;
        else if ( is_const_val(&ins->l, 1) )
          rest = &ins->r;
        if ( rest != nullptr )
        {
          const mop_t *nx = bnot_operand(rest);
          if ( nx != nullptr )
          {
            rewrite_unop(ins, m_neg, *nx);
            return 1;
          }
          const minsn_t *addI3 = as_insn(rest, m_add);
          if ( addI3 != nullptr )
          {
            const minsn_t *nb = nullptr;
            const mop_t *oth = nullptr;
            if ( split_one(addI3, m_bnot, &nb, &oth) )
            {
              rewrite_binop(ins, m_sub, *oth, nb->l);
              return 1;
            }
          }
        }
      }

      // x + 0  =>  x
      if ( is_num(&ins->r) && num_val(&ins->r) == 0 )
      {
        ins->opcode = m_mov;
        ins->r.erase();
        return 1;
      }
      if ( is_num(&ins->l) && num_val(&ins->l) == 0 )
      {
        ins->l.swap(ins->r);
        ins->opcode = m_mov;
        ins->r.erase();
        return 1;
      }
      break;
    }

    case m_sub:
    {
      // (x|y) - (x&y)  =>  x ^ y   (sub is not commutative: l=or, r=and)
      const minsn_t *orI  = as_insn(&ins->l, m_or);
      const minsn_t *andI = as_insn(&ins->r, m_and);
      if ( orI != nullptr && andI != nullptr && same_pair(orI, andI) )
      {
        rewrite_binop(ins, m_xor, orI->l, orI->r);
        return 1;
      }
      // (x+y) - (x|y)  =>  x & y
      const minsn_t *addI = as_insn(&ins->l, m_add);
      const minsn_t *orI2 = as_insn(&ins->r, m_or);
      if ( addI != nullptr && orI2 != nullptr && same_pair(addI, orI2) )
      {
        rewrite_binop(ins, m_and, addI->l, addI->r);
        return 1;
      }

      // a - (-b)  =>  a + b
      {
        const mop_t *nb = neg_operand(&ins->r);
        if ( nb != nullptr )
        {
          rewrite_binop(ins, m_add, ins->l, *nb);
          return 1;
        }
      }

      // -x - 1  =>  ~x
      if ( is_const_val(&ins->r, 1) )
      {
        const mop_t *nx = neg_operand(&ins->l);
        if ( nx != nullptr )
        {
          rewrite_unop(ins, m_bnot, *nx);
          return 1;
        }
      }

      // a - (~b + 1) => a + b (since ~b+1 == -b).
      // The former ~b-1 / ~b+(-1) pattern was wrong by two modulo 2^N.
      {
        const minsn_t *rsub = as_insn(&ins->r, m_sub);
        if ( rsub != nullptr && is_const_val(&rsub->r, -1) )
        {
          const mop_t *bb = bnot_operand(&rsub->l);
          if ( bb != nullptr )
          {
            rewrite_binop(ins, m_add, ins->l, *bb);
            return 1;
          }
        }
        const minsn_t *radd = as_insn(&ins->r, m_add);
        if ( radd != nullptr )
        {
          const minsn_t *nb = nullptr;
          const mop_t *oth = nullptr;
          if ( split_one(radd, m_bnot, &nb, &oth) && is_const_val(oth, 1) )
          {
            rewrite_binop(ins, m_add, ins->l, nb->l);
            return 1;
          }
        }
      }

      // (a & ~b) - (~a & b)  =>  a - b
      {
        const minsn_t *lA = as_insn(&ins->l, m_and);
        const minsn_t *rA = as_insn(&ins->r, m_and);
        if ( lA != nullptr && rA != nullptr )
        {
          mop_t lp, ln, rp, rn;
          if ( split_with_not(lA, &lp, &ln) && split_with_not(rA, &rp, &rn)
            && lp == rn && ln == rp )
          {
            rewrite_binop(ins, m_sub, lp, ln);
            return 1;
          }
        }
      }

      // 2*(a & ~b) - (a ^ b)  =>  a - b
      {
        const mop_t *m2 = mul_by_operand(&ins->l, 2);
        const minsn_t *xr = as_insn(&ins->r, m_xor);
        if ( m2 != nullptr && xr != nullptr )
        {
          const minsn_t *andI2 = as_insn(m2, m_and);
          mop_t p, ni;
          if ( andI2 != nullptr && split_with_not(andI2, &p, &ni)
            && ( (xr->l == p && xr->r == ni) || (xr->l == ni && xr->r == p) ) )
          {
            rewrite_binop(ins, m_sub, p, ni);
            return 1;
          }
        }
      }

      // (a + b) - 2*(a & b)  =>  a ^ b
      {
        const minsn_t *addI2 = as_insn(&ins->l, m_add);
        const mop_t *m2 = mul_by_operand(&ins->r, 2);
        if ( addI2 != nullptr && m2 != nullptr )
        {
          const minsn_t *andI2 = as_insn(m2, m_and);
          if ( andI2 != nullptr && same_pair(addI2, andI2) )
          {
            rewrite_binop(ins, m_xor, addI2->l, addI2->r);
            return 1;
          }
        }
      }

      // a - (2*(b & ~(a ^ b)) - b)  =>  a ^ b
      {
        const minsn_t *R = as_insn(&ins->r, m_sub);
        if ( R != nullptr )
        {
          const mop_t *m2 = mul_by_operand(&R->l, 2);
          const mop_t *bB = &R->r;
          if ( m2 != nullptr )
          {
            const minsn_t *andI2 = as_insn(m2, m_and);
            const minsn_t *nb = nullptr;
            const mop_t *oth = nullptr;
            if ( andI2 != nullptr && split_one(andI2, m_bnot, &nb, &oth)
              && *oth == *bB )
            {
              const minsn_t *xr = as_insn(&nb->l, m_xor);
              if ( xr != nullptr )
              {
                const mop_t *aA = nullptr;
                if ( xr->l == *bB )
                  aA = &xr->r;
                else if ( xr->r == *bB )
                  aA = &xr->l;
                if ( aA != nullptr )
                {
                  rewrite_binop(ins, m_xor, *aA, *bB);
                  return 1;
                }
              }
            }
          }
        }
      }
      break;
    }

    case m_bnot:
    {
      // ~~x  =>  x
      const minsn_t *inner = as_insn(&ins->l, m_bnot);
      if ( inner != nullptr )
      {
        mop_t x = inner->l;
        ins->opcode = m_mov;
        ins->l = x;
        ins->r.erase();
        return 1;
      }

      // ~(~a | ~b)  =>  a & b       (De Morgan)
      {
        const minsn_t *orI = as_insn(&ins->l, m_or);
        if ( orI != nullptr )
        {
          const mop_t *na = bnot_operand(&orI->l);
          const mop_t *nb = bnot_operand(&orI->r);
          if ( na != nullptr && nb != nullptr )
          {
            rewrite_binop(ins, m_and, *na, *nb);
            return 1;
          }
        }
      }

      // ~(~a & ~b)  =>  a | b       (De Morgan)
      {
        const minsn_t *andI2 = as_insn(&ins->l, m_and);
        if ( andI2 != nullptr )
        {
          const mop_t *na = bnot_operand(&andI2->l);
          const mop_t *nb = bnot_operand(&andI2->r);
          if ( na != nullptr && nb != nullptr )
          {
            rewrite_binop(ins, m_or, *na, *nb);
            return 1;
          }
        }
      }

      // ~(x - 1)  =>  -x           (also ~(x + (-1)))
      {
        const minsn_t *sb = as_insn(&ins->l, m_sub);
        if ( sb != nullptr && is_const_val(&sb->r, 1) )
        {
          rewrite_unop(ins, m_neg, sb->l);
          return 1;
        }
        const minsn_t *ad = as_insn(&ins->l, m_add);
        if ( ad != nullptr )
        {
          if ( is_const_val(&ad->r, -1) )
          {
            rewrite_unop(ins, m_neg, ad->l);
            return 1;
          }
          if ( is_const_val(&ad->l, -1) )
          {
            rewrite_unop(ins, m_neg, ad->r);
            return 1;
          }
        }
      }
      break;
    }

    case m_xor:
    {
      // x ^ x  =>  0
      if ( ins->l == ins->r )
      {
        int sz = pick_size(ins);
        ins->opcode = m_mov;
        ins->l.make_number(0, sz, ins->ea);
        ins->r.erase();
        return 1;
      }
      break;
    }

    case m_and:
    {
      // x & x  =>  x
      if ( ins->l == ins->r )
      {
        ins->opcode = m_mov;
        ins->r.erase();
        return 1;
      }

      // (a ^ ~b) & a  =>  a & b
      {
        const minsn_t *xr = nullptr;
        const mop_t *oth = nullptr;
        if ( split_one(ins, m_xor, &xr, &oth) )
        {
          mop_t p, ni;
          if ( split_with_not(xr, &p, &ni) && *oth == p )
          {
            rewrite_binop(ins, m_and, p, ni);
            return 1;
          }
        }
      }

      // (a | b) & ~(a ^ b)  =>  a & b
      {
        const minsn_t *orI = nullptr;
        const mop_t *oth = nullptr;
        if ( split_one(ins, m_or, &orI, &oth) )
        {
          const minsn_t *nb = as_insn(oth, m_bnot);
          if ( nb != nullptr )
          {
            const minsn_t *xr = as_insn(&nb->l, m_xor);
            if ( xr != nullptr && same_pair(orI, xr) )
            {
              rewrite_binop(ins, m_and, orI->l, orI->r);
              return 1;
            }
          }
        }
      }
      break;
    }

    case m_or:
    {
      // x | 0  =>  x
      if ( is_num(&ins->r) && num_val(&ins->r) == 0 )
      {
        ins->opcode = m_mov;
        ins->r.erase();
        return 1;
      }
      if ( is_num(&ins->l) && num_val(&ins->l) == 0 )
      {
        ins->l.swap(ins->r);
        ins->opcode = m_mov;
        ins->r.erase();
        return 1;
      }

      // (a & b) | (a ^ b)  =>  a | b
      {
        const minsn_t *andI = nullptr;
        const mop_t *oth = nullptr;
        if ( split_one(ins, m_and, &andI, &oth) )
        {
          const minsn_t *xr = as_insn(oth, m_xor);
          if ( xr != nullptr && same_pair(andI, xr) )
          {
            rewrite_binop(ins, m_or, andI->l, andI->r);
            return 1;
          }
        }
      }

      // (~a & b) | (a & ~b)  =>  a ^ b
      {
        const minsn_t *lA = as_insn(&ins->l, m_and);
        const minsn_t *rA = as_insn(&ins->r, m_and);
        if ( lA != nullptr && rA != nullptr )
        {
          mop_t lp, ln, rp, rn;
          if ( split_with_not(lA, &lp, &ln) && split_with_not(rA, &rp, &rn)
            && lp == rn && ln == rp )
          {
            rewrite_binop(ins, m_xor, lp, ln);
            return 1;
          }
        }
      }
      break;
    }

    case m_neg:
    {
      // -(-a + (-b))  =>  a + b
      const minsn_t *addI = as_insn(&ins->l, m_add);
      if ( addI != nullptr )
      {
        const mop_t *na = neg_operand(&addI->l);
        const mop_t *nb = neg_operand(&addI->r);
        if ( na != nullptr && nb != nullptr )
        {
          rewrite_binop(ins, m_add, *na, *nb);
          return 1;
        }
      }
      break;
    }

    default:
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
// Affine / constant-fold reduction (public).
//--------------------------------------------------------------------------

// A single term in an affine reduction: a leaf operand with a running
// coefficient (integer for +/- chains, or a parity bit for xor chains).
struct affine_leaf
{
  mop_t op;
  int coeff;
};

// Merge operand `m` (signed by `sign`) into the variable list, combining with
// an existing structurally-equal leaf. Leaf identity uses mop_t::operator==.
static void add_var(std::vector<affine_leaf> *vars, const mop_t *m, int sign)
{
  for ( affine_leaf &v : *vars )
  {
    if ( v.op == *m )
    {
      v.coeff += sign;
      return;
    }
  }
  affine_leaf lf;
  lf.op = *m;
  lf.coeff = sign;
  vars->push_back(lf);
}

// Flatten an additive (+/-/neg/mov) expression tree, accumulating the constant
// part into *cst and variable coefficients into *vars. *nleaves counts the
// number of leaves consumed (used as a simplification-progress metric).
static void collect_add(const mop_t *m, int sign, int64_t *cst,
                        std::vector<affine_leaf> *vars, int *nleaves, int depth)
{
  if ( m == nullptr )
    return;
  if ( depth <= 40 && m->t == mop_n )
  {
    *cst += int64_t(sign) * int64_t(num_val(m));
    ++*nleaves;
    return;
  }
  if ( depth <= 40 && m->t == mop_d && m->d != nullptr )
  {
    const minsn_t *s = m->d;
    switch ( s->opcode )
    {
      case m_add:
        collect_add(&s->l, sign, cst, vars, nleaves, depth + 1);
        collect_add(&s->r, sign, cst, vars, nleaves, depth + 1);
        return;
      case m_sub:
        collect_add(&s->l, sign, cst, vars, nleaves, depth + 1);
        collect_add(&s->r, -sign, cst, vars, nleaves, depth + 1);
        return;
      case m_neg:
        collect_add(&s->l, -sign, cst, vars, nleaves, depth + 1);
        return;
      case m_mov:
        collect_add(&s->l, sign, cst, vars, nleaves, depth + 1);
        return;
      default:
        break;
    }
  }
  add_var(vars, m, sign);
  ++*nleaves;
}

// Flatten an xor/mov expression tree; constants xor into *cst, variables get a
// running parity in *vars. *nleaves counts leaves consumed.
static void collect_xor(const mop_t *m, uint64_t *cst,
                        std::vector<affine_leaf> *vars, int *nleaves, int depth)
{
  if ( m == nullptr )
    return;
  if ( depth <= 40 && m->t == mop_n )
  {
    *cst ^= num_val(m);
    ++*nleaves;
    return;
  }
  if ( depth <= 40 && m->t == mop_d && m->d != nullptr )
  {
    const minsn_t *s = m->d;
    if ( s->opcode == m_xor )
    {
      collect_xor(&s->l, cst, vars, nleaves, depth + 1);
      collect_xor(&s->r, cst, vars, nleaves, depth + 1);
      return;
    }
    if ( s->opcode == m_mov )
    {
      collect_xor(&s->l, cst, vars, nleaves, depth + 1);
      return;
    }
  }
  add_var(vars, m, 1);
  ++*nleaves;
}

// Reduce a +/-/neg node by cancelling injected constants and opposite terms
// over at most two variables. Returns true if `ins` was rewritten simpler.
static bool try_additive_reduce(minsn_t *ins)
{
  int64_t cst = 0;
  int nleaves = 0;
  std::vector<affine_leaf> vars;
  switch ( ins->opcode )
  {
    case m_add:
      collect_add(&ins->l, +1, &cst, &vars, &nleaves, 0);
      collect_add(&ins->r, +1, &cst, &vars, &nleaves, 0);
      break;
    case m_sub:
      collect_add(&ins->l, +1, &cst, &vars, &nleaves, 0);
      collect_add(&ins->r, -1, &cst, &vars, &nleaves, 0);
      break;
    case m_neg:
      collect_add(&ins->l, -1, &cst, &vars, &nleaves, 0);
      break;
    default:
      return false;
  }

  std::vector<affine_leaf> nz;
  for ( const affine_leaf &v : vars )
    if ( v.coeff != 0 )
      nz.push_back(v);

  int sz = pick_size(ins);
  uint64_t mask = size_mask(sz);
  uint64_t cmask = uint64_t(cst) & mask;
  int emitted = int(nz.size()) + (cmask != 0 ? 1 : 0);
  if ( emitted >= nleaves )       // no net simplification -> avoid churn
    return false;
  if ( nz.size() > 2 )
    return false;

  if ( nz.empty() )
  {
    ins->opcode = m_mov;
    ins->l.make_number(cmask, sz, ins->ea);
    ins->r.erase();
    return true;
  }
  if ( nz.size() == 1 )
  {
    int c = nz[0].coeff;
    mop_t v = nz[0].op;
    if ( c == 1 )
    {
      if ( cmask == 0 )
      {
        rewrite_unop(ins, m_mov, v);
        return true;
      }
      mop_t k;
      k.make_number(cmask, sz, ins->ea);
      rewrite_binop(ins, m_add, v, k);
      return true;
    }
    if ( c == -1 )
    {
      if ( cmask == 0 )
      {
        rewrite_unop(ins, m_neg, v);
        return true;
      }
      mop_t k;
      k.make_number(cmask, sz, ins->ea);
      rewrite_binop(ins, m_sub, k, v);
      return true;
    }
    return false;
  }

  // Exactly two surviving variables; only handle the unit-coefficient forms.
  if ( cmask != 0 )
    return false;
  int c0 = nz[0].coeff;
  int c1 = nz[1].coeff;
  mop_t v0 = nz[0].op;
  mop_t v1 = nz[1].op;
  if ( c0 == 1 && c1 == 1 )
  {
    rewrite_binop(ins, m_add, v0, v1);
    return true;
  }
  if ( c0 == 1 && c1 == -1 )
  {
    rewrite_binop(ins, m_sub, v0, v1);
    return true;
  }
  if ( c0 == -1 && c1 == 1 )
  {
    rewrite_binop(ins, m_sub, v1, v0);
    return true;
  }
  return false;
}

// Reduce an xor node by cancelling injected constants and duplicate terms.
static bool try_xor_reduce(minsn_t *ins)
{
  uint64_t cst = 0;
  int nleaves = 0;
  std::vector<affine_leaf> vars;
  collect_xor(&ins->l, &cst, &vars, &nleaves, 0);
  collect_xor(&ins->r, &cst, &vars, &nleaves, 0);

  std::vector<affine_leaf> nz;
  for ( const affine_leaf &v : vars )
    if ( (v.coeff & 1) != 0 )
      nz.push_back(v);

  int sz = pick_size(ins);
  uint64_t mask = size_mask(sz);
  uint64_t cmask = cst & mask;
  int emitted = int(nz.size()) + (cmask != 0 ? 1 : 0);
  if ( emitted >= nleaves )
    return false;
  if ( nz.size() > 2 )
    return false;

  if ( nz.empty() )
  {
    ins->opcode = m_mov;
    ins->l.make_number(cmask, sz, ins->ea);
    ins->r.erase();
    return true;
  }
  if ( nz.size() == 1 )
  {
    mop_t v = nz[0].op;
    if ( cmask == 0 )
    {
      rewrite_unop(ins, m_mov, v);
      return true;
    }
    mop_t k;
    k.make_number(cmask, sz, ins->ea);
    rewrite_binop(ins, m_xor, v, k);
    return true;
  }
  if ( cmask != 0 )
    return false;
  rewrite_binop(ins, m_xor, nz[0].op, nz[1].op);
  return true;
}

bool try_affine_simplify(minsn_t *ins)
{
  if ( ins == nullptr )
    return false;

  // First try a whole-expression constant fold. eval_insn_const already
  // rejects jumps, calls, stores, etc.
  uint64_t v = 0;
  if ( eval_insn_const(ins, &v) )
  {
    // Already a constant move -- nothing to do (avoids self-triggering).
    if ( ins->opcode == m_mov && is_num(&ins->l) )
      return false;

    int sz = pick_size(ins);
    v &= size_mask(sz);

    ins->opcode = m_mov;
    ins->l.make_number(v, sz, ins->ea);
    ins->r.erase();
    return true;
  }

  // Not fully constant: fold injected/cancelling constants over <=2 vars.
  switch ( ins->opcode )
  {
    case m_add:
    case m_sub:
    case m_neg:
      return try_additive_reduce(ins);
    case m_xor:
      return try_xor_reduce(ins);
    default:
      return false;
  }
}

//--------------------------------------------------------------------------
// Block-level MBA simplification (public).
//--------------------------------------------------------------------------

// Recurse into subexpressions first, then simplify this node. Returns the
// number of rewrites applied in this subtree.
static int simplify_insn_rec(minsn_t *ins)
{
  if ( ins == nullptr )
    return 0;
  int cnt = 0;
  if ( ins->l.t == mop_d )
    cnt += simplify_insn_rec(ins->l.d);
  if ( ins->r.t == mop_d )
    cnt += simplify_insn_rec(ins->r.d);
  if ( ins->d.t == mop_d )
    cnt += simplify_insn_rec(ins->d.d);

  // Prefer a structural MBA identity; if none fired, try constant folding.
  if ( try_mba_identity(ins) != 0 )
    ++cnt;
  else if ( try_affine_simplify(ins) )
    ++cnt;

  return cnt;
}

int simplify_mba_block(mblock_t *blk)
{
  if ( blk == nullptr )
    return 0;
  int changed = 0;
  for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
  {
    if ( simplify_insn_rec(ins) != 0 )
      ++changed;
  }
  if ( changed > 0 )
    blk->mark_lists_dirty();
  return changed;
}

//--------------------------------------------------------------------------
// Opaque-predicate elimination (public).
//
// Ported in spirit from promon_cff_deobfuscator.find_opaque_predicates: the
// native version recognizes tautologies like x*(x-1)%2==0 that always steer a
// CSEL/branch one way. Here we work on microcode: whenever a conditional jump's
// condition provably folds to a constant, we fold the branch to its taken edge
// (or to fall-through) and drop the dead edge.
//--------------------------------------------------------------------------

int eliminate_opaque_predicates(mba_t *mba)
{
  if ( mba == nullptr )
    return 0;

  int changes = 0;
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    minsn_t *tail = blk->tail;
    if ( tail == nullptr )
      continue;

    mcode_t op = tail->opcode;
    bool is_cjmp = op == m_jcnd || (op >= m_jnz && op <= m_jle);
    if ( !is_cjmp )
      continue;

    // We need a clean 2-way branch with a block-reference target.
    if ( blk->nsucc() != 2 || tail->d.t != mop_b )
      continue;

    int target = tail->d.b;
    int s0 = blk->succset[0];
    int s1 = blk->succset[1];
    if ( s0 == s1 )
      continue;
    if ( target != s0 && target != s1 )
      continue;
    int fall = (s0 == target) ? s1 : s0;

    int taken = 0;
    if ( !eval_condition(tail, &taken) )
      continue;

    int keep = taken ? target : fall;
    int drop = taken ? fall : target;

    // Rewrite the tail. If the surviving edge is the physical fall-through
    // (serial+1) we can simply drop the branch; otherwise emit an explicit
    // goto so control flow stays consistent with the block layout.
    if ( keep == blk->serial + 1 )
    {
      blk->make_nop(tail);
    }
    else
    {
      tail->opcode = m_goto;
      tail->l.make_blkref(keep);
      tail->r.erase();
      tail->d.erase();
    }

    // Fix the CFG edges.
    if ( drop != keep )
    {
      blk->succset.del(drop);
      mba->get_mblock(drop)->predset.del(blk->serial);
    }
    blk->mark_lists_dirty();
    ++changes;
  }

  // Structural consistency is maintained per changed block via
  // blk->mark_lists_dirty() above; the caller does a single
  // mark_chains_dirty() and one verify(true) after all passes.
  return changes;
}

} // namespace unslop
