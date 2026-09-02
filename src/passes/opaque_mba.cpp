#include "opaque_mba.h"
#include "microcode_utils.h"
#include "mba_simplify.h"

#include <bytes.hpp>
#include <map>
#include <array>
#include <cstdint>

namespace unslop {

//--------------------------------------------------------------------------
// Numeric helpers.
//--------------------------------------------------------------------------
static uint64_t smask(int size)
{
  if ( size <= 0 || size >= 8 )
    return ~uint64_t(0);
  return (uint64_t(1) << (size * 8)) - 1;
}

// Inverse of an odd value modulo 2**(size*8), by Newton iteration.
static uint64_t inv_pow2(uint64_t a, int size)
{
  uint64_t mask = smask(size);
  a &= mask;
  uint64_t x = a;                 // good to 3 bits
  for ( int i = 0; i < 6; ++i )   // doubles the correct bits each round -> 64
    x = (x * (2 - a * x)) & mask;
  return x & mask;
}

// Immediate value of a mop_n operand (full width), or false.
static bool get_num(const mop_t *m, uint64_t *out)
{
  if ( m == nullptr || m->t != mop_n || m->nnn == nullptr )
    return false;
  *out = m->nnn->value;
  return true;
}

// Peel value-preserving extension wrappers (xdu/xds) off a byte operand.
static const mop_t *strip_ext(const mop_t *m)
{
  while ( m != nullptr && m->t == mop_d && m->d != nullptr
       && (m->d->opcode == m_xdu || m->d->opcode == m_xds) )
    m = &m->d->l;
  return m;
}

// If `m` wraps a sub-instruction with opcode `op` (after stripping
// extensions), return it, else nullptr.
static minsn_t *sub_of(const mop_t *m, mcode_t op)
{
  const mop_t *s = strip_ext(m);
  if ( s != nullptr && s->t == mop_d && s->d != nullptr && s->d->opcode == op )
    return s->d;
  return nullptr;
}

// Resolve a microcode operand to a global address (table base candidate).
static bool global_ea(const mop_t *m, ea_t *out)
{
  const mop_t *s = strip_ext(m);
  if ( s == nullptr )
    return false;
  if ( s->t == mop_v ) { *out = s->g; return true; }
  if ( s->t == mop_a && s->a != nullptr && s->a->t == mop_v ) { *out = s->a->g; return true; }
  uint64_t n;
  if ( get_num(s, &n) && is_mapped((ea_t)n) ) { *out = (ea_t)n; return true; }
  return false;
}

// Decompose an address expression `base + index` into (global base, index).
static bool base_plus_index(const mop_t *addr, ea_t *base, const mop_t **index)
{
  minsn_t *add = sub_of(addr, m_add);
  if ( add == nullptr )
    return false;
  if ( global_ea(&add->l, base) ) { *index = &add->r; return true; }
  if ( global_ea(&add->r, base) ) { *index = &add->l; return true; }
  return false;
}

// An immutable byte-table load: ldx of size 1 at (global_base + index).
static bool byte_table_load(const mop_t *m, ea_t *base, const mop_t **index)
{
  minsn_t *ld = sub_of(m, m_ldx);
  if ( ld == nullptr || ld->d.size != 1 )
    return false;
  return base_plus_index(&ld->r, base, index);
}

// `X ^ const` -> (other, const). Commutative.
static bool xor_const(const mop_t *m, const mop_t **other, uint64_t *k)
{
  minsn_t *x = sub_of(m, m_xor);
  if ( x == nullptr )
    return false;
  if ( get_num(&x->l, k) ) { *other = &x->r; return true; }
  if ( get_num(&x->r, k) ) { *other = &x->l; return true; }
  return false;
}

// Two byte operands are the same pure value (no side effects).
static bool same_byte(const mop_t *a, const mop_t *b)
{
  const mop_t *sa = strip_ext(a);
  const mop_t *sb = strip_ext(b);
  return sa != nullptr && sb != nullptr
      && sa->size == 1 && sb->size == 1
      && sa->equal_mops(*sb, EQ_IGNSIZE)
      && !sa->has_side_effects() && !sb->has_side_effects();
}

static bool same_pure(const mop_t *a, const mop_t *b, int size)
{
  if ( a == nullptr || b == nullptr )
    return false;
  if ( size > 0 && (a->size != size || b->size != size) )
    return false;
  return a->equal_mops(*b, EQ_IGNSIZE)
      && !a->has_side_effects() && !b->has_side_effects();
}

// Recognize 2*x / x+x / x<<1 -> x.
static const mop_t *double_of(const mop_t *m)
{
  if ( m == nullptr || m->t != mop_d || m->d == nullptr )
    return nullptr;
  minsn_t *n = m->d;
  uint64_t k;
  if ( n->opcode == m_mul )
  {
    if ( get_num(&n->l, &k) && k == 2 ) return &n->r;
    if ( get_num(&n->r, &k) && k == 2 ) return &n->l;
  }
  else if ( n->opcode == m_add )
  {
    if ( same_pure(&n->l, &n->r, 0) ) return &n->l;
  }
  else if ( n->opcode == m_shl )
  {
    if ( get_num(&n->r, &k) && k == 1 && !n->l.has_side_effects() ) return &n->l;
  }
  return nullptr;
}

// `X op const` where op is commutative -> (other, const).
static bool binop_const(const mop_t *m, mcode_t op, const mop_t **other, uint64_t *k)
{
  minsn_t *n = sub_of(m, op);
  if ( n == nullptr )
    return false;
  if ( get_num(&n->l, k) ) { *other = &n->r; return true; }
  if ( get_num(&n->r, k) ) { *other = &n->l; return true; }
  return false;
}

//--------------------------------------------------------------------------
// Verified S-box table cache.
//--------------------------------------------------------------------------
struct Table { std::array<uint8_t,256> b; bool perm; };

static const Table *load_table(ea_t ea)
{
  static std::map<ea_t, Table> cache;
  auto it = cache.find(ea);
  if ( it != cache.end() )
    return &it->second;
  Table t{};
  t.perm = false;
  if ( is_mapped(ea) && get_bytes(t.b.data(), 256, ea) == 256 )
  {
    std::array<bool,256> seen{};
    bool ok = true;
    for ( int i = 0; i < 256; ++i )
    {
      if ( seen[t.b[i]] ) { ok = false; break; }
      seen[t.b[i]] = true;
    }
    t.perm = ok;
  }
  auto &slot = cache[ea];
  slot = t;
  return &slot;
}

// Constant result of x ^ outer[inner[x] ^ c] for all x, or -1 if not constant.
// Proven per (inner,outer,c) and cached.
static int sbox_chain_const(ea_t inner_ea, ea_t outer_ea, uint8_t c)
{
  static std::map<uint64_t, int> cache;
  uint64_t key = (uint64_t(inner_ea) << 24) ^ (uint64_t(outer_ea) << 8) ^ c;
  auto it = cache.find(key);
  if ( it != cache.end() )
    return it->second;

  int result = -1;
  const Table *inner = load_table(inner_ea);
  const Table *outer = load_table(outer_ea);
  if ( inner->perm && outer->perm )
  {
    int constant = -1;
    bool ok = true;
    for ( int x = 0; x < 256; ++x )
    {
      int v = x ^ outer->b[uint8_t(inner->b[x] ^ c)];
      if ( constant < 0 )
        constant = v;
      else if ( constant != v ) { ok = false; break; }
    }
    if ( ok )
      result = constant;
  }
  cache[key] = result;
  return result;
}

//--------------------------------------------------------------------------
// Rewriters.
//--------------------------------------------------------------------------
static void to_const(minsn_t *ins, uint64_t value)
{
  int size = ins->d.size;
  ins->opcode = m_mov;
  ins->l.make_number(value & smask(size), size, ins->ea);
  ins->r.erase();
}

static void to_move(minsn_t *ins, const mop_t *value)
{
  mop_t v = *value;
  ins->opcode = m_mov;
  ins->l = v;
  ins->r.erase();
}

static void to_binop(minsn_t *ins, mcode_t op, const mop_t *value, uint64_t k)
{
  int size = ins->d.size;
  mop_t l = *value;
  ins->opcode = op;
  ins->l = l;
  ins->r.make_number(k & smask(size), size, ins->ea);
}

//--------------------------------------------------------------------------
// Matchers (each returns true and rewrites `ins` in place, or false).
//--------------------------------------------------------------------------

// x ^ outer[inner[x] ^ c]  ->  const
static bool try_sbox_chain(minsn_t *ins)
{
  if ( ins->opcode != m_xor || ins->d.size != 1 )
    return false;
  for ( int order = 0; order < 2; ++order )
  {
    const mop_t *value   = order ? &ins->r : &ins->l;
    const mop_t *outerop = order ? &ins->l : &ins->r;
    ea_t outer_ea; const mop_t *middle;
    if ( !byte_table_load(outerop, &outer_ea, &middle) )
      continue;
    const mop_t *inner_op; uint64_t c;
    if ( !xor_const(middle, &inner_op, &c) )
      continue;
    ea_t inner_ea; const mop_t *idx;
    if ( !byte_table_load(inner_op, &inner_ea, &idx) )
      continue;
    if ( !same_byte(value, idx) )
      continue;
    int k = sbox_chain_const(inner_ea, outer_ea, uint8_t(c));
    if ( k < 0 )
      continue;
    to_const(ins, uint64_t(k));
    return true;
  }
  return false;
}

// (x ^ ~c) + ((2*x) & ~(2*c+1)) + 1  ->  x - c
static bool try_mba_sub(minsn_t *ins)
{
  if ( ins->opcode != m_add )
    return false;
  int size = ins->d.size;
  if ( size != 1 && size != 2 && size != 4 && size != 8 )
    return false;
  uint64_t mask = smask(size);

  // Flatten the (add (add A B) C) chain into up to 3 terms.
  const mop_t *terms[4]; int nt = 0;
  const mop_t *stack[4]; int ns = 0;
  stack[ns++] = &ins->r;
  stack[ns++] = &ins->l;
  while ( ns > 0 && nt < 4 )
  {
    const mop_t *t = stack[--ns];
    minsn_t *a = (t->t == mop_d && t->d != nullptr && t->d->opcode == m_add
                  && t->d->d.size == size && !t->has_side_effects()) ? t->d : nullptr;
    if ( a != nullptr && ns + 2 <= 4 ) { stack[ns++] = &a->r; stack[ns++] = &a->l; }
    else terms[nt++] = t;
  }
  if ( nt != 3 )
    return false;

  int one_i = -1;
  for ( int i = 0; i < 3; ++i )
  {
    uint64_t v;
    if ( get_num(terms[i], &v) && (v & mask) == 1 ) { one_i = i; break; }
  }
  if ( one_i < 0 )
    return false;
  const mop_t *rest[2]; int ri = 0;
  for ( int i = 0; i < 3; ++i ) if ( i != one_i ) rest[ri++] = terms[i];

  for ( int order = 0; order < 2; ++order )
  {
    const mop_t *xorT = order ? rest[1] : rest[0];
    const mop_t *andT = order ? rest[0] : rest[1];
    const mop_t *xval; uint64_t inv_c;
    const mop_t *aval; uint64_t and_mask;
    if ( !binop_const(xorT, m_xor, &xval, &inv_c) )
      continue;
    if ( !binop_const(andT, m_and, &aval, &and_mask) )
      continue;
    const mop_t *dv = double_of(aval);
    if ( dv == nullptr || !same_pure(xval, dv, size) )
      continue;
    uint64_t c = (~inv_c) & mask;
    uint64_t expect = (~((2 * c + 1) & mask)) & mask;
    if ( (and_mask & mask) != expect )
      continue;
    to_binop(ins, m_sub, xval, c);
    return true;
  }
  return false;
}

// (x*a + b)*inv(a) + rb  ->  x     (proves a*inv==1 and b*inv+rb==0)
static bool try_affine_add(minsn_t *ins)
{
  if ( ins->opcode != m_add )
    return false;
  int size = ins->d.size;
  if ( size != 1 && size != 2 && size != 4 && size != 8 )
    return false;
  uint64_t mask = smask(size);

  const mop_t *mul_term; uint64_t rb;
  if ( !( (get_num(&ins->r, &rb) && (mul_term = &ins->l, true))
       || (get_num(&ins->l, &rb) && (mul_term = &ins->r, true)) ) )
    return false;
  const mop_t *encoded; uint64_t inv;
  if ( !binop_const(mul_term, m_mul, &encoded, &inv) )
    return false;
  const mop_t *prod; uint64_t b;
  if ( !binop_const(encoded, m_add, &prod, &b) )
    return false;
  const mop_t *xval; uint64_t a;
  if ( !binop_const(prod, m_mul, &xval, &a) )
    return false;
  if ( xval->size != size || xval->has_side_effects() )
    return false;
  if ( ((a * inv) & mask) != 1 )
    return false;
  if ( ((b * inv + rb) & mask) != 0 )
    return false;
  to_move(ins, xval);
  return true;
}

// inv(a) * (a * (x ^ c)) ^ c  ->  x     (proves a*inv==1 and both c equal)
static bool try_affine_xor(minsn_t *ins)
{
  if ( ins->opcode != m_xor )
    return false;
  int size = ins->d.size;
  if ( size != 1 && size != 2 && size != 4 && size != 8 )
    return false;
  uint64_t mask = smask(size);

  const mop_t *mul_term; uint64_t outer_c;
  if ( !( (get_num(&ins->r, &outer_c) && (mul_term = &ins->l, true))
       || (get_num(&ins->l, &outer_c) && (mul_term = &ins->r, true)) ) )
    return false;
  const mop_t *first; uint64_t inv;
  if ( !binop_const(mul_term, m_mul, &first, &inv) )
    return false;
  const mop_t *encoded; uint64_t a;
  if ( !binop_const(first, m_mul, &encoded, &a) )
    return false;
  const mop_t *xval; uint64_t inner_c;
  if ( !binop_const(encoded, m_xor, &xval, &inner_c) )
    return false;
  if ( xval->size != size || xval->has_side_effects() )
    return false;
  if ( (outer_c & mask) != (inner_c & mask) )
    return false;
  if ( ((a * inv) & mask) != 1 )
    return false;
  to_move(ins, xval);
  return true;
}

// (x*x) & 3 in {0,1}  (or %4) -> always 1.  Matches the setbe form.
static bool square_residue(const mop_t *m)
{
  const mop_t *sq_op = nullptr;
  const mop_t *other; uint64_t k;
  if ( binop_const(m, m_and, &other, &k) && k == 3 )
    sq_op = other;
  else
  {
    minsn_t *mod = sub_of(m, m_umod);
    uint64_t four;
    if ( mod != nullptr && get_num(&mod->r, &four) && four == 4 )
      sq_op = &mod->l;
  }
  if ( sq_op == nullptr )
    return false;
  minsn_t *mul = sub_of(sq_op, m_mul);
  return mul != nullptr && same_pure(&mul->l, &mul->r, 0);
}

static bool try_opaque_square(minsn_t *ins)
{
  uint64_t one;
  if ( ins->opcode == m_setbe && get_num(&ins->r, &one) && one == 1
    && square_residue(&ins->l) )
  {
    to_const(ins, 1);
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
// Visitor.
//--------------------------------------------------------------------------
struct OpaqueVisitor : public minsn_visitor_t
{
  int changed = 0;
  int idaapi visit_minsn() override
  {
    minsn_t *ins = curins;
    if ( try_sbox_chain(ins)
      || try_mba_sub(ins)
      || try_affine_add(ins)
      || try_affine_xor(ins)
      || try_opaque_square(ins) )
      ++changed;
    return 0;
  }
};

int simplify_opaque_mba(mba_t *mba)
{
  if ( mba == nullptr )
    return 0;
  int total = 0;
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    if ( blk == nullptr )
      continue;
    OpaqueVisitor mv;
    blk->for_all_insns(mv);
    if ( mv.changed > 0 )
    {
      blk->mark_lists_dirty();
      total += mv.changed;
    }
    // Also run the general MBA identity ruleset (Hikari set: (x^y)+2*(x&y) ->
    // x+y, selector folds, ~x+1 -> -x, ...). It normally runs only in the CFF
    // post-process path, but Arxan-style targets have NO dispatcher, so their
    // residual MBA never reached it. Self-proving and safe to run per block.
    total += simplify_mba_block(blk);
  }
  return total;
}

} // namespace unslop
