// OLLVM / Hikari (Appdome) profile for the Unslopper deflattener.
//
// This is the baseline profile. OLLVM-style control-flow flattening uses a
// single dispatcher block (the block with the most predecessors) that switches
// on a state variable compared against a set of random-looking 32-bit "magic"
// constants. There is no state encoding: the raw state value is the canonical
// value (transform_state is identity), and the generic core already recovers
// the dispatcher, so configure() does no extra work.
//
// Ported from appdome-research/scripts/cff_deflat.py (_find_dispatcher,
// _build_reg_map, comparison-constant collection) and the state-var scoring in
// deobfuscate_cff.py (a state variable is one compared against >= 3 distinct
// large constants).

#include "profile.h"
#include "microcode_utils.h"

#include <map>
#include <set>

namespace unslop {

// A "magic" state constant looks random and large: OLLVM state IDs are 32-bit
// values well above small loop-counter / index territory.
static const uint64_t MAGIC_MIN = 0x1000000ull; // 16,777,216

// True for the microcode comparison opcodes that can carry a state test.
// Covers the conditional jumps (m_jcnd..m_jle) plus the table jump m_jtbl.
static bool is_cmp_op(mcode_t op)
{
  return is_cond_jump(op) || op == m_jtbl;
}

// Resolve the constant an operand denotes: either a literal immediate, or the
// last constant moved into a register (via the whole-function reg map).
static bool operand_const(
        const mop_t *m,
        const std::map<mreg_t, uint64_t> &reg_map,
        uint64_t *out)
{
  if ( is_num(m) )
  {
    *out = num_val(m);
    return true;
  }
  if ( is_reg(m) )
  {
    auto it = reg_map.find(m->r);
    if ( it != reg_map.end() )
    {
      *out = it->second;
      return true;
    }
  }
  return false;
}

class OllvmProfile : public Profile
{
public:
  const char *name() const override { return "ollvm"; }
  ProfileKind kind() const override { return ProfileKind::OLLVM; }

  bool detect(mba_t *mba, const std::map<mreg_t, uint64_t> &reg_map) override
  {
    if ( mba == nullptr )
      return false;

    // 1. There must be a heavily-shared dispatcher block: the maximum number
    //    of predecessors across all blocks must be >= 3 (a flattened function
    //    routes many case-blocks back through one dispatcher).
    int max_pred = 0;
    for ( int i = 0; i < mba->qty; ++i )
    {
      int np = mba->get_mblock(i)->npred();
      if ( np > max_pred )
        max_pred = np;
    }
    if ( max_pred < 3 )
      return false;

    // 2. Some register or stack variable must be compared against >= 3 distinct
    //    large "magic" constants. Constants may appear as literal immediates in
    //    the comparison, or be materialized into a register first, so build the
    //    whole-function `mov #const, reg` map and resolve through it (the
    //    caller supplies it as the shared map built once per function, FIX 2).

    // Track distinct magic constants per compared variable. Registers are keyed
    // by (0, reg); stack slots by (1, offset).
    std::map<std::pair<int, int64_t>, std::set<uint64_t>> var_consts;

    for ( int i = 0; i < mba->qty; ++i )
    {
      mblock_t *blk = mba->get_mblock(i);
      for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
      {
        if ( !is_cmp_op(ins->opcode) )
          continue;

        // Try both orderings: (var, const) and (const, var).
        const mop_t *sides[2][2] = {
          { &ins->l, &ins->r },
          { &ins->r, &ins->l },
        };
        for ( int k = 0; k < 2; ++k )
        {
          const mop_t *var_op = sides[k][0];
          const mop_t *cst_op = sides[k][1];

          std::pair<int, int64_t> key;
          if ( is_reg(var_op) )
            key = std::make_pair(0, int64_t(var_op->r));
          else if ( is_stk(var_op) && var_op->s != nullptr )
            key = std::make_pair(1, int64_t(var_op->s->off));
          else
            continue;

          uint64_t c;
          if ( !operand_const(cst_op, reg_map, &c) )
            continue;

          // Only random-looking large 32-bit values count as state magic.
          uint64_t c32 = c & 0xFFFFFFFFull;
          if ( c32 < MAGIC_MIN )
            continue;

          var_consts[key].insert(c32);
        }
      }
    }

    for ( const auto &kv : var_consts )
    {
      if ( kv.second.size() >= 3 )
        return true;
    }
    return false;
  }

  // The generic dispatcher recovery in the core already handles OLLVM: this
  // profile adds no refinement, it just declares a usable configuration.
  bool configure(mba_t *mba, DispatcherInfo *di,
                 const std::map<mreg_t, uint64_t> &regmap) override
  {
    qnotused(mba);
    qnotused(di);
    qnotused(regmap);
    return true;
  }

  // No state encoding — raw == canonical.
  uint64_t transform_state(uint64_t raw) override { return raw; }

  // No family-specific post-processing beyond the generic core.
  int post_process(mba_t *mba, int changes) override
  {
    qnotused(mba);
    qnotused(changes);
    return 0;
  }
};

Profile *make_ollvm()
{
  return new OllvmProfile();
}

} // namespace unslop
