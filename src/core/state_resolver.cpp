// State-value resolution for the Unslopper deflattener.
//
// Ported from appdome-research/scripts/cff_deflat.py:
//   _resolve_sv_in_block (~363-432)  -> resolve_state_in_block
//   _forward_map         (~437-507)  -> forward_state_map
//
// resolve_state_in_block micro-emulates a block, tracking a set of possible
// values per register (mov #const / mov reg,reg), and follows single- and
// multi-predecessor chains backward up to depth 5. If the state register ends
// up with more than one possible value it is treated as ambiguous.
//
// forward_state_map finds every `mov #const, state_reg` site and follows the
// CFG forward (<= 20 visited blocks) to the goto-to-dispatcher block it reaches,
// guarding against the state register being overwritten on the way.
//
// NOTE: IDA SDK 9.5 has no m_cmov opcode (conditional selects are lowered to
// m_jcnd), so the Python CMOV branch has no analogue here. The set-valued
// register environment is kept intact because the multi-predecessor merge below
// still relies on it to detect ambiguity.

#include "state_resolver.h"
#include "microcode_utils.h"
#include "unslop_log.h"

#include <algorithm>
#include <deque>
#include <functional>
#include <optional>

namespace unslop {

bool resolve_state_in_block(mba_t *mba,
                            int serial,
                            mreg_t state_reg,
                            const std::map<mreg_t, uint64_t> &regmap,
                            const std::set<int> &disp_blocks,
                            uint64_t *out)
{
  // Recursive micro-emulator mirroring the Python _scan_block closure.
  std::function<std::optional<uint64_t>(int, int)> scan =
      [&](int blk_serial, int depth) -> std::optional<uint64_t>
  {
    if ( depth > 5
      || blk_serial < 0
      || blk_serial >= mba->qty
      || disp_blocks.count(blk_serial) != 0 )
    {
      return std::nullopt;
    }

    mblock_t *blk = mba->get_mblock(blk_serial);

    // Micro-emulate: track possible values per register.
    std::map<mreg_t, std::set<uint64_t>> local_regs;

    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( ins->opcode == m_mov && ins->d.t == mop_r )
      {
        if ( is_num(&ins->l) )
        {
          local_regs[ins->d.r] = { num_val(&ins->l) };
        }
        else if ( ins->l.t == mop_r )
        {
          mreg_t src = ins->l.r;
          auto lit = local_regs.find(src);
          if ( lit != local_regs.end() )
          {
            local_regs[ins->d.r] = lit->second;
          }
          else
          {
            auto git = regmap.find(src);
            if ( git != regmap.end() )
              local_regs[ins->d.r] = { git->second };
            // else: source unknown -> leave destination untouched.
          }
        }
      }
    }

    // Check the state register (and the neighbouring reg ids, matching the
    // Python +/-1 heuristic). Return the unique value, or nullopt if ambiguous.
    const mreg_t cands[3] = {
      state_reg,
      mreg_t(state_reg - 1),
      mreg_t(state_reg + 1),
    };
    for ( mreg_t r : cands )
    {
      auto it = local_regs.find(r);
      if ( it != local_regs.end() )
      {
        if ( it->second.size() == 1 )
          return *it->second.begin();
        return std::nullopt; // ambiguous -- conditional assignment
      }
    }

    // Not found in this block -- try predecessors.
    if ( blk->npred() == 1 )
      return scan(blk->pred(0), depth + 1);

    if ( blk->npred() > 1 && depth < 4 )
    {
      std::set<uint64_t> results;
      int lim = std::min(blk->npred(), 8);
      for ( int j = 0; j < lim; ++j )
      {
        std::optional<uint64_t> v = scan(blk->pred(j), depth + 1);
        if ( v.has_value() )
          results.insert(*v);
      }
      if ( results.size() == 1 )
        return *results.begin();
    }

    return std::nullopt;
  };

  std::optional<uint64_t> res = scan(serial, 0);
  if ( res.has_value() )
  {
    if ( out != nullptr )
      *out = *res;
    DLOG(L_TRACE, "resolve blk %d -> state=0x%llx",
         serial, (unsigned long long)*res);
    return true;
  }
  DLOG(L_TRACE, "resolve blk %d -> ambiguous/unresolved", serial);
  return false;
}

void forward_state_map(mba_t *mba,
                       mreg_t state_reg,
                       const std::set<int> &disp_blocks,
                       const std::map<mreg_t, uint64_t> &regmap,
                       std::map<int, uint64_t> *out)
{
  if ( out == nullptr )
    return;

  // Register ids the Python treats as "the state var" (state_reg +/- 1).
  auto is_state_reg = [&](mreg_t r) -> bool
  {
    return r == state_reg
        || r == mreg_t(state_reg - 1)
        || r == mreg_t(state_reg + 1);
  };

  // Find all sites where the state register is assigned a known constant,
  // using local propagation within each block.
  std::vector<std::pair<int, uint64_t>> assign_sites; // (block serial, value)

  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *blk = mba->get_mblock(i);
    std::map<mreg_t, uint64_t> local;

    for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
    {
      if ( ins->opcode == m_mov && ins->d.t == mop_r )
      {
        mreg_t r = ins->d.r;
        if ( is_num(&ins->l) )
        {
          uint64_t v = num_val(&ins->l);
          local[r] = v;
          if ( is_state_reg(r) )
            assign_sites.emplace_back(i, v);
        }
        else if ( ins->l.t == mop_r )
        {
          bool have = false;
          uint64_t src_val = 0;
          auto lit = local.find(ins->l.r);
          if ( lit != local.end() )
          {
            src_val = lit->second;
            have = true;
          }
          else
          {
            auto git = regmap.find(ins->l.r);
            if ( git != regmap.end() )
            {
              src_val = git->second;
              have = true;
            }
          }
          if ( have )
          {
            local[r] = src_val;
            if ( is_state_reg(r) )
              assign_sites.emplace_back(i, src_val);
          }
        }
      }
    }
  }

  // For each assignment site, follow the CFG forward to a goto-to-dispatcher.
  for ( const auto &site : assign_sites )
  {
    int start_blk = site.first;
    uint64_t const_val = site.second;

    std::set<int> visited;
    std::deque<int> queue;
    queue.push_back(start_blk);

    while ( !queue.empty() )
    {
      int s = queue.front();
      queue.pop_front();

      if ( visited.count(s) != 0 )
        continue;
      visited.insert(s);
      if ( visited.size() > 20 ) // limit search depth
        break;

      if ( s < 0 || s >= mba->qty )
        continue;
      mblock_t *blk = mba->get_mblock(s);
      minsn_t *tail = blk->tail;

      // Does this block goto the dispatcher?
      if ( tail != nullptr
        && tail->opcode == m_goto
        && tail->l.t == mop_b
        && disp_blocks.count(tail->l.b) != 0 )
      {
        // Ensure the state register is not overwritten between the assignment
        // site and this goto. Same block as the site is always OK; otherwise
        // reject if this block writes the state register again.
        if ( s == start_blk )
        {
          (*out)[s] = const_val;
        }
        else
        {
          bool overwritten = false;
          for ( minsn_t *ins = blk->head; ins != nullptr; ins = ins->next )
          {
            if ( ins->opcode == m_mov && ins->d.t == mop_r
              && is_state_reg(ins->d.r) )
            {
              overwritten = true;
              break;
            }
          }
          if ( !overwritten )
            (*out)[s] = const_val;
        }
        continue; // do not descend past a dispatcher edge
      }

      // Follow successors, but never into the dispatcher.
      for ( int j = 0; j < blk->nsucc(); ++j )
      {
        int succ = blk->succ(j);
        if ( disp_blocks.count(succ) == 0 && visited.count(succ) == 0 )
          queue.push_back(succ);
      }
    }
  }
}

} // namespace unslop
