#pragma once

// Pure CFG postcondition for an emulated dispatcher rewrite. The rewritten
// graph may retain an unreachable dispatcher self-cycle, but no dispatcher
// block may remain reachable from the function entry.

#include <vector>

namespace unslop {

inline bool dispatcher_unreachable_from_entry(
    const std::vector<std::vector<int>> &successors,
    const std::vector<int> &dispatcher_blocks)
{
  const int count = int(successors.size());
  if ( count == 0 || dispatcher_blocks.empty() )
    return false;

  std::vector<unsigned char> dispatcher(count, 0);
  for ( int block : dispatcher_blocks )
  {
    if ( block < 0 || block >= count )
      return false;
    dispatcher[block] = 1;
  }

  std::vector<unsigned char> seen(count, 0);
  std::vector<int> pending{0};
  seen[0] = 1;
  while ( !pending.empty() )
  {
    const int block = pending.back();
    pending.pop_back();
    if ( dispatcher[block] )
      return false;
    for ( int next : successors[block] )
    {
      if ( next < 0 || next >= count )
        return false;
      if ( !seen[next] )
      {
        seen[next] = 1;
        pending.push_back(next);
      }
    }
  }
  return true;
}

} // namespace unslop
