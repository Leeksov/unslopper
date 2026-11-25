#pragma once

#include <map>

// Keep the largest verified per-decompilation CFG edit count for each function.
// Repeated F5 can replay the same edits, so summing across decompilations would
// make a function appear to have more distinct recovered edges than it has.
template <class Key>
class CffActivity
{
  std::map<Key, int> maximum_edges;

public:
  void note_verified(Key key, int decompilation_edges)
  {
    if (decompilation_edges > maximum_edges[key])
      maximum_edges[key] = decompilation_edges;
  }

  int observed_edges(Key key) const
  {
    auto it = maximum_edges.find(key);
    return it == maximum_edges.end() ? 0 : it->second;
  }

  void clear() { maximum_edges.clear(); }
};
