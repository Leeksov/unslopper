#include "../src/core/dispatcher_postcondition.h"

#include <cassert>
#include <vector>

int main()
{
  using unslop::dispatcher_unreachable_from_entry;
  using Graph = std::vector<std::vector<int>>;

  // The dispatcher can retain its self-cycle after the rewrite, provided it
  // is completely disconnected from the function's entry.
  assert(dispatcher_unreachable_from_entry(Graph{{1}, {3}, {2}, {}}, {2}));

  // An unresolved direct goto or physical fallthrough to the dispatcher is a
  // failed full-unflattening postcondition, even if other edges were rewired.
  assert(!dispatcher_unreachable_from_entry(Graph{{1}, {2}, {2}, {}}, {2}));
  assert(!dispatcher_unreachable_from_entry(Graph{{1}, {2}, {3}, {}}, {2}));

  // Every dispatcher node must be unreachable, not merely its nominated root.
  assert(!dispatcher_unreachable_from_entry(Graph{{1}, {3}, {3}, {}}, {2, 3}));
  assert(!dispatcher_unreachable_from_entry(Graph{{1}, {2}}, {0}));

  // Incomplete or malformed graphs fail closed.
  assert(!dispatcher_unreachable_from_entry(Graph{{2}, {}}, {1}));
  assert(!dispatcher_unreachable_from_entry(Graph{{1}, {}}, {}));
  assert(!dispatcher_unreachable_from_entry(Graph{}, {0}));
}
