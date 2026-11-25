#include "../src/core/cff_activity.h"

#include <cassert>
#include <cstdint>

int main()
{
  CffActivity<std::uint64_t> activity;
  constexpr std::uint64_t function = 0x4D98;
  constexpr std::uint64_t other = 0x4F68;

  // Two verified maturity passes in the first decompilation.
  int current_edges = 8;
  activity.note_verified(function, current_edges);
  current_edges += 24;
  activity.note_verified(function, current_edges);
  assert(activity.observed_edges(function) == 32);

  // A fresh F5 resets the last-run row; prior verified activity survives.
  current_edges = 0;
  assert(current_edges == 0);
  assert(activity.observed_edges(function) == 32);

  // Replaying the same edits must not inflate historical coverage.
  activity.note_verified(function, 8);
  activity.note_verified(function, 32);
  assert(activity.observed_edges(function) == 32);
  activity.note_verified(function, 40);
  assert(activity.observed_edges(function) == 40);

  activity.note_verified(other, 20);
  assert(activity.observed_edges(other) == 20);
  assert(activity.observed_edges(0x6104) == 0);
  activity.clear();
  assert(activity.observed_edges(function) == 0);
  assert(activity.observed_edges(other) == 0);
}
