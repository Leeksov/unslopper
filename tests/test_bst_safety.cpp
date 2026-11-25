#include "../src/core/bst_safety.h"

int main()
{
  using unslop::bst_state_write_overlaps;
  using unslop::bst_terminal_branch_shape;

  if ( !bst_terminal_branch_shape(true, 2, 12, 11, 11) ) return 1;
  if ( bst_terminal_branch_shape(false, 2, 12, 11, 11) ) return 2;
  if ( bst_terminal_branch_shape(true, 3, 12, 11, 11) ) return 3;
  if ( bst_terminal_branch_shape(true, 2, 12, 13, 11) ) return 4;
  if ( bst_terminal_branch_shape(true, 2, 11, 11, 11) ) return 5;

  // Exact, partial and neighbouring writes have distinct meanings.
  if ( !bst_state_write_overlaps(100, 4, 100, 4) ) return 6;
  if ( !bst_state_write_overlaps(100, 4, 102, 1) ) return 7;
  if ( !bst_state_write_overlaps(100, 4, 99, 2) ) return 8;
  if ( bst_state_write_overlaps(100, 4, 99, 1) ) return 9;
  if ( bst_state_write_overlaps(100, 4, 104, 4) ) return 10;
  return 0;
}
