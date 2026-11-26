#pragma once

#include <cstdint>
#include <vector>

namespace unslop {

// Microregister offsets are byte addresses. A later write to any byte of the
// 32-bit state invalidates a previously recovered state constant.
inline bool bst_state_write_overlaps(uint64_t state_reg, int state_size,
                                     uint64_t write_reg, int write_size)
{
  return state_size > 0 && write_size > 0
      && state_reg < write_reg + uint64_t(write_size)
      && write_reg < state_reg + uint64_t(state_size);
}

// A tree node must have one explicit branch target and one physical
// fallthrough. Merely containing a conditional earlier in the block is not
// enough to prove which successor it selects.
inline bool bst_terminal_branch_shape(bool is_terminal, int successors,
                                      int branch_target, int fallthrough,
                                      int next_serial)
{
  return is_terminal && successors == 2
      && branch_target != fallthrough
      && fallthrough == next_serial;
}

// Directly rewiring an identity BST entry bypasses every instruction in its
// comparison nodes. Only NOPs may precede the terminal branch in that mode.
inline bool bst_branch_prefix_only_nops(const std::vector<int> &prefix,
                                        int nop_opcode)
{
  for ( int opcode : prefix )
    if ( opcode != nop_opcode )
      return false;
  return true;
}

} // namespace unslop
