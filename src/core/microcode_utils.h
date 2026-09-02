#pragma once
// Shared Hex-Rays microcode helpers used by the deflattener core and profiles.
#include <hexrays.hpp>
#include <set>
#include <map>
#include <vector>
#include <cstdint>

namespace unslop {

// True if operand is an immediate number.
bool is_num(const mop_t *m);

// Immediate value of a mop_n operand (masked to 32 bit by default), or def.
uint64_t num_val(const mop_t *m, uint64_t def = 0);

// True if operand is a register.
inline bool is_reg(const mop_t *m) { return m != nullptr && m->t == mop_r; }

// True if operand is a stack slot.
inline bool is_stk(const mop_t *m) { return m != nullptr && m->t == mop_S; }

// True if operand is a block reference (jump/goto target).
inline bool is_blkref(const mop_t *m) { return m != nullptr && m->t == mop_b; }

// Compare two operands for structural equality on reg/stack identity.
bool mop_equal(const mop_t *a, const mop_t *b);

// Number of instructions in a block.
int insn_count(const mblock_t *blk);

// Opcode sets used to classify comparison / conditional-branch tails.
bool is_cond_jump(mcode_t op);

// Signed 32-bit reinterpretation.
int64_t s32(uint64_t v);

// Collect `mov #const, reg` assignments across the whole array (register map).
void build_reg_const_map(mba_t *mba, std::map<mreg_t, uint64_t> *out);

} // namespace unslop
