#pragma once
// Shared data types for the Unslopper deflattener: profile kinds, state-transition
// edges, and the DispatcherInfo record that carries a recovered flattening
// dispatcher between detection, resolution, and CFG rewriting.
#include <hexrays.hpp>
#include <set>
#include <map>
#include <vector>
#include <cstdint>

namespace unslop {

// Which protector / obfuscator family a Profile models.
enum class ProfileKind
{
  GENERIC,
  OLLVM,
  PROMON,
  DEXPROTECTOR,
  MVG,
  FAIRPLAY,   // Apple makeOpaque: S-box/MBA/affine/opaque + VM dispatch LUT
  ARXAN,      // branding-stripped MBA branch obfuscator (integrity-centric)
};

// One edge of the recovered state machine: block writing `to_state` before
// jumping back to the dispatcher, guarded (optionally) by a condition.
struct StateTransition
{
  uint64_t from_state = 0;
  uint64_t to_state   = 0;
  bool is_conditional = false;
  bool is_true_branch = false;
};

// Everything known about a single flattening dispatcher inside one mba_t.
struct DispatcherInfo
{
  int block_idx = -1;                    // serial of the dispatcher head block
  mop_t state_var;                       // operand carrying the state value
  mreg_t state_reg = mreg_t(-1);         // register form of the state var, if any
  std::set<int> dispatcher_blocks;       // all blocks that form the dispatcher
  std::map<uint64_t, int> state_map;     // state constant -> target block serial
  std::set<uint64_t> state_consts;       // every observed state constant
  std::set<uint64_t> bst_pivots;         // binary-search-tree comparison pivots
  uint64_t initial_state = 0;            // state assigned at the prologue
  bool valid = false;                    // whether this record is usable
  int detection_strategy = 0;            // 0=none,1=max-preds,2=jump-table,
                                         // 3=state-var-heuristic,4=emulated-BST

  // ── XOR-keyed binary-search-tree dispatcher (DexProtector / OLLVM range) ──
  //
  // Some dispatchers do not compare the raw state variable against equality
  // constants; they first apply a reversible selector transform
  //     t = ((state ^ sel_xor_key) + sel_add)   [as signed 32-bit]
  // and then route through a binary-search tree of <=/</>=/> comparisons of t
  // against threshold pivots. The state_map for such a dispatcher is built by
  // EMULATING the tree once per candidate state constant (build_state_map_
  // emulated), so the map is keyed by the RAW K the case block installs - the
  // transform is applied inside the emulator, never again at lookup time.
  uint64_t sel_xor_key = 0;              // XOR key applied to the state (0 = none)
  int64_t  sel_add     = 0;              // signed constant added after the XOR
  bool     sel_has_transform = false;    // a (state ^ key) [+/-] const was found

  // Register the tree actually compares (the transform result). Distinct from
  // state_reg, which is where case blocks store the raw state.
  mreg_t sel_reg_cmp = mreg_t(-1);

  // Where the raw state lives. Either a register (sel_state_reg) or a memory
  // slot addressed as (ldx sel_state_sel, sel_state_addr); DexProtector keeps
  // it in a stack/frame slot, OLLVM usually in a register.
  bool   sel_mem_state = false;
  mreg_t sel_state_reg = mreg_t(-1);
  mop_t  sel_state_sel;                  // memory selector operand (e.g. cs)
  mop_t  sel_state_addr;                 // memory address operand (e.g. x19+0x18)

  // Per-block raw state constant installed by that block, recovered by the
  // emulated-BST path (block serial -> raw K). When populated the CFG rewriter
  // uses it directly and does NOT re-apply any profile transform.
  std::map<int, uint64_t> block_state;
  bool emulated = false;                 // state_map came from BST emulation
};

} // namespace unslop
