#include "svc_resolver.h"
#include "mba_simplify.h"
#include "microcode_utils.h"
#include "unslop_log.h"

#include <idp.hpp>      // str2reg
#include <funcs.hpp>    // get_func
#include <bytes.hpp>    // get_dword, get_qword, set_cmt, is_mapped

#include <cstdint>
#include <cstdio>
#include <map>
#include <set>

namespace unslop {

//--------------------------------------------------------------------------
// BitGuard / MVG obfuscated Darwin syscall resolution at the microcode level.
//
// Reference: mvg-research/mvg_svc_resolver.py (Romain Thomas' BitGuard/MVG
// articles). Native ARM64 `svc #0x80` encodes as 0xD4001001; the Darwin
// syscall selector is placed into architectural X16 by an MBA (mixed
// boolean-arithmetic) expression. Here we:
//
//   1. locate every `svc #0x80` site (raw opcode at the instruction ea, which
//      covers both the raw svc and any helper/low-level-call lowering of it),
//   2. find the microcode that defines X16 reaching that site,
//   3. run the MBA simplifier / affine constant folder over that defining
//      expression, and
//   4. when (and only when) it collapses to a single constant, annotate the
//      svc ea with the resolved Darwin syscall number.
//
// Safety: we never rewrite the flow; we only add a comment, and only when the
// fold yields one unambiguous constant selector. Anything dynamic or
// file-backed (that the pure-constant folder cannot prove) is left untouched.
//--------------------------------------------------------------------------

// AArch64 SVC encoding: base 0xD4000001, imm16 at bits [20:5].
static const uint32_t SVC_MASK   = 0xFFE0001Fu;
static const uint32_t SVC_OPCODE = 0xD4000001u;
static const uint32_t SVC_IMM    = 0x80u;        // Darwin uses svc #0x80

// True if the 4 bytes at `ea` decode to `svc #0x80`.
static bool is_svc_word(ea_t ea)
{
  if ( ea == BADADDR )
    return false;
  uint32_t w = get_dword(ea);
  return (w & SVC_MASK) == SVC_OPCODE && ((w >> 5) & 0xFFFFu) == SVC_IMM;
}

// Human-readable hint for a Darwin selector (numbers stay authoritative).
static const char *darwin_hint(int64_t n)
{
  switch ( n )
  {
    case -47: return "mach_msg2_trap";
    case -31: return "mach_msg_trap";
    case -28: return "task_self_trap";
    case -14: return "_kernelrpc_mach_vm_protect_trap";
    case 1:   return "exit";
    case 2:   return "fork";
    case 3:   return "read";
    case 4:   return "write";
    case 5:   return "open";
    case 6:   return "close";
    case 10:  return "unlink";
    case 20:  return "getpid";
    case 26:  return "ptrace";
    case 33:  return "access";
    case 37:  return "kill";
    case 39:  return "getppid";
    case 54:  return "ioctl";
    case 73:  return "munmap";
    case 74:  return "mprotect";
    case 92:  return "fcntl";
    case 97:  return "socket";
    case 98:  return "connect";
    case 116: return "gettimeofday";
    case 138: return "utimes";
    case 159: return "unmount";
    case 191: return "pathconf";
    case 197: return "mmap";
    case 202: return "sysctl";
    case 338: return "stat64";
    case 339: return "fstat64";
    case 340: return "lstat64";
    case 344: return "getdirentries64";
    case 347: return "getfsstat64";
    case 372: return "thread_selfid";
    case 381: return "__mac_syscall";
    case 437: return "openat";
    case 463: return "fstatat64";
    default:  return nullptr;
  }
}

// Forward decls for the recursive resolver.
static const minsn_t *reaching_def(mba_t *mba, mblock_t *blk,
                                   const minsn_t *site, mreg_t reg);

// Fold an operand that should be a constant ADDRESS (mop_n, or a small
// add/sub tree of constants -- e.g. adrp+add already lowered by Hex-Rays).
static bool fold_addr_const(const mop_t *m, uint64_t *out)
{
  if ( m == nullptr )
    return false;
  if ( is_num(m) ) { *out = num_val(m); return true; }
  if ( m->t == mop_d && m->d != nullptr )
  {
    const minsn_t *d = m->d;
    uint64_t a = 0, b = 0;
    if ( (d->opcode == m_add || d->opcode == m_sub)
      && fold_addr_const(&d->l, &a) && fold_addr_const(&d->r, &b) )
    {
      *out = d->opcode == m_add ? a + b : a - b;
      return true;
    }
    if ( d->opcode == m_mov )
      return fold_addr_const(&d->l, out);
  }
  return false;
}

// If `m` is a memory load (ldx) whose address folds to a constant that is
// mapped in the image, replace it with the value read from the IDB. The
// __DATA key globals MVG uses are file-initialised to the real key, so the
// linker value is exactly what the slice consumes. Reads the width implied by
// the load's destination size (4 or 8 bytes).
static void subst_memory_loads(mop_t *m)
{
  if ( m == nullptr || m->t != mop_d || m->d == nullptr )
    return;
  minsn_t *d = m->d;
  if ( d->opcode == m_ldx )
  {
    uint64_t addr = 0;
    if ( fold_addr_const(&d->r, &addr) && is_mapped(ea_t(addr)) )
    {
      int sz = (m->size >= 1 && m->size <= 8) ? m->size : 4;
      uint64_t val = sz >= 8 ? get_qword(ea_t(addr))
                             : uint64_t(get_dword(ea_t(addr)));
      m->make_number(val, sz, BADADDR);
      return;
    }
  }
  subst_memory_loads(&d->l);
  subst_memory_loads(&d->r);
  subst_memory_loads(&d->d);
}

// Substitute register leaves whose value is known in `env`, and fold constant
// memory loads, throughout a (copied) expression tree.
static void subst_known(mop_t *m, const std::map<mreg_t, uint64_t> &env)
{
  if ( m == nullptr )
    return;
  if ( m->t == mop_r )
  {
    std::map<mreg_t, uint64_t>::const_iterator it = env.find(m->r);
    if ( it != env.end() )
    {
      int sz = (m->size >= 1 && m->size <= 8) ? m->size : 8;
      m->make_number(it->second, sz, BADADDR);
    }
    return;
  }
  if ( m->t == mop_d && m->d != nullptr )
  {
    subst_memory_loads(m);            // may replace *m with a number
    if ( m->t != mop_d )
      return;
    subst_known(&m->d->l, env);
    subst_known(&m->d->r, env);
    subst_known(&m->d->d, env);
  }
}

// Recursively resolve the constant value of register `reg` reaching `site` in
// `blk`: find its reaching def, resolve that def's own register inputs (by
// recursion) and constant memory loads, then affine-fold to a single constant.
// `env` memoises already-resolved registers; `depth` bounds the slice.
static bool resolve_reg_value(
        mba_t *mba, mblock_t *blk, const minsn_t *site, mreg_t reg,
        std::map<mreg_t, uint64_t> &env, int depth, uint64_t *out)
{
  std::map<mreg_t, uint64_t>::const_iterator known = env.find(reg);
  if ( known != env.end() ) { *out = known->second; return true; }
  if ( depth > 24 )
    return false;

  const minsn_t *def = reaching_def(mba, blk, site, reg);
  if ( def == nullptr )
    return false;

  // Copy the def and try to constant-fold it. First resolve every register the
  // def reads, recursively, seeding env so shared subexpressions fold once.
  minsn_t tmp(*def);

  // Collect the register leaves the def depends on and resolve each.
  std::set<mreg_t> deps;
  struct { static void collect(const mop_t *m, mreg_t self, std::set<mreg_t> *o)
    {
      if ( m == nullptr ) return;
      if ( m->t == mop_r && m->r != self ) o->insert(m->r);
      else if ( m->t == mop_d && m->d != nullptr )
      { collect(&m->d->l, self, o); collect(&m->d->r, self, o); collect(&m->d->d, self, o); }
    } } C;
  C.collect(&tmp.l, reg, &deps);
  C.collect(&tmp.r, reg, &deps);
  for ( mreg_t dr : deps )
  {
    if ( env.find(dr) != env.end() )
      continue;
    uint64_t dv = 0;
    // Resolve the dependency at the DEF site (its own reaching def).
    if ( resolve_reg_value(mba, blk, def, dr, env, depth + 1, &dv) )
      env[dr] = dv;
  }

  subst_known(&tmp.l, env);
  subst_known(&tmp.r, env);
  subst_known(&tmp.d, env);
  try_affine_simplify(&tmp);

  if ( tmp.opcode == m_mov && is_num(&tmp.l) )
  {
    *out = num_val(&tmp.l);
    env[reg] = *out;
    return true;
  }
  return false;
}
// Find the last instruction in `blk` (searching head..before, or the whole
// block when `before` is null) that defines register `reg`. Returns nullptr
// if none.
static const minsn_t *last_def_in_block(
        const mblock_t *blk,
        const minsn_t *before,
        mreg_t reg)
{
  if ( blk == nullptr )
    return nullptr;
  const minsn_t *def = nullptr;
  for ( const minsn_t *ins = blk->head;
        ins != nullptr && ins != before;
        ins = ins->next )
  {
    if ( ins->d.t == mop_r && ins->d.r == reg )
      def = ins;
  }
  return def;
}

// Find the definition of `reg` that reaches the syscall site `site` in `blk`:
// the last def in this block before `site`, else walk a unique single-
// predecessor chain (bounded, cycle-guarded) and take the last def there.
static const minsn_t *reaching_def(
        mba_t *mba,
        mblock_t *blk,
        const minsn_t *site,
        mreg_t reg)
{
  const minsn_t *def = last_def_in_block(blk, site, reg);
  if ( def != nullptr )
    return def;

  std::set<int> seen;
  mblock_t *cur = blk;
  for ( int depth = 0; depth < 8 && cur != nullptr; ++depth )
  {
    if ( !seen.insert(cur->serial).second )
      break;                          // cycle
    if ( cur->npred() != 1 )
      break;                          // ambiguous; stay safe
    mblock_t *pred = mba->get_mblock(cur->predset[0]);
    def = last_def_in_block(pred, nullptr, reg);
    if ( def != nullptr )
      return def;
    cur = pred;
  }
  return nullptr;
}

int resolve_svcs(mba_t *mba, const std::map<mreg_t, uint64_t> &regs)
{
  if ( mba == nullptr )
    return 0;

  // architectural X16 -> microcode register. str2reg returns -1 off-ARM64,
  // which naturally disables this pass on other targets.
  int x16_reg = str2reg("X16");
  if ( x16_reg < 0 )
    return 0;
  mreg_t x16 = reg2mreg(x16_reg);
  if ( x16 == mreg_t(-1) )
    return 0;

  // The `mov #const, reg` assignments used to substitute constant register
  // inputs into the (possibly split) MBA selector expression are supplied by
  // the caller as the shared map built once per function (FIX 2).

  int changes = 0;
  int found = 0, no_def = 0, no_fold = 0;
  std::set<ea_t> resolved;            // one change per distinct svc ea

  // Scan the FUNCTION'S ADDRESS RANGE for `svc #0x80` words: Hex-Rays does not
  // keep a minsn at the raw svc ea (it lowers/optimizes the trap), so we cannot
  // rely on minsn->ea. For each svc site we find the microcode block whose ea
  // range covers it and the instruction at/just-before it, then backward-slice
  // X16 from there.
  func_t *pfn = get_func(mba->entry_ea);
  ea_t fstart = pfn != nullptr ? pfn->start_ea : mba->entry_ea;
  ea_t fend   = pfn != nullptr ? pfn->end_ea   : mba->entry_ea + 4;

  for ( ea_t svc_ea = fstart; svc_ea + 4 <= fend; svc_ea += 4 )
  {
    if ( !is_svc_word(svc_ea) )
      continue;
    if ( resolved.count(svc_ea) != 0 )
      continue;
    ++found;

    // Find the microcode block covering svc_ea and the anchor minsn (last insn
    // whose ea <= svc_ea) to backward-slice from.
    mblock_t *blk = nullptr;
    const minsn_t *site = nullptr;
    for ( int i = 0; i < mba->qty; ++i )
    {
      mblock_t *b = mba->get_mblock(i);
      if ( svc_ea < b->start || svc_ea >= b->end )
        continue;
      blk = b;
      for ( minsn_t *ins = b->head; ins != nullptr; ins = ins->next )
        if ( ins->ea <= svc_ea )
          site = ins;
      break;
    }
    if ( blk == nullptr )
    {
      ++no_def;
      DLOG(L_DEBUG, "svc @0x%llx: no covering block", (unsigned long long)svc_ea);
      // Diagnostic: show blocks whose range is nearest to the svc ea.
      for ( int i = 0; i < mba->qty; ++i )
      {
        mblock_t *b = mba->get_mblock(i);
        if ( svc_ea >= b->start && svc_ea < b->end + 0x40 )
          DLOG(L_TRACE, "  near blk %d [0x%llx,0x%llx) tailop=%d",
               i, (unsigned long long)b->start, (unsigned long long)b->end,
               b->tail ? int(b->tail->opcode) : -1);
      }
      continue;
    }

    {
      std::map<mreg_t, uint64_t> env(regs);   // seed with mov-#imm regmap
      uint64_t v = 0;
      if ( !resolve_reg_value(mba, blk, site, x16, env, 0, &v) )
      { ++no_fold; DLOG(L_DEBUG, "svc @0x%llx: X16 did not fold to constant", (unsigned long long)svc_ea); continue; }

      // Normalize the 32-bit Darwin selector held in X16. Both zero- and
      // sign-extended 32-bit forms are canonical; any other high half is
      // ambiguous, so we leave it unresolved rather than guess.
      uint64_t high = v >> 32;
      if ( high != 0 && high != 0xFFFFFFFFull )
        continue;
      uint32_t raw = uint32_t(v & 0xFFFFFFFFull);
      int64_t num = (raw & 0x80000000u) != 0
                  ? int64_t(raw) - (int64_t(1) << 32)
                  : int64_t(raw);
      const char *ns = num < 0 ? "mach_trap" : "bsd_syscall";
      const char *hint = darwin_hint(num);

      char cmt[160];
      if ( hint != nullptr )
      {
        qsnprintf(cmt, sizeof(cmt),
                  "MVG svc: Darwin syscall %lld (%s) [%s]  X16=0x%llX",
                  (long long)num, hint, ns, (unsigned long long)v);
      }
      else
      {
        qsnprintf(cmt, sizeof(cmt),
                  "MVG svc: Darwin syscall %lld [%s]  X16=0x%llX",
                  (long long)num, ns, (unsigned long long)v);
      }

      // Annotate the svc site ea (falls back to a disassembly comment; there
      // is no per-instruction microcode comment API in this SDK).
      set_cmt(svc_ea, cmt, false);
      resolved.insert(svc_ea);
      ++changes;
    }
  }

  if ( found > 0 )
    DLOG(L_INFO, "svc scan: found=%d resolved=%d no_def=%d no_fold=%d",
         found, changes, no_def, no_fold);
  return changes;
}

} // namespace unslop
