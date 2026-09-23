/*
 *  Unslopper - a Hex-Rays microcode-level control-flow-flattening remover.
 *
 *  This translation unit is the plugin entry point and the deflattening
 *  orchestrator. It installs a custom block-level optimizer (optblock_t)
 *  that runs, exactly once per function, at the MMAT_LOCOPT maturity level.
 *
 *  Pipeline (ported from CFFDeflattener / _deflat in cff_deflat.py):
 *      1. select a Profile (first whose detect() fires, else generic)
 *      2. detect_dispatcher()      - recover the flattening dispatcher
 *      3. profile->configure()     - refine the DispatcherInfo
 *      4. rewrite_cfg()            - retarget flattened gotos to real targets
 *      5. profile->post_process()  - family-specific cleanup
 *      6. mba->verify(true)        - on failure the function is marked skip
 *
 *  Modelled on the vds11 sample (optblock_t + plugin_ctx_t + PLUGIN_MULTI).
 */

#include <hexrays.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <cstdlib>
#include <map>
#include <set>
#include <vector>

#include "unslop_types.h"
#include "unslop_log.h"
#include "microcode_utils.h"
#include "dispatcher.h"
#include "state_resolver.h"
#include "cfg_rewriter.h"
#include "mba_simplify.h"
#include "opaque_mba.h"
#include "fairplay_dispatch.h"
#include "coreald_sbox.h"
#include "profile.h"
#include "stack_jtbl.h"
#include "ixguard_mba.h"
#include "hash_predicates.h"
#include "svc_flags.h"
#include "anti_decompiler.h"
#include "semantic_diffusion.h"
#include "virtual_call.h"
#include "svc_resolver.h"
#include "verified_jump.h"
#include "arxan_branches.h"

namespace unslop {

//--------------------------------------------------------------------------
// FIX 3: upper size cap. Functions with more than this many microcode blocks
// are skipped outright - they are almost never real CFF and the full-MBA
// analysis would hang IDA's single UI thread. Overridable once at plugin init
// from the environment (UNSLOP_MAX_BLOCKS).
static int g_max_blocks = 4000;

//--------------------------------------------------------------------------
// Profile registry.
//
// The factories return freshly-allocated Profile instances; the header
// contract is that callers do not own the returned pointers, so we build a
// single persistent set of instances on first use and hand back the same
// pointers on every call. They live for the lifetime of the process.
std::vector<Profile*> all_profiles()
{
  static std::vector<Profile*> profiles;
  if ( profiles.empty() )
  {
    // Detection-priority order: the more specific families first, the
    // generic OLLVM shape last so it does not shadow the others.
    profiles.push_back(make_mvg());
    profiles.push_back(make_promon());
    profiles.push_back(make_dexprotector());
    profiles.push_back(make_ollvm());
  }
  return profiles;
}

//--------------------------------------------------------------------------
// Unslopper block optimizer.
struct UnslopperOptblock : public optblock_t
{
  // Dedup is keyed by (entry_ea, maturity): the pipeline now runs once per
  // maturity level (GLBOPT1 and GLBOPT2), so a function may legitimately be
  // processed at each level. Entries belong to one generated microcode array,
  // not the database lifetime: hxe_microcode clears them for every fresh
  // decompilation, including after mark_cfunc_dirty() or a type change.
  typedef std::pair<ea_t, int> fkey_t;
  std::set<fkey_t> done;         // (func, maturity) already processed (dedup)
  std::set<fkey_t> skip;         // (func, maturity) that failed verification
  std::set<fkey_t> not_cff;      // FIX 6: no dispatcher / rejected by pre-filter
  std::set<ea_t>   svc_done;     // functions already syscall-annotated (once)
  bool active = true;
  bool hash_snapshot = false;
  struct Diagnostics {
    StackJtblDiagnostics stack;
    ArxanDiagnostics arxan;
    CoreALDDiagnostics coreald;
    std::string hash_reason="not_attempted";
    int mba=0,hash=0,hash_candidates=0,edges=0,errors=0,svc_flags=0;
  };
  std::map<ea_t,Diagnostics> diagnostics;

  // Statistics.
  int stat_deflattened = 0;     // functions with >=1 change
  int stat_changes     = 0;     // total CFG edges rewritten
  int stat_errors      = 0;     // functions that errored / failed verify

  virtual int idaapi func(mblock_t *blk) override;

  int run_pipeline(mba_t *mba, bool *definitely_not_cff);

  void begin_decompilation(ea_t ea)
  {
    for ( auto *cache : { &done, &skip, &not_cff } )
    {
      auto first = cache->lower_bound(fkey_t(ea, 0));
      auto last = first;
      while ( last != cache->end() && last->first == ea )
        ++last;
      cache->erase(first, last);
    }
    svc_done.erase(ea);
    diagnostics[ea]=Diagnostics{};
  }

  void reset()
  {
    done.clear();
    skip.clear();
    not_cff.clear();
    svc_done.clear();
    diagnostics.clear();
    stat_deflattened = 0;
    stat_changes = 0;
    stat_errors = 0;
  }
};

//--------------------------------------------------------------------------
// Run the full deflattening pipeline over one microcode array. Returns the
// number of changes made. Does not touch the dedup sets or verify (the caller
// owns those), so it mirrors _deflat() in the Python driver.
int UnslopperOptblock::run_pipeline(mba_t *mba, bool *definitely_not_cff)
{
  // Whether this function can be cached as "not CFF" when we return 0. Set on
  // the pre-filter rejections and on a missing/invalid dispatcher; left false
  // for return paths that only fail a profile refinement (those may still be
  // CFF and are worth re-attempting).
  *definitely_not_cff = false;

  StackJtblDiagnostics stack_report;
  int stack_changes = unflatten_stack_jtbl(mba,&stack_report);
  if(mba->maturity==MMAT_GLBOPT1)
    diagnostics[mba->entry_ea].stack=stack_report;
  if ( stack_changes > 0 )
    return stack_changes;

  // Too small to be a flattened function (lower guard).
  if ( mba->qty < 6 )
  {
    *definitely_not_cff = true;
    return 0;
  }

  // FIX 3: upper size cap. Above the cap the full-MBA analysis is too
  // expensive to run on IDA's UI thread; treat as not-CFF and bail.
  if ( mba->qty > g_max_blocks )
  {
    *definitely_not_cff = true;
    return 0;
  }

  // FIX 3 + FIX 4: single O(instructions) pass over the whole array. It
  // computes the maximum predecessor count (a cheap CFF pre-filter) and, in
  // the same walk, records which trigger opcodes are present so the four
  // extra microcode passes can be signature-gated below.
  int max_npred = 0;
  bool has_ijmp = false;      // any m_ijmp        -> anti-decompiler indirect jmp
  bool has_icall = false;     // any m_icall       -> virtual-call devirtualization
  bool has_ptrcast = false;   // any m_low/m_xdu/m_xds cast
  bool has_svc = false;       // any m_call/m_icall (conservative syscall flag)
  bool has_stackrt = false;   // any m_stx/m_ldx   -> stack round-trip
  for ( int i = 0; i < mba->qty; ++i )
  {
    mblock_t *b = mba->get_mblock(i);
    if ( b == nullptr )
      continue;
    int np = b->npred();
    if ( np > max_npred )
      max_npred = np;
    for ( minsn_t *ins = b->head; ins != nullptr; ins = ins->next )
    {
      switch ( ins->opcode )
      {
        case m_ijmp:  has_ijmp = true;  break;
        case m_icall: has_icall = true; has_svc = true; break;
        case m_call:  has_svc = true;   break;
        case m_low:
        case m_xdu:
        case m_xds:   has_ptrcast = true; break;
        case m_stx:
        case m_ldx:   has_stackrt = true; break;
        default: break;
      }
    }
  }

  // FIX 3: no block has 3+ predecessors -> there is no flattening dispatcher
  // to recover. Reject cheaply before building the reg-map / detecting.
  if ( max_npred < 3 )
  {
    *definitely_not_cff = true;
    return 0;
  }

  // FIX 2: build the register-constant map ONCE for the whole function and
  // thread it through every pass that would otherwise rebuild it (dispatcher
  // detection, profile detect/configure, CFG rewrite, svc resolution). This is
  // the single remaining call to build_reg_const_map outside microcode_utils.
  std::map<mreg_t, uint64_t> regmap;
  build_reg_const_map(mba, &regmap);

  // 1. Pick a profile: first whose structural detect() fires. If none match
  //    we fall back to a generic pass (no profile) that still tries to
  //    recover a dispatcher and rewrite it.
  Profile *profile = nullptr;
  for ( Profile *p : all_profiles() )
  {
    if ( p != nullptr && p->detect(mba, regmap) )
    {
      profile = p;
      break;
    }
  }
  DLOG(L_INFO, "profile: %s (qty=%d max_npred=%d)",
       profile != nullptr ? profile->name() : "no profile",
       mba->qty, max_npred);

  // 2. Recover the dispatcher. Required for both the profile and the
  //    generic fallback path.
  DispatcherInfo di;
  if ( !detect_dispatcher(mba, &di, regmap) || !di.valid )
  {
    DLOG(L_INFO, "no dispatcher");
    *definitely_not_cff = true;
    return 0;
  }
  DLOG(L_INFO,
       "dispatcher: strategy=%d block_idx=%d state_reg=%d states=%d disp_blocks=%d",
       di.detection_strategy, di.block_idx, int(di.state_reg),
       int(di.state_map.size()), int(di.dispatcher_blocks.size()));

  // Route each rewriter to the maturity where its mutations are valid:
  //   - emulated D-810 path  -> GLBOPT1/GLBOPT2 (structurer runs after)
  //   - register/legacy path -> LOCOPT only (corrupts GLBOPT microcode)
  // Returning 0 (not marking not_cff) lets the other maturity handle it.
  if ( di.emulated )
  {
    if ( mba->maturity != MMAT_GLBOPT1 && mba->maturity != MMAT_GLBOPT2 )
    {
      DLOG(L_DEBUG, "defer emulated path to GLBOPT (maturity=%d)", mba->maturity);
      return 0;
    }
  }
  else
  {
    // The register/legacy rewriter is opt-in: it is weaker on register-BST
    // dispatchers AND can still produce microcode Hex-Rays rejects (INTERR) on
    // some shapes. Default OFF so the plugin is crash-safe out of the box; the
    // strong+stable emulated path handles transform-BST protectors. Enable with
    // UNSLOP_LEGACY=1 to attempt register-BST families (e.g. AppDome/Promon).
    static int legacy = -1;
    if ( legacy < 0 )
    {
      qstring ev;
      legacy = (qgetenv("UNSLOP_LEGACY", &ev) && atoi(ev.c_str()) != 0) ? 1 : 0;
    }
    if ( !legacy )
    {
      DLOG(L_DEBUG, "register path disabled (set UNSLOP_LEGACY=1 to enable)");
      *definitely_not_cff = true;
      return 0;
    }
    if ( mba->maturity != MMAT_LOCOPT )
    {
      DLOG(L_DEBUG, "defer register path to LOCOPT (maturity=%d)", mba->maturity);
      return 0;
    }
  }

  // 3. Let the matched profile refine the recovered dispatcher. A profile
  //    may reject the function by returning false from configure().
  // When the emulated-BST resolver (strategy 4) already produced an exact
  // per-block state map, it is authoritative: skip profile refinement so a
  // greedily-matched profile (e.g. promon on a DexProtector XOR-BST) cannot
  // pollute di->state_map or reset the strategy.
  if ( profile != nullptr && !di.emulated )
  {
    if ( !profile->configure(mba, &di, regmap) )
      return 0;
  }

  // 4. Rewrite the flattened CFG into direct edges. rewrite_cfg's return
  //    folds edge rewrites and pruned blocks together; recover the pruned
  //    count from the block-count delta so the summary can break them out.
  int qty_before = mba->qty;
  int cfg_ret = rewrite_cfg(mba, &di, profile, regmap);
  int stat_pruned = qty_before - mba->qty;   // blocks removed by pruning
  int stat_edges  = cfg_ret - stat_pruned;    // edges actually rewritten
  int changes = cfg_ret;

  // 5. Family-specific cleanup (opaque predicates, MBA, ...).
  int stat_mba = 0;
  if ( profile != nullptr && changes > 0 )
  {
    stat_mba = profile->post_process(mba, changes);
    changes += stat_mba;
  }

  // 6. New microcode passes. FIX 4: signature-gate each pass on the trigger
  //    opcodes recorded during the single scan above. A pass is skipped only
  //    when its trigger opcode is definitively absent; when in doubt we still
  //    run it (correctness first). semantic-diffusion is a cheap stack
  //    round-trip fold, gated on any m_stx/m_ldx to stack.
  int stat_adec = 0, stat_sdiff = 0, stat_vcall = 0, stat_svc = 0;
  if ( has_ijmp || has_ptrcast )
  {
    stat_adec = resolve_anti_decompiler(mba);
    changes += stat_adec;
  }
  if ( has_stackrt )
  {
    stat_sdiff = fold_semantic_diffusion(mba);
    changes += stat_sdiff;
  }
  if ( has_icall )
  {
    stat_vcall = devirtualize_calls(mba);
    changes += stat_vcall;
  }
  // (syscall annotation moved to an INDEPENDENT layer in func(): it must run
  //  on functions that have no CFF dispatcher, so it cannot live here.)

  DLOG(L_INFO,
       "passes: edges=%d pruned=%d adec=%d sdiff=%d vcall=%d svc=%d mba=%d "
       "(total=%d)",
       stat_edges, stat_pruned, stat_adec, stat_sdiff, stat_vcall, stat_svc,
       stat_mba, changes);

  // FIX 5: the pass files no longer mark chains dirty themselves; do it
  // exactly once here, only when something actually changed.
  if ( changes > 0 )
    mba->mark_chains_dirty();

  return changes;
}

//--------------------------------------------------------------------------
int idaapi UnslopperOptblock::func(mblock_t *blk)
{
  if ( !active )
    return 0;

  mba_t *mba = blk->mba;
  // Run the full unflatten pipeline at the GLOBAL-optimization maturities so
  // Hex-Rays' structurer restructures the resulting direct edges into if/while
  // AFTER we unflatten. GLBOPT1 gives an early shot on already-propagated
  // microcode; GLBOPT2 (most global opts done) is the primary, cleanest pass.
  // Accept both the local-opt and global-opt maturities. The register/legacy
  // rewriter is only valid at MMAT_LOCOPT (it corrupts the more-optimized
  // GLBOPT microcode -> Hex-Rays INTERR); the emulated D-810 path needs the
  // later GLBOPT maturities so the structurer re-forms if/while afterwards.
  // run_pipeline routes each path to its safe maturity once the dispatcher is
  // classified (see the di.emulated gate below).
  if ( mba == nullptr
    || (mba->maturity != MMAT_LOCOPT
        && mba->maturity != MMAT_GLBOPT1
        && mba->maturity != MMAT_GLBOPT2) )
  {
    return 0;
  }

  // Process each (function, maturity) exactly once. func() is invoked per-block,
  // but the pipeline analyses the whole array, so we gate on (entry_ea,maturity).
  ea_t ea = mba->entry_ea;
  fkey_t key(ea, int(mba->maturity));
  if ( done.find(key) != done.end()
    || skip.find(key) != skip.end()
    || not_cff.find(key) != not_cff.end() )  // FIX 6: negative-result cache
  {
    return 0;
  }
  done.insert(key);
  log_begin_func(ea);

  // ---- Independent syscall-annotation layer (decoupled from CFF) ----------
  // BitGuard/MVG hides the Darwin selector in an MBA slice ending in svc #0x80.
  // Most of these live in ordinary RASP/mach wrappers with NO CFF dispatcher,
  // so this must run regardless of dispatcher recovery. Annotation-only (adds a
  // comment via the resolved constant); it never mutates the CFG.
  DLOG(L_DEBUG, "svc layer check: maturity=%d ea=0x%llx already=%d",
       int(mba->maturity), (unsigned long long)ea,
       svc_done.find(ea)!=svc_done.end()?1:0);
  // NOTE: the microcode svc fold is UNRELIABLE on Guardsquare/MVG — Hex-Rays
  // folds the svc slice out of the microcode, so most sites have no covering
  // block and the few that fold can be wrong. The reliable path is the offline
  // disassembly resolver (mvg_svc_map.json + tools/apply_svc_map.py). This
  // microcode pass is therefore opt-in via UNSLOP_SVC=1.
  static int svc_on = -1;
  if ( svc_on < 0 ) { qstring ev; svc_on = (qgetenv("UNSLOP_SVC",&ev)&&atoi(ev.c_str())!=0)?1:0; }
  if ( svc_on && mba->maturity == MMAT_LOCOPT && svc_done.find(ea) == svc_done.end() )
  {
    svc_done.insert(ea);
    std::map<mreg_t, uint64_t> svc_regmap;
    build_reg_const_map(mba, &svc_regmap);
    int n = resolve_svcs(mba, svc_regmap);
    if ( n > 0 )
      DLOG(L_INFO, "svc layer: annotated %d syscall(s)", n);
  }

  // ---- makeOpaque / MBA simplification layer (decoupled from CFF) ---------
  // FairPlay (`makeOpaque`) and Arxan-style MBA obfuscators do not flatten the
  // CFG; they wrap expressions in opaque algebra (S-box chains, affine round-
  // trips, opaque predicates, MBA spellings of x-c). These handlers have NO
  // dispatcher, so this must run regardless of CFF recovery. Every rule is
  // self-proving (verified S-box tables, proven modular inverses, always-true
  // residues), so it is safe to run unconditionally. Opt out with
  // UNSLOP_NO_OPAQUE=1. The single strict verify below covers these edits.
  int opaque_changes = 0;
  int ixguard_mba_changes = simplify_ixguard_mba(mba);
  auto &report=diagnostics[ea];
  report.mba+=ixguard_mba_changes;
  int hash_candidates=0;std::string hash_reason;
  int hash_changes=simplify_hash_predicates(mba,hash_snapshot,&hash_candidates,&hash_reason);
  report.hash+=hash_changes;report.hash_candidates+=hash_candidates;
  if(hash_candidates || !report.hash_candidates)report.hash_reason=hash_reason;
  static int opq_on = -1;
  if ( opq_on < 0 )
  {
    qstring ev;
    opq_on = (qgetenv("UNSLOP_NO_OPAQUE", &ev) && atoi(ev.c_str()) != 0) ? 0 : 1;
  }
  if ( opq_on )
  {
    try { opaque_changes = simplify_opaque_mba(mba); }
    catch ( ... ) { opaque_changes = 0; }
    if ( opaque_changes > 0 )
    {
      mba->mark_chains_dirty();
      DLOG(L_INFO, "opaque layer: simplified %d expression(s)", opaque_changes);
    }
  }

  opaque_changes += ixguard_mba_changes+hash_changes;

  int changes = 0;
  bool not_cff_result = false;
  try
  {
    changes = run_pipeline(mba, &not_cff_result);
  }
  catch ( ... )
  {
    // A profile / recovery step threw: leave the function untouched.
    DLOG(L_ERROR, "pipeline threw an exception");
    ++stat_errors;
    ++report.errors;
    log_end_func();
    return 0;
  }

  if ( changes <= 0 && opaque_changes <= 0 )
  {
    // Cache a rejection for the remaining callbacks on this generated array.
    // A new decompilation must reconsider it: types or bytes may have changed.
    if ( not_cff_result )
      not_cff.insert(key);
    log_end_func();
    return 0;
  }

  // FIX 1: exactly ONE verify, here at the end of func(). Debug builds do the
  // full always-verify; release does the cheaper conditional check. Either way
  // a corrupt result throws and we mark the function skip so the broken form
  // is never emitted again.
  try
  {
    // Always strict-verify: a deobfuscator must never hand Hex-Rays corrupt
    // microcode (that triggers INTERR and aborts IDA). On failure we mark the
    // (func,maturity) as skip so it is not re-attempted.
    mba->verify(true);
  }
  catch ( ... )
  {
    DLOG(L_ERROR, "verify FAILED after pipeline (function skipped)");
    skip.insert(key);
    ++stat_errors;
    ++report.errors;
    log_end_func();
    return 0;
  }

  qstring fname;
  if ( get_func_name(&fname, ea) <= 0 )
    fname.sprnt("%a", ea);
  stat_changes += changes;
  report.edges+=changes;
  if ( changes > 0 )
  {
    ++stat_deflattened;
    if ( opaque_changes > 0 )
      msg("[unslop] %s: deflattened, %d edge(s) rewritten (+%d opaque)\n",
          fname.c_str(), changes, opaque_changes);
    else
      msg("[unslop] %s: deflattened, %d edge(s) rewritten\n", fname.c_str(), changes);
  }
  else
  {
    // Opaque-only cleanup: no dispatcher, but makeOpaque/MBA expressions folded.
    msg("[unslop] %s: %d opaque expression(s) simplified\n",
        fname.c_str(), opaque_changes);
  }
  DLOG(L_INFO, "func done: %d edge(s), %d opaque", changes, opaque_changes);

  log_end_func();
  return changes + opaque_changes;
}

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  UnslopperOptblock optimizer;
  bool installed = false;
  bool callback_installed = false;
  std::map<ea_t,int> arxan_pending;

  static ssize_t idaapi on_hexrays_event(
          void *ud, hexrays_event_t event, va_list va)
  {
    if ( event == hxe_flowchart_ea )
    {
      const auto *fc = va_arg(va, const qflow_chart_ea_t *);
      mba_t *mba = va_arg(va, mba_t *);
      bitset_t *reachable = va_arg(va, bitset_t *);
      auto *ctx = static_cast<plugin_ctx_t *>(ud);
      if ( mba != nullptr )
        ctx->arxan_pending[mba->entry_ea] = ctx->optimizer.active
          ? expand_arxan_reachability(fc, mba, reachable) : 0;
    }
    if ( event == hxe_preoptimized )
    {
      mba_t *mba = va_arg(va, mba_t *);
      auto *ctx = static_cast<plugin_ctx_t *>(ud);
      if ( mba != nullptr && ctx->optimizer.active )
      {
        auto it = ctx->optimizer.diagnostics.find(mba->entry_ea);
        if ( it != ctx->optimizer.diagnostics.end()
             && (it->second.arxan.changed > 0 || it->second.coreald.changed > 0) )
        {
          try
          {
            mba->verify(true);
            if ( it->second.arxan.changed > 0 ) it->second.arxan.verified = 1;
          }
          catch ( ... )
          {
            ++it->second.errors;
            ++ctx->optimizer.stat_errors;
            msg("[unslop] native microcode verification failed at %a\n", mba->entry_ea);
            return MERR_BADBLK;
          }
        }
      }
    }
    if ( event == hxe_microcode )
    {
      mba_t *mba = va_arg(va, mba_t *);
      if ( mba != nullptr )
      {
        auto *ctx = static_cast<plugin_ctx_t *>(ud);
        ctx->optimizer.begin_decompilation(mba->entry_ea);
        ctx->optimizer.diagnostics[mba->entry_ea].arxan.reachable_added = ctx->arxan_pending[mba->entry_ea];
        ctx->arxan_pending.erase(mba->entry_ea);
        if ( ctx->optimizer.active )
          ctx->optimizer.diagnostics[mba->entry_ea].svc_flags=preserve_svc_carry(mba);
        if ( ctx->optimizer.active )
        {
          restore_arxan_branches(mba, &ctx->optimizer.diagnostics[mba->entry_ea].arxan);
          restore_verified_jumps(mba);
          restore_coreald_sboxes(mba, &ctx->optimizer.diagnostics[mba->entry_ea].coreald);
        }
      }
    }
    return 0;
  }

  plugin_ctx_t()
  {
    callback_installed = install_hexrays_callback(on_hexrays_event, this);
    if ( !callback_installed )
    {
      optimizer.active = false;
      msg("[unslop] cannot install decompilation lifecycle callback\n");
      return;
    }
    install_optblock_handler(&optimizer);
    installed = true;
    msg("[unslop] installed - press F5 to decompile with deflattening\n");
  }

  ~plugin_ctx_t()
  {
    if ( installed )
      remove_optblock_handler(&optimizer);
    if ( callback_installed )
      remove_hexrays_callback(on_hexrays_event, this);
    term_hexrays_plugin();
  }

  virtual bool idaapi run(size_t arg) override;
};

//--------------------------------------------------------------------------
// run() argument protocol:
//   1 - disable  (remove handler)
//   2 - enable   (install handler)
//   3 - status
//   0 / other - toggle
bool idaapi plugin_ctx_t::run(size_t arg)
{
  switch ( arg )
  {
    case 1: // disable
      if ( installed )
      {
        remove_optblock_handler(&optimizer);
        installed = false;
      }
      optimizer.active = false;
      msg("[unslop] disabled\n");
      break;

    case 2: // enable
      if ( !installed )
      {
        install_optblock_handler(&optimizer);
        installed = true;
      }
      optimizer.active = true;
      msg("[unslop] enabled\n");
      break;

    case 3: // status
      msg("[unslop] %s - %d function(s) deflattened, %d edge(s), %d error(s)\n",
          (installed && optimizer.active) ? "ON" : "OFF",
          optimizer.stat_deflattened,
          optimizer.stat_changes,
          optimizer.stat_errors);
      break;

    case 4: // Structured per-function diagnostic summaries for this instance.
      for(const auto &row:optimizer.diagnostics) {
        const auto &d=row.second;
        msg("[unslop-report] {\"ea\":\"0x%llx\",\"stack\":\"%s\",\"cases\":%d,\"contexts\":%d,\"mba\":%d,\"hash\":%d,\"hash_candidates\":%d,\"hash_reason\":\"%s\",\"edges\":%d,\"errors\":%d,\"svc_flags\":%d}\n",
            (unsigned long long)row.first,d.stack.reason.c_str(),d.stack.cases,d.stack.contexts,
            d.mba,d.hash,d.hash_candidates,d.hash_reason.c_str(),d.edges,d.errors,d.svc_flags);
        msg("[unslop-arxan] {\"ea\":\"0x%llx\",\"verified\":%d,\"reachable_added\":%d,\"matched\":%d,\"changed\":%d,\"ownership_rejected\":%d,\"entry_rejected\":%d,\"missing_block\":%d}\n",
            (unsigned long long)row.first,d.arxan.verified,d.arxan.reachable_added,d.arxan.matched,d.arxan.changed,
            d.arxan.ownership_rejected,d.arxan.entry_rejected,d.arxan.missing_block);
        msg("[unslop-coreald] {\"ea\":\"0x%llx\",\"markers\":%d,\"proven\":%d,\"changed\":%d,\"rejected\":%d}\n",
            (unsigned long long)row.first,d.coreald.markers,d.coreald.proven,d.coreald.changed,d.coreald.rejected);
      }
      break;
    case 20: // Explicit analysis assumption; does not patch target data.
      optimizer.hash_snapshot=true;
      for(const auto &row:optimizer.diagnostics)
        if(row.second.hash_candidates)mark_cfunc_dirty(row.first,false);
      msg("[unslop] FNV FIXED-SEED SNAPSHOT enabled: conditional analysis view, not runtime immutability\n");
      break;
    case 21:
      optimizer.hash_snapshot=false;
      for(const auto &row:optimizer.diagnostics)
        if(row.second.hash_candidates)mark_cfunc_dirty(row.first,false);
      msg("[unslop] FNV fixed-seed snapshot disabled\n");
      break;

    case 10: // FairPlay: resolve the VM dispatch handler table (one-shot)
      fairplay_resolve_vm_table();
      break;

    default: // toggle
      if ( installed && optimizer.active )
      {
        remove_optblock_handler(&optimizer);
        installed = false;
        optimizer.active = false;
        msg("[unslop] toggled OFF - %d deflattened, %d error(s)\n",
            optimizer.stat_deflattened, optimizer.stat_errors);
      }
      else
      {
        if ( !installed )
        {
          install_optblock_handler(&optimizer);
          installed = true;
        }
        optimizer.active = true;
        optimizer.reset();
        msg("[unslop] toggled ON\n");
      }
      break;
  }
  return true;
}

} // namespace unslop

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr; // no decompiler available

  // Initialize the debug-logging / diagnostics subsystem from the environment.
  unslop::log_init();

  // FIX 3: read the block-count cap override once, at plugin init.
  qstring env;
  if ( qgetenv("UNSLOP_MAX_BLOCKS", &env) )
  {
    int v = atoi(env.c_str());
    if ( v > 0 )
      unslop::g_max_blocks = v;
  }

  const char *hxver = get_hexrays_version();
  msg("[unslop] Hex-Rays %s detected, Unslopper deflattener ready\n", hxver);
  auto *ctx = new unslop::plugin_ctx_t;
  if ( !ctx->callback_installed )
  {
    delete ctx;
    return nullptr;
  }
  return ctx;
}

//--------------------------------------------------------------------------
static const char comment[] =
  "Unslopper: microcode-level control-flow-flattening remover";
static const char help[] =
  "Unslopper removes control-flow flattening at the Hex-Rays microcode "
  "(mba_t) level.\n"
  "Run with argument 1 to disable, 2 to enable, 3 for status, or no "
  "argument to toggle.\n";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,           // works with multiple idbs in parallel; visible in menu
  init,                   // initialize
  nullptr,                // terminate (must be nullptr for PLUGIN_MULTI)
  nullptr,                // run (must be nullptr for PLUGIN_MULTI)
  comment,                // long comment about the plugin
  help,                   // multiline help about the plugin
  "Unslopper",               // the preferred short name of the plugin
  "Ctrl-Shift-U",         // the preferred hotkey to run the plugin
};
