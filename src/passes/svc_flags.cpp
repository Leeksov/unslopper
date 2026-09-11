#include "svc_flags.h"
#include <bytes.hpp>

namespace unslop
{
// The ARM processor's mac_syscall helper does not define CF. Without an
// explicit post-SVC value, CFF range-check carry leaks into the real error
// check. Represent this hidden output as a stateful analysis intrinsic, not
// as an imported API and not as a guessed success/failure constant.
int preserve_svc_carry(mba_t *mba)
{
  int n = 0;
  for (int b = 0; b < mba->qty; ++b)
  {
    auto blk = mba->get_mblock(b);
    for (auto i = blk->head; i;)
    {
      auto next = i->next;
      minsn_t *call = nullptr;
      if (i->opcode == m_call || i->opcode == m_icall)
        call = i;
      else if (i->opcode == m_mov && i->l.t == mop_d && i->l.d &&
               (i->l.d->opcode == m_call || i->l.d->opcode == m_icall))
        call = i->l.d;
      if (i->ea != BADADDR && get_dword(i->ea) == 0xd4001001 && call)
      {
        if (call->opcode == m_call && call->l.t == mop_h)
          call->l.make_helper("__unslop_darwin_svc");
        // At GENERATED the SVC helper is still its own top-level instruction.
        tinfo_t boolean(BTF_BOOL);
        mop_t result;
        result.make_reg(mr_cf, 1);
        mcallargs_t args;
        auto capture =
            mba->create_helper_call(i->ea, "__unslop_darwin_svc_carry", &boolean, &args, &result);
        if (!capture)
        {
          i = next;
          continue;
        }
        // The intrinsic reads only the preceding instruction's hidden carry
        // result and must not clobber X0 or any other architectural output.
        if (capture->d.t == mop_f)
        {
          auto ci = capture->d.f;
          ci->spoiled.clear();
          ci->spoiled.add(mr_cf, 1);
          ci->flags |= FCI_SPLOK | FCI_FINAL;
          ci->flags &= ~(FCI_PURE | FCI_NOSIDE);
        }
        blk->insert_into_block(capture, i);
        blk->mark_lists_dirty();
        ++n;
      }
      i = next;
    }
  }
  return n;
}
} // namespace unslop
