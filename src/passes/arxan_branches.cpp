#include "arxan_branches.h"
#include "arxan_patterns.h"
#include <bytes.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <segment.hpp>
#include <xref.hpp>
#include <map>
#include <vector>

namespace unslop {
namespace {
bool enabled()
{
  qstring disabled; qgetenv("UNSLOP_NO_ARXAN", &disabled);
  return PH.id == PLFM_ARM && inf_is_64bit()
      && (disabled.empty() || disabled[0]!='1');
}
bool make_image(ea_t entry, arxan::Image *image)
{
  segment_t *seg=getseg(entry);
  if (seg == nullptr || !(seg->perm & SEGPERM_EXEC)) return false;
  image->text_start=seg->start_ea; image->text_end=seg->end_ea;
  image->read_word=[](uint64_t ea, uint32_t *word) {
    uint8_t bytes[4];
    if (get_bytes(bytes, sizeof(bytes), ea_t(ea)) != sizeof(bytes)) return false;
    *word=uint32_t(bytes[0]) | (uint32_t(bytes[1])<<8)
        | (uint32_t(bytes[2])<<16) | (uint32_t(bytes[3])<<24);
    return true;
  };
  image->readonly=[](uint64_t ea, uint64_t length) {
    segment_t *s=getseg(ea_t(ea));
    return s != nullptr && ea < s->end_ea && length <= s->end_ea-ea
        && !(s->perm & SEGPERM_WRITE);
  };
  return true;
}
bool owned(func_t *fn, const arxan::Proof &p)
{
  func_t *target=get_func(p.target);
  if (target == nullptr || target->start_ea != fn->start_ea) return false;
  for (ea_t ea=p.start; ea<=p.site; ea+=4) {
    func_t *owner=get_func(ea);
    if (owner == nullptr || owner->start_ea != fn->start_ea) return false;
  }
  return true;
}
bool entries_valid(const arxan::Proof &p)
{
  for (ea_t ea=p.start+4; ea<=p.site; ea+=4) {
    xrefblk_t xref;
    for (bool ok=xref.first_to(ea, XREF_ALL); ok; ok=xref.next_to())
      if (xref.iscode && (xref.from<p.start || xref.from>p.site)) return false;
  }
  xrefblk_t xref;
  for (bool ok=xref.first_from(p.site,XREF_FAR);ok;ok=xref.next_from())
    if (xref.iscode && xref.user && (xref.type==fl_JN || xref.type==fl_JF)
        && xref.to!=p.target) return false;
  return true;
}
}

int expand_arxan_reachability(const qflow_chart_ea_t *fc, mba_t *mba, bitset_t *reachable)
{
  if (!enabled() || fc==nullptr || mba==nullptr || reachable==nullptr) return 0;
  func_t *fn=get_func(mba->entry_ea); arxan::Image image;
  if (fn==nullptr || fc->func_ea!=fn->start_ea || !make_image(fn->start_ea,&image)) return 0;
  std::map<ea_t,int> by_start;
  std::vector<int> pending;
  for (int i=0;i<fc->nproper;++i) {
    by_start[fc->blocks[i].start_ea]=i;
    if (reachable->has(i)) pending.push_back(i);
  }
  int added=0;
  for (size_t at=0;at<pending.size();++at) {
    int i=pending[at]; const auto &block=fc->blocks[i];
    auto include=[&](int target) {
      if (target>=0 && target<fc->nproper && !reachable->has(target)) {
        reachable->add(target); pending.push_back(target); ++added;
      }
    };
    // Follow ordinary successors only after a block has become reachable.
    for (int successor:block.succ) include(successor);
    if (block.end_ea<block.start_ea+4) continue;
    arxan::Proof proof;
    if (!arxan::match(image,block.end_ea-4,&proof) || !owned(fn,proof) || !entries_valid(proof)) continue;
    auto target=by_start.find(proof.target);
    if (target!=by_start.end()) include(target->second);
  }
  return added;
}

int restore_arxan_branches(mba_t *mba, ArxanDiagnostics *diagnostics)
{
  ArxanDiagnostics local;
  auto &d = diagnostics ? *diagnostics : local;
  if (!enabled() || mba==nullptr || mba->maturity>MMAT_GENERATED) return 0;
  func_t *fn=get_func(mba->entry_ea); arxan::Image image;
  if (fn==nullptr || !make_image(fn->start_ea,&image)) return 0;
  for (int i=0; i<mba->qty; ++i) {
    mblock_t *block=mba->get_mblock(i);
    minsn_t *tail=block->tail;
    if (tail == nullptr || tail->opcode != m_ijmp || tail->ea == BADADDR) continue;
    arxan::Proof proof;
    if (!arxan::match(image, tail->ea, &proof)) continue;
    ++d.matched;
    if (!owned(fn,proof)) { ++d.ownership_rejected; continue; }
    if (!entries_valid(proof)) { ++d.entry_rejected; continue; }
    bool has_block=false;
    for (int j=0; j<mba->qty; ++j)
      if (j != i && mba->get_mblock(j)->start == proof.target) { has_block=true; break; }
    if (!has_block) { ++d.missing_block; continue; }
    // GENERATED uses EA operands. Subsequent Hex-Rays phases rebuild the CFG.
    tail->opcode=m_goto;
    tail->l.make_gvar(proof.target);
    tail->r.erase(); tail->d.erase();
    ++d.changed;
  }
  return d.changed;
}
}
