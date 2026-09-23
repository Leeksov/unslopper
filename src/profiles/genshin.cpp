// Genshin native pre-decompilation profile.
//
// Hex-Rays can truncate a function before Unslopper's optblock pass runs when
// IDA records only 1–4 entries for a larger relocated BR X8 table. A separate
// offline analyzer emits proof-gated manifests; this profile checks every
// original byte, table slot, target owner and incoming edge in the live IDB,
// then optionally rewrites only the final BR in each proven local slice.
// This is an IDB analysis view. Writable table immutability is not claimed.

#include "genshin.h"
#include "profile.h"

#include <auto.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <nalt.hpp>
#include <parsejson.hpp>
#include <xref.hpp>

#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace unslop {
namespace {

constexpr uint32_t BR_X8 = 0xd61f0100;
constexpr const char *FORMAT = "yuanshen-idb-branch-manifest-v1";

struct Site
{
  ea_t ea = BADADDR;
  ea_t target = BADADDR;
  uint32_t replacement = 0;
  bool conditional = false;
  bool strided = false;
  bool indexed_bool = false;
  ea_t slice_start = BADADDR;
  ea_t context_start = BADADDR;
  std::string context;
  std::vector<std::pair<ea_t, ea_t>> slots;
};

bool fail(GenshinReport *report, const char *message)
{
  report->error = message;
  return false;
}

bool read_num(const jobj_t &obj, const char *key, uint64_t *out)
{
  const jvalue_t *value = obj.get_value(key, JT_NUM);
  if ( value == nullptr || value->num() < 0 )
    return false;
  *out = uint64_t(value->num());
  return true;
}

bool read_ea(const jobj_t &obj, const char *key, ea_t *out)
{
  uint64_t number;
  if ( !read_num(obj, key, &number) || number > uint64_t(BADADDR) )
    return false;
  *out = ea_t(number);
  return true;
}

bool read_sha256(std::string *out)
{
  uchar digest[32];
  if ( !retrieve_input_file_sha256(digest) )
    return false;
  static const char *digits = "0123456789abcdef";
  out->clear();
  for ( unsigned i = 0; i < 32; ++i )
  {
    out->push_back(digits[digest[i] >> 4]);
    out->push_back(digits[digest[i] & 15]);
  }
  return true;
}

int nibble(char c)
{
  if ( c >= '0' && c <= '9' ) return c - '0';
  if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
  if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
  return -1;
}

bool original_context_matches(const Site &site)
{
  if ( site.context_start > site.slice_start || site.context_start > site.ea
    || site.ea-site.context_start > 672
    || site.context.size() != 2*size_t(site.ea+4-site.context_start) )
    return false;
  for ( size_t i = 0, n=site.context.size()/2; i < n; ++i )
  {
    int hi = nibble(site.context[2*i]);
    int lo = nibble(site.context[2*i+1]);
    if ( hi < 0 || lo < 0
      || get_original_byte(site.context_start+i) != uint64_t((hi<<4)|lo) )
      return false;
  }
  return true;
}

bool encoded_target_matches(const Site &site)
{
  uint32_t word = site.replacement;
  int64_t delta = 0;
  if ( site.strided )
  {
    // CBZ/CBNZ X9: the retained UBFIZ produces either 0 or one stride.
    if ( (word & 0xfe00001f) != 0xb4000009 )
      return false;
    int64_t imm = (word >> 5) & 0x7ffff;
    if ( imm & (1LL<<18) ) imm -= 1LL<<19;
    delta = imm * 4;
  }
  else if ( site.indexed_bool )
  {
    // CBZ/CBNZ W9: the retained selector is proven to be 0 or 1.
    if ( (word & 0xfe00001f) != 0x34000009 )
      return false;
    int64_t imm = (word >> 5) & 0x7ffff;
    if ( imm & (1LL<<18) ) imm -= 1LL<<19;
    delta = imm * 4;
  }
  else if ( site.conditional )
  {
    if ( (word & 0xff000010) != 0x54000000 || (word & 15) >= 14 )
      return false;
    int64_t imm = (word >> 5) & 0x7ffff;
    if ( imm & (1LL<<18) ) imm -= 1LL<<19;
    delta = imm * 4;
  }
  else
  {
    if ( (word & 0xfc000000) != 0x14000000 )
      return false;
    int64_t imm = word & 0x3ffffff;
    if ( imm & (1LL<<25) ) imm -= 1LL<<26;
    delta = imm * 4;
  }
  return uint64_t(int64_t(site.ea) + delta) == uint64_t(site.target);
}

bool parse_site(const jvalue_t &value, Site *out)
{
  if ( value.type() != JT_OBJ ) return false;
  const jobj_t &obj = value.obj();
  uint64_t word;
  if ( !read_ea(obj, "site", &out->ea)
    || !read_ea(obj, "target", &out->target)
    || !read_num(obj, "replacement", &word)
    || word > UINT32_MAX )
    return false;
  out->replacement = uint32_t(word);
  const jvalue_t *kind = obj.get_value("kind", JT_STR);
  const jvalue_t *context = obj.get_value("original_context_hex", JT_STR);
  const jvalue_t *slots = obj.get_value("table_slots", JT_ARR);
  const jvalue_t *targets = obj.get_value("table_targets", JT_ARR);
  if ( kind == nullptr || context == nullptr || slots == nullptr || targets == nullptr )
    return false;
  out->context = context->str();
  out->strided = std::strcmp(kind->str(), "strided_bool") == 0;
  out->indexed_bool = std::strcmp(kind->str(), "indexed_bool") == 0;
  out->conditional = out->strided || out->indexed_bool
                  || std::strcmp(kind->str(), "conditional") == 0;
  if ( !out->conditional && std::strcmp(kind->str(), "direct") != 0 )
    return false;
  if ( out->conditional )
  {
    if ( out->ea < 24 ) return false;
    if ( obj.has_value("slice_start") )
    {
      if ( !read_ea(obj, "slice_start", &out->slice_start) ) return false;
    }
    else
      out->slice_start = out->ea - 24; // backward-compatible v1 manifest
  }
  else if ( !read_ea(obj, "adrp_ea", &out->slice_start) )
    return false;
  if ( obj.has_value("original_context_start") )
  {
    if ( !read_ea(obj, "original_context_start", &out->context_start) ) return false;
  }
  else
  {
    if ( out->ea < 32 ) return false;
    out->context_start = out->ea - 32; // backward-compatible v1 manifest
  }
  const jarr_t &slot_array = slots->arr();
  const jarr_t &target_array = targets->arr();
  size_t expected = out->conditional ? 2 : 1;
  if ( slot_array.values.size() != expected || target_array.values.size() != expected )
    return false;
  for ( size_t i = 0; i < expected; ++i )
  {
    const jvalue_t &slot = slot_array.values[i];
    const jvalue_t &target = target_array.values[i];
    if ( slot.type() != JT_NUM || target.type() != JT_NUM
      || slot.num() < 0 || target.num() < 0 )
      return false;
    out->slots.emplace_back(ea_t(slot.num()), ea_t(target.num()));
  }
  if ( out->slice_start >= out->ea || out->ea-out->slice_start > 672 )
    return false;
  if ( out->conditional )
  {
    bool has_branch = false, has_fallthrough = false;
    for ( const auto &slot : out->slots )
    {
      has_branch |= slot.second == out->target;
      has_fallthrough |= slot.second == out->ea+4;
    }
    if ( !has_branch || !has_fallthrough || out->target == out->ea+4 )
      return false;
  }
  else if ( out->slots[0].second != out->target )
    return false;
  return encoded_target_matches(*out);
}

bool validate_site(const Site &site, ea_t start, ea_t end, GenshinReport *report)
{
  if ( site.ea < start || site.ea >= end || site.target < start || site.target >= end
    || !is_code(get_full_flags(site.ea)) )
    return fail(report, "site or target not defined within function");
  func_t *owner = get_func(site.target);
  if ( owner == nullptr || owner->start_ea != start )
    return fail(report, "IDA does not own a recovered target in the function");
  uint32_t current = uint32_t(get_dword(site.ea));
  if ( current != BR_X8 && current != site.replacement )
    return fail(report, "BR site differs from the original or proposed instruction");
  if ( get_original_dword(site.ea) != BR_X8 || !original_context_matches(site) )
    return fail(report, "original instruction context differs from manifest");
  for ( const auto &slot : site.slots )
    if ( get_qword(slot.first) != uint64_t(slot.second) )
      return fail(report, "relocated pointer slot differs from manifest");
  for ( ea_t interior=site.slice_start+4; interior<site.ea; interior+=4 )
  {
    xrefblk_t xref;
    for ( bool ok=xref.first_to(interior, XREF_ALL); ok; ok=xref.next_to() )
      if ( xref.iscode && (xref.from<site.slice_start || xref.from>=site.ea) )
        return fail(report, "incoming code edge bypasses the proven selector slice");
  }
  xrefblk_t xref;
  for ( bool ok=xref.first_from(site.ea, XREF_FAR); ok; ok=xref.next_from() )
    if ( xref.iscode && (xref.to<start || xref.to>=end || xref.user && xref.to!=site.target) )
      return fail(report, "unexpected or user-defined outgoing code edge");
  return true;
}

class GenshinProfile : public Profile
{
public:
  const char *name() const override { return "genshin"; }
  ProfileKind kind() const override { return ProfileKind::GENSHIN; }
  bool native_only() const override { return true; }
  bool detect(mba_t *, const std::map<mreg_t, uint64_t> &) override { return false; }
  bool configure(mba_t *, DispatcherInfo *,
                 const std::map<mreg_t, uint64_t> &) override { return false; }
};

} // anonymous namespace

Profile *make_genshin()
{
  static GenshinProfile profile;
  return &profile;
}

bool run_genshin_manifest(const char *path, bool apply, GenshinReport *report)
{
  if ( report == nullptr ) return false;
  *report = GenshinReport{};
  if ( path == nullptr || *path == '\0' ) return fail(report, "manifest path missing");
  if ( PH.id != PLFM_ARM || !inf_is_64bit() )
    return fail(report, "Genshin profile requires an AArch64 IDB");
  if ( is_auto_enabled() )
    return fail(report, "disable autoanalysis before the Genshin native pass");

  jvalue_t root;
  qstring parse_error;
  if ( parse_json_file(&root, path, &parse_error) != eOk || root.type() != JT_OBJ )
    return fail(report, "manifest JSON could not be parsed");
  const jobj_t &obj = root.obj();
  const jvalue_t *format = obj.get_value("format", JT_STR);
  const jvalue_t *sha = obj.get_value("binary_sha256", JT_STR);
  const jvalue_t *items = obj.get_value("items", JT_ARR);
  ea_t start, end;
  uint64_t count;
  if ( format == nullptr || std::strcmp(format->str(), FORMAT) != 0
    || sha == nullptr || items == nullptr
    || !read_ea(obj, "function_start", &start)
    || !read_ea(obj, "function_end", &end)
    || !read_num(obj, "br_count", &count)
    || start >= end || count == 0 || count > 10000 )
    return fail(report, "manifest header or count invalid");
  std::string input_sha;
  if ( !read_sha256(&input_sha) || input_sha != sha->str() )
    return fail(report, "input SHA-256 differs from manifest");
  func_t *fn = get_func(start);
  if ( fn == nullptr || fn->start_ea != start || fn->end_ea != end )
    return fail(report, "IDA has not defined the complete expected function");
  report->function_start = start;

  const jarr_t &rows = items->arr();
  if ( rows.values.size() != count )
    return fail(report, "manifest does not cover every original BR X8");
  std::vector<Site> sites;
  sites.reserve(count);
  std::set<ea_t> unique_sites;
  for ( const jvalue_t &row : rows.values )
  {
    Site site;
    if ( !parse_site(row, &site) || !unique_sites.insert(site.ea).second )
      return fail(report, "invalid or duplicate site in manifest");
    if ( !validate_site(site, start, end, report) )
      return false;
    if ( get_dword(site.ea) == site.replacement )
      ++report->already_folded;
    sites.push_back(std::move(site));
  }
  int original_br_count = 0;
  for ( ea_t ea=start; ea+4<=end; ea+=4 )
    if ( get_original_dword(ea) == BR_X8 )
      ++original_br_count;
  if ( original_br_count != int(count) )
    return fail(report, "uncovered original BR X8 sites remain in this function");
  report->sites = int(count);
  if ( !apply ) return true;

  for ( const Site &site : sites )
  {
    if ( get_dword(site.ea) == site.replacement ) continue;
    std::vector<ea_t> old_targets;
    xrefblk_t xref;
    for ( bool ok=xref.first_from(site.ea, XREF_FAR); ok; ok=xref.next_from() )
      if ( xref.iscode ) old_targets.push_back(xref.to);
    switch_info_t si;
    if ( get_switch_info(&si, site.ea) > 0 )
      del_switch_info(site.ea);
    for ( ea_t old : old_targets )
      if ( old != site.target ) del_cref(site.ea, old, false);
    if ( !patch_dword(site.ea, site.replacement) )
      return fail(report, "IDA could not patch a validated BR site");
    add_cref(site.ea, site.target, fl_JN);
    if ( site.conditional ) add_cref(site.ea, site.ea+4, fl_F);
    ++report->changed;
  }
  if ( report->changed > 0 ) clear_cached_cfuncs();
  return true;
}

} // namespace unslop
