// SDK-independent driver for the same C++ matcher compiled into the plugin.
#include "arxan_patterns.h"
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <vector>
#include <tuple>
using namespace unslop::arxan;
uint32_t make_adr(unsigned reg, uint64_t at, uint64_t target) {
  uint32_t delta=uint32_t(target-at)&0x1fffff;
  return 0x10000000u|((delta&3)<<29)|((delta>>2)<<5)|reg;
}
void fixtures() {
  std::vector<uint32_t> words={0xd2800028,make_adr(9,0x1004,0x1010),0x9b087d28,0xd61f0100,0xd65f03c0};
  Image im; im.text_start=0x1000; im.text_end=0x1000+4*words.size();
  im.read_word=[&](uint64_t ea,uint32_t *w) { if(ea<im.text_start || ea+4>im.text_end || (ea&3))return false;*w=words[(ea-im.text_start)/4];return true; };
  im.readonly=[&](uint64_t ea,uint64_t n){return ea>=im.text_start && ea+n<=im.text_end;};
  Proof p;assert(match(im,0x100c,&p));assert(p.target==0x1010 && p.start==0x1000);
  words[0]=0xd2800048;assert(!match(im,0x100c,&p)); // Multiply by two is not covered.
  words={0xf90023ff,0xf94023eb,make_adr(8,0x1008,0x102c),0xb9800109,0x8b080128,
         0x8a0b0109,0xd280004a,0x9b0a7d29,0xca0b0108,0x8b090108,0xd61f0100,4,0xd65f03c0};
  im.text_end=0x1000+words.size()*4;assert(match(im,0x1028,&p));assert(p.target==0x1030);
  im.readonly=[](uint64_t,uint64_t){return false;};assert(!match(im,0x1028,&p));
  std::cout<<"native fixture tests passed\n";
}
int main(int argc,char **argv) {
  if(argc==1){fixtures();return 0;}
  if(argc<5)return 2;
  std::ifstream file(argv[1],std::ios::binary);
  if(!file)return 3;
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),{});
  using Segment=std::tuple<uint64_t,uint64_t,uint64_t,unsigned>;
  std::vector<Segment> segments;
  for(int i=4;i<argc;++i){
    std::string spec=argv[i];for(char &c:spec)if(c==',')c=' ';
    std::istringstream in(spec);uint64_t va,fo,fs;unsigned prot;in>>va>>fo>>fs>>prot;
    if(!in || fo>data.size() || fs>data.size()-fo)return 4;
    segments.emplace_back(va,fo,fs,prot);
  }
  Image im;im.text_start=std::stoull(argv[2],nullptr,0);im.text_end=std::stoull(argv[3],nullptr,0);
  im.read_word=[&](uint64_t ea,uint32_t *w){
    for(auto s:segments){auto [va,fo,fs,prot]=s;
      if(ea>=va && ea-va<=fs && fs-(ea-va)>=4){const auto *p=&data[fo+ea-va];*w=uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);return true;}}
    return false;
  };
  im.readonly=[&](uint64_t ea,uint64_t n){for(auto s:segments){auto [va,fo,fs,prot]=s;if(ea>=va && ea-va<=fs && n<=fs-(ea-va) && !(prot&2))return true;}return false;};
  for(uint64_t ea=im.text_start;ea+4<=im.text_end;ea+=4){
    uint32_t w;if(!im.read_word(ea,&w))return 5;
    if(w!=0xd61f0100 && w!=0xd61f0120)continue;
    Proof p;if(match(im,ea,&p))std::cout<<std::hex<<p.site<<' '<<p.target<<' '<<p.start<<' '<<name(p.pattern)<<'\n';
  }
}
