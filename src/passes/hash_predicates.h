#pragma once
#include <hexrays.hpp>
#include <string>
namespace unslop {
int simplify_hash_predicates(mba_t *mba,bool snapshot,int *matched,std::string *reason);
}
