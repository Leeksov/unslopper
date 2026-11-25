#pragma once

namespace unslop
{
// A memory store cannot clobber a microregister. A nested call can, so it is
// always a full fact barrier even when it appears inside an m_stx operand.
inline constexpr bool affine_store_keeps_register_facts(bool contains_call)
{
  return !contains_call;
}

// MERR_STOP does not establish that the detached downstream optimizer reached
// the requested maturity. Accept only an explicit success at that boundary.
inline constexpr bool affine_trial_completed(int error_code, int maturity,
                                             int minimum_maturity)
{
  return error_code == 0 && maturity >= minimum_maturity;
}
} // namespace unslop
