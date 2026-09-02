#pragma once
//
// Unslopper debug-logging + diagnostics subsystem.
//
// A tiny, near-zero-overhead logger + MBA dumper used to localize a broken
// CFF/MBA recovery. Everything is a no-op when UNSLOP_LOG is unset (the
// default L_OFF): the DLOG() macro short-circuits on a single integer compare
// before touching any argument.
//
// Configuration is read ONCE from the environment (via qgetenv, never raw
// getenv - pro.h bans it) by log_init():
//   UNSLOP_LOG          0..5  -> LogLevel (also UNSLOP_DEBUG=1 => L_DEBUG)
//   UNSLOP_LOG_FILE     append target (default "/tmp/unslop.log")
//   UNSLOP_ONLY_EA      hex EA; when set, only that function logs/acts verbose
//   UNSLOP_VERIFY_STEPS 0/1   step-verify inside rewrite_cfg
//   UNSLOP_DUMP_MBA     0/1   dump microcode to /tmp/unslop_<ea>_<why>.mc
//
#include <hexrays.hpp>
#include <cstdint>

namespace unslop {

enum LogLevel
{
  L_OFF   = 0,
  L_ERROR = 1,
  L_WARN  = 2,
  L_INFO  = 3,
  L_DEBUG = 4,
  L_TRACE = 5,
};

// Initialize the logger from the environment. Idempotent; call from plugin
// init(). Safe to call more than once.
void log_init();

// True if a line at `lvl` should be emitted right now: the configured level is
// >= lvl AND the current function context passes the UNSLOP_ONLY_EA filter.
bool log_enabled(LogLevel lvl);

// Emit one formatted line to BOTH msg() (IDA output window) and the log file.
// Prefixed with a tag and the current function EA context when one is set.
AS_PRINTF(2, 3) void dlog(LogLevel lvl, const char *fmt, ...);

// Per-function logging context: lines carry [0xEA] while one is active.
void log_begin_func(ea_t ea);
void log_end_func();
ea_t log_cur_func();

// Diagnostic toggles.
bool verify_steps_enabled();   // UNSLOP_VERIFY_STEPS
bool dump_mba_enabled();       // UNSLOP_DUMP_MBA
bool only_ea_active(ea_t ea);  // true if UNSLOP_ONLY_EA unset or == ea

// Dump the microcode of `mba` to /tmp/unslop_<ea>_<why>.mc. No-op unless
// dump_mba_enabled(). `why` is sanitized into the filename.
void dump_mba_to_file(mba_t *mba, const char *why);

// Level-gated log. Evaluates its arguments only when the level is enabled, so
// with UNSLOP_LOG unset the whole statement is a single integer compare.
#define DLOG(lvl, ...)                                   \
  do {                                                   \
    if ( ::unslop::log_enabled(lvl) )                    \
      ::unslop::dlog((lvl), __VA_ARGS__);                \
  } while ( 0 )

} // namespace unslop
