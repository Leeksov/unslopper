// Unslopper debug-logging + diagnostics subsystem implementation.
//
// See unslop_log.h. All state is process-global, initialized once from the
// environment. When UNSLOP_LOG is unset the level is L_OFF and log_enabled()
// returns false on the first compare, so the DLOG() macro costs one branch.
#include "unslop_log.h"

#include <pro.h>
#include <kernwin.hpp>   // msg()
#include <fpro.h>        // qfopen / qfclose / qvfprintf
#include <cstdarg>
#include <cstdlib>       // atoi / strtoull

namespace unslop {

namespace {

// ── global configuration, populated once by log_init ─────────────────
bool     g_inited      = false;
LogLevel g_level       = L_OFF;
qstring  g_logfile;                 // resolved UNSLOP_LOG_FILE
bool     g_only_ea_set = false;
ea_t     g_only_ea     = BADADDR;
bool     g_verify_steps = false;
bool     g_dump_mba     = false;

// Current per-function context. BADADDR means "no function context".
ea_t     g_cur_func    = BADADDR;

// Parse a hex/dec EA string ("0x..." or bare hex/decimal). Returns BADADDR on
// an empty/garbage value.
ea_t parse_ea(const char *s)
{
  if ( s == nullptr || s[0] == '\0' )
    return BADADDR;
  // strtoull with base 0 handles 0x-prefixed hex and decimal; treat a bare
  // token without 0x as hex too, since EAs are conventionally hex.
  char *end = nullptr;
  int base = ( s[0] == '0' && (s[1] == 'x' || s[1] == 'X') ) ? 16 : 16;
  unsigned long long v = strtoull(s, &end, base);
  if ( end == s )
    return BADADDR;
  return ea_t(v);
}

} // anonymous namespace

//-------------------------------------------------------------------------
void log_init()
{
  if ( g_inited )
    return;
  g_inited = true;

  qstring env;

  // UNSLOP_LOG: explicit 0..5 level.
  if ( qgetenv("UNSLOP_LOG", &env) && !env.empty() )
  {
    int v = atoi(env.c_str());
    if ( v < 0 )
      v = 0;
    if ( v > int(L_TRACE) )
      v = int(L_TRACE);
    g_level = LogLevel(v);
  }

  // UNSLOP_DEBUG=1 implies at least L_DEBUG (kept in sync with the old
  // UNSLOP_DEBUG build/verify gate).
  if ( qgetenv("UNSLOP_DEBUG", &env) && atoi(env.c_str()) != 0 )
  {
    if ( g_level < L_DEBUG )
      g_level = L_DEBUG;
  }

  // UNSLOP_LOG_FILE (default /tmp/unslop.log).
  if ( qgetenv("UNSLOP_LOG_FILE", &env) && !env.empty() )
    g_logfile = env;
  else
    g_logfile = "/tmp/unslop.log";

  // UNSLOP_ONLY_EA (hex).
  if ( qgetenv("UNSLOP_ONLY_EA", &env) && !env.empty() )
  {
    ea_t e = parse_ea(env.c_str());
    if ( e != BADADDR )
    {
      g_only_ea_set = true;
      g_only_ea = e;
    }
  }

  // UNSLOP_VERIFY_STEPS / UNSLOP_DUMP_MBA (0/1).
  if ( qgetenv("UNSLOP_VERIFY_STEPS", &env) && atoi(env.c_str()) != 0 )
    g_verify_steps = true;
  if ( qgetenv("UNSLOP_DUMP_MBA", &env) && atoi(env.c_str()) != 0 )
    g_dump_mba = true;
}

//-------------------------------------------------------------------------
bool only_ea_active(ea_t ea)
{
  if ( !g_only_ea_set )
    return true;
  return ea == g_only_ea;
}

bool verify_steps_enabled() { return g_verify_steps; }
bool dump_mba_enabled()     { return g_dump_mba; }

ea_t log_cur_func()         { return g_cur_func; }
void log_begin_func(ea_t ea) { g_cur_func = ea; }
void log_end_func()          { g_cur_func = BADADDR; }

//-------------------------------------------------------------------------
bool log_enabled(LogLevel lvl)
{
  if ( g_level < lvl )
    return false;
  // Honour the UNSLOP_ONLY_EA filter against the current function context.
  // With no context yet (BADADDR) we still allow the line through when a
  // filter is set, so pre-func lines (init, etc.) are not silently dropped.
  if ( g_only_ea_set && g_cur_func != BADADDR && g_cur_func != g_only_ea )
    return false;
  return true;
}

//-------------------------------------------------------------------------
static const char *level_tag(LogLevel lvl)
{
  switch ( lvl )
  {
    case L_ERROR: return "E";
    case L_WARN:  return "W";
    case L_INFO:  return "I";
    case L_DEBUG: return "D";
    case L_TRACE: return "T";
    default:      return "?";
  }
}

//-------------------------------------------------------------------------
void dlog(LogLevel lvl, const char *fmt, ...)
{
  // Format the caller's message.
  char body[1024];
  va_list va;
  va_start(va, fmt);
  qvsnprintf(body, sizeof(body), fmt, va);
  va_end(va);

  // Build the full line: "[unslop][L][0xEA] body".
  char line[1280];
  if ( g_cur_func != BADADDR )
  {
    qsnprintf(line, sizeof(line), "[unslop][%s][0x%llx] %s\n",
              level_tag(lvl), (unsigned long long)g_cur_func, body);
  }
  else
  {
    qsnprintf(line, sizeof(line), "[unslop][%s] %s\n",
              level_tag(lvl), body);
  }

  // 1. IDA output window.
  msg("%s", line);

  // 2. Append to the log file (best effort; a failed open is silently
  //    ignored so logging never disrupts the pipeline).
  if ( !g_logfile.empty() )
  {
    FILE *fp = qfopen(g_logfile.c_str(), "a");
    if ( fp != nullptr )
    {
      qfprintf(fp, "%s", line);
      qfclose(fp);
    }
  }
}

//-------------------------------------------------------------------------
void dump_mba_to_file(mba_t *mba, const char *why)
{
  if ( !g_dump_mba || mba == nullptr )
    return;

  // Sanitize `why` into a filename-safe token.
  char tok[64];
  {
    const char *s = ( why != nullptr ) ? why : "dump";
    size_t j = 0;
    for ( size_t i = 0; s[i] != '\0' && j + 1 < sizeof(tok); ++i )
    {
      char c = s[i];
      bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
             || (c >= '0' && c <= '9') || c == '_' || c == '-';
      tok[j++] = ok ? c : '_';
    }
    tok[j] = '\0';
    if ( j == 0 )
    {
      tok[0] = 'd'; tok[1] = 'u'; tok[2] = 'm'; tok[3] = 'p'; tok[4] = '\0';
    }
  }

  ea_t ea = ( g_cur_func != BADADDR ) ? g_cur_func : mba->entry_ea;

  char path[512];
  qsnprintf(path, sizeof(path), "/tmp/unslop_0x%llx_%s.mc",
            (unsigned long long)ea, tok);

  FILE *fp = qfopen(path, "w");
  if ( fp == nullptr )
  {
    dlog(L_ERROR, "dump_mba_to_file: cannot open %s", path);
    return;
  }

  // file_printer_t routes mba_t::print straight to the FILE*.
  file_printer_t vp(fp);
  mba->print(vp);
  qfclose(fp);

  dlog(L_DEBUG, "dumped MBA (%s) to %s", tok, path);
}

} // namespace unslop
