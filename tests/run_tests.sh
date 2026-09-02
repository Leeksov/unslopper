#!/bin/bash
# Deslop test driver: for each sample, decompile CFF candidates with and without
# the plugin (isolated IDAUSR dirs), then diff goto/switch/line metrics.
set -u
IDAT="/Applications/IDA Professional 9.4.app/Contents/MacOS/idat"
ROOT="/Users/leeksov/Desktop/researches/deflat-toolkit"
DY="/Users/leeksov/Desktop/tools/idasdk/ida-sdk/src/bin/plugins/deflat.dylib"
HARNESS="$ROOT/tests/harness.py"
SAMPLES="$ROOT/samples"
WORK="$ROOT/tests/work"
LIC="$HOME/.idapro/idapro_96-6F40-20E1-E2.hexlic"

rm -rf "$WORK"; mkdir -p "$WORK"

# Isolated user dirs cloned from real ~/.idapro (keeps accepted-license + python
# config in ida.reg), with a clean plugins/ dir: baseline empty, test = deflat only.
UBASE="$WORK/idausr_base"; UTEST="$WORK/idausr_test"
rsync -a --exclude plugins --exclude mcp "$HOME/.idapro/" "$UBASE/" 2>/dev/null
rsync -a --exclude plugins --exclude mcp "$HOME/.idapro/" "$UTEST/" 2>/dev/null
mkdir -p "$UBASE/plugins" "$UTEST/plugins"
cp "$DY" "$UTEST/plugins/deflat.dylib"; codesign -s - -f "$UTEST/plugins/deflat.dylib" 2>/dev/null

run_one() {  # $1=sample_path $2=usrdir $3=out.json $4=force
  local bin="$1" usr="$2" out="$3" force="$4"
  local wd; wd="$WORK/$(basename "$bin").$4.db"
  mkdir -p "$wd"; cp "$bin" "$wd/target"
  DESLOP_FORCE="$force" IDAUSR="$usr" TVHEADLESS=1 \
    "$IDAT" -A -L"$wd/ida.log" -S"$HARNESS $out" -c "$wd/target" >/dev/null 2>&1
}

for s in appdome dexprotector mvg promon; do
  bin="$SAMPLES/$s"
  [ -f "$bin" ] || { echo "skip $s (missing)"; continue; }
  echo "=== $s ==="
  run_one "$bin" "$UBASE" "$WORK/$s.base.json" 0
  run_one "$bin" "$UTEST" "$WORK/$s.test.json" 1
  python3 "$ROOT/tests/diff.py" "$WORK/$s.base.json" "$WORK/$s.test.json" "$s"
done
echo "done. artifacts in $WORK"
