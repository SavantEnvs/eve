#!/usr/bin/env bash
#
# mayhem/test.sh — run the eve TTS unit tests built by mayhem/build.sh (mayhem-build/tests/*).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Each binary is one upstream TTS unit test. TTS prints "Results: <N> tests - <P>/<N> (..) success"
# and, on failures, "- <F>/<N> (..) failure(s)" / "invalid(s)"; it exits non-zero on any failure.
# A binary that exits 0 without a Results line with a positive success count counts as failed,
# so a no-op/neutered build cannot pass.
TDIR="$SRC/mayhem-build/tests"
[ -d "$TDIR" ] || { echo "test.sh: $TDIR missing — run mayhem/build.sh first" >&2; emit_ctrf tts 0 1; exit 1; }
passed=0; failed=0; ran=0
for t in "$TDIR"/*; do
  [ -x "$t" ] || continue
  ran=$((ran+1))
  out=$("$t" 2>&1); rc=$?
  line=$(printf '%s\n' "$out" | grep -a 'Results:' | tail -1)
  n=$(printf '%s' "$line" | sed -n 's/.*Results: \([0-9]*\) test.*/\1/p')
  s=$(printf '%s' "$line" | sed -n 's/.* \([0-9]*\)\/[0-9]* ([0-9.]*%) success.*/\1/p')
  f=$(printf '%s' "$line" | grep -o '[0-9]*/[0-9]* ([0-9.]*%) \(failure\|invalid\)' | cut -d/ -f1 | awk '{s+=$1} END {print s+0}')
  [ -n "$n" ] || n=0; [ -n "$s" ] || s=0; [ -n "$f" ] || f=0
  if [ "$rc" -ne 0 ] || [ "$n" -eq 0 ] || [ "$s" -eq 0 ]; then
    echo "FAIL $(basename "$t"): rc=$rc ${line:-no Results line}"
    printf '%s\n' "$out" | tail -15
    # count at least one failure for the binary
    [ "$f" -gt 0 ] || f=1
  else
    echo "PASS $(basename "$t"): $line"
  fi
  passed=$((passed+s)); failed=$((failed+f))
done
[ "$ran" -gt 0 ] || { echo "test.sh: no test binaries in $TDIR" >&2; failed=1; }
emit_ctrf tts "$passed" "$failed" 0
