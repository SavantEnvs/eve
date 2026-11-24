#!/usr/bin/env bash
# mayhem/build.sh — build eve's fuzz harnesses and a subset of its own TTS unit tests.
# eve is header-only C++20: "building the project" means compiling its headers into each harness
# TU, so every harness is compiled with $SANITIZER_FLAGS $DEBUG_FLAGS and the library code is
# instrumented. Binaries: /mayhem/fuzz_<t> (libFuzzer) and /mayhem/fuzz_<t>-standalone.
# Unit tests (normal flags, no sanitizers): mayhem-build/cmake/unit/unit.*.exe (gitignored by upstream's
# `*build*/` rule), run by mayhem/test.sh. Idempotent; needs no network.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS
cd "$SRC"

# SIMD level is a compile-time choice in eve. SSE4.2 (x86-64-v2) is on every x86-64 fuzz host
# Mayhem uses; AVX2/AVX-512 are not guaranteed, and -march=native would bake in the build host's.
ARCH_FLAGS="-msse4.2"
CXXSTD="-std=c++20"
OUT="$SRC/mayhem-build"
mkdir -p "$OUT/obj"

TARGETS="combinatorial algo memory math special core"

"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/obj/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/obj/standalone_main.o"

build_harness() {
  local t="$1"
  local fuzz_cov=""
  # -fsanitize=fuzzer-no-link adds SanCov to the object; only when a libFuzzer engine is in use.
  [ -n "$LIB_FUZZING_ENGINE" ] && fuzz_cov="-fsanitize=fuzzer-no-link"
  "$CXX" $CXXSTD $ARCH_FLAGS -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $fuzz_cov -I"$SRC/include" \
    -c "$SRC/mayhem/harnesses/fuzz_$t.cpp" -o "$OUT/obj/fuzz_$t.o"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/fuzz_$t.o" "$OUT/obj/lsan_off.o" \
    -lm -o "$SRC/fuzz_$t"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/obj/fuzz_$t.o" "$OUT/obj/standalone_main.o" "$OUT/obj/lsan_off.o" \
    -lm -o "$SRC/fuzz_$t-standalone"
}

# Upstream's whole TTS unit suite (`ninja unit.exe`: every test/unit/** directory), built with
# upstream's CMake and its normal compile options (no sanitizers) into mayhem-build/cmake/unit/.
# Ninja's -j is capped by memory: each eve test TU needs up to ~2 GB, and the build runs under the
# grader's memory limit (cgroup memory.max, else MemAvailable).
mem_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
if [ -r /sys/fs/cgroup/memory.max ] && [ "$(cat /sys/fs/cgroup/memory.max)" != max ]; then
  cg_kb=$(( $(cat /sys/fs/cgroup/memory.max) / 1024 ))
  [ "$cg_kb" -lt "$mem_kb" ] && mem_kb=$cg_kb
fi
TEST_JOBS=$(( mem_kb / (2 * 1024 * 1024) )); [ "$TEST_JOBS" -ge 1 ] || TEST_JOBS=1
[ "$TEST_JOBS" -le "$MAYHEM_JOBS" ] || TEST_JOBS=$MAYHEM_JOBS
build_tests() {
  cmake -S "$SRC" -B "$OUT/cmake" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_FLAGS="$ARCH_FLAGS $COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" \
    -DEVE_BUILD_TEST=ON -DEVE_BUILD_DOCUMENTATION=OFF -DEVE_BUILD_BENCHMARKS=OFF -DEVE_BUILD_RANDOM=OFF \
    >"$OUT/cmake-configure.log" 2>&1 || { cat "$OUT/cmake-configure.log" >&2; return 1; }
  ninja -C "$OUT/cmake" -j"$TEST_JOBS" unit.exe
}

pids=()
rc=0
# Harnesses first (they are few and big), then the test suite with its own memory-capped -j.
for t in $TARGETS; do build_harness "$t" & pids+=($!); done
for p in "${pids[@]}"; do wait "$p" || rc=1; done
pids=()
build_tests || rc=1
[ "$rc" -eq 0 ] || { echo "build.sh: a harness or test failed to build" >&2; exit 1; }
for t in $TARGETS; do test -x "$SRC/fuzz_$t" && test -x "$SRC/fuzz_$t-standalone"; done
echo "build.sh: built $(echo $TARGETS | wc -w) harnesses and $(find "$OUT/cmake/unit" -maxdepth 1 -name 'unit.*.exe' -type f | wc -l) unit test binaries"
