#!/usr/bin/env bash
# mayhem/build.sh — build eve's fuzz harnesses and a subset of its own TTS unit tests.
# eve is header-only C++20: "building the project" means compiling its headers into each harness
# TU, so every harness is compiled with $SANITIZER_FLAGS $DEBUG_FLAGS and the library code is
# instrumented. Binaries: /mayhem/fuzz_<t> (libFuzzer) and /mayhem/fuzz_<t>-standalone.
# Unit tests (normal flags, no sanitizers): mayhem-build/tests/<name> (gitignored by upstream's
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
mkdir -p "$OUT/obj" "$OUT/tests"

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

# Upstream TTS unit tests covering the fuzzed modules, built with normal (unsanitized) flags.
TESTS="
module/combinatorial/nth_prime.cpp
module/combinatorial/prime_ceil.cpp
module/combinatorial/prime_floor.cpp
module/algo/algorithm/find_if_generic.cpp
module/algo/algorithm/copy_if_special_cases.cpp
module/algo/algorithm/reverse_generic.cpp
module/math/sin.cpp
module/special/tgamma.cpp
"
build_test() {
  local rel="$1" name
  name=$(echo "${rel%.cpp}" | tr '/' '.')
  "$CXX" $CXXSTD $ARCH_FLAGS -O1 $COVERAGE_FLAGS -I"$SRC/include" -I"$SRC/test" \
    "$SRC/test/unit/$rel" -lm -o "$OUT/tests/$name"
}

pids=()
for t in $TARGETS; do build_harness "$t" & pids+=($!); done
for rel in $TESTS; do build_test "$rel" & pids+=($!); done
rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
[ "$rc" -eq 0 ] || { echo "build.sh: a harness or test failed to build" >&2; exit 1; }
for t in $TARGETS; do test -x "$SRC/fuzz_$t" && test -x "$SRC/fuzz_$t-standalone"; done
echo "build.sh: built $(echo $TARGETS | wc -w) harnesses and $(echo $TESTS | wc -w) unit tests"
