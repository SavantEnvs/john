#!/usr/bin/env bash
#
# mayhem/build.sh — build John the Ripper twice (offline, in place):
#   1. NORMAL flags  -> stashed in mayhem/out/run-normal (what mayhem/test.sh exercises)
#   2. SANITIZED     -> /mayhem/run/* (the *2john tools fuzzed as file-input targets) plus the
#                       in-process libFuzzer harness /mayhem/fuzz_john_formats (+ -standalone)
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. See the template header
# for the build contract the base image exports (CC, SANITIZER_FLAGS, DEBUG_FLAGS, ...).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

: "${SRC:=/mayhem}"
cd "$SRC"
OUT_DIR="$SRC/mayhem/out"
mkdir -p "$OUT_DIR"

# --enable-simd=sse2 pins the SIMD baseline: auto-detection would bake the build host's CPU
# (e.g. AVX-512) into the binaries, which then die with SIGILL on a different fuzzing host.
# --disable-openmp keeps runs deterministic and single-process.
CONFIGURE_OPTS=(--disable-openmp --disable-opencl --enable-simd=sse2)

clean_tree() {
  make -C src clean >/dev/null 2>&1 || true
}

# 1) NORMAL build for the functional oracle (-O2, no sanitizers, no debug-flag overrides).
clean_tree
rm -rf "$OUT_DIR/run-normal"
(
  cd src
  env -u CFLAGS -u LDFLAGS -u CPPFLAGS ./configure CC="$CC" CFLAGS="-O2 $COVERAGE_FLAGS" \
      LDFLAGS="$COVERAGE_FLAGS" "${CONFIGURE_OPTS[@]}"
  make -j"$MAYHEM_JOBS"
)
cp -a run "$OUT_DIR/run-normal"
clean_tree

# 2) SANITIZED build. -O2 is required: ed25519-donna's inline asm does not compile at -O0.
#    --enable-fuzz is upstream's own hook that exports ldr_load_pw_line() for format fuzzing.
#    UBSan's `function` and `alignment` checks are relaxed: john stores format methods behind
#    incompatibly-typed pointers (e.g. DES_bs_get_binary called as void *(*)(char *)) and does
#    misaligned loads/stores of hash words throughout (dynamic_fmt.c, luks, unicode.c), which would
#    abort on every valid descrypt/dynamic/LUKS/... hash. ASan and all other UBSan checks stay halting.
#    -fsanitize=fuzzer-no-link gives the project code (not just the harness) SanCov coverage.
rm -f run/john
(
  cd src
  env -u CFLAGS -u LDFLAGS -u CPPFLAGS ./configure CC="$CC" \
      CFLAGS="-O2 $SANITIZER_FLAGS -fno-sanitize=function,alignment -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
      LDFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" \
      "${CONFIGURE_OPTS[@]}" --enable-fuzz
  # loader.o first, through harness.mk (its per-file flag does not reach the top-level make's
  # recursive sub-makes); the main make then finds it up to date.
  make -f Makefile -f ../mayhem/harness.mk MAYHEM_DIR=../mayhem loader.o
  make -j"$MAYHEM_JOBS" 2>&1 | tee "$OUT_DIR/build-sanitized.log"
)

# 3) libFuzzer harness + standalone reproducer. The link line is taken from the build log of
#    ../run/john with john.o swapped for the harness object (the harness #includes john.c).
(
  cd src
  make -f Makefile -f ../mayhem/harness.mk MAYHEM_DIR=../mayhem fuzz_john_formats.o
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c ../mayhem/lsan_off.cc -o "$OUT_DIR/lsan_off.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT_DIR/standalone_main.o"

  link_cmd=$(grep -E -- ' -o \.\./run/john$' "$OUT_DIR/build-sanitized.log" | tail -1)
  [ -n "$link_cmd" ] || { echo "cannot find the john link line in the build log" >&2; exit 1; }
  case "$link_cmd" in *" john.o "*) ;; *) echo "john.o missing from link line" >&2; exit 1;; esac

  fuzz_link=${link_cmd// john.o / fuzz_john_formats.o }
  fuzz_link=${fuzz_link% -o ../run/john}
  eval "$fuzz_link" "$OUT_DIR/lsan_off.o" "$LIB_FUZZING_ENGINE" -o "$SRC/fuzz_john_formats"
  eval "$fuzz_link" "$OUT_DIR/lsan_off.o" "$OUT_DIR/standalone_main.o" -o "$SRC/fuzz_john_formats-standalone"
)

# The *2john tools are fuzzed as file-input targets from the sanitized tree; zip2john, rar2john and
# gpg2john are symlinks to run/john (argv[0] dispatch).
for t in zip2john rar2john gpg2john dmg2john bitlocker2john hccap2john keepass2john putty2john \
         wpapcap2john uaf2john racf2john vncpcap2john; do
  [ -e "run/$t" ] || { echo "missing run/$t" >&2; exit 1; }
done

# To regenerate mayhem/john_formats/testsuite (format seeds): compile mayhem/gen_seeds.c like
# fuzz_john_formats.c (see harness.mk), link as above without the fuzzing engine, and run it with
# the output directory as its only argument.
