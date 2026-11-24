#!/usr/bin/env bash
#
# mayhem/build.sh — build SWI-Prolog's core (src/, boot/, library/) twice and the fuzz harnesses.
#
#   build/fuzz  static libswipl.a with ASan+UBSan (halting) + SanCov + DWARF 3; the harnesses link it.
#               Its runtime home (boot.prc + library) is build/fuzz/home, which each harness finds
#               relative to its own executable (/mayhem/fuzz_<t> -> /mayhem/build/fuzz/home).
#   build/test  the normal (unsanitized) build that mayhem/test.sh runs upstream's tests with.
#
# packages/* are git submodules that this fork does not carry. The Dockerfile caches the ones the
# harnesses use (sgml, clib, json, redis) at their gitlink commits under /opt/toolchains/deps;
# they are copied into the empty submodule directories here and linked statically into the fuzz
# build (STATIC_EXTENSIONS). The test build stays core-only. `build` is in upstream's .gitignore, so
# `git clean -ffdX` removes both build trees.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS
# The build runs the freshly built (instrumented) swipl to compile boot.prc; its leaks are irrelevant.
export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0"
export LANG=C.UTF-8

cd "$SRC"

FUZZ_PACKAGES=(sgml clib json redis)
for p in "${FUZZ_PACKAGES[@]}"; do
  sha=$(git -c safe.directory="$SRC" ls-tree HEAD "packages/$p" | awk '{print $3}')
  dep="/opt/toolchains/deps/swipl-$p-$sha/src"
  [ -d "$dep" ] || { echo "missing cached package $dep (see mayhem/Dockerfile)" >&2; exit 1; }
  if [ ! -e "packages/$p/CMakeLists.txt" ]; then
    cp -R "$dep/." "packages/$p/"
    chmod -R u+w "packages/$p"
  fi
done

COMMON_CMAKE=(
  -G Ninja
  -DCMAKE_BUILD_TYPE=None
  -DSWIPL_SHARED_LIB=OFF
  -DUSE_TCMALLOC=OFF
  -DINSTALL_DOCUMENTATION=OFF
)

# 1) Sanitized + coverage-instrumented core.
#    -DVMI_CC= : the VM's tail-called instruction functions default to clang-19's preserve_none
#    calling convention, which clang's backend cannot combine with ASan's dynamic allocas
#    ("Stack realignment in presence of dynamic allocas is not supported with this calling
#    convention" on pl-wam.c). An empty VMI_CC keeps the same musttail VM with the default convention.
#    -fno-sanitize=function (only when UBSan is on): the static package registry (pl-load.c)
#    calls every package's install_<pkg>() through a generic void(*)(void) pointer, which UBSan's
#    function-type check reports on the first package load, so nothing could run. All other ASan and
#    UBSan checks stay on and halting.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -DVMI_CC="
case "$SANITIZER_FLAGS" in *undefined*) FUZZ_CFLAGS="$FUZZ_CFLAGS -fno-sanitize=function" ;; esac
cmake -S . -B build/fuzz "${COMMON_CMAKE[@]}" -DBUILD_TESTING=OFF \
  -DSWIPL_PACKAGES=ON -DSTATIC_EXTENSIONS=ON -DSWIPL_PACKAGES_BASIC=ON -DSWIPL_PACKAGES_JSON=ON \
  -DSWIPL_PACKAGES_ARCHIVE=OFF -DSWIPL_PACKAGES_ODBC=OFF -DSWIPL_PACKAGES_BDB=OFF \
  -DSWIPL_PACKAGES_PCRE=OFF -DSWIPL_PACKAGES_YAML=OFF -DSWIPL_PACKAGES_JAVA=OFF \
  -DSWIPL_PACKAGES_PYTHON=OFF -DSWIPL_PACKAGES_SSL=OFF -DSWIPL_PACKAGES_TIPC=OFF \
  -DSWIPL_PACKAGES_TERM=OFF -DSWIPL_PACKAGES_GUI=OFF \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS"
ninja -C build/fuzz -j"$MAYHEM_JOBS"

# The libraries the swipl executable links against, as the build itself resolved them.
mapfile -t LINK_LIBS < <(ninja -C build/fuzz -t commands src/swipl | tail -1 | tr ' ' '\n' \
  | grep -E '\.a$|^-l|\.so(\.[0-9]+)*$' | sed -E "s|^([^/-])|build/fuzz/\1|")
echo "harness link libs: ${LINK_LIBS[*]}"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/standalone_main.o

TARGETS=(read trie compile format text arith fast_read wildcard format_time sgml json uri redis)
for t in "${TARGETS[@]}"; do
  # Binary inputs are passed as octets (fast_read; read copies them to a temporary file, read
  # back as UTF-8 source); the op-script targets read their scripts as ISO-Latin-1,
  # where every byte is a character, so an in-memory truncated UTF-8 sequence (an assertion in
  # Speekcode) cannot mask them.
  case "$t" in
    read|fast_read|redis) enc=ENC_OCTET ;;
    *) enc=ENC_ISO_LATIN_1 ;;
  esac
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link \
    -DFUZZ_PRED="\"fuzz_$t\"" -DFUZZ_ENC="$enc" -Isrc -Isrc/os -Ibuild/fuzz/src \
    -c mayhem/harnesses/fuzz_swipl.c -o "build/fuzz/fuzz_$t.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build/fuzz/fuzz_$t.o" build/fuzz/lsan_off.o \
    -Wl,--export-dynamic "${LINK_LIBS[@]}" -lm -lpthread -ldl -o "$SRC/fuzz_$t"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "build/fuzz/fuzz_$t.o" build/fuzz/standalone_main.o build/fuzz/lsan_off.o \
    -Wl,--export-dynamic "${LINK_LIBS[@]}" -lm -lpthread -ldl -o "$SRC/fuzz_$t-standalone"
done

# 2) Normal build for the functional suite (project's own flags, no sanitizers).
cmake -S . -B build/test "${COMMON_CMAKE[@]}" -DBUILD_TESTING=ON -DSWIPL_PACKAGES=OFF \
  -DCMAKE_C_FLAGS="-O2 $COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="-O2 $COVERAGE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
ninja -C build/test -j"$MAYHEM_JOBS"
