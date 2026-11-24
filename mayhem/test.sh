#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
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

# EDIT: RUN the test runner that mayhem/build.sh produced, then map its output to counts.
#   ctest:        (cd build-tests && ctest) ; parse "<P> tests passed, <F> failed out of <T>"
#   gtest binary: ./build-tests/<prog> ; parse "[==========] N ... ran." / "[  PASSED  ] P" / "[ SKIPPED ] S"
#   make/minunit: ./out/<runner> ; parse its pass/fail/total
# Do NOT compile here — if the runner is absent, fail (build.sh should have produced it).

# Runs SWI-Prolog's own test driver (tests/test.pl) on the normal build from build.sh (build/test),
# one test directory per CTRF test, plus known-answer checks whose output is compared exactly.
SWIPL="$SRC/build/test/src/swipl"
[ -x "$SWIPL" ] || { echo "missing $SWIPL — run mayhem/build.sh first" >&2; emit_ctrf swipl-tests 0 1 0; exit 1; }
export LANG=C.UTF-8
passed=0; failed=0

# Upstream's own suite (tests/test.pl) needs library(plunit), which lives in the packages/plunit
# submodule this fork does not carry, so the oracle is a set of known-answer checks over the
# subsystems the fuzz targets exercise (reader, writer, arithmetic, format, text, tries,
# fast_term serialization, glob, time, compiler).
# 2) Known-answer checks: goal -> exact stdout.
check() {
  local name="$1" goal="$2" want="$3" got
  got=$("$SWIPL" -f none --no-packs -q -g "$goal" -t halt 2>&1)
  if [ "$got" = "$want" ]; then echo "PASS ka:$name"; passed=$((passed+1))
  else echo "FAIL ka:$name: want [$want] got [$got]"; failed=$((failed+1)); fi
}
check bigint     'X is 2**100, write(X), nl' '1267650600228229401496703205376'
check rational   'X is 1r3 + 1r6, write(X), nl' '1r2'
check read       'term_string(T, "foo(X, [a|B], \"s\", 0'"'"'c, {x})"), write_canonical(T), nl' "foo(_,[a|_],\"s\",99,{}(x))"
check ops        'term_to_atom(T, "a:-b,c;d->e"), write_canonical(T), nl' ":-(a,;(','(b,c),->(d,e)))"
check format     'format("~a|~t~w~10||~e|~2f~n", [x, 42, 1.5, 3.14159])' 'x|      42|1.500000e+00|3.14'
check format_d   'format("~D~n", [1234567])' '1,234,567'
check atom       'atom_codes(A, [0'"'"'h,0'"'"'i]), atom_length(A, L), upcase_atom(A, U), write(A-L-U), nl' 'hi-2-HI'
check split      'split_string("a,b,,c", ",", "", P), print(P), nl' '["a","b","","c"]'
check trie       'trie_new(T), trie_insert(T, f(a), 1), trie_insert(T, g(X), 2), trie_update(T, f(a), 3), findall(K-V, trie_gen(T, K, V), L), msort(L, S), numbervars(S, 0, _), print(S), nl' '[f(a)-3,g(A)-2]'
check trie_del   'trie_new(T), trie_insert(T, k, v), trie_delete(T, k, V), findall(K, trie_gen(T, K, _), L), write(V-L), nl' 'v-[]'
check fast_term  'fast_term_serialized(f(X, "s", 1.5, [X]), S), fast_term_serialized(T, S), numbervars(T, 0, _), print(T), nl' 'f(A,"s",1.5,[A])'
check wildcard   '( wildcard_match("*.p[lr]", "foo.pl") -> write(yes) ; write(no) ), ( wildcard_match("{a,b}?", "cd") -> write(yes) ; write(no) ), nl' 'yesno'
check time       'format_time(atom(A), "%Y-%m-%dT%H:%M:%S", 0, posix), stamp_date_time(86400, date(Y,M,D,_,_,_,_,_,_), 0), write(A/Y/M/D), nl' '1970-01-01T00:00:00/1970/1/2'
check compile    'assertz((p(X, Y) :- ( X == Y -> Y = same ; Y = diff ))), p(a, R), write(R), nl' 'diff'
check float      'X is 10/4, Y is 7 // 2, Z is -7 mod 3, W is truncate(2.7), write([X,Y,Z,W]), nl' '[2.5,3,2,2]'
check gcd        'X is gcd(123456789012345678901234567890, 9876543210), write(X), nl' '90'
check writeq     'writeq(['"'"'hello world'"'"', "str", 0'"'"'a, f(-1), - 1, 1-2-3, a=b, [x|y]]), nl' "['hello world',\"str\",97,f(-1),- 1,1-2-3,a=b,[x|y]]"
check write_ops  'X = (a:-b,c), write_canonical(X), nl, writeq(-(-(1))), nl, writeq(1 - (2 - 3)), nl' ':-(a,'"','"'(b,c))
- - 1
1-(2-3)'
check escapes    'atom_codes(A, [7,10,0'"'"'x]), writeq(A), nl' "'\\a\\nx'"
check dict       'term_string(D, "_{b:2, a:1}"), get_dict(a, D, V), dict_pairs(D, _, P), print(V-P), nl' '1-[a-1,b-2]'
check sub_atom   'findall(S, sub_atom(abc, _, 2, _, S), L), print(L), nl' '[ab,bc]'
check number     'atom_number('"'"'0x1F'"'"', X), number_codes(Y, "1.0e3"), atom_number('"'"'12r5'"'"', Z), print(X/Y/Z), nl' '31/1000.0/12r5'
check text_utf8  'atom_codes(A, [0x41, 0xe9, 0x4e2d]), atom_length(A, L), string_code(3, A, C), print(L/C), nl' '3/20013'
check format_e   'format("~8|abc~t~20|~w~n", [x])' '        abc         x'
check format_r   'format("~8r ~16R ~c~n", [255, 255, 65])' '377 FF A'
check copy       'copy_term(f(X,Y,X), C), numbervars(C, 0, _), print(C), nl' 'f(A,B,A)'
check sort       'sort(0, @>=, [c,a,b,a], L), msort([b,1,"s",f(x),2.0], M), print(L-M), nl' '[c,b,a,a]-[1,2.0,"s",b,f(x)]'

emit_ctrf swipl-tests "$passed" "$failed" 0
