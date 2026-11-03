#!/usr/bin/env bash
#
# mayhem/test.sh — RUN John the Ripper's behavioral checks against the NORMAL (unsanitized) build that
# mayhem/build.sh stashed in mayhem/out/run-normal. Nothing is compiled here.
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


J="$SRC/mayhem/out/run-normal"
[ -x "$J/john" ] || { echo "missing $J/john — mayhem/build.sh did not produce the normal build" >&2; emit_ctrf "john-selftest" 0 1 0; exit 1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
export HOME="$W"
cd "$W"

passed=0 failed=0
check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then passed=$((passed+1)); else failed=$((failed+1)); echo "FAIL $1: expected [$2] got [$3]" >&2; fi
}

# 1) Crack known hashes of "password"/"secret" with a wordlist; `--show` must print the plaintext.
printf 'letmein\npassword\nsecret\nqwerty\n' > words.lst
crack() { # crack <format> <hash...>
  local fmt="$1"; shift
  : > hashes.txt
  local i=0
  for h in "$@"; do i=$((i+1)); echo "user$i:$h" >> hashes.txt; done
  rm -f "$W/pot"
  "$J/john" --format="$fmt" --pot="$W/pot" --wordlist=words.lst hashes.txt >/dev/null 2>&1
  "$J/john" --format="$fmt" --pot="$W/pot" --show hashes.txt 2>/dev/null | sed -n '/^user/p'
}
out=$(crack Raw-MD5 5f4dcc3b5aa765d61d8327deb882cf99 5ebe2294ecd0e0f08eab7690d2a6ee69)
check raw-md5 $'user1:password\nuser2:secret' "$out"
out=$(crack Raw-SHA1 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8)
check raw-sha1 'user1:password' "$out"
out=$(crack Raw-SHA256 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8)
check raw-sha256 'user1:password' "$out"
out=$(crack NT 8846f7eaee8fb117ad06bdd830b7586c)
check nt 'user1:password' "$out"
out=$(crack md5crypt '$1$hGU3PgOd$Eg5.KbyWrE1vgKSPIHR.C0')
check md5crypt 'user1:password' "$out"
out=$(crack descrypt 'abJnggxhB/yWI')
check descrypt 'user1:password' "$out"

# 2) A hash for a different password must NOT be cracked.
out=$(crack Raw-MD5 d41d8cd98f00b204e9800998ecf8427e)
check no-false-positive '' "$out"

# 3) Built-in known-answer self-tests of a spread of formats.
for fmt in raw-md5 raw-sha1 raw-sha256 raw-sha512 nt md5crypt sha512crypt bcrypt descrypt \
           hmac-sha256 pbkdf2-hmac-sha1 zip rar5 7z krb5pa-md5 wpapsk mysql-sha1 Raw-Keccak-256 \
           PKZIP keepass dmg bitlocker gpg pdf ssh; do
  res=$("$J/john" --test=0 --format="$fmt" 2>&1 | grep -E '^Testing:' || true)
  case "$res" in
    *PASS*) passed=$((passed+1));;
    *) failed=$((failed+1)); echo "FAIL selftest $fmt: [$res]" >&2;;
  esac
done

# 4) unshadow merges passwd and shadow by user name.
printf 'root:x:0:0:root:/root:/bin/sh\nbob:x:1000:1000:Bob:/home/bob:/bin/sh\n' > passwd
printf 'root:$1$hGU3PgOd$Eg5.KbyWrE1vgKSPIHR.C0:19000:0:99999:7:::\nbob:*:19000:0:99999:7:::\n' > shadow
out=$("$J/unshadow" passwd shadow)
check unshadow $'root:$1$hGU3PgOd$Eg5.KbyWrE1vgKSPIHR.C0:0:0:root:/root:/bin/sh\nbob:*:1000:1000:Bob:/home/bob:/bin/sh' "$out"

# 5) Format listing exposes the formats this suite depends on.
fmts=$("$J/john" --list=formats 2>/dev/null | tr ',' '\n' | tr -d ' ')
for f in md5crypt sha512crypt bcrypt NT; do
  case $'\n'"$fmts"$'\n' in *$'\n'"$f"$'\n'*) passed=$((passed+1));; *) failed=$((failed+1)); echo "FAIL format list lacks $f" >&2;; esac
done

emit_ctrf "john-selftest" "$passed" "$failed" 0
