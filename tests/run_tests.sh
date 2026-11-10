#!/bin/bash
# CLI tests (Milestones 1-2). Usage: tests/run_tests.sh ./lpm
#
# Every test runs against a throwaway --root directory, never against /.

LPM="${1:-./lpm}"
PASS=0
FAIL=0

if [ ! -x "$LPM" ]; then
    echo "lpm binary not found at '$LPM' (run 'make' first)" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# run <args...> : runs lpm, captures stdout/stderr/exit code
run() {
    "$LPM" "$@" >"$WORK/out" 2>"$WORK/err"
    CODE=$?
}

ok()   { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
bad()  {
    FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"
    echo "        exit=$CODE"; sed 's/^/        out| /' "$WORK/out"; sed 's/^/        err| /' "$WORK/err"
}

# check <name> <expected-exit> <stream: out|err> <grep-pattern>
check() {
    if [ "$CODE" -eq "$2" ] && grep -q -- "$4" "$WORK/$3"; then ok "$1"; else bad "$1"; fi
}

# --- fixtures ---------------------------------------------------------
NODB="$WORK/root-nodb"                     # root with no database at all
EMPTY="$WORK/root-empty"                   # initialised but empty database
FULL="$WORK/root-full"                     # two installed packages
mkdir -p "$NODB" "$EMPTY/var/lib/lpm/installed" "$FULL/var/lib/lpm/installed"

printf 'name=libfoo\nversion=1.2.0\n' > "$FULL/var/lib/lpm/installed/libfoo.meta"
printf 'name=hello\nversion=1.0\n'    > "$FULL/var/lib/lpm/installed/hello.meta"
printf 'name=nover\n'                 > "$FULL/var/lib/lpm/installed/nover.meta"
printf 'junk\n'                       > "$FULL/var/lib/lpm/installed/notes.txt"
printf 'version=6.6.6\n'              > "$FULL/var/lib/lpm/installed/Bad..Name.meta"

echo "Running Milestone 1 tests with $LPM"

run help;               check "help prints usage"                0 out "Usage:"
run --help;             check "--help prints usage"              0 out "Commands:"
run;                    check "no command is a usage error"      2 err "no command given"
run version;            check "version command"                  0 out "0.1.0"
run -V;                 check "-V option"                        0 out "LFS Package Manager"
run frobnicate;         check "unknown command rejected"         2 err "unknown command 'frobnicate'"
run --bogus list;       check "unknown option rejected"          2 err "unknown option '--bogus'"
run --root;             check "--root without argument"          2 err "requires a directory"
run --root "$WORK/does-not-exist" list
                        check "--root must exist"                1 err "not accessible"
run --root "$NODB" list;  check "list: no database"              0 out "database not initialised"
run --root "$EMPTY" list; check "list: empty database"           0 out "No packages installed."
run --root "$FULL" list;  check "list: shows package count"      0 out "Installed packages (3)"

# sorted output: hello must come before libfoo
run --root "$FULL" list
if [ "$CODE" -eq 0 ] && [ "$(grep -n hello "$WORK/out" | cut -d: -f1)" -lt \
                          "$(grep -n libfoo "$WORK/out" | cut -d: -f1)" ]; then
    ok "list: sorted by name"; else bad "list: sorted by name"; fi

run --root "$FULL" list;  check "list: shows version"            0 out "libfoo  *1.2.0"
run --root "$FULL" list;  check "list: missing version shown ?"  0 out "nover  *?"
run --root "$FULL" list;  check "list: warns on invalid name"    0 err "invalid package name: Bad..Name.meta"
run --root="$FULL" list;  check "--root=DIR form"                0 out "hello"
run list extra;           check "list rejects extra arguments"   2 err "too many arguments"
run --root "$EMPTY" install foo.pkg
                          check "install not implemented yet"    1 err "not implemented"
run install;              check "install requires argument"      2 err "requires an argument"

# --- Milestone 2: metadata parser through the CLI ---------------------
# A separate root, so the Milestone 1 fixtures and assertions above stay
# exactly as they were.
INFO="$WORK/root-info"
mkdir -p "$INFO/var/lib/lpm/installed"
D="$INFO/var/lib/lpm/installed"
HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
printf 'name=hello\nversion=1.2.0\ndescription=A simple hello world program\ndepends=libfoo>=1.0\ndepends=libbar=2.1\nmanifest_sha256=%s\n' "$HEX" > "$D/hello.meta"
printf 'name=libfoo\nversion=1.0\n'      > "$D/libfoo.meta"
printf 'name=broken\nversion=1..2\n'     > "$D/broken.meta"
printf 'name=other\nversion=1.0\n'       > "$D/mismatch.meta"
ln -s hello.meta "$D/linked.meta"

echo "Running Milestone 2 CLI tests"
run --root "$INFO" info hello;   check "info: shows version"            0 out "^Version: *1.2.0$"
run --root "$INFO" info hello;   check "info: shows description"        0 out "^Description: *A simple hello world program$"
run --root "$INFO" info hello;   check "info: shows >= dependency"      0 out "libfoo >= 1.0"
run --root "$INFO" info hello;   check "info: shows = dependency"       0 out "libbar = 2.1"
run --root "$INFO" info hello;   check "info: shows manifest digest"    0 out "^Manifest SHA256: $HEX$"
run --root "$INFO" info libfoo;  check "info: no dependencies"          0 out "^Dependencies: *(none)$"
run --root "$INFO" info libfoo;  check "info: no digest recorded"       0 out "(not recorded)"
run --root "$INFO" info nothere; check "info: missing package"          1 err "package 'nothere' is not installed"
run --root "$NODB" info hello;   check "info: no database"              1 err "is not installed"
run --root "$INFO" info ../etc;  check "info: rejects unsafe name"      1 err "invalid package name"
run --root "$INFO" info broken;  check "info: damaged record is error"  1 err "broken.meta:2: invalid version '1..2'"
run --root "$INFO" info mismatch; check "info: name/filename mismatch"  1 err "does not match its database filename"
run --root "$INFO" info linked;  check "info: refuses symlinked record" 1 err "symbolic link"
run info;                        check "info requires argument"         2 err "requires an argument"
run --root "$INFO" list;         check "list: damaged record shown ?"   0 out "broken  *?"
run --root "$INFO" list;         check "list: damaged record warning"   0 err "damaged database record .*broken.meta:2"
run --root "$INFO" list;         check "list: valid record version"     0 out "hello  *1.2.0"
run --root "$FULL" list;         check "list: legacy record explained"  0 err "nover.meta: missing required field 'version'"

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
