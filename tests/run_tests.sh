#!/bin/bash
# CLI tests (Milestones 1-3). Usage: tests/run_tests.sh ./lpm [build/lpm-db-demo]
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

# --- Milestone 3: database registration, removal, locking, check -----
# Uses build/lpm-db-demo (a test/demo driver of the database API, never
# installed) and fresh roots, so every assertion above stays as it was.
DEMO="${2:-./build/lpm-db-demo}"
umask 022   # the database refuses group/other-writable directories

rund() {
    "$DEMO" "$@" >"$WORK/out" 2>"$WORK/err"
    CODE=$?
}
nocheck() { if [ "$CODE" -eq "$2" ] && ! grep -q -- "$4" "$WORK/$3"; then ok "$1"; else bad "$1"; fi; }

echo "Running Milestone 3 CLI tests with $DEMO"
if [ ! -x "$DEMO" ]; then
    CODE=127; : >"$WORK/out"; echo "missing $DEMO (run 'make demo')" >"$WORK/err"
    bad "demo tool is built"
else
M3="$WORK/root-m3"
IN="$WORK/m3-input"
mkdir -p "$M3" "$IN"
DB="$M3/var/lib/lpm"
printf 'name=hello\nversion=1.2.0\ndescription=A simple hello world program\ndepends=libfoo>=1.0\n' > "$IN/hello.meta"
printf '/usr/share/doc/hello/README\n/usr/bin/hello\n' > "$IN/hello.list"
printf 'name=libfoo\nversion=1.10\n'  > "$IN/libfoo.meta"
printf '/usr/lib/libfoo.so.1\n'       > "$IN/libfoo.list"
printf 'name=bad\nversion=01\n'       > "$IN/bad.meta"
printf 'name=evil\nversion=1\n'       > "$IN/evil.meta"
printf '/usr/bin/x\n/../../etc/passwd\n' > "$IN/evil.list"
printf 'name=thief\nversion=1\n'      > "$IN/thief.meta"
printf '/usr/bin/hello\n'             > "$IN/thief.list"

rund --root "$M3" init;          check "demo: init creates database"        0 out "Initialised an empty package database"
run --root "$M3" list;           check "list: new database is empty"        0 out "No packages installed."
rund --root "$M3" register "$IN/libfoo.meta" "$IN/libfoo.list"
                                 check "demo: register libfoo"              0 out "Registered libfoo 1.10"
rund --root "$M3" register "$IN/hello.meta" "$IN/hello.list"
                                 check "demo: registration installs nothing" 0 out "No files were installed"
run --root "$M3" list;           check "list: shows registered package"     0 out "hello  *1.2.0"
run --root "$M3" info hello;     check "info: reads registered record"      0 out "libfoo >= 1.0"
rund --root "$M3" register "$IN/hello.meta" "$IN/hello.list"
                                 check "demo: duplicate rejected"           1 err "package 'hello' is already registered"
rund --root "$M3" register "$IN/bad.meta"
                                 check "demo: invalid metadata rejected"    1 err "bad.meta:2: invalid version '01'"
rund --root "$M3" register "$IN/evil.meta" "$IN/evil.list"
                                 check "demo: traversal path rejected"      1 err "'..' component"
rund --root "$M3" register "$IN/thief.meta" "$IN/thief.list"
                                 check "demo: file conflict rejected"       1 err "already owned by package 'hello'"
if ls -A "$DB/installed" "$DB/files" | grep -q 'lpm-tmp'; then bad "failed operations leave no temp files"
else ok "failed operations leave no temp files"; fi
run --root "$M3" check;          check "check: consistent after failures"   0 out "No problems found by the implemented checks"
run --root "$M3" check;          check "check: counts owned files"          0 out "Checked 2 records (2 valid) owning 3 files"
rund --root "$M3" exists hello;  check "demo: exists"                       0 out "hello is registered"
rund --root "$M3" files hello;   check "demo: file list stored sorted"      0 out "^/usr/bin/hello$"

mkdir -p "$M3/usr/bin" && echo payload > "$M3/usr/bin/hello"
rund --root "$M3" unregister hello
                                 check "demo: unregister deletes no files"  0 out "No package files were deleted"
if [ -f "$M3/usr/bin/hello" ] && [ ! -e "$DB/installed/hello.meta" ] && [ ! -e "$DB/files/hello.list" ]
then ok "unregister removed records, kept payload"; else bad "unregister removed records, kept payload"; fi
run --root "$M3" list;           nocheck "list: unregistered package gone"  0 out "hello"
rund --root "$M3" unregister hello
                                 check "demo: unregister missing package"   1 err "package 'hello' is not registered"
run --root "$M3" check;          check "check: libfoo still consistent"     0 out "No problems found"

rund compare 1.9 1.10;           check "demo: 1.9 < 1.10"                   0 out "^1.9 < 1.10$"
rund compare 1.0 1;              check "demo: 1.0 == 1"                     0 out "^1.0 == 1$"
rund compare 10.0 9.99;          check "demo: 10.0 > 9.99"                  0 out "^10.0 > 9.99$"
rund compare 01 1;               check "demo: invalid version rejected"     1 err "invalid version"
rund satisfies 2.1 '>=' 2.0;     check "demo: 2.1 satisfies >= 2.0"         0 out "^2.1 satisfies >= 2.0$"
rund satisfies 2.1 '=' 2.0;      check "demo: 2.1 does not satisfy = 2.0"   0 out "does not satisfy"

# Locking: a second writer is refused while the first holds the lock.
"$DEMO" --root "$M3" hold-lock 20 >"$WORK/lockout" 2>&1 &
LPID=$!
for _ in $(seq 100); do grep -q Holding "$WORK/lockout" 2>/dev/null && break; sleep 0.1; done
rund --root "$M3" register "$IN/hello.meta" "$IN/hello.list"
                                 check "demo: locked database refused"      1 err "locked by another LPM process"
kill "$LPID" 2>/dev/null; wait "$LPID" 2>/dev/null
rund --root "$M3" register "$IN/hello.meta" "$IN/hello.list"
                                 check "demo: lock released by killed holder" 0 out "Registered hello"

# check reports problems and deletes nothing.
printf '/usr/bin/ghost\n' > "$DB/files/ghost.list"
printf 'name=hel'         > "$DB/installed/.lpm-tmp.hello.meta.1.0"
run --root "$M3" check;          check "check: orphaned file list"          1 out "orphaned file list.*files/ghost.list"
run --root "$M3" check;          check "check: abandoned temporary file"    1 out "abandoned temporary file"
run --root "$M3" check;          check "check: problem count"               1 out "2 problems found. Nothing was changed"
if [ -f "$DB/files/ghost.list" ]; then ok "check deletes nothing"; else bad "check deletes nothing"; fi

LEG="$WORK/root-legacy"
mkdir -p "$LEG/var/lib/lpm/installed"
printf 'name=nover\n' > "$LEG/var/lib/lpm/installed/nover.meta"
run --root "$LEG" check;         check "check: legacy damaged record"       1 out "damaged record.*nover.meta: missing required field 'version'"
run --root "$NODB" check;        check "check: no database"                 0 out "nothing to check"
run help;                        check "help: check is implemented"         0 out "check  *Check database consistency$"

# Safety rails of the demo tool and of the database itself.
rund init;                       check "demo: --root is mandatory"          2 err "--root DIR is required"
rund --root / init;              check "demo: refuses the real root"        2 err "refusing to operate on '/'"
rund --root /usr/.. init;        check "demo: refuses / spelled differently" 2 err "refusing to operate"
SYM="$WORK/root-sym"
mkdir -p "$SYM/var/lib/lpm" "$WORK/elsewhere"
ln -s "$WORK/elsewhere" "$SYM/var/lib/lpm/installed"
rund --root "$SYM" register "$IN/libfoo.meta"
                                 check "demo: symlinked database refused"   1 err "symbolic link"
if [ -z "$(ls -A "$WORK/elsewhere")" ]; then ok "symlink target untouched"; else bad "symlink target untouched"; fi
GW="$WORK/root-gw"
rund --root "$GW" init >/dev/null 2>&1; mkdir -p "$GW"; rund --root "$GW" init
chmod g+w "$GW/var/lib/lpm/installed"
rund --root "$GW" register "$IN/libfoo.meta"
                                 check "demo: group-writable db refused"    1 err "writable by group or others"
fi

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
