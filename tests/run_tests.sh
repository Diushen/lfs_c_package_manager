#!/bin/bash
# CLI tests (Milestones 1-6). Usage: tests/run_tests.sh ./lpm [build/lpm-db-demo] [build/lpm-sign]
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
# Milestone 4 implemented `install`, so (with the project owner's approval)
# this check now uses `remove`, still unimplemented: same exit code and message.
run --root "$EMPTY" remove foo
                          check "remove not implemented yet"     1 err "not implemented"
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


# --- Milestone 4: package verification and installation --------------
# Packages are built with tools/lpm-mkpkg.sh (bash + coreutils + GNU tar)
# and installed only into throw-away roots; the real / is never used.
MKPKG="$(dirname "$0")/../tools/lpm-mkpkg.sh"
echo "Running Milestone 4 CLI tests"
P4="$WORK/m4"
mkdir -p "$P4"
sha_of() { sha256sum "$1" | cut -d' ' -f1; }

# Milestone 6: installation requires a signature by a trusted key, so the
# Milestone 4/5 fixtures below are signed with a throw-away key (made
# fresh by OpenSSL for this run, never stored) and each test root that
# installs trusts it. The assertions themselves are unchanged.
SIGN="${3:-./build/lpm-sign}"
KEYS="$WORK/keys"
mkdir -p "$KEYS"
openssl genpkey -algorithm ED25519 -out "$KEYS/priv.pem" 2>/dev/null
chmod 600 "$KEYS/priv.pem"
openssl pkey -in "$KEYS/priv.pem" -pubout -out "$KEYS/pub.pem" 2>/dev/null
sign_in_place() { "$SIGN" "$KEYS/priv.pem" "$1" "$1.signed" >/dev/null && mv "$1.signed" "$1"; }
trust() { "$LPM" --root "$1" key add "$KEYS/pub.pem" >/dev/null; }

# A package source tree: binary, symlink, config, doc, empty directory.
SRC="$P4/hello-src"
mkdir -p "$SRC/payload/usr/bin" "$SRC/payload/etc" \
         "$SRC/payload/usr/share/doc/hello" "$SRC/payload/usr/share/hello/empty"
printf '#!/bin/sh\necho "Hello from LPM"\n' > "$SRC/payload/usr/bin/hello"
chmod 755 "$SRC/payload/usr/bin/hello"
ln -s hello "$SRC/payload/usr/bin/hi"
printf 'greeting=hello\n' > "$SRC/payload/etc/hello.conf"
printf 'Hello demo package\n' > "$SRC/payload/usr/share/doc/hello/README"
printf "lpm-cli-isolation-$$\n" > "$SRC/payload/usr/bin/lpm-cli-isolation-$$"
printf 'name=hello\nversion=1.2.0\ndescription=Hello demo package\n' > "$SRC/metadata.in"

if bash "$MKPKG" "$SRC" "$P4/hello.lpm" xz >"$WORK/out" 2>"$WORK/err"; then CODE=0; else CODE=$?; fi
check "mkpkg: builds an xz package" 0 out "Built"
bash "$MKPKG" "$SRC" "$P4/hello.tar.gz.lpm" gz >/dev/null 2>&1
bash "$MKPKG" "$SRC" "$P4/hello.tar.lpm" none >/dev/null 2>&1
for f in "$P4/hello.lpm" "$P4/hello.tar.gz.lpm" "$P4/hello.tar.lpm"; do sign_in_place "$f"; done
K4="$P4/trust-root"; mkdir "$K4"; trust "$K4"   # a root whose store trusts the key
HSHA=$(sha_of "$P4/hello.lpm")
HSHA_UP=$(echo "$HSHA" | tr a-f A-F)
ZERO=0000000000000000000000000000000000000000000000000000000000000000

# Milestone 6 (approved): exit 0 now means "installable", so these checks
# verify against the trust store of $K4.
run --root "$K4" verify "$P4/hello.lpm";    check "verify: good package"               0 out "INTEGRITY OK"
run --root "$K4" verify "$P4/hello.lpm";    check "verify: counts payload"             0 out "4 files, 1 symlink"
run --root "$K4" verify "$P4/hello.lpm";    check "verify: prints package SHA-256"     0 out "Package SHA-256:  $HSHA"
run --root "$K4" verify "$P4/hello.tar.gz.lpm"; check "verify: gzip package"           0 out "INTEGRITY OK"
run --root "$K4" verify "$P4/hello.tar.lpm";    check "verify: uncompressed package"   0 out "INTEGRITY OK"
run --root "$K4" verify "$P4/hello.lpm" --sha256 "$HSHA";    check "verify: correct --sha256"   0 out "matches --sha256"
run --root "$K4" verify "$P4/hello.lpm" --sha256 "$HSHA_UP"; check "verify: uppercase --sha256" 0 out "matches --sha256"
run verify "$P4/hello.lpm" --sha256 "$ZERO";    check "verify: wrong --sha256"         1 err "INTEGRITY FAILURE: package file SHA-256 mismatch"
run verify "$P4/hello.lpm" --sha256 abc;        check "verify: malformed --sha256"     1 err "exactly 64 hexadecimal digits"
run verify "$P4/hello.lpm" --bogus x;           check "verify: bad option"             2 err "usage"
run verify "$P4/missing.lpm";               check "verify: missing file"               1 err "No such file"

R4="$P4/root"
mkdir "$R4"
trust "$R4"
run --root "$R4" install "$P4/hello.lpm" --sha256 "$HSHA"
                                            check "install: succeeds"                  0 out "Installed hello 1.2.0"
if [ -x "$R4/usr/bin/hello" ] && [ "$("$R4/usr/bin/hello")" = "Hello from LPM" ] &&
   [ -L "$R4/usr/bin/hi" ] && [ -f "$R4/etc/hello.conf" ] && [ -d "$R4/usr/share/hello/empty" ]
then ok "install: files extracted into the root"; else bad "install: files extracted into the root"; fi
if [ ! -e "/usr/bin/lpm-cli-isolation-$$" ] && [ -f "$R4/usr/bin/lpm-cli-isolation-$$" ]
then ok "install: nothing written to the host /usr"; else bad "install: nothing written to the host /usr"; fi
run --root "$R4" list;                      check "install: listed"                    0 out "hello  *1.2.0"
run --root "$R4" info hello;                check "install: manifest digest recorded"  0 out "^Manifest SHA256: [0-9a-f]\{64\}$"
run --root "$R4" check;                     check "install: database consistent"       0 out "owning 5 files"
run --root "$R4" install "$P4/hello.lpm";   check "install: second time refused"       1 err "already registered"

# Wrong whole-file digest: refused before the archive is even read.
R5="$P4/root-wrongsha"; mkdir "$R5"
run --root "$R5" install "$P4/hello.lpm" --sha256 "$ZERO"
                                            check "install: wrong --sha256 rejected"   1 err "INTEGRITY FAILURE"
if [ -z "$(ls -A "$R5")" ]; then ok "install: wrong --sha256 wrote nothing"; else bad "install: wrong --sha256 wrote nothing"; fi

# Tampered payload: same metadata and manifest, one file changed.
T="$P4/tamper"; mkdir "$T"
tar -xJf "$P4/hello.lpm" -C "$T"
printf '#!/bin/sh\necho owned\n' > "$T/payload/usr/bin/hello"
tar -cJf "$P4/tampered.lpm" -C "$T" metadata.txt manifest.txt payload
R6="$P4/root-tampered"; mkdir "$R6"
run verify "$P4/tampered.lpm";              check "verify: tampered package fails"     1 err "SHA-256 mismatch for /usr/bin/hello"
run --root "$R6" install "$P4/tampered.lpm"; check "install: tampered package rejected" 1 err "INTEGRITY FAILURE"
if [ ! -e "$R6/usr" ] && [ ! -e "$R6/etc" ]; then ok "install: tampered package installed nothing"
else bad "install: tampered package installed nothing"; fi
run --root "$R6" list;                      check "install: tampered not registered"   0 out "No packages installed."

# Malicious archives: valid metadata and hashes, hostile entry names.
EV="$P4/evil"; mkdir -p "$EV/payload/etc"
printf 'pwned\n' > "$EV/payload/etc/escape.txt"
printf 'file %s 0644 /etc/escape.txt\n' "$(sha_of "$EV/payload/etc/escape.txt")" > "$EV/manifest.txt"
printf 'name=evil\nversion=1\nmanifest_sha256=%s\n' "$(sha_of "$EV/manifest.txt")" > "$EV/metadata.txt"
tar -cf "$P4/traversal.lpm" -C "$EV" metadata.txt manifest.txt \
    --transform='s,^payload/etc/escape.txt$,payload/../../escape.txt,' payload/etc/escape.txt 2>/dev/null
tar -P -cf "$P4/absolute.lpm" -C "$EV" metadata.txt manifest.txt \
    --transform="s,^payload/etc/escape.txt\$,$P4/abs-escape.txt," payload/etc/escape.txt 2>/dev/null
R7="$P4/jail/root"; mkdir -p "$R7"
run --root "$R7" install "$P4/traversal.lpm"; check "install: path traversal rejected"  1 err "path traversal"
run --root "$R7" install "$P4/absolute.lpm";  check "install: absolute path rejected"   1 err "absolute path"
if [ ! -e "$P4/jail/escape.txt" ] && [ ! -e "$P4/escape.txt" ] && [ ! -e "$P4/abs-escape.txt" ] &&
   [ "$(ls -A "$P4/jail")" = "root" ]
then ok "install: nothing escaped the root"; else bad "install: nothing escaped the root"; fi

# Symlink escapes.
SL="$P4/symlink-src"; mkdir -p "$SL/payload/usr/lib"
ln -s /etc "$SL/payload/usr/lib/evil"
printf 'name=evil\nversion=1\n' > "$SL/metadata.in"
bash "$MKPKG" "$SL" "$P4/symlink.lpm" none >/dev/null 2>&1
R8="$P4/root-symlink"; mkdir "$R8"
run --root "$R8" install "$P4/symlink.lpm"; check "install: absolute symlink rejected"  1 err "symlink target must be relative"
R9="$P4/root-planted"; mkdir -p "$R9" "$P4/elsewhere"; trust "$R9"
ln -s "$P4/elsewhere" "$R9/usr"             # planted before installing
run --root "$R9" install "$P4/hello.lpm";   check "install: planted symlink refused"    1 err "symbolic link or not a directory"
if [ -z "$(ls -A "$P4/elsewhere")" ]; then ok "install: nothing written through planted symlink"
else bad "install: nothing written through planted symlink"; fi

# Existing unowned file is never overwritten.
R10="$P4/root-existing"; mkdir -p "$R10/etc"; trust "$R10"
printf 'hand-made\n' > "$R10/etc/hello.conf"
run --root "$R10" install "$P4/hello.lpm";  check "install: existing file conflict"     1 err "already exists in the target root"
if [ "$(cat "$R10/etc/hello.conf")" = "hand-made" ] && [ ! -e "$R10/usr" ]
then ok "install: existing file kept, nothing placed"; else bad "install: existing file kept, nothing placed"; fi

# The real root is refused before anything is read. The package is the
# tampered one, so even a broken guard could not install anything.
run install "$P4/tampered.lpm";             check "install: real root refused"          1 err "real root filesystem is disabled"

# An interrupted installation is reported by check.
mkdir -p "$R4/var/lib/lpm/staging/install.999.0"
run --root "$R4" check;                     check "check: interrupted install reported" 1 out "interrupted installation"
rmdir "$R4/var/lib/lpm/staging/install.999.0"

run help;                                   check "help: install implemented"           0 out "install <file.lpm> \[--sha256 HEX\]  *Install a local package (not into / yet)$"
run help;                                   check "help: remove still planned"          0 out "remove <package>.*(planned)$"


# --- Milestone 5: dependency planning and installation ---------------
echo "Running Milestone 5 CLI tests"
P5="$WORK/m5"
D5="$P5/pkgs"
mkdir -p "$D5"
# mkdep NAME VERSION [DEPENDS...]: one package with one file.
mkdep() {
    local name=$1 ver=$2 s; shift 2
    s=$(mktemp -d "$P5/src.XXXXXX")
    mkdir -p "$s/payload/usr/share/$name"
    echo "$name $ver" > "$s/payload/usr/share/$name/README"
    printf 'name=%s\nversion=%s\n' "$name" "$ver" > "$s/metadata.in"
    for d in "$@"; do printf 'depends=%s\n' "$d" >> "$s/metadata.in"; done
    bash "$MKPKG" "$s" "${OUTDIR:-$D5}/$name-$ver.lpm" gz >/dev/null
    sign_in_place "${OUTDIR:-$D5}/$name-$ver.lpm"
    rm -rf "$s"
}
mkdep libc 1.0
mkdep liba 1.2 'libc>=1.0'
mkdep libb 1.0 'libc>=1.0'
mkdep app 1.0 'liba>=1.0' 'libb>=1.0'

R11="$P5/root"; mkdir "$R11"
run --root "$R11" plan "$D5/app-1.0.lpm" --package-dir "$D5"
                                    check "plan: succeeds"                     0 out "Status: dependency resolution successful"
                                    check "plan: 1. libc (shared, once)"       0 out "^  1\. libc 1.0  \[transitive dependency\]"
                                    check "plan: 2. liba"                      0 out "^  2\. liba 1.2  \[direct dependency\]"
                                    check "plan: 3. libb"                      0 out "^  3\. libb 1.0  \[direct dependency\]"
                                    check "plan: 4. app last"                  0 out "^  4\. app 1.0  \[requested\]"
                                    check "plan: shows graph edges"            0 out "-> libc >= 1.0  =>  libc 1.0"
                                    check "plan: package count"                0 out "^Packages to install: 4$"
if [ "$(grep -c "libc 1.0  \[" "$WORK/out")" = 1 ]; then ok "plan: libc listed once"; else bad "plan: libc listed once"; fi
if [ -z "$(ls -A "$R11")" ]; then ok "plan: wrote nothing"; else bad "plan: wrote nothing"; fi

trust "$R11"   # after the "plan wrote nothing" check above
run --root "$R11" install "$D5/app-1.0.lpm"
                                    check "install: missing deps rejected"     1 err "missing dependency: liba >= 1.0 (required by app 1.0)"
                                    check "install: says rejected"             1 err "Installation rejected"
if [ ! -e "$R11/usr" ]; then ok "install: rejection installed nothing"; else bad "install: rejection installed nothing"; fi
run --root "$R11" install "$D5/app-1.0.lpm" --package-dir "$D5"
                                    check "install: with --package-dir"        0 out "Dependencies satisfied: 0 already installed, 3 installed now"
                                    check "install: requested package last"    0 out "Installed app 1.0"
if [ "$(grep -n 'Installed libc' "$WORK/out" | cut -d: -f1)" -lt "$(grep -n 'Installed app' "$WORK/out" | cut -d: -f1)" ]
then ok "install: dependency installed first"; else bad "install: dependency installed first"; fi
run --root "$R11" list;             check "install: four packages listed"      0 out "Installed packages (4)"
run --root "$R11" check;            check "install: database consistent"       0 out "No problems found"
run --root "$R11" plan "$D5/app-1.0.lpm" --package-dir "$D5"
                                    check "plan: already installed"            1 err "already registered"

# Scenario E: an installed dependency satisfies the plan.
R12="$P5/root-installed"; mkdir "$R12"; trust "$R12"
run --root "$R12" install "$D5/libc-1.0.lpm";  check "install: libc alone"     0 out "Installed libc 1.0"
run --root "$R12" plan "$D5/liba-1.2.lpm" --package-dir "$D5"
                                    check "plan: installed dep satisfied"      0 out "^  libc 1.0  \[direct dependency\]$"
                                    check "plan: only liba to install"         0 out "^Packages to install: 1$"
run --root "$R12" install "$D5/liba-1.2.lpm"
                                    check "install: installed dep suffices"    0 out "Dependencies satisfied: 1 already installed, 0 installed now"

# Scenario B / C / D: missing, circular, conflicting.
OUTDIR="$P5/bad"; mkdir -p "$OUTDIR"
mkdep app2 1.0 'missinglib>=2.0'
mkdep cyc-a 1 'cyc-b>=1'
mkdep cyc-b 1 'cyc-c>=1'
mkdep cyc-c 1 'cyc-a>=1'
mkdep library 1.0
mkdep library 3.1
mkdep needs-new 1 'library>=3.0'
mkdep needs-old 1 'library<2.0'
mkdep both 1 'needs-new>=1' 'needs-old>=1'
OUTDIR=
R13="$P5/root-bad"; mkdir "$R13"
run --root "$R13" plan "$P5/bad/app2-1.0.lpm" --package-dir "$P5/bad"
                                    check "plan: missing dependency"           1 err "missing dependency: missinglib >= 2.0 (required by app2 1.0)"
                                    check "plan: no plan produced"             1 err "No installation plan was produced"
run --root "$R13" plan "$P5/bad/cyc-a-1.lpm" --package-dir "$P5/bad"
                                    check "plan: cycle detected"               1 err "dependency cycle detected: cyc-a -> cyc-b -> cyc-c -> cyc-a"
run --root "$R13" install "$P5/bad/cyc-a-1.lpm" --package-dir "$P5/bad"
                                    check "install: cycle rejected"            1 err "dependency cycle detected"
run --root "$R13" plan "$P5/bad/both-1.lpm" --package-dir "$P5/bad"
                                    check "plan: version conflict"             1 err "conflicting requirements: library < 2.0 (required by needs-old 1)"
if [ ! -e "$R13/usr" ] && [ ! -e "$R13/var/lib/lpm/installed/cyc-a.meta" ]
then ok "plan/install: failures changed nothing"; else bad "plan/install: failures changed nothing"; fi

# Scenario F: a corrupted dependency stops the whole installation.
T5="$P5/tamper"; mkdir -p "$T5" "$P5/corrupt"
cp "$D5"/*.lpm "$P5/corrupt/"
tar -xzf "$D5/libc-1.0.lpm" -C "$T5"
echo "tampered" > "$T5/payload/usr/share/libc/README"
tar -czf "$P5/corrupt/libc-1.0.lpm" -C "$T5" metadata.txt manifest.txt payload
R14="$P5/root-corrupt"; mkdir "$R14"; trust "$R14"
run --root "$R14" install "$P5/corrupt/app-1.0.lpm" --package-dir "$P5/corrupt"
                                    check "install: corrupted dependency"      1 err "INTEGRITY FAILURE: libc 1.0: SHA-256 mismatch"
if [ ! -e "$R14/usr" ] && [ ! -e "$R14/var/lib/lpm/installed/app.meta" ]
then ok "install: nothing installed after corruption"; else bad "install: nothing installed after corruption"; fi

run --root "$R11" plan "$D5/app-1.0.lpm" --sha256 abc
                                    check "plan: rejects --sha256"             2 err "usage"
run help;                           check "help: plan command"                 0 out "plan <file.lpm> \[--package-dir DIR\]  *Show the dependency plan"
run help;                           check "help: --package-dir option"         0 out "--package-dir DIR  plan, install"


# --- Milestone 6: Ed25519 signatures and trusted keys ------------------
echo "Running Milestone 6 CLI tests"
P6="$WORK/m6"
mkdir -p "$P6/pkgs"
openssl genpkey -algorithm ED25519 -out "$KEYS/other.pem" 2>/dev/null   # a stranger
chmod 600 "$KEYS/other.pem"
KID=$("$LPM" --root "$K4" key list | awk 'NR==2{print $1}')

R15="$P6/root"; mkdir "$R15"
run --root "$R15" key list;                 check "key: empty store"                   0 out "No trusted keys"
run --root "$R15" key add "$KEYS/pub.pem";  check "key: add prints fingerprint"        0 out "Trusted key added: $KID (ed25519)"
if [ -f "$R15/etc/lpm/trusted-keys/$KID.pub" ] && [ ! -e /etc/lpm/trusted-keys/$KID.pub ]
then ok "key: stored under --root only"; else bad "key: stored under --root only"; fi
run --root "$R15" key add "$KEYS/pub.pem";  check "key: duplicate refused"             1 err "already trusted"
run --root "$R15" key add "$KEYS/priv.pem"; check "key: private key refused"           1 err "PRIVATE key"
printf 'not a key\n' > "$P6/junk.pem"
run --root "$R15" key add "$P6/junk.pem";   check "key: malformed key refused"         1 err "not a PEM public key"
run --root "$R15" key list;                 check "key: list shows fingerprint"        0 out "^  $KID  ed25519$"
run --root "$R15" key remove nothex;        check "key: bad id refused"                1 err "64 lowercase hex"
run --root "$R15" key frob;                 check "key: unknown subcommand"            2 err "usage"

# Packages: trusted, unsigned, stranger, tampered metadata.
S6="$P6/src"; mkdir -p "$S6/payload/usr/share/demo"
echo demo > "$S6/payload/usr/share/demo/README"
printf 'name=demo\nversion=1.0\n' > "$S6/metadata.in"
bash "$MKPKG" "$S6" "$P6/demo-unsigned.lpm" gz >/dev/null
"$SIGN" "$KEYS/priv.pem" "$P6/demo-unsigned.lpm" "$P6/demo.lpm" >"$WORK/out" 2>"$WORK/err"; CODE=$?
                                            check "sign: signs a package"              0 out "Signed demo 1.0 with Ed25519 key $KID"
"$SIGN" "$KEYS/priv.pem" "$P6/demo-unsigned.lpm" "$P6/demo.lpm" >"$WORK/out" 2>"$WORK/err"; CODE=$?
                                            check "sign: never overwrites"             1 err "must not exist"
"$SIGN" "$KEYS/priv.pem" "$P6/demo.lpm" "$P6/twice.lpm" >"$WORK/out" 2>"$WORK/err"; CODE=$?
                                            check "sign: refuses to sign twice"        1 err "already signed"
"$SIGN" "$KEYS/other.pem" "$P6/demo-unsigned.lpm" "$P6/demo-other.lpm" >/dev/null
if tar -tzf "$P6/demo.lpm" | head -3 | tr '\n' ' ' | grep -q "^metadata.txt manifest.txt signature.txt "
then ok "sign: signature.txt is the third entry"; else bad "sign: signature.txt is the third entry"; fi
if ! tar -xzOf "$P6/demo.lpm" signature.txt | grep -q PRIVATE; then ok "sign: no private key in package"
else bad "sign: no private key in package"; fi

run --root "$R15" verify "$P6/demo.lpm";          check "verify: trusted => exit 0"   0 out "AUTHENTICATED: signed by a trusted key"
                                                  check "verify: shows signing key"   0 out "Signing key:    $KID"
run --root "$R15" verify "$P6/demo-unsigned.lpm"; check "verify: unsigned => exit 3"  3 out "Signature:      none (unsigned)"
run --root "$R15" verify "$P6/demo-other.lpm";    check "verify: stranger => exit 3"  3 out "Trust:          NOT trusted"
                                                  check "verify: stranger sig valid"  3 out "Signature:      Ed25519, valid"
T6="$P6/t"; mkdir "$T6"; tar -xzf "$P6/demo.lpm" -C "$T6"
sed -i 's/^version=1.0$/version=9.0/' "$T6/metadata.txt"
tar -czf "$P6/demo-tampered.lpm" -C "$T6" metadata.txt manifest.txt signature.txt payload
run --root "$R15" verify "$P6/demo-tampered.lpm"; check "verify: tampered metadata => 1" 1 out "Signature:      Ed25519, INVALID"
                                                  check "verify: tamper reported"     1 err "AUTHENTICATION FAILURE"
run verify "$P6/demo.lpm";                        check "verify: host store not used" 3 out "NOT trusted"

run --root "$R15" install "$P6/demo-unsigned.lpm"; check "install: unsigned refused"  1 err "AUTHENTICATION FAILURE: demo 1.0: the package is not signed"
run --root "$R15" install "$P6/demo-other.lpm";    check "install: untrusted refused" 3 err "is not trusted"
run --root "$R15" install "$P6/demo-tampered.lpm"; check "install: tampered refused"  1 err "invalid signature"
if [ ! -e "$R15/usr" ]; then ok "install: refusals installed nothing"; else bad "install: refusals installed nothing"; fi
run --root "$R15" install "$P6/demo.lpm";          check "install: trusted installs"  0 out "Authenticated demo 1.0: Ed25519 signature by trusted key"
run --root "$R15" key remove "$KID";               check "key: remove"                0 out "Removed trusted key $KID"
run --root "$R15" list;                            check "key: removal keeps installed" 0 out "demo  *1.0"

# Dependencies: every package must be authenticated.
R16="$P6/root-deps"; mkdir "$R16"; trust "$R16"
OUTDIR="$P6/pkgs"
mkdep libc 1.0; mkdep liba 1.0 'libc>=1.0'; mkdep libb 1.0 'libc>=1.0'
mkdep app 1.0 'liba>=1.0' 'libb>=1.0'
OUTDIR=
mv "$P6/pkgs/libb-1.0.lpm" "$P6/libb-good.lpm"
mkdir -p "$P6/lb"; tar -xzf "$P6/libb-good.lpm" -C "$P6/lb"
tar -czf "$P6/libb-unsigned.lpm" -C "$P6/lb" metadata.txt manifest.txt payload
"$SIGN" "$KEYS/other.pem" "$P6/libb-unsigned.lpm" "$P6/pkgs/libb-1.0.lpm" >/dev/null
run --root "$R16" install "$P6/pkgs/app-1.0.lpm" --package-dir "$P6/pkgs"
                                            check "deps: untrusted libb rejects all"   3 err "libb 1.0: signing key .* is not trusted"
if [ ! -e "$R16/usr" ] && [ "$("$LPM" --root "$R16" list)" = "No packages installed." ]
then ok "deps: nothing installed"; else bad "deps: nothing installed"; fi
cp "$P6/libb-good.lpm" "$P6/pkgs/libb-1.0.lpm"
run --root "$R16" install "$P6/pkgs/app-1.0.lpm" --package-dir "$P6/pkgs"
                                            check "deps: all trusted installs"         0 out "Authenticated libc 1.0"
run --root "$R16" list;                     check "deps: four packages"                0 out "Installed packages (4)"

# A trusted package may still not write into LPM's protected areas.
S7="$P6/src-evil"; mkdir -p "$S7/payload/etc/lpm/trusted-keys"
cp "$KEYS/pub.pem" "$S7/payload/etc/lpm/trusted-keys/evil.pub"
printf 'name=evil\nversion=1.0\n' > "$S7/metadata.in"
bash "$MKPKG" "$S7" "$P6/evil.lpm" gz >/dev/null; sign_in_place "$P6/evil.lpm"
run --root "$R16" install "$P6/evil.lpm";   check "install: trust store protected"     1 err "protected area"
if [ ! -e "$R16/etc/lpm/trusted-keys/evil.pub" ]; then ok "install: no key planted"; else bad "install: no key planted"; fi

run help;                                   check "help: key command"                  0 out "key list | add FILE.pem | remove KEY_ID"

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
