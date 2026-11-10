# lfs_c_package_manager

C package manager for my Linux From Scratch Distribution - Part of my Capstone

## LPM — LFS Package Manager

A small package manager written in C for a Linux From Scratch 13.1-systemd
system.

## Status

| Milestone | Feature                                           | State |
|-----------|---------------------------------------------------|-------|
| 1         | Skeleton, CLI, `help`, `version`, `list`          | done  |
| 2         | Metadata parser, package structures, `info`       | done  |
| 3         | Version comparison, locked atomic database writes, file ownership, `check` | done |
| 4–12      | dependency graph, archive, SHA-256, Ed25519, install, remove | planned |

`lpm install`, `lpm remove` and `lpm verify` are still **not implemented**.
Milestone 3 can *record* packages in the database (through the demo tool
below), but recording is bookkeeping, not installation.

## Build and test

    make              # release build of lpm (-O2), no external libraries
    make test         # build everything, run CLI tests + all unit tests
    make debug        # rebuild with AddressSanitizer + UBSan ...
    make test         # ... and test that build (debug stays active until `make clean`)
    make unit-test    # only the unit tests
    make demo         # only build/lpm-db-demo (Milestone 3 demonstration)
    make clean
    make install      # installs lpm only, never the test or demo programs

    build/test_metadata -v tests/fixtures   # -v prints every diagnostic
    build/test_version  -v
    build/test_filelist -v
    build/test_database -v                  # also prints each injected fault

The unit tests use GNU ld `--wrap` (binutils is part of base LFS) to inject
allocation failures and, for the database, system-call failures.

## Usage

    lpm [--root DIR] <command> [arguments]

`--root DIR` makes LPM treat `DIR` as `/`; the database then lives at
`DIR/var/lib/lpm`. Use it for all testing so the real system is untouched.

    lpm --root ./demo-root list
    lpm --root ./demo-root info hello
    lpm --root ./demo-root check

## Layout

    include/            one public header per module
      lpm.h             shared constants, status codes, config
      util.h            diagnostics, safe paths, package-name rule
      metadata.h        metadata parser + writer, lpm_package, limits  (M2, M3)
      version.h         version ordering, constraint evaluation         (M3)
      filelist.h        file-ownership records                          (M3)
      database.h        installed-package database                      (M1-M3)
      commands.h        command table
    src/                implementation of each header + main.c
    tools/
      lpm-db-demo.c     demonstration driver for the database API       (M3)
    tests/
      run_tests.sh      CLI tests (Milestones 1-3)
      test_framework.h  tiny shared test framework                      (M3)
      test_metadata.c   metadata parser unit tests                      (M2)
      test_version.c    version comparison unit tests                   (M3)
      test_filelist.c   file-list unit tests                            (M3)
      test_database.c   database unit tests with fault injection        (M3)
      fixtures/         example valid/invalid metadata files            (M2)
    examples/           demonstration packages (later milestones)

Module dependencies point one way only:

    main.c ─► commands.c ─► database.c ─┬─► filelist.c ─┐
                                        ├─► version.c ──┼─► metadata.c ─► util.c
                                        └───────────────┘

`metadata.c` knows nothing about the database or the CLI, and `version.c`
touches no files. Each unit-test binary links only the modules it tests
(`test_version` = version + metadata + util), which shows those boundaries
are real.

---

## Package metadata (Milestone 2)

### Fields

| Field             | Required                         | Repeatable | Value |
|-------------------|----------------------------------|------------|-------|
| `name`            | yes                              | no         | package name (rules below) |
| `version`         | yes                              | no         | numeric dotted version |
| `description`     | no                               | no         | printable ASCII, may be empty |
| `depends`         | no                               | yes        | `NAME>=VERSION` or `NAME=VERSION` |
| `manifest_sha256` | yes for `.pkg` files, no for installed records | no | 64 lowercase hex digits |

Two validation profiles share one parser:

* `LPM_META_INSTALLED`: `name` and `version` are required. Used for
  database records.
* `LPM_META_DISTRIBUTABLE`: `manifest_sha256` is required as well. Used for
  package files.

### Grammar

    file      = { line } ;
    line      = ( blank | comment | field ) ( LF | CRLF | end-of-file ) ;
    blank     = { SP | TAB } ;
    comment   = { SP | TAB } "#" { any-printable } ;
    field     = { SP | TAB } key { SP | TAB } "=" { SP | TAB } value { SP | TAB } ;
    key       = letter-digit-underscore { letter-digit-underscore } ;
    value     = everything after the FIRST "=", trimmed ;

Rules:

* The only bytes allowed are printable ASCII (0x20–0x7E) and TAB. A NUL byte,
  any other control character (including a CR that is not part of CRLF), or
  any byte ≥ 0x80 is rejected. That means no UTF-8, and no byte-order mark.
* Lines end with LF or CRLF, and the two may be mixed. The last line does not
  need a newline.
* Whitespace (spaces and tabs) around the key, around `=` and at the ends of
  the value is ignored. Spaces *inside* a description are kept. Whitespace
  inside a name, version or dependency is an error.
* Keys are case-sensitive: `Name=` is an unsupported field. Unknown fields are
  rejected, not ignored.
* `#` starts a comment only as the first non-blank character of a line. A
  `#` later in a line is part of the value.
* Scalar fields may appear once. Repeating one, even with the same value, is
  an error.
* The parser stops at the first error. It never repairs, guesses or skips
  past bad input.

### Names

The rule is `lpm_is_valid_package_name()` from Milestone 1, and it is applied
everywhere: `name=`, dependency names and database filenames. A name is 1–64
characters from `a-z 0-9 + . _ -`, and the first character must be a letter
or digit. This rejects names like `../hello`, `/hello`, `hello/world`, `Hello`
and `-rf`, so a name can never escape a directory when it is used to build a
path.

### Versions

    version = number { "." number } ;      1..64 characters
    number  = "0" | nonzero-digit { digit } ;

* **Valid:** `1`, `1.0`, `1.2.3`, `16.2.0`, `0.0.1`
* **Invalid:** `1..2`, `.1`, `1.`, `1.2beta`, `v1.0`, `1.0-rc1`, `01`, `1.02`

Policy for the comparison module in a later milestone:

* Components are compared **numerically**, never as text and never as a
  floating-point number. Without that rule, `1.10` would come before `1.9`.
* **Leading zeros are forbidden**, so every number has only one spelling.
  This also allows comparing components of any length without integer
  overflow: a longer component is larger, and two components of equal length
  compare like strings.
* **Missing trailing components count as 0**, so `1` = `1.0` = `1.0.0`.

### Dependencies

    depends=openssl>=3.0     →  { name "openssl", op LPM_DEP_MINIMUM, version "3.0" }
    depends=zlib=1.3         →  { name "zlib",    op LPM_DEP_EXACT,   version "1.3" }

* Write one dependency per line. Order is preserved.
* The operator is the whole run of characters from `< > = ! ~ ^` after the
  name, and it must be exactly `>=` or `=`. So `<`, `>`, `<=`, `==`, `!=`,
  `~=` and `^` are reported as unsupported operators. They are never misread
  as a different name/operator split.
* A version constraint is required. Use `NAME>=0` for "any version".
* A package may not depend on the same package twice, even with a different
  constraint. It also may not depend on itself.

### Examples

Valid:

```ini
# hello 1.2.0
name=hello
version=1.2.0
description=A simple hello world program
depends=libfoo>=1.0
depends=libbar=2.1
manifest_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Invalid, with the parser's diagnostics:

```text
depends=libfoo>=         metadata.txt:4: invalid dependency 'libfoo>=': missing version
depends=libfoo<2         ...: invalid dependency 'libfoo<2': unsupported operator '<' (only '>=' and '=' are supported)
name=../etc              ...: invalid package name '../etc': use a-z 0-9 + . _ - and start with a letter or digit
version=1.0-rc1          ...: invalid version '1.0-rc1': expected numbers separated by dots, e.g. 1.2.3, without leading zeros
name=a  (twice)          ...: duplicate field 'name' (it may appear only once)
license=MIT              ...: unsupported field 'license' (field names are case-sensitive)
```

More are in [tests/fixtures/](tests/fixtures/). Run
`build/test_metadata -v tests/fixtures` to see every diagnostic.

### Resource limits

Each limit is checked **before** the work it protects, so hostile input can
never make the parser allocate or scan without bound.

| Resource              | Limit        | Enforced |
|-----------------------|--------------|----------|
| metadata file         | 64 KiB       | `fstat` size before reading; at most limit + 1 bytes are ever read |
| one line              | 4096 bytes   | before the line is copied (LF/CRLF not counted) |
| name / dependency name | 64 chars    | before allocation |
| version               | 64 chars     | before allocation |
| description           | 1024 chars   | before allocation |
| dependencies          | 128          | before the array grows |
| SHA-256 digest        | exactly 64 hex | before it is stored |

The constants are in [include/metadata.h](include/metadata.h). The name limit
is `LPM_MAX_NAME_LEN` in `lpm.h`, shared with Milestone 1. The worst-case
memory for one parse is about 64 KiB of input, plus one 4 KiB line buffer,
plus 128 dependencies.

### Errors

Parser functions return an `lpm_status` and never print or call `exit()`:

* `LPM_OK`
* `LPM_ERR_INVALID`: bad metadata
* `LPM_ERR_NOMEM`
* `LPM_ERR_IO`
* `LPM_ERR_NOT_FOUND`: no such file

The details go into an `lpm_meta_error`:

* an exact `code`, for example `LPM_META_ERR_DUPLICATE_DEPEND`
* the `line` (0 means the whole file)
* the `field`
* a human-readable `message`

The *caller* decides how to report the error, so each problem is printed
exactly once. `lpm info` prints it as an error. `lpm list` prints it as a
warning and keeps going. Process exit codes are unchanged: 0 for success, 2
for a usage error, 1 for anything else.

### Memory ownership

* An `lpm_package` owns its `name`, `version`, `description`, its
  `dependencies` array, and every string inside that array.
* One `lpm_package_free(&pkg)` releases everything and resets the object to
  empty. It is safe on `NULL`, on a zeroed object, on a partly built object,
  and when called twice.
* Parsing is all-or-nothing:
  * The package is built in a private temporary.
  * The temporary is copied to the caller's object only after every check
    passes.
  * On failure, the caller's object is left empty and there is nothing to
    free.
* **Precondition:** the output object must not already own memory. It is
  overwritten, not freed, so free an old package first.

```c
#include "metadata.h"

lpm_package pkg;
lpm_meta_error err;

if (lpm_metadata_parse_file("hello.meta", LPM_META_INSTALLED, &pkg, &err) != LPM_OK) {
    char msg[512];
    lpm_meta_error_format(&err, "hello.meta", msg, sizeof(msg));
    lpm_error("%s", msg);              /* e.g. "hello.meta:3: duplicate field 'name' ..." */
    return;                            /* pkg is empty: nothing to free */
}
for (size_t i = 0; i < pkg.dependency_count; i++)
    printf("%s %s %s\n", pkg.dependencies[i].name,
           lpm_dep_operator_str(pkg.dependencies[i].op), pkg.dependencies[i].version);
lpm_package_free(&pkg);
```

### Files and symlinks

`lpm_metadata_read_file()`:

* opens with `O_NOFOLLOW`, so it never reads through a symlink;
* opens with `O_NONBLOCK`, so a FIFO cannot hang it;
* calls `fstat` on the *open descriptor*, so the file checked is the file
  read, with no check-then-open race;
* accepts only regular files, rejecting directories, devices and FIFOs;
* never writes to or modifies any file.

### Compatibility with Milestone 1

* The temporary `read_version_field()` is gone. `database.c` now calls
  `lpm_db_load_package()`, which runs the strict parser with the INSTALLED
  profile. It also checks that the record's `name=` matches its filename.
* **Damaged records:** Milestone 1 data includes records with no `version=`
  line. A damaged record is still listed by `lpm list`, because its files may
  be installed, but with version `?` and a warning saying exactly what is
  wrong. No version is invented, and the strict parser is not weakened to
  accept these records. `lpm info` treats the same record as an error.
* Everything else in `list` is unchanged: sorting, missing-database handling,
  invalid-filename warnings, skipping symlinks, and `--root`.
* All 20 Milestone 1 CLI tests run unchanged.

### SHA-256 and Ed25519 (later milestones)

Planned package layout: `metadata.txt`, `manifest.txt`, `payload/`, and
`signature.sig`.

The chain of trust has four steps:

1. Ed25519 signs the **exact raw bytes** of `metadata.txt`.
2. `metadata.txt` declares `manifest_sha256`, the SHA-256 of `manifest.txt`.
3. `manifest.txt` declares the SHA-256 of every payload file.
4. Each payload file is checked against its hash.

The parser is ready for this:

* `lpm_metadata_read_file()` returns the raw bytes unchanged, CRs and
  comments included.
* The verifier will check the signature on that buffer and then pass the
  **same buffer** to `lpm_metadata_parse_buffer()`. The file is never re-read
  in between, and nothing is ever re-serialised.
* Parsed metadata counts as untrusted until that verification succeeds.
* The digest has a single spelling, 64 lowercase hex characters, so it can be
  compared directly with what the hashing code produces.
* Trusted public keys will come from the local system (`/etc/lpm/keys/`), not
  from the package.

Signatures provide authenticity and integrity, not confidentiality. Packages
are not encrypted.

### Design decisions (summary)

* **One strict parser with profiles, not two parsers.** The rules are written
  once, so database records and package files cannot drift apart.
* **Reject, never repair.** If the parser fixed bad input, the meaning of a
  signed file would depend on parser quirks. Rejection is predictable and
  easy to test.
* **Limits checked while parsing, not afterwards.** Memory use has a fixed
  upper bound, whatever the input.
* **Structured errors instead of printing.** Callers choose the severity, and
  tests check exact codes and line numbers rather than message text.
* **ASCII only.** It removes UTF-8 validation, terminal escape injection and
  look-alike characters entirely, at the cost of non-English descriptions.

### Known limitations

* Descriptions must be ASCII.
* Only `=` and `>=` constraints are supported. There are no ranges, `<`, or
  pre-release versions such as `1.0-rc1`.
* Versions with leading zeros (`2024.01`) are rejected by design.
* Upgrades are not handled yet (later milestones).

---

## Version comparison and package database (Milestone 3)

### What changed

| File | Change |
|------|--------|
| `include/version.h`, `src/version.c` | **new**: `lpm_version_compare()`, `lpm_version_satisfies()` |
| `include/filelist.h`, `src/filelist.c` | **new**: file-ownership records (validate, parse, write, conflicts) |
| `src/metadata.c` | **added** `lpm_metadata_serialize()`, `lpm_package_equal()`, a directory-relative bounded reader; `lpm_metadata_read_file()` keeps its behaviour |
| `src/database.c` | **added** `lpm_db_open/close`, `register`, `unregister`, `exists`, `read_file_list`, `check`; `list` and `info` are unchanged |
| `src/commands.c` | `lpm check` implemented |
| `include/lpm.h` | status codes `LPM_ERR_EXISTS`, `LPM_ERR_BUSY`, `LPM_ERR_CONFLICT` (appended) |
| `tools/lpm-db-demo.c` | **new**: demonstration driver (not installed) |
| `tests/` | `test_version.c`, `test_filelist.c`, `test_database.c`, 41 new CLI checks |

### Version comparison

Versions are the strings the Milestone 2 validator accepts: numbers separated
by dots, no leading zeros (`1`, `1.10`, `16.2.0`). There is only one validator;
`version.c` calls `lpm_is_valid_version()`.

Rules:

1. Compare components left to right, as numbers: `1.9 < 1.10`.
2. A missing trailing component counts as `0`: `1 == 1.0 == 1.0.0`, but
   `1 < 1.0.1`.

How it avoids overflow: components are **never converted to integers**.
Because leading zeros are forbidden, a component with more digits is always
larger, and two components with the same number of digits compare like their
characters. So `18446744073709551616` (one more than `UINT64_MAX`) is handled
the same way as `7`. Cost: O(length), no allocation.

What is deliberately *not* used:

* `strcmp("1.9", "1.10")` says `1.9` is newer, because `'9' > '1'`.
* Floating point says `1.10 == 1.1` and loses digits.

```c
int r;
if (lpm_version_compare("1.9", "1.10", &r) == LPM_OK)   /* r == -1 */
    ...
```

An invalid version returns `LPM_ERR_INVALID` and **leaves `*result
untouched**, so a caller can never mistake an error for an ordering.

### Dependency constraints

`lpm_version_satisfies(installed, &dependency, &ok)` evaluates one parsed
`depends=` entry:

| Constraint | Satisfied when | Examples |
|------------|----------------|----------|
| `NAME=V`   | installed == V (numerically) | `2.0` and `2.0.0` satisfy `=2.0`; `2.1` does not |
| `NAME>=V`  | installed >= V | `2.1` satisfies `>=2.0`; `1.9` does not |

It compares versions only: it does not look up `NAME` or read the database.
The dependency solver in Milestone 4 does that.

### Database layout

    <root>/var/lib/lpm/
        installed/<name>.meta    package record (metadata, INSTALLED profile)
        files/<name>.list        paths the package owns
        lock                     flock() target, mode 0644, empty

Records are written in exactly the Milestone 2 format, so `lpm list` and
`lpm info` read them with the same strict parser.

### Operations

| Function | Needs | Does |
|----------|-------|------|
| `lpm_db_open(cfg, mode, wait_ms, &db, &err)` | — | opens every directory safely and takes the lock (READ: shared; WRITE/CREATE: exclusive) |
| `lpm_db_register_package(&db, &pkg, &files, &err)` | WRITE | validates, then writes `.list` and `.meta` atomically |
| `lpm_db_unregister_package(&db, name, &err)` | WRITE | removes `.meta`, then `.list` |
| `lpm_db_package_exists(&db, name, &yes, &err)` | any | is `<name>.meta` present? |
| `lpm_db_read_file_list(&db, name, &list, &err)` | any | reads and validates `<name>.list` |
| `lpm_db_check(&db, report_fn, ctx, &summary, &err)` | any | reports problems, changes nothing |
| `lpm_db_close(&db)` | — | releases the lock |

**Registration is bookkeeping, not installation.** It writes two small text
files and touches no package files. **Unregistration deletes database records
only**; the package's files stay where they are (a test checks this).

**Registration does not mean "verified".** A record says nothing about
signatures or checksums. The installer in a later milestone must verify the
package's Ed25519 signature and SHA-256 manifest itself, before it installs
anything, and must never treat "already registered" as a reason to skip that.

Registration fails, leaving the database unchanged, if:

* the package is already registered (`LPM_ERR_EXISTS`);
* any listed path is already owned by another registered package, or is a
  parent directory of one, or lies inside a file another package owns
  (`LPM_ERR_CONFLICT`);
* the package or file list is invalid (`LPM_ERR_INVALID`);
* another package's file list cannot be read or is damaged. Without every
  list, conflicts cannot be ruled out, so the database fails closed.

### Writing records safely (serialisation)

`lpm_metadata_serialize()` lives in `metadata.c`, next to the parser, so the
format is defined in a single module. It:

* validates every field with the parser's own rules;
* **rejects** what cannot be stored exactly, and never truncates, trims or
  escapes. A description containing a newline would inject a new field
  (`description=x` + newline + `manifest_sha256=...`), so it is refused;
  leading or trailing blanks would be trimmed when read back, so they are
  refused too;
* writes fields in a fixed order (`name`, `version`, `description`,
  `depends` in their given order, `manifest_sha256`), so the same package
  always produces the same bytes;
* finally **parses its own output again and compares** it with the input. If
  the two ever differed, nothing would be written.

Serialisation is used for database records only. A distributable package's
signed `metadata.txt` must never be replaced by a re-serialised copy: the
signature covers the original bytes.

### Atomic writes

Each file is replaced in seven steps:

1. Create `.lpm-tmp.<name>.<pid>.<n>` in the **same directory**
   (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600).
2. Write everything, retrying short writes and `EINTR`.
3. `fchmod` it to 0644, so `lpm list` works for any user.
4. `fsync` the file: its contents are on disk.
5. `close`, checking the result.
6. `renameat` it over the final name. Within one directory this is atomic:
   readers see the whole old file or the whole new one.
7. `fsync` the directory: the rename itself is on disk.

If anything fails before step 6, the temporary file is deleted and the old
file is untouched. Temporary names start with `.`, so `lpm list` ignores
them, and `lpm check` reports any left behind by a crash.

### Two files, one registration: the consistency strategy

A rename is atomic for **one** file. Registration changes two files, so it
cannot be one atomic step, and this design does not pretend it is. Instead,
one file is the **commit record**:

* **Register:** write `files/<name>.list` (steps 1-7), then
  `installed/<name>.meta` (steps 1-7). The package is registered **if and only
  if** its `.meta` exists, so the `.meta` rename is the commit point. If the
  `.meta` step fails, the `.list` is removed again.
* **Unregister:** delete the `.meta` first (the commit point), then the
  `.list`.

So after a crash at any moment the database is in one of three states:

| State | Meaning | What happens |
|-------|---------|--------------|
| old | nothing happened | — |
| new | the operation completed | — |
| `.list` without `.meta` | crash between the two steps | the orphaned list **owns nothing**: only lists with a `.meta` count. `lpm check` reports it, and the next registration of that name replaces it |

A `.meta` without its `.list` can never come from a crash, because the
`.list` is always written first and deleted last.

**Guarantees, and their limits**

* *Process crash* (kill -9, segfault, OOM): verified by a test that kills the
  registering process at every one of its system calls, then checks the three
  states above, that `lpm check` names every leftover, that the lock was
  released, and that registering again works.
* *Power loss*: the `fsync` calls are what make the steps above durable. That
  relies on the filesystem honouring `fsync` (ext4 does). It **was not tested**
  by cutting power, and the tests cannot detect a missing `fsync`.
* If the final directory `fsync` fails, the record is in place but may not
  survive a power cut. The call then returns `LPM_ERR_IO` with "not flushed"
  in the message instead of claiming success.
* This is not a general transaction system: there is no journal and no
  automatic rollback after a reboot. Recovery means reporting the leftover,
  which is the conservative choice for a capstone. Automatic cleanup could be
  added later, but it deletes things.

### Locking

Writers take an exclusive `flock()` on `var/lib/lpm/lock` and hold it from
`lpm_db_open()` to `lpm_db_close()`. That covers the whole logical operation:
the duplicate check, the ownership check and both writes.

* **Why `flock`, not a lock file that is created and deleted:** the kernel
  releases a `flock` when its holder exits or crashes, so a stale lock can
  never block the database. There is also no check-then-create race. A test
  kills a lock holder with SIGKILL and then takes the lock.
* **No hang and no deadlock:** LPM takes only one lock, and waits for it in
  50 ms steps for at most `wait_ms` (0 = fail at once, `lpm check` waits 5 s).
  After that the call returns `LPM_ERR_BUSY` ("locked by another LPM
  process"). An error from `flock` itself is reported and nothing proceeds
  unlocked.
* **Readers** (`lpm check`) take a shared lock, so they never see a half-done
  operation. `lpm list` and `lpm info` read single files, which are always
  complete thanks to the atomic rename, so they take no lock (unchanged from
  Milestone 2).
* **Limit:** the lock only coordinates LPM processes. A program that ignores
  it can still change the files.

### Filesystem protections

| Threat | Protection |
|--------|------------|
| `../` or `/` in a package name | the name validator runs before any filename is built |
| symlink anywhere in `var/lib/lpm/...` | the root is opened once; every directory below it is opened relative to its parent with `O_NOFOLLOW` + `O_DIRECTORY`; files use `openat`/`renameat`/`unlinkat`/`fstatat` on those descriptors. A symlink makes the open fail, and swapping one in later does not redirect anything |
| symlinked or odd record, list or lock file | `O_NOFOLLOW`, `fstat` on the open descriptor, regular files only |
| directory writable by others | every database directory and the lock file must belong to the current user or root, and must not be group/other-writable |
| existing record replaced by accident | duplicate check under the lock |
| temporary file hijacked | `O_CREAT` + `O_EXCL` + `O_NOFOLLOW`, mode 0600 |
| writing outside the root | no absolute paths are built for writes |

`--root` is a redirection, **not a sandbox**. The root directory itself may be
reached through symlinks, because the user chose it. Everything below it is
checked.

Root-owned demo trees: when root runs LPM on a tree owned by another user,
the ownership rule refuses it. That is deliberate: it is the classic way an
unprivileged user tricks a root process into writing where they choose.

### File ownership records

`files/<name>.list` holds one path per line, sorted:

    /usr/bin/hello
    /usr/share/doc/hello/README

The rules:

* A path names an object **inside the target root** and is written with a
  leading `/`. `--root` is never stored.
* No empty, `.` or `..` components, no `//`, no trailing `/`.
* Printable ASCII. No component may begin or end with a space.
* Entries are **files and symlinks, never directories**. Directories are
  shared between packages. So a path that is also the parent of another path
  is a conflict, inside one list and across packages.
* Sorted and without duplicates, so the same file set always gives the same
  bytes. Every line ends with LF, so a truncated last line is detected.
* A list is a *claim*. It does not prove the files exist, and Milestone 3
  never looks at or deletes them.

How conflicts are found: all paths are sorted, so a duplicate sits next to its
twin. Each parent prefix (`/usr`, `/usr/share`, ...) of each path is then
looked up by binary search. That takes O(n · depth · log n) time.

### `lpm check`

Read-only: it reports and never repairs or deletes, so suspicious entries can
be inspected.

| Implemented check | Reported as |
|-------------------|-------------|
| `.meta` fails strict parsing, or `name=` does not match the filename | damaged record |
| symlink, directory, or unknown file in `installed/` or `files/` | unexpected entry |
| `.lpm-tmp.*` left by an interrupted write | abandoned temporary file |
| registered package without a `.list` (e.g. pre-Milestone-3 records) | missing file list |
| `.list` fails validation | damaged file list |
| `.list` without a `.meta` | orphaned file list |
| one path claimed twice, or a file versus a parent directory, across packages | file ownership conflict |
| dependency not registered, damaged, or wrong version | unsatisfied dependency |

**Not checked yet** (and `lpm check` says so): whether owned files exist on
disk or match their checksums, and signatures. Those arrive with the
installer milestones. It prints "No problems found by the implemented
checks", never "the system is consistent". The exit status is 1 when
problems are found.

### Resource limits

| Limit | Value | Why |
|-------|-------|-----|
| path length | 1024 bytes | far above real FHS paths; bounds each line |
| path component | 255 bytes | `NAME_MAX` on Linux |
| files per package | 65,536 | bounds memory and conflict checking |
| `.list` file size | 8 MiB | checked with `fstat` before reading |
| metadata record | 64 KiB, other Milestone 2 limits | unchanged |
| lock wait | caller's `wait_ms` | no unbounded hang |

Each limit is enforced before the work it protects, and the writer refuses
output the reader would reject (for example 65,536 long paths larger than
8 MiB). Array growth is checked for overflow.

### Testing (Milestone 3)

| Suite | Tests | What it covers |
|-------|-------|----------------|
| `test_version` | 17 | all specification examples; >64-bit components; 64-character versions; invalid, NULL and empty input; `=`/`>=`; 20,000 comparisons against an independent integer reference model; total-order properties (reflexive, antisymmetric, transitive) |
| `test_filelist` | 19 | valid and invalid paths; limits ±1 (path, component, count, size); duplicates; file-versus-parent conflicts; round trip; allocation failures; 20,000 mutated inputs |
| `test_database` | 40 | see below |
| `run_tests.sh` | 41 new checks | demo tool + `lpm list/info/check` end to end |

`test_database` checks:

* **Normal operations:** init, register, load, exists, duplicates, unregister
  (payload files kept), sorted listing, isolated roots, upgrading a
  Milestone 1 database.
* **Attacks:** invalid names, field injection, path traversal, symlinked
  directories (each of five levels), symlinked records, list and lock file,
  group-writable and foreign-owned directories (the latter only as root),
  unreadable directories (skipped as root).
* **Every single failure:** for each system call and allocation that a
  registration or removal makes, the test fails exactly that one (`ENOSPC`,
  `EIO`, `EMFILE`, ...). Afterwards it checks the files on disk: the package
  is fully absent or fully registered, no temporary file remains, and
  `lpm check` is clean.
* **Short writes and EINTR:** every write moves 1-3 bytes and every other
  call is interrupted; the result is still byte-exact.
* **Crashes:** the child process is killed at its 1st, 2nd, ... system call,
  and the parent checks the result as described above.
* **Locking:** exclusion within and between processes; bounded waiting; lock
  released by a killed holder; `flock` failure; 8 processes racing (distinct
  names all succeed; the same name gives exactly one winner; the same file
  gives exactly one owner).
* **check:** a clean database, and a database seeded with all eight problem
  kinds; each must be reported exactly once, and nothing may change.
* **Limits:** a 65,536-file list; lists over 8 MiB; records over 64 KiB;
  binary garbage.

Mutation check: each of these deliberate bugs was caught by at least one test:
* lexicographic digit comparison;
* no duplicate check;
* following symlinks;
* no rollback of the file list;
* writing the commit record first;
* no ownership check.

### Demonstration (safe, disposable root)

`build/lpm-db-demo` drives the public database API. It requires `--root`,
refuses `/` however it is spelled, and is never installed.

```sh
make && make demo
R=$(mktemp -d)                                  # disposable root
cat > /tmp/hello.meta <<'X'
name=hello
version=1.2.0
description=A simple hello world program
depends=libfoo>=1.0
X
printf 'name=libfoo\nversion=1.10\n'         > /tmp/libfoo.meta
printf '/usr/bin/hello\n/usr/share/doc/hello/README\n' > /tmp/hello.list
printf '/usr/lib/libfoo.so.1\n'              > /tmp/libfoo.list

build/lpm-db-demo --root "$R" init                                   # 1 create database
build/lpm-db-demo --root "$R" register /tmp/libfoo.meta /tmp/libfoo.list
build/lpm-db-demo --root "$R" register /tmp/hello.meta /tmp/hello.list  # 2 register
./lpm --root "$R" list                                               # 3 listed
./lpm --root "$R" info hello                                         # 4 details
build/lpm-db-demo --root "$R" register /tmp/hello.meta /tmp/hello.list  # 5 duplicate: refused
printf 'name=bad\nversion=01\n' > /tmp/bad.meta
build/lpm-db-demo --root "$R" register /tmp/bad.meta                 # 6 invalid: refused
./lpm --root "$R" check                                              # 10 still consistent
build/lpm-db-demo --root "$R" unregister hello                       # 7 remove record
./lpm --root "$R" list                                               # 8 gone
build/lpm-db-demo compare 1.9 1.10                                   # 9 1.9 < 1.10
build/lpm-db-demo compare 1.0 1                                      #   1.0 == 1
build/lpm-db-demo satisfies 2.1 '>=' 2.0                             #   satisfied
build/lpm-db-demo --root "$R" hold-lock 30 &                         # locking:
sleep 1
build/lpm-db-demo --root "$R" register /tmp/hello.meta /tmp/hello.list  #   refused: locked
kill %1
printf '/usr/bin/ghost\n' > "$R/var/lib/lpm/files/ghost.list"       # simulate a crash
./lpm --root "$R" check                                              #   reported, not deleted
rm -rf "$R"
```

### Known limitations (Milestone 3)

* Process-crash consistency is tested; power-loss durability relies on
  `fsync` and was not tested by cutting power.
* The lock coordinates LPM processes only.
* Leftovers after a crash are reported, not cleaned up automatically.
* File-list paths must be ASCII.
* A registration rewrites no existing record: upgrades (replacing a
  registered version) come with the installer.
* `lpm check` does not yet look at the files on disk.
* Tested on Ubuntu 20.04 (WSL 2, GCC 9.4, ext4), not yet on the LFS machine
  (GCC 16.2).

### How this prepares Milestone 4

* **Graph nodes:** each registered package is an `lpm_package` read by the
  strict parser. Its `dependencies` array gives the outgoing edges.
* **Edge check:** `lpm_version_satisfies()` decides whether an installed
  package satisfies an edge's constraint; `lpm check` already uses it in
  exactly this way.
* **Graph reads:** `lpm_db_open(READ)` takes a shared lock, so the solver can
  read a consistent snapshot of the installed set.
* **Conflict checks:** file lists and `lpm_owned_paths_conflicts()` are ready
  for the installer to reject a package before extraction.
