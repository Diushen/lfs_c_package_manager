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
| 4         | Package archives (libarchive), SHA-256 integrity (OpenSSL), `verify`, `install` | done |
| 5         | Dependency graph: version constraints, cycle detection, topological order, `plan`, multi-package `install` | done |
| 6         | Ed25519 signatures, trusted-key store (`key`), authenticated `verify` and `install` | done |
| later     | `remove`, upgrades, installing into the real `/` | planned |

`lpm install` now requires **integrity** (SHA-256) **and authenticity** (an
Ed25519 signature by a key in the root's trust store), for every package it
installs. It still refuses the real `/`: that final step is left for LFS
integration. `lpm remove` is not implemented yet.

## Build and test

    make              # release build of lpm (-O2)
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
    build/test_integrity -v / test_archive -v / test_install -v   (Milestone 4)

Requirements: GCC (C11), GNU make, binutils, **OpenSSL** (libcrypto, part of
base LFS) and **libarchive** built with zlib and liblzma (BLFS; zlib and xz
are in base LFS). `pkg-config`/`pkgconf` is used when present; otherwise
`-larchive -lcrypto`. The CLI tests also use GNU tar and `sha256sum`.

The unit tests use GNU ld `--wrap` (binutils is part of base LFS) to inject
allocation failures and, for the database, system-call failures.

## Usage

    lpm [--root DIR] <command> [arguments]

`--root DIR` makes LPM treat `DIR` as `/`; the database then lives at
`DIR/var/lib/lpm`. Use it for all testing so the real system is untouched.

    lpm --root ./demo-root list
    lpm --root ./demo-root info hello
    lpm --root ./demo-root check
    lpm verify hello.lpm [--sha256 HEX]
    lpm --root ./demo-root install hello.lpm [--sha256 HEX] [--package-dir DIR]
    lpm --root ./demo-root plan app.lpm [--package-dir DIR]
    lpm --root ./demo-root key add publisher.pub | key list | key remove KEY_ID
    build/lpm-sign private.pem unsigned.lpm signed.lpm

## Layout

    include/            one public header per module
      lpm.h             shared constants, status codes, config
      util.h            diagnostics, safe paths, package-name rule
      metadata.h        metadata parser + writer, lpm_package, limits  (M2, M3)
      version.h         version ordering, constraint evaluation         (M3)
      filelist.h        file-ownership records                          (M3)
      database.h        installed-package database                      (M1-M3)
      integrity.h       SHA-256 via OpenSSL EVP                         (M4)
      lpm_archive.h     the only libarchive user; safe extraction       (M4)
      safefs.h          symlink-refusing, root-relative file creation   (M4)
      manifest.h        manifest.txt parser                             (M4)
      pkg.h             reading + verifying a .lpm package              (M4)
      install.h         verify / install pipeline (multi-package in M5)  (M4, M5)
      solver.h          dependency graph, cycles, topological order     (M5)
      plan.h            gathers candidates + installed set for solver   (M5)
      signature.h       Ed25519 keys, signatures, signature record      (M6)
      trust.h           trusted-key store, authentication decision      (M6)
      commands.h        command table
    src/                implementation of each header + main.c
    tools/
      lpm-db-demo.c     demonstration driver for the database API       (M3)
      lpm-mkpkg.sh      builds .lpm packages (bash, coreutils, GNU tar)  (M4)
      lpm-sign.c        signs a .lpm with an Ed25519 private key         (M6)
    tests/
      run_tests.sh      CLI tests (Milestones 1-5)
      test_framework.h  tiny shared test framework                      (M3)
      test_metadata.c   metadata parser unit tests                      (M2)
      test_version.c    version comparison unit tests                   (M3)
      test_filelist.c   file-list unit tests                            (M3)
      test_database.c   database unit tests with fault injection        (M3)
      test_integrity.c  SHA-256 known-answer and error tests            (M4)
      test_archive.c    safe extraction and attack tests                (M4)
      test_install.c    end-to-end install, tampering, faults, crashes  (M4)
      test_solver.c     solver algorithms on in-memory packages         (M5)
      test_deps.c       planning + multi-package install, end to end    (M5)
      test_signature.c  Ed25519, RFC 8032 vectors, signature record     (M6)
      test_auth.c       trust store, authentication, signed installs    (M6)
      test_signing.h    ephemeral test keys (no key is ever committed)  (M6)
      fixtures/         example valid/invalid metadata files            (M2)
    examples/           demonstration packages (later milestones)

Module dependencies point one way only:

    main.c ─► commands.c ─► install.c ─► plan.c ─► solver.c ─► version.c
                     │                 │
                     │                 ├─► pkg.c ─┬─► manifest.c
                     │                 │        ├─► archive.c ──► libarchive
                     │                 │        └─► integrity.c ─► OpenSSL
                     │                 └─► safefs.c
                     └─────────────► database.c ─┬─► filelist.c ─┐
                                                 ├─► version.c ──┼─► metadata.c ─► util.c
                                                 └───────────────┘

`metadata.c` knows nothing about the database or the CLI, and `version.c`
touches no files. Only `archive.c` includes libarchive and only
`integrity.c` includes OpenSSL, so either library could be replaced by
changing one file. Each unit-test binary links only the modules it tests
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

---

## Archives, SHA-256 and installation (Milestone 4)

### Package format (`.lpm`)

A `.lpm` file is a tar archive (ustar, pax or GNU), either uncompressed or
compressed with gzip or xz. Its entries come in this order:

| Entry | Content |
|-------|---------|
| `metadata.txt` | Milestone 2 format, DISTRIBUTABLE profile (needs `manifest_sha256`) |
| `manifest.txt` | one line per payload object: `file <sha256> <mode> <path>`, `symlink <target> <path>`, `dir <mode> <path>` |
| `payload/...`  | the files, e.g. `payload/usr/bin/hello` becomes `<root>/usr/bin/hello` |

Build one with `tools/lpm-mkpkg.sh SRCDIR OUT.lpm [none|gz|xz]`. `SRCDIR`
holds `metadata.in` (no `manifest_sha256`) and `payload/`.

### Libraries

* **libarchive** reads the archive. It detects the compression
  automatically, but only the tar format and the gzip and xz filters are
  enabled. If libarchive would fall back to running an external program
  (`xz -d`), LPM refuses instead.
  * Only `src/archive.c` includes libarchive.
  * libarchive never writes anything: LPM creates every file itself.
  * It is a BLFS package, so build it on LFS before `make`.
* **OpenSSL libcrypto** computes SHA-256 through the EVP interface, which is
  not deprecated in either OpenSSL 1.1 or 3.x.
  * It is part of base LFS, and the later Ed25519 milestone will use the
    same library.
  * libsodium was not chosen because it would be a second crypto
    dependency.
  * LPM does not implement SHA-256 itself.

### SHA-256 verification

The chain is checked in this order, and nothing reaches the root unless
every step holds:

1. **Optional `--sha256 HEX`:** the digest of the whole package file, for
   example one published next to a download. It is checked on the same open
   descriptor that libarchive reads next, so the file cannot be swapped in
   between. A digest you type may be upper or lower case.
2. **`metadata.txt`** is parsed strictly. Its raw bytes are kept for the
   future signature check.
3. **`SHA-256(manifest.txt)`** must equal `manifest_sha256`, and it is
   checked before the manifest is parsed.
4. **Each payload file** is streamed through SHA-256 in 64 KiB chunks, so
   memory use is constant, and must match its manifest line.

Rules for the comparison:
* Digests are compared in constant time.
* Inside packages there is exactly one spelling, 64 lowercase hex digits,
  as in Milestone 2.

Each error is distinct:

| Error | Status code |
|-------|-------------|
| missing file | `LPM_ERR_NOT_FOUND` |
| unreadable file | `LPM_ERR_IO` |
| hashing failed | `LPM_ERR_CRYPTO` |
| malformed digest | `LPM_ERR_INVALID` |
| digests differ | `LPM_ERR_INTEGRITY`; the message shows both digests and the file |

### Safe extraction rules

They apply to `lpm_archive_extract()` and to installation alike.

**Names are rejected, never repaired, when they are:**
* absolute (`/etc/passwd`);
* contain a `..` component (`../x`, `usr/../../etc/x`);
* empty or `.` components, control characters, non-ASCII, or a leading or
  trailing space in a component.

**Files are never written through a symlink.**
* Every directory is opened from its parent with
  `openat(O_NOFOLLOW | O_DIRECTORY)`.
* A symlink in the archive cannot be used as a directory later, and neither
  can one already planted in the target root.

**Symlink policy.** A link target must be relative and contain no `..`, so a
link can only point at or below its own directory. Absolute targets such as
`/etc` are rejected, and a file, or a symlink, can't be the parent of another
manifest entry.

**Hard links, devices, FIFOs and sockets** are rejected.

**Modes**
* Installation: manifest modes above `0755` (setuid, setgid, sticky, group-
  or world-writable) are rejected.
* Generic extraction: modes are masked to `0755`.
* Ownership is never changed: files belong to whoever runs LPM.

**No overwriting.**
* Installation refuses to replace a file that already exists, whether or not
  LPM owns it (`linkat` fails instead of replacing).
* Extraction uses `O_CREAT | O_EXCL`.

**Limits:** 8 GiB of extracted data and 262,144 entries per archive; the
Milestone 3 path limits still apply.

### `--root` behaviour

* Everything, including the database and the staging area, goes below
  `--root`. The tests check that nothing appears next to the root or on the
  host.
* `lpm install` without `--root`, or with any spelling of `/`, is refused
  until packages are authenticated.

### How `lpm install` works

Every step below happens while holding the database lock:

1. Open the package file, optionally check `--sha256`, then lock and create
   the database.
2. Verify the package as described above. Verified files go into
   `var/lib/lpm/staging/install.<pid>.<n>/`, never into the root directly.
3. Pre-flight checks:
   - the package is not already registered;
   - no file is owned by another package;
   - nothing already exists where a file should go;
   - no path passes through a symlink.
4. Commit: hard-link each staged, verified file into place, then create the
   symlinks and directories.
5. Register the package. The file list is the files and symlinks, and the
   record keeps `manifest_sha256`.
6. Remove the staging directory.

If step 4 or 5 fails, every file and directory created in step 4 is removed
again and the database stays unchanged. Every single injected failure in the
tests ends in either "fully installed" or "untouched".

### Known limitations

* Integrity is not authenticity: anyone can build a package whose hashes
  match. Ed25519 signatures over `metadata.txt` come later, and so does
  installing into `/`.
* **This is not a full transaction.** A crash (power cut or `kill -9`)
  during steps 4–5 can leave files without a record.
  * It is never silent: the staging directory remains, and `lpm check`
    reports "interrupted installation".
  * The crash test found such a state at 70 of 149 crash points, and every
    one was reported.
  * Removing such leftovers, and `lpm remove` itself, come in a later
    milestone.
* Staging and the target must be on the same filesystem, because a hard
  link can't cross filesystems. Otherwise installation fails with a clear
  message and rolls back.
* Files are placed from `/usr`, `/etc` and so on, never through symlinks. On
  LFS, `/bin`, `/lib` and `/sbin` are symlinks into `/usr`, so packages must
  use `/usr/bin` and the like.
* Installing over files that already exist (upgrades) isn't supported.

### Tests

| Program | Tests | Covers |
|---------|-------|--------|
| `build/test_integrity` | 13 | NIST vectors ("abc", empty, 448-bit, one million `a`), a 96 MiB streamed file, mismatch, case normalisation, malformed digests, missing / unreadable / FIFO |
| `build/test_archive` | 23 | normal extraction, gzip/xz, nested and empty directories, corrupt and truncated archives, traversal, absolute paths, four symlink escapes, hard links, devices, overwrite, rollback, descriptor leaks |
| `build/test_install` | 26 | verify, install, `--sha256`, tampered payload / manifest / symlink, structural errors, attacks, conflicts, real-root refusal, a failure injected at every system call and allocation, a crash at every system call, disk full, cross-filesystem |
| `tests/run_tests.sh` | 37 new | the same flows through the real `lpm` binary, with packages built by `lpm-mkpkg.sh` and GNU tar |

**Sanitizer hangs on new kernels with old GCC.** On a kernel with
`vm.mmap_rnd_bits = 32` (e.g. WSL2 6.x), the AddressSanitizer runtime of
older GCC releases (GCC 9 in Ubuntu 20.04) can hang at random, even in
`lpm help`. This is a sanitizer bug, not an LPM bug: Milestone 3's code
hangs the same way.

The workaround turns off address randomisation for the test run only:

    make debug && setarch "$(uname -m)" -R make test

GCC 16 on LFS shouldn't need it.

### Demonstration (never touches the real system)

```sh
make
S=$(mktemp -d); R=$(mktemp -d)
mkdir -p $S/payload/usr/bin $S/payload/etc
printf '#!/bin/sh\necho "Hello from LPM"\n' > $S/payload/usr/bin/hello
chmod 755 $S/payload/usr/bin/hello
echo greeting=hello > $S/payload/etc/hello.conf
printf 'name=hello\nversion=1.0\ndescription=Demo\n' > $S/metadata.in
tools/lpm-mkpkg.sh $S /tmp/hello.lpm xz

./lpm verify /tmp/hello.lpm                       # 1. integrity OK
./lpm --root $R install /tmp/hello.lpm            # 2. installed into $R
find $R/usr $R/etc; $R/usr/bin/hello; ./lpm --root $R list

T=$(mktemp -d); tar -xJf /tmp/hello.lpm -C $T     # 3. change one file
echo 'echo pwned' >> $T/payload/usr/bin/hello
tar -cJf /tmp/bad.lpm -C $T metadata.txt manifest.txt payload
./lpm --root $(mktemp -d) install /tmp/bad.lpm    #    INTEGRITY FAILURE, nothing installed

E=$(mktemp -d); mkdir -p $E/payload/etc; echo pwned > $E/payload/etc/x   # 4. escape attempt
printf 'file %s 0644 /etc/x\n' $(sha256sum $E/payload/etc/x | cut -d' ' -f1) > $E/manifest.txt
printf 'name=evil\nversion=1\nmanifest_sha256=%s\n' $(sha256sum $E/manifest.txt | cut -d' ' -f1) > $E/metadata.txt
tar -cf /tmp/evil.lpm -C $E metadata.txt manifest.txt \
    --transform='s,^payload/etc/x$,payload/../../escape.txt,' payload/etc/x
./lpm --root $R install /tmp/evil.lpm             #    path traversal rejected
ls $R/../escape.txt $R/../../escape.txt           #    neither exists
```

---

## Dependency resolution (Milestone 5)

### Dependencies in metadata

Dependencies use the Milestone 2 `depends=` lines, one per dependency:

| Line | Meaning |
|------|---------|
| `depends=libfoo>=1.2` | at least 1.2 |
| `depends=libbar=2.0` | exactly 2.0 (numerically, so `2.0.0` matches too) |
| `depends=libold<3.0` | below 3.0, strictly (**new in Milestone 5**) |

* Only these three operators exist; `<=`, `>`, `!=`, `~` and the rest are
  rejected.
* Versions are compared with the Milestone 3 rules
  (`lpm_version_satisfies()`).
* Package names are lowercase (`liba`, not `libA`).

### How a plan is made (`lpm plan`, `lpm install`)

The planner never writes anything. It gathers:

* **Installed packages** from the database under `--root`, read under a
  shared lock. They are fixed: LPM doesn't upgrade, so an installed version
  must satisfy every requirement on it.
* **The requested `.lpm` file.**
* **Candidates:** every `*.lpm` in `--package-dir DIR`, in sorted order.
  * Hidden files and other names are ignored.
  * The requested file may sit in the same directory.
  * Two candidates with the same name and version (`1.0` and `1.0.0`
    count as the same) are refused as ambiguous.
  * For planning, only each candidate's `metadata.txt` is read. That isn't
    verification.

**Version selection** is a bounded backtracking search (`src/solver.c`):

1. Names are handled in discovery order: the requested package, then its
   dependencies in declaration order, then theirs.
2. For each name, versions are tried from highest to lowest. A version is
   accepted only if:
   - it satisfies every requirement already placed on that name; and
   - its own requirements hold for every name already chosen.
3. If a name has no acceptable version, the search goes back to the
   previous name and tries its next version.

So the result is **globally consistent**: every requirement in the plan
holds for the single version chosen for each name. The policy is to take the
highest compatible version, deciding earlier-discovered names first.

Each version tried counts as one step, and the search stops at 100,000
steps. The worst case is exponential, which is why the limit exists: no
package can make LPM search forever.

**The graph** has one node per selected package, stored as adjacency lists.
Edge `j` of a node is that package's `j`-th `depends=` line, so each edge
keeps its constraint. Installed packages are leaves.

**Cycle detection and order** use one iterative depth-first search from the
requested package, with three colours: white (unvisited), grey (on the
current path) and black (done).
* Reaching a grey node is a cycle. LPM reports it as
  `a -> b -> c -> a`, or `a -> a` for a direct self-dependency.
* A package is added to the order when it turns black, after all of its
  dependencies. This post-order is the installation order.
* The traversal is iterative, so even a 1,024-deep chain can't overflow the
  C stack.

**Complexity**, with V packages in the plan and E dependency edges:

| Part | Time | Space |
|------|------|-------|
| Cycle detection and topological sort | O(V + E) | O(V) |
| Depth computation (direct or transitive), breadth-first | O(V + E) | O(V) |
| Name table | O(N log N) for N names | O(N) |
| Version selection | O(steps × requirements per name) | O(V + E) |

Version selection, the candidate search, is bounded by the step limit.

**Determinism:** discovery order, version order and edge order are all
fixed, so the same inputs always produce the same plan.

**Limits:**
* 4,096 candidates plus installed packages.
* 1,024 packages per plan.
* 100,000 search steps.
* 128 dependencies per package (the Milestone 2 limit).

Exceeding any of these is a clear error, never a partial plan.

### Example

```
app -> liba -> libc
app -> libb -> libc
```

```
$ lpm --root R plan pkgs/app-1.0.lpm --package-dir pkgs
Dependency graph (package -> requirement => selected):
  app 1.0
      -> liba >= 1.0  =>  liba 1.2
      -> libb >= 1.0  =>  libb 1.0
  liba 1.2
      -> libc >= 1.0  =>  libc 1.0
  ...
Installation order (dependencies first):
  1. libc 1.0  [transitive dependency]
  2. liba 1.2  [direct dependency]
  3. libb 1.0  [direct dependency]
  4. app 1.0  [requested]
```

`libc` appears once, before both of its users.
* **Direct dependency:** depth 1, named in the requested package's own
  metadata.
* **Transitive dependency:** depth 2 or more, needed only through another
  package.

### Errors

The status is `LPM_ERR_DEPENDENCY` unless noted; the error code is in
`lpm_meta_error.code`.

| Code | Example message |
|------|-----------------|
| `DEP_MISSING` | `missing dependency: libbar >= 2.0 (required by app 1.0); it is neither installed nor available` |
| `DEP_INSTALLED` | `version conflict: required libfoo >= 2.0 (required by app 1.0); installed libfoo 1.5 (installed packages are not upgraded)` |
| `DEP_CONFLICT` | `conflicting requirements: library < 2.0 (required by b 1.0); library >= 3.0 (required by a 1.0); available versions of library: 3.1, 1.0` |
| `DEP_CYCLE` | `dependency cycle detected: a -> b -> c -> a` |
| `DEP_DUPLICATE` | `two candidates for libc 1.0: pkgs/libc-1.0.lpm and pkgs/libc-copy.lpm` |
| `DEP_LIMIT` | `dependency search gave up after 100000 candidate attempts` |
| `DEP_ALREADY` (`LPM_ERR_EXISTS`) | `package 'app' is already registered (installed version 1.0)` |

An unreadable or invalid candidate stops planning, with the file named in
the message. When the search fails, the error reported is the first one met
in its deterministic search order.

### Installation with dependencies

* **`lpm install app.lpm`** now checks dependencies: a missing or
  unsatisfied one is refused before anything is written.
* **`lpm install app.lpm --package-dir DIR`** also installs the missing
  dependencies, as one all-or-nothing operation:

1. Refuse `/`. Check that the requested file exists and matches `--sha256`
   (if given) before anything is created.
2. Lock the database and plan against the installed set seen under that
   lock.
3. Verify and stage every package of the plan, using all the Milestone 4
   checks: metadata, manifest hash, every payload hash, safe paths, staging,
   ownership and filesystem pre-flight.
   - The verified metadata must equal what the plan was built from, so a
     file swapped in between is refused.
   - A dependency is never trusted just because it appears in the plan.
4. Check the new packages against each other: no two may install the same
   file.
5. Commit in dependency order: each package's files, then its record.
6. If any package fails in step 5, the whole run is undone, newest first.
   Each package is unregistered, and exactly the files and directories this
   run created are removed. Nothing belonging to other packages is touched.

**Tested:** injecting a failure into every single system call and allocation
of a four-package install, 482 cases, always ended with all four installed
or none. **Not covered:** a crash or power loss during step 5 can still leave
a partial state. The crash test shows `lpm check` always reports it, through
the staging directories left behind.

### Known limitations

* No upgrades or downgrades: an installed version is final until `lpm
  remove` exists.
* Installed packages' own dependencies are not re-examined (`lpm check`
  reports unsatisfied ones).
* A cycle is reported for the versions selected. The search does not try
  other versions just to avoid a cycle.
* When several conflicts exist, only the first one in search order is
  reported.
* Planning reads only metadata, so a candidate with a corrupt payload
  appears in a plan; `install` rejects it.
* Candidates come only from a local directory; there are no repositories or
  downloads.

### Tests

| Program | Tests | Covers |
|---------|-------|--------|
| `build/test_solver` | 31 | no dependencies, direct, multiple, transitive, diamond, installed, missing, too old, damaged record; self, 2-, 3- and 5-cycles; determinism; duplicate references; `=`, `>=`, `<`; conflicting requirements; highest compatible version; backtracking; impossible combinations; duplicate candidates; malformed candidates; a 1,024-deep chain and a 200-node graph; every limit; allocation failures |
| `build/test_deps` | 16 | Scenarios A–G with real `.lpm` files; package-directory handling; conflicts between new packages; `--sha256`; the real-root refusal; a file swapped after planning; every single failure of a multi-package install; a crash at every system call |
| `tests/run_tests.sh` | 33 new | `lpm plan` and `lpm install --package-dir` end to end |

### Demonstration (temporary directories only)

```sh
make
P=$(mktemp -d); R=$(mktemp -d)
mk() {   # mk NAME VERSION [DEPENDS...]
    s=$(mktemp -d); mkdir -p $s/payload/usr/share/$1
    echo "$1 $2" > $s/payload/usr/share/$1/README
    printf 'name=%s\nversion=%s\n' $1 $2 > $s/metadata.in
    n=$1; v=$2; shift 2
    for d in "$@"; do echo "depends=$d" >> $s/metadata.in; done
    tools/lpm-mkpkg.sh $s $P/$n-$v.lpm gz; rm -rf $s
}
mk libc 1.0
mk liba 1.0 'libc>=1.0'
mk libb 1.0 'libc>=1.0'
mk app  1.0 'liba>=1.0' 'libb>=1.0'

./lpm --root $R plan $P/app-1.0.lpm --package-dir $P     # graph + order
./lpm --root $R install $P/app-1.0.lpm                   # refused: missing liba
./lpm --root $R install $P/app-1.0.lpm --package-dir $P  # installs libc, liba, libb, app
./lpm --root $R list

C=$(mktemp -d); P0=$P; P=$C                              # a cycle
mk cyc-a 1 'cyc-b>=1'; mk cyc-b 1 'cyc-c>=1'; mk cyc-c 1 'cyc-a>=1'
./lpm --root $(mktemp -d) plan $C/cyc-a-1.lpm --package-dir $C   # cyc-a -> cyc-b -> cyc-c -> cyc-a
P=$P0
```

---

## Ed25519 signatures and trusted keys (Milestone 6)

### Why SHA-256 alone is not enough

The SHA-256 values in `metadata.txt` and `manifest.txt` prove the package is
**internally consistent**. Anyone who changes a file can recompute every
hash, so they say nothing about **who** made the package.

A digital signature does. Only the holder of a private key can produce a
signature that verifies with the matching public key. LPM accepts a package
only if that public key is one you explicitly trusted.

**Why Ed25519:**
* small keys and signatures (32 and 64 bytes);
* deterministic, with no random number needed while signing;
* fast, and resistant to many implementation mistakes;
* available in OpenSSL, which LPM already uses.

### The trust chain

```
  trusted public key   (<root>/etc/lpm/trusted-keys, added by you)
          |  Ed25519 verifies
          v
  metadata.txt         name, version, dependencies, manifest_sha256
          |  manifest_sha256
          v
  manifest.txt         path, mode and SHA-256 of every file
          |  per-file SHA-256
          v
  payload/...          every installed byte
```

### Exactly what is signed

```
LPM-SIGNED-METADATA-V1\n  ||  the raw bytes of metadata.txt
```

* **The prefix is domain separation.** A signature made for LPM metadata
  can't be valid for anything else, and a future format can change the
  prefix.
* **Metadata is signed exactly as stored**, never reconstructed.
* **The signature covers identity.** Changing the name, version or
  dependencies invalidates it.
* **Pure Ed25519.** There is no separate digest step: OpenSSL's one-shot
  `EVP_DigestSign` and `EVP_DigestVerify` are used, as Ed25519 requires.
* **The signature isn't part of the signed data**, so nothing is circular.

### Package format

```
example-1.0.lpm            tar (plain, gzip or xz)
├── metadata.txt           1st entry (Milestone 2)
├── manifest.txt           2nd entry (Milestone 4)
├── signature.txt          3rd entry (Milestone 6)
└── payload/...
```

`signature.txt` has exactly five lines, in this order, in lowercase hex:

```
format=lpm-signature-v1
algorithm=ed25519
public_key=<64 hex digits: the signer's raw public key>
key_id=<64 hex digits: SHA-256 of that public key>
signature=<128 hex digits: the 64-byte signature>
```

**Rejected as malformed:**
* a second `signature.txt`, or one anywhere other than third;
* any other layout;
* another format or algorithm;
* a `key_id` that isn't the hash of `public_key`.

**Old packages:** unsigned packages remain readable. `verify` reports them
as unsigned, and `install` refuses them.

**The embedded `public_key` is never trusted.** It only lets `verify` say
whether the signature is mathematically valid. Installation verifies the
signature again with the *trusted copy* of the key from the trust store.

### Key IDs and the trust store

* **Key ID:** lowercase hex SHA-256 of the 32 raw public-key bytes. Because
  it's derived from the key, nobody can choose an ID that names somebody
  else's key.
* **Storage:**
  - Each trusted key is stored at `<root>/etc/lpm/trusted-keys/<key_id>.pub`,
    in canonical PEM.
  - The store belongs to `--root`: a test root never sees the host's keys,
    and the reverse.
* **Safety checks:**
  - Every directory is opened without following symlinks, and must belong to
    you or root and not be group- or world-writable.
  - A key file whose content doesn't hash to its file name is rejected as
    tampered.

```sh
lpm --root R key add publisher.pub   # validate, show the fingerprint, store
lpm --root R key list
lpm --root R key remove KEY_ID       # "revocation": stops future installs
```

**Rules for `key add`:**
* It accepts exactly one Ed25519 public key in PEM.
* It refuses private keys, other key types, garbage and duplicates.
* It writes atomically: a temporary file, `fsync`, then `linkat`, which
  never overwrites.
* Changes happen under the database's exclusive lock, which the installer
  also holds.

**What packages can't do:**
* Packages can't add keys: install refuses any path under `/etc/lpm` or
  `/var/lib/lpm`, even in a trusted package.
* A key embedded in a package is never imported.

### Signing packages

```sh
openssl genpkey -algorithm ED25519 -out private.pem   # keep secret, chmod 600
openssl pkey -in private.pem -pubout -out public.pem  # give this to users
tools/lpm-mkpkg.sh SRCDIR unsigned.lpm
build/lpm-sign private.pem unsigned.lpm signed.lpm
```

**What `lpm-sign` checks:** it refuses to sign a package with invalid
metadata or a manifest that doesn't match. It also refuses an
already-signed package, and an output file that already exists.

**Private keys:**
* `lpm-sign` never prints the private key, and wipes its copy after use. It
  warns if the key file is readable by others.
* Private keys belong nowhere near packages, roots or Git. `.gitignore`
  excludes `*.pem`.
* Development keys are for testing, not production trust anchors.

### `lpm verify`

`lpm [--root R] verify FILE.lpm [--sha256 HEX]` checks integrity as in
Milestone 4. It then checks authenticity against the trust store of
`--root` (default `/`, i.e. `/etc/lpm/trusted-keys`). Signature validity and
trust are reported separately:

```
Authentication (trust store: R/etc/lpm/trusted-keys):
  Signature:      Ed25519, valid
  Signing key:    31b0d44e...
  Trust:          trusted
Result:           INTEGRITY OK, AUTHENTICATED: signed by a trusted key ...
```

| Exit | Meaning |
|------|---------|
| 0 | intact and signed by a trusted key: installable |
| 1 | tampered: an integrity failure, or a malformed or invalid signature |
| 3 | intact but **not authenticated**: unsigned, or the signer is not trusted |

A valid signature from an unknown key exits with 3 and is never called
authenticated.

### Installation policy

1. Plan the dependencies. Metadata used for planning is still unverified, so
   it's provisional only.
2. For **every** selected package, from the same open file descriptor:
   integrity (Milestone 4), then the signature by a **trusted** key over the
   exact `metadata.txt` bytes just read, then a check that the verified
   metadata equals the planned metadata.
3. Pre-flight the whole set, including the protected-path rule.
4. Commit in dependency order, all or nothing (Milestone 5).

If any package fails at step 2, whether unsigned, invalid, untrusted or
tampered, nothing is installed and nothing is registered. The error names
the package. There is no bypass flag, for any root. The real `/` is still
refused.

### Threat model

**Defended:**
* tampering with the payload, manifest or metadata;
* forged, malformed or duplicated signatures;
* unknown signers, and borrowed key IDs;
* tampered trust-store files;
* swapping a package between planning and installation;
* sneaking an untrusted package in as a dependency;
* packages planting keys;
* and all Milestone 4 archive attacks.

**Not defended:**
* A trusted publisher who is compromised, or whose key is stolen, or who
  deliberately signs something malicious. A signature proves origin, not
  safety.
* **Replay of an old, validly signed version:** there are no expiry dates
  and no timestamping.
* **Revocation is local:** you remove the key yourself; there is no online
  revocation list.
* Bugs in LPM itself.

### Compatibility

* **OpenSSL:** 1.1.1 or 3.x, through the EVP interface (`EVP_PKEY_ED25519`,
  `EVP_DigestSign`/`EVP_DigestVerify`, `EVP_PKEY_new_raw_public_key`). These
  are non-deprecated in both. Tested with OpenSSL 1.1.1f in WSL; not yet with
  OpenSSL 3 on LFS.
* **New external dependencies:** none.
* **Test tools:** the CLI tests also need the `openssl` command, to make
  throw-away keys.

### Tests

| Program | Tests | Covers |
|---------|-------|--------|
| `build/test_signature` | 9 | RFC 8032 test vectors 1–3, signing and verifying; wrong key; changed message; every flipped signature bit; empty message; domain separation; key lengths and IDs; PEM import, including private, X25519, garbage and two-key files; every malformation of the signature record; allocation failures |
| `build/test_auth` | 20 | key import, fingerprint, duplicates, list, remove, unknown keys; tampered and symlinked stores; separate stores per root; failures during key import; every package outcome; key-ID substitution; removed keys; dependencies that are unsigned, untrusted or tampered; several signers; substitution during install; protected paths; real-root refusal; every single failure of a signed four-package install |
| `tests/run_tests.sh` | 36 new | `key`, `lpm-sign`, `verify` exit codes 0/1/3, authenticated install, untrusted dependency, trust-store protection |

### Demonstration (temporary directories only)

```sh
make && make demo                        # builds lpm and build/lpm-sign
D=$(mktemp -d); R=$D/root; mkdir -p $R $D/pkgs

# A. keys: the private key signs (keep it secret), the public key verifies
openssl genpkey -algorithm ED25519 -out $D/priv.pem; chmod 600 $D/priv.pem
openssl pkey -in $D/priv.pem -pubout -out $D/pub.pem
openssl genpkey -algorithm ED25519 -out $D/stranger.pem; chmod 600 $D/stranger.pem

# B. build + sign: mk NAME VERSION [DEPENDS...]  (K = signing key, OUT = directory)
mk() { s=$(mktemp -d); mkdir -p $s/payload/usr/share/$1
       echo "$1 $2" > $s/payload/usr/share/$1/README
       printf 'name=%s\nversion=%s\n' $1 $2 > $s/metadata.in; n=$1; v=$2; shift 2
       for d in "$@"; do echo "depends=$d" >> $s/metadata.in; done
       tools/lpm-mkpkg.sh $s $s.lpm gz >/dev/null
       build/lpm-sign ${K:-$D/priv.pem} $s.lpm ${OUT:-$D/pkgs}/$n-$v.lpm; rm -rf $s $s.lpm; }
mk libc 1.0; mk liba 1.0 'libc>=1.0'; mk libb 1.0 'libc>=1.0'; mk app 1.0 'liba>=1.0' 'libb>=1.0'
tar -tzf $D/pkgs/app-1.0.lpm | head -3          # metadata.txt manifest.txt signature.txt

# C. trust the publisher's public key in the temporary root
./lpm --root $R key add $D/pub.pem
./lpm --root $R key list

# D. verify: integrity + signature + trust            -> exit 0
./lpm --root $R verify $D/pkgs/app-1.0.lpm; echo "exit $?"

# E. tamper with the metadata without re-signing         -> exit 1, INVALID
T=$(mktemp -d); tar -xzf $D/pkgs/libc-1.0.lpm -C $T
sed -i 's/^version=1.0$/version=9.0/' $T/metadata.txt
tar -czf $D/tampered.lpm -C $T metadata.txt manifest.txt signature.txt payload
./lpm --root $R verify $D/tampered.lpm; echo "exit $?"

# F. a package from an unknown signer                     -> exit 3, NOT trusted
K=$D/stranger.pem OUT=$D mk solo 1.0
./lpm --root $R verify $D/solo-1.0.lpm; echo "exit $?"

# G. authenticated dependency installation
./lpm --root $R plan $D/pkgs/app-1.0.lpm --package-dir $D/pkgs
./lpm --root $R install $D/pkgs/app-1.0.lpm --package-dir $D/pkgs
./lpm --root $R list

# H. one dependency signed by the stranger: everything is refused
R2=$D/root2; mkdir -p $R2 $D/evil; ./lpm --root $R2 key add $D/pub.pem
cp $D/pkgs/libc-1.0.lpm $D/pkgs/liba-1.0.lpm $D/pkgs/app-1.0.lpm $D/evil/
K=$D/stranger.pem OUT=$D/evil mk libb 1.0 'libc>=1.0'
./lpm --root $R2 install $D/evil/app-1.0.lpm --package-dir $D/evil; echo "exit $?"
./lpm --root $R2 list                                   # No packages installed.
ls $R2                                                  # etc var: no usr
```

**Direct vs. transitive dependencies:** in the `plan` output, `liba` and
`libb` are marked direct, because `app` names them. `libc` is marked
transitive, needed only through them. It appears once and is installed first.
