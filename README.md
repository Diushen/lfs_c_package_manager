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
| 3–12      | database writes, dependency graph, archive, SHA-256, Ed25519, install, remove | planned |

## Build and test

    make              # release build (-O2), no external libraries
    make test         # CLI tests + metadata unit tests
    make debug        # rebuild with AddressSanitizer + UBSan ...
    make test         # ... and test that build (debug stays active until `make clean`)
    make unit-test    # only the metadata unit tests
    build/test_metadata -v tests/fixtures   # also print every diagnostic
    make clean

The unit tests are linked with GNU ld `--wrap=malloc,calloc,realloc` (binutils
is part of base LFS) so that allocation failures can be injected.

## Usage

    lpm [--root DIR] <command> [arguments]

`--root DIR` makes LPM treat `DIR` as `/`; the database then lives at
`DIR/var/lib/lpm`. Use it for all testing so the real system is untouched.

    lpm --root ./demo-root list
    lpm --root ./demo-root info hello

## Layout

    include/            one public header per module
      lpm.h             shared constants, status codes, config
      util.h            diagnostics, safe paths, package-name rule
      metadata.h        metadata parser, lpm_package, limits      (Milestone 2)
      database.h        installed-package database
      commands.h        command table
    src/                implementation of each header + main.c
    tests/
      run_tests.sh      CLI tests (Milestone 1 + 2)
      test_metadata.c   metadata parser unit tests              (Milestone 2)
      fixtures/         example valid/invalid metadata files    (Milestone 2)
    examples/           demonstration packages (later milestones)

Module dependencies point one way only:

    main.c ──► commands.c ──► database.c ──► metadata.c ──► util.c
                     └──────────────────────────┘

`metadata.c` knows nothing about the database or the CLI. The unit-test binary
links only `metadata.o` and `util.o`, which proves it.

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
* Upgrades and file lists are not handled yet (later milestones).
