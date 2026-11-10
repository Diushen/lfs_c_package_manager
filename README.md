# lfs_c_package_manager

C package manager for my Linux From Scratch Distribution - Part of my Capstone

## LPM — LFS Package Manager

A small package manager written in C for a Linux From Scratch 13.1-systemd
system.

## Status

| Milestone | Feature                                  | State |
|-----------|------------------------------------------|-------|
| 1         | Skeleton, CLI, `help`, `version`, `list` | done  |
| 2–12      | metadata, database, dependency graph, archive, SHA-256, Ed25519, install, remove | planned |

## Build

    make            # release build
    make debug      # with AddressSanitizer + UBSan
    make test       # run the test suite
    make clean

## Usage

    lpm [--root DIR] <command> [arguments]

`--root DIR` makes LPM treat `DIR` as `/`; the database then lives at
`DIR/var/lib/lpm`. Use it for all testing so the real system is untouched.

## Layout

    include/   public headers (one per module)
    src/       implementation
    tests/     test scripts
    examples/  demonstration packages (later milestones)
