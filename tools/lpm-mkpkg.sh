#!/bin/bash
# lpm-mkpkg.sh - build an LPM package (.lpm) from a source directory.
#
#   tools/lpm-mkpkg.sh SRCDIR OUT.lpm [none|gz|xz]
#
# SRCDIR must contain:
#   metadata.in   name=, version=, optional description= and depends= lines
#                 (no manifest_sha256: it is computed here)
#   payload/      the files exactly as they should appear below the root,
#                 e.g. payload/usr/bin/hello
#
# Produces a tar archive whose entries are, in order: metadata.txt,
# manifest.txt, payload/... (the layout lpm expects; see include/pkg.h).
# Uses only base-LFS tools: bash, coreutils (sha256sum, stat, readlink,
# sort), findutils and GNU tar. Modes are limited to 0755 (lpm rejects
# setuid/setgid/sticky and group/world-writable modes).
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: $0 SRCDIR OUT.lpm [none|gz|xz]" >&2
    exit 2
fi
SRC=$1
OUT=$2
COMP=${3:-xz}

[ -f "$SRC/metadata.in" ] || { echo "$0: $SRC/metadata.in is missing" >&2; exit 1; }
[ -d "$SRC/payload" ]     || { echo "$0: $SRC/payload/ is missing" >&2; exit 1; }
if grep -q '^manifest_sha256=' "$SRC/metadata.in"; then
    echo "$0: metadata.in must not contain manifest_sha256 (it is computed)" >&2
    exit 1
fi

case "$COMP" in
    none) TARCOMP= ;;
    gz)   TARCOMP=-z ;;
    xz)   TARCOMP=-J ;;
    *)    echo "$0: compression must be none, gz or xz" >&2; exit 2 ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export LC_ALL=C

# One manifest line per payload entry, sorted, path last.
(
    cd "$SRC/payload"
    find . -mindepth 1 | sort | while IFS= read -r p; do
        rel=${p#.}                       # "./usr/bin/x" -> "/usr/bin/x"
        mode=$(printf '%04o' $(( 8#$(stat -c %a "$p") & 8#755 )))
        if [ -L "$p" ]; then
            echo "symlink $(readlink "$p") $rel"
        elif [ -d "$p" ]; then
            echo "dir $mode $rel"
        elif [ -f "$p" ]; then
            echo "file $(sha256sum "$p" | cut -d' ' -f1) $mode $rel"
        else
            echo "$0: unsupported file type: $rel" >&2
            exit 1
        fi
    done
) > "$WORK/manifest.txt"

cp "$SRC/metadata.in" "$WORK/metadata.txt"
[ -z "$(tail -c1 "$WORK/metadata.txt")" ] || echo >> "$WORK/metadata.txt"
echo "manifest_sha256=$(sha256sum "$WORK/manifest.txt" | cut -d' ' -f1)" >> "$WORK/metadata.txt"

# The modes stored in the archive are irrelevant (the manifest decides),
# but are normalised anyway; owner and time are fixed for reproducibility.
tar $TARCOMP -c -f "$OUT" --owner=0 --group=0 --numeric-owner --mtime=@0 \
    --mode='go-w,-s,-t' \
    -C "$WORK" metadata.txt manifest.txt \
    -C "$SRC" --sort=name payload
echo "Built $OUT ($(wc -l < "$WORK/manifest.txt") manifest entries)"
