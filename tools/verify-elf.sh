#!/usr/bin/env bash
set -euo pipefail

kernel="${1:?usage: verify-elf.sh <kernel.elf>}"
readelf_bin="${LLVM_READELF:-llvm-readelf}"

header="$($readelf_bin -h "$kernel")"
programs="$($readelf_bin -lW "$kernel")"

printf '%s\n' "$header" | grep -q 'Class:.*ELF64'
printf '%s\n' "$header" | grep -q 'Machine:.*Advanced Micro Devices X86-64'
printf '%s\n' "$header" | grep -q 'Entry point address:.*0xffffffff'

if printf '%s\n' "$programs" | grep -E 'LOAD.*RWE' >/dev/null; then
    echo 'error: RWX load segment detected' >&2
    exit 1
fi

stack_line="$(printf '%s\n' "$programs" | grep 'GNU_STACK' || true)"
if [[ -z "$stack_line" ]]; then
    echo 'error: GNU_STACK segment missing' >&2
    exit 1
fi
if printf '%s\n' "$stack_line" | grep -E 'RWE|E[[:space:]]' >/dev/null; then
    echo 'error: executable stack detected' >&2
    exit 1
fi

printf 'ELF verification passed: ELF64 x86_64, high-half entry, no RWX LOAD, NX stack.\n'
