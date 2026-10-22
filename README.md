# Doxxer Kernel

Doxxer is an experimental privacy-first x86_64 operating-system kernel. This repository currently contains the first UEFI prototype: a freestanding C++20 kernel booted by Limine, with COM1 diagnostics and a small framebuffer console.

> This milestone is a research prototype, not a production-secure operating system.

## Current milestone

- x86_64 UEFI boot through Limine
- QEMU + EDK2 development target
- COM1 serial logging
- Monochrome framebuffer logo and boot status
- Entropy-seeded stack protector
- Zone-aware physical page allocator with secure page wiping
- Contiguous and aligned page allocation with boot-time invariants
- W^X-compatible ELF segments and non-executable stack
- Bootable GPT/FAT disk image and UEFI ISO
- Automated disk and ISO smoke tests
- High-memory QEMU test covering the allocator's normal-memory zone

Virtual memory management, interrupts, user mode, networking, drivers, Secure Boot, and physical-hardware support are intentionally deferred.

## Prerequisites

The Windows bootstrap uses MSYS2 and installs GNU Make, xorriso, mtools, gptfdisk, NASM, LLVM/Clang, and the Limine build prerequisites. QEMU is expected at `C:\Program Files\qemu`.

```powershell
.\tools\bootstrap.ps1
```

The Limine bootloader and protocol repositories are pinned Git submodules. After cloning manually, initialize them with:

```powershell
git submodule update --init --recursive
```

## Build and run

```powershell
.\tools\build.ps1
.\tools\build.ps1 -Target kernel
.\tools\run.ps1 -Media disk
.\tools\run.ps1 -Media iso
.\tools\test.ps1
```

From an MSYS2 UCRT64 shell, the corresponding targets are:

```bash
make kernel
make disk
make iso
make run
make run-iso
make test
```

Artifacts are written to `build/doxxer-kernel.elf`, `dist/doxxer-uefi.img`, and `dist/doxxer.iso`.

## Design principles

1. Keep the trusted computing base small.
2. Default to no capability rather than implicit capability.
3. Fail closed when mandatory boot information is missing.
4. Keep executable, read-only, and writable kernel regions separate.
5. Treat reproducible and auditable builds as a security feature.

See [`docs/MEMORY.md`](docs/MEMORY.md) for the memory architecture,
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the initial threat model, and
[`SECURITY.md`](SECURITY.md) for reporting guidance.

## License

Doxxer Kernel is licensed under the Apache License 2.0. Limine and other submodules retain their own licenses.
