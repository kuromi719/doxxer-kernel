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
- Four-level x86_64 virtual memory manager with NX-by-default W^X mappings
- Isolated address spaces, guard pages, PCID metadata, and 2 MiB page support
- Kernel-owned active address space with guarded runtime and exception stacks
- Private GDT/TSS/IDT, 256 interrupt stubs, and register-rich exception diagnostics
- Boot-time breakpoint, IST-routing, and real guard-page fault recovery tests
- Hardened slab/page kernel heap with keyed canaries, quarantine, and secure wiping
- Checksummed RSDP/XSDT, MADT, and HPET discovery with bounded ACPI parsing
- Explicit uncached MMIO mappings for Local APIC, I/O APIC, and HPET registers
- Legacy PIC shutdown, fail-closed I/O APIC masking, and calibrated periodic APIC timer
- Registered external-interrupt dispatch with a live boot-time timer delivery test
- Four-CPU SMP bring-up with isolated guarded stacks, per-CPU GDT/TSS state, and GS-based CPU-local identity
- Cross-CPU fixed IPI delivery test with bounded HPET startup and response deadlines
- Bounded per-CPU kernel task queues with isolated guarded stacks and generation-safe handles
- IPI wakeups, idle `hlt`, explicit task lifecycle, stack wiping, and cross-CPU execution tests
- Capability-first kernel authority model with attenuation, revocation ancestry, typed objects, and pinned leases
- Entropy-keyed 36-bit token authentication plus generational stale-handle rejection
- Cross-domain capability delegation with rights attenuation and source-revocation ancestry
- Capability-gated bounded IPC channels with split send, receive, and administration endpoints
- Transactional capability attachment to IPC messages with cross-domain attenuation
- Manual- and auto-reset capability events with non-blocking, allocation-free wait semantics
- Isolated process containers with private address spaces, capability domains, and explicit lifecycle
- Pointer-free versioned syscall request ABI for IPC, events, and process control
- Capability service registry with validated names and revocable attenuated resolution
- Page-aware user-memory validation and bounded copy helpers with no user-pointer dereference
- Strict ELF64 loader with transactional rollback, W^X segments, and zeroed BSS
- W^X-compatible ELF segments and non-executable stack
- Bootable GPT/FAT disk image and UEFI ISO
- Automated disk and ISO smoke tests
- 128 MiB low-memory and 5 GiB high-memory QEMU coverage

Hardware syscall entry, user-mode execution, preemptive scheduling, networking, general drivers,
Secure Boot, and physical-hardware support are intentionally deferred.

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
[`docs/CPU_PROTECTION.md`](docs/CPU_PROTECTION.md) for descriptor, exception, and stack design,
[`docs/HEAP.md`](docs/HEAP.md) for dynamic allocation invariants,
[`docs/INTERRUPTS.md`](docs/INTERRUPTS.md) for ACPI and interrupt-controller design,
[`docs/SMP.md`](docs/SMP.md) for multiprocessor and CPU-local invariants,
[`docs/SCHEDULER.md`](docs/SCHEDULER.md) for kernel task dispatch and isolation,
[`docs/CAPABILITIES.md`](docs/CAPABILITIES.md) for the authority and object-lifetime model,
[`docs/IPC.md`](docs/IPC.md) for bounded capability channels,
[`docs/EVENTS.md`](docs/EVENTS.md) for synchronization objects,
[`docs/PROCESSES.md`](docs/PROCESSES.md) for isolated process containers,
[`docs/SYSCALL_ABI.md`](docs/SYSCALL_ABI.md) for the versioned syscall contract,
[`docs/SERVICES.md`](docs/SERVICES.md) for capability-oriented service discovery,
[`docs/USER_MEMORY.md`](docs/USER_MEMORY.md) for safe address-space copy rules,
[`docs/ELF_LOADER.md`](docs/ELF_LOADER.md) for executable validation and mapping,
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the initial threat model, and
[`SECURITY.md`](SECURITY.md) for reporting guidance.

## License

Doxxer Kernel is licensed under the Apache License 2.0. Limine and other submodules retain their own licenses.
