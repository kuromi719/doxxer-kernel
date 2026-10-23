# Doxxer Kernel

Doxxer is an experimental privacy-first x86_64 operating-system kernel. This repository currently contains the first UEFI prototype: a freestanding C++20 kernel booted by Limine, with COM1 diagnostics and a small framebuffer console.

> This milestone is a research prototype, not a production-secure operating system.

## Current milestone

- x86_64 UEFI boot through Limine
- QEMU + EDK2 development target
- COM1 serial logging
- Framebuffer boot trace and centered Doxxer wordmark
- Entropy-seeded stack protector
- Zone-aware physical page allocator with secure page wiping
- Contiguous and aligned page allocation with boot-time invariants
- Four-level x86_64 virtual memory manager with NX-by-default W^X mappings
- Isolated address spaces, guard pages, PCID metadata, and 2 MiB page support
- Kernel-owned active address space with guarded runtime and exception stacks
- Private GDT/TSS/IDT, 256 interrupt stubs, and register-rich exception diagnostics
- Boot-time breakpoint, IST-routing, and real guard-page fault recovery tests
- Hardened slab/page kernel heap with keyed canaries, quarantine, and secure wiping
- Entropy-derived ChaCha20 + HMAC-SHA-256 sealed-memory vault for idle secrets
- Ephemeral guarded shadow-memory regions for authenticated secret working sets
- Checksummed RSDP/XSDT, MADT, and HPET discovery with bounded ACPI parsing
- Explicit uncached MMIO mappings for Local APIC, I/O APIC, and HPET registers
- Legacy PIC shutdown, fail-closed I/O APIC masking, and calibrated periodic APIC timer
- Registered external-interrupt dispatch with a live boot-time timer delivery test
- Four-CPU SMP bring-up with isolated guarded stacks, per-CPU GDT/TSS state, and GS-based CPU-local identity
- Cross-CPU fixed IPI delivery test with bounded HPET startup and response deadlines
- Dedicated per-CPU 32 KiB NX syscall stacks with dual guard pages and integrity canaries
- SWAPGS syscall entry with process-bound dispatch and validated fixed-selector IRETQ return
- Deadline-bounded SMP rendezvous installation and verification of syscall MSRs on every CPU
- SWAPGS-safe user-origin interrupt entry and validated CPL3 exception delivery probe
- Bounded per-CPU kernel task queues with isolated guarded stacks and generation-safe handles
- IPI wakeups, idle `hlt`, explicit task lifecycle, stack wiping, and cross-CPU execution tests
- Scheduler-owned, per-CPU user-thread binding with typed execution leases and generation-safe teardown
- Capability-first kernel authority model with attenuation, revocation ancestry, typed objects, and pinned leases
- Entropy-keyed 36-bit token authentication plus generational stale-handle rejection
- Cross-domain capability delegation with rights attenuation and source-revocation ancestry
- Capability-gated bounded IPC channels with split send, receive, and administration endpoints
- Transactional capability attachment to IPC messages with cross-domain attenuation
- Manual- and auto-reset capability events with non-blocking, allocation-free wait semantics
- Isolated process containers with private address spaces, capability domains, and explicit lifecycle
- Pointer-free versioned syscall request ABI for IPC, events, and process control
- Process-lease-bound syscall gateway with bounded request/response copies through isolated windows
- Capability service registry with validated names and revocable attenuated resolution
- Page-aware user-memory validation and bounded copy helpers with no user-pointer dereference
- Per-CPU supervisor-only, NX temporary windows for runtime access to user-owned physical pages
- Strict ELF64 loader with transactional rollback, W^X segments, and zeroed BSS
- Closed-by-default executable policy with SHA-256 measurements and irreversible boot-time sealing
- Capability-owned user-thread contexts with pinned process spaces and guarded stacks
- Execute-right-gated user-thread leases with exclusive ready/running lifecycle transitions
- Hardware-verified CPL3 `IRETQ` entry and `SYSCALL` return-to-kernel boundary probe
- An immutable, measured ring-3 heartbeat ELF launched after the 30-second logo hold
- A kernel-rendered early-session desktop surface shown only after the first validated user syscall
- Immutable supervisor stack windows shared into processes without user accessibility or ownership
- Fail-closed Intel VT-d activation with an empty root table that denies all PCI DMA by default
- Boot-keyed shadow page ledger with typed ownership, zero-on-transition, and user-map enforcement
- Non-reusable address-space memory domains blocking cross-process RAM mapping and direct access
- Sealed user and supervisor mapping references preventing free/reuse behind live page-table aliases
- Reference-counted page-table graph links preventing linked paging structures from being recycled
- No public broad-HHDM accessor for user or general kernel-owned pages
- Mandatory per-CPU WP, NX, SMEP, SMAP, UMIP, timestamp restriction, and advertised speculation controls
- Runtime verification of RX/R/RW kernel image mappings on the active page tables
- W^X-compatible ELF segments and non-executable stack
- Bootable GPT/FAT disk image and UEFI ISO
- Automated disk and ISO smoke tests
- 128 MiB low-memory and 5 GiB high-memory QEMU coverage

The early-session surface is **not yet a user-owned DoxxerUI compositor**. The
ring-3 task proves a persistent, isolated user ABI loop but does not own the
framebuffer or handle input. Persistent multi-application scheduling,
preemption, a general app launcher, storage and filesystem services, keyboard
and pointer drivers beyond the F5 development hotkey, networking, Secure Boot,
and physical-hardware support remain deferred. This is not a complete or
production-secure operating system.

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

`test.ps1` runs fast `TEST_MODE` boot smoke tests; that mode intentionally
skips presentation delays. To independently exercise the production timing,
native-size logo pixels, thirty-second logo-to-early-session transition, and F5 guest restart,
build the normal disk image and run the separate headless QEMU integration test
(Python 3.10+ and Pillow required):

```powershell
.\tools\build.ps1 -Target disk
python tools/test-production-boot.py --media disk
```

The production test copies the image before launch and does not control the
visible live VM. It checks the boot presentation and first fallback desktop
frame only; it does not establish that a full compositor, filesystem, or
complete operating system is available. Screenshots and serial diagnostics are
saved under `build/test-logs/production-disk/` (or `production-iso/`).
It also holds the early session for two seconds after its ready marker and
rejects any panic; this specifically guards against a stale temporary-mapping
TLB entry breaking the second or later user syscall. It is a runtime
regression check, not a proof that all address-space transitions are safe.

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

`run.ps1` starts a native, visible QEMU window as a persistent Doxxer live VM.
It is not a browser preview, and the window stays open until it is closed
manually. The live VM can be controlled independently:

```powershell
.\tools\live.ps1 -Action Status
.\tools\live.ps1 -Action Reset
.\tools\live.ps1 -Action Reload -Media disk
.\tools\live.ps1 -Action Stop
```

The boot trace presents actual kernel initialization results. An active check
is yellow `PROGRESS`, a verified 100% check is green `PASSED`, and a failed
check is red `FAIL`. F5 restarts the VM during the trace, success hold, logo,
and final idle state. A failure never advances to the logo: F5 reboots
immediately and a 60-second watchdog reboots automatically. After every check
reaches 100%, the trace remains visible for five seconds, followed by the
Doxxer logo for thirty seconds.

The logo screen displays only the user-supplied 556 x 69 wordmark, centered at
native size on a dark background. Its source is `assets/boot-wordmark.png`;
`kernel/src/graphics/boot_wordmark.inc` contains the same RGB pixels so the
freestanding kernel needs no PNG decoder. If the source changes, regenerate the
header with `python tools/generate-boot-wordmark.py` (Pillow is needed only for
this development step, not for building or booting Doxxer).

## Design principles

1. Keep the trusted computing base small.
2. Default to no capability rather than implicit capability.
3. Fail closed when mandatory boot information is missing.
4. Keep executable, read-only, and writable kernel regions separate.
5. Treat reproducible and auditable builds as a security feature.

See [`docs/MEMORY.md`](docs/MEMORY.md) for the memory architecture,
[`docs/MEMORY_ISOLATION.md`](docs/MEMORY_ISOLATION.md) for the shadow ownership ledger,
[`docs/MEMORY_DOMAINS.md`](docs/MEMORY_DOMAINS.md) for cross-address-space RAM isolation,
[`docs/TEMPORARY_MAPPINGS.md`](docs/TEMPORARY_MAPPINGS.md) for ephemeral user-page access,
[`docs/PAGE_TABLE_LIFETIMES.md`](docs/PAGE_TABLE_LIFETIMES.md) for paging-structure ownership,
[`docs/DMA_ISOLATION.md`](docs/DMA_ISOLATION.md) for default-deny VT-d policy,
[`docs/CPU_HARDENING.md`](docs/CPU_HARDENING.md) for mandatory per-processor controls,
[`docs/CPU_PROTECTION.md`](docs/CPU_PROTECTION.md) for descriptor, exception, and stack design,
[`docs/HEAP.md`](docs/HEAP.md) for dynamic allocation invariants,
[`docs/SEALED_MEMORY.md`](docs/SEALED_MEMORY.md) for authenticated encryption of idle secrets,
[`docs/SHADOW_MEMORY_REGIONS.md`](docs/SHADOW_MEMORY_REGIONS.md) for guarded secret working sets,
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
[`docs/USER_THREADS.md`](docs/USER_THREADS.md) for ring-3 context and stack invariants,
[`docs/RING3_TRANSITION.md`](docs/RING3_TRANSITION.md) for the hardware privilege-boundary probe,
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the initial threat model, and
[`SECURITY.md`](SECURITY.md) for reporting guidance.

## License

Doxxer Kernel is licensed under the Apache License 2.0. Limine and other submodules retain their own licenses.
