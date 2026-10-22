# Symmetric Multiprocessing

## Model

Doxxer brings secondary x86_64 processors online through Limine's pinned MP protocol while retaining ownership of the runtime environment installed after entry. The firmware MADT processor count and bootstrap APIC identity must agree with Limine's response. Duplicate processor or APIC identifiers, x2APIC mode, missing records, or more than 64 processors fail boot.

Limine supplies only the rendezvous mechanism. Before releasing a processor, the bootstrap processor allocates and maps all of its protected state. Each secondary processor then switches to Doxxer's active CR3 and private kernel stack in one assembly transition.

## Per-CPU isolation

Each secondary processor owns:

- A 32 KiB kernel stack with an unmapped page at both boundaries
- A separate 32 KiB normal exception IST with guards
- A separate 32 KiB emergency IST with guards
- A private GDT and TSS
- CPU-local identity and lifecycle counters

The IDT and handler table are shared and installed before processors are released. The TSS is never shared because the x86 busy state and IST pointers are processor-specific.

The `IA32_GS_BASE` MSR points at a cache-line-aligned CPU record. Interrupt code validates the self pointer, bounded CPU index, and Local APIC ID before modifying CPU-local state. This avoids repeatedly scanning global topology in future hot paths and establishes the base needed by a scheduler.

## Publication and ordering

CPU records and mappings are completed before the MP `goto_address` is published with release ordering. Secondary status transitions use release stores; the bootstrap processor observes them with acquire loads. Startup is successful only when every discovered processor reaches the online state before a one-second HPET deadline.

## Cross-CPU test

Vector `0xE1` is reserved as a kernel IPI probe. The bootstrap processor sends a fixed IPI to every secondary processor and requires each CPU-local acknowledgement counter to advance before a 250 ms HPET deadline. The handler performs only validation, an atomic counter increment, and Local APIC EOI.

Automated QEMU tests now use four virtual processors for disk, ISO, low-memory, and high-memory configurations. This makes multiprocessor startup a required boot invariant rather than untested optional code.

## Deferred work

- Per-CPU run queues and scheduling clocks
- Scheduler-aware cross-CPU calls and TLB shootdowns
- CPU hot-plug and graceful offlining
- x2APIC and interrupt-remapping support
- NUMA topology, locality-aware allocation, and affinity policy
- XSAVE/FPU ownership and user-mode context switching
