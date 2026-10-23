# Symmetric Multiprocessing

## Model

Doxxer brings secondary x86_64 processors online through Limine's pinned MP protocol while retaining ownership of the runtime environment installed after entry. The firmware MADT processor count and bootstrap APIC identity must agree with Limine's response. Duplicate processor or APIC identifiers, x2APIC mode, missing records, or more than 64 processors fail boot.

Limine supplies only the rendezvous mechanism. Before releasing a processor, the bootstrap processor allocates and maps all of its protected state. Each secondary processor then switches to Doxxer's active CR3 and private kernel stack in one assembly transition.

## Per-CPU isolation

Each secondary processor owns:

- A 32 KiB kernel stack with an unmapped page at both boundaries
- A separate 32 KiB normal exception IST with guards
- A separate 32 KiB emergency IST with guards
- A dedicated 32 KiB syscall stack with guards and a CPU-bound integrity canary
- A private GDT and TSS
- CPU-local identity and lifecycle counters

The bootstrap processor also receives a private syscall stack. Syscall stacks are supervisor-only,
NX, zeroed before publication, and separated from task, interrupt, and exception stacks so an
untrusted user stack is never reused for privileged ABI dispatch. Both boundary pages remain
unmapped. The lowest mapped word carries a canary derived from CPU identity and the stack's owned
physical allocation, keyed by the boot entropy-seeded stack guard.

The IDT and handler table are shared and installed before processors are released. The TSS is never shared because the x86 busy state and IST pointers are processor-specific.

The `IA32_GS_BASE` MSR points at a cache-line-aligned CPU record and `IA32_KERNEL_GS_BASE` is cleared before a processor is published. Interrupt code validates the self pointer, bounded CPU index, and Local APIC ID before modifying CPU-local state. A user transition swaps the CPU record into `IA32_KERNEL_GS_BASE`; `SYSCALL` executes `SWAPGS` before reading the bound process pointer, saved user RSP, or guarded stack top. This avoids repeatedly scanning global topology in hot paths and keeps user-controlled GS state outside privileged addressing.

The scheduler controls the user-thread execution pointer installed in each CPU record. It accepts
only a live, typed execution lease with a pinned process address space and requires interrupts
disabled so the binding cannot migrate
between validation and publication. A per-CPU generation-tagged handle enforces single ownership
and same-CPU teardown; duplicate, stale, forged, or mismatched unbind operations fail closed.

## Publication and ordering

CPU records and mappings are completed before the MP `goto_address` is published with release ordering. Secondary status transitions use release stores; the bootstrap processor observes them with acquire loads. Startup is successful only when every discovered processor reaches the online state before a one-second HPET deadline.

A serialized, generation-tagged rendezvous IPI can run bounded CPU-local initialization on every
online processor. Completion and success are recorded per CPU and must arrive before a 250 ms HPET
deadline. The syscall layer uses this path to install and read back `EFER.SCE`, `STAR`, `LSTAR`, and
`FMASK` on every processor before any persistent user execution is permitted.

## Cross-CPU test

Vector `0xE1` is reserved as a kernel IPI probe. The bootstrap processor sends a fixed IPI to every secondary processor and requires each CPU-local acknowledgement counter to advance before a 250 ms HPET deadline. The handler validates CPU identity and the local syscall-stack canary before acknowledging, then performs only an atomic counter increment and Local APIC EOI. The bootstrap processor additionally walks every syscall-stack mapping and requires supervisor-only, writable, NX pages plus unmapped guards.

Automated QEMU tests use four virtual processors for disk, ISO, low-memory, and high-memory configurations, plus explicit one-CPU and eight-CPU variants. This makes both uniprocessor fallback and multiprocessor startup required boot invariants rather than untested optional code.

## Deferred work

- Preemptive scheduling clocks and thread context switching
- Scheduler-aware cross-CPU calls and TLB shootdowns
- CPU hot-plug and graceful offlining
- x2APIC and interrupt-remapping support
- NUMA topology, locality-aware allocation, and affinity policy
- XSAVE/FPU ownership and user-mode context switching
