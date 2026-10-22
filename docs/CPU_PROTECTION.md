# CPU Protection and Exception Architecture

## Descriptor ownership

Doxxer replaces firmware and bootloader descriptor state before declaring the
kernel ready. Its private GDT contains kernel and future ring-3 code/data
descriptors plus a 64-bit available TSS descriptor. The TSS denies ring-3 port
I/O by placing its bitmap beyond the descriptor limit and records the future
ring-3 transition stack in `RSP0`.

The IDT owns all 256 vectors. Assembly stubs normalize hardware and synthetic
error codes, preserve every general-purpose register, clear the direction flag,
and pass a stable `ExceptionFrame` to C++. Interrupt gates keep maskable
interrupts disabled while privileged exception state is inspected.

## Guarded stacks

The active kernel address space contains three 64 KiB supervisor-only stacks:

- the normal kernel runtime stack;
- IST1 for ordinary exceptions and page faults; and
- IST2 for double fault, NMI, and machine check emergencies.

Each mapping is NX and has an unmapped 4 KiB guard page below and above it. The
upper guard also makes the stack top an exact page boundary: the first hardware
push lands in mapped memory, while overflow and underflow fail closed.

After the new PML4, GDT, TSS, and IDT become active, execution permanently moves
off the Limine boot stack and onto the guarded Doxxer runtime stack.

## Failure handling

Expected boot probes may recover from only two precisely scoped events:

1. an `INT3` verifies gate dispatch and return; and
2. a read from the runtime stack's lower guard verifies page-fault error state,
   `CR2`, recovery RIP rewriting, and IST placement.

All other exceptions are fatal. The serial/framebuffer logger reports the
vector, symbolic name, error code, RIP, CS, RFLAGS, RSP, SS, CR2, and every
general-purpose register before entering the interrupt-disabled halt loop.

External IRQ routing and interrupt enablement remain deferred until a local APIC
and timer layer can acknowledge sources deterministically.
