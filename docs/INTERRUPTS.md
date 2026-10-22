# ACPI and Interrupt Architecture

## Boot discovery

Doxxer obtains only the RSDP pointer from Limine. The kernel then validates the ACPI chain itself rather than accepting pre-parsed firmware data. RSDP v1 and extended checksums are verified, XSDT is preferred, and every referenced SDT must have a valid length and checksum. Root entry count, individual table size, MADT record length, I/O APIC count, and interrupt-override count are bounded.

The current milestone requires MADT and HPET. MADT supplies the bootstrap processor APIC identity, Local APIC address, I/O APIC descriptors, and ISA interrupt-source overrides. HPET supplies an independent monotonic clock used to calibrate and test the Local APIC timer. Missing or malformed mandatory data stops boot.

## Controller policy

Controller registers are mapped into a dedicated lower-half supervisor MMIO region. Mappings are writable, non-executable, global, and cache-disabled. They are intentionally separate from heap and stack arenas.

Initialization is fail-closed:

1. Verify the CPU advertises xAPIC and that the APIC-base MSR agrees with MADT.
2. Mask both legacy 8259 PICs.
3. Mask Local APIC timer, LINT, and error sources before enabling the APIC in software.
4. Enumerate every I/O APIC and mask every redirection entry.
5. Enable HPET and calibrate the Local APIC timer over a 10 ms reference interval.
6. Register private timer and spurious vectors, enable interrupts, and require at least three timer deliveries before a 250 ms HPET deadline.

I/O APIC inputs remain masked in this milestone. Device-specific routing will be introduced only with ownership metadata and handlers, avoiding a global Windows-style IRQ abstraction that lets unrelated subsystems manipulate arbitrary routes.

## Dispatch contract

CPU exceptions remain fatal unless they are part of an explicit boot self-test. Vectors 32–255 may return only when a kernel handler was registered while interrupts were disabled. Unregistered external vectors use the same register-rich fatal path as unexpected exceptions.

All vectors currently use an IST-backed interrupt frame. NMI, double fault, and machine check retain the separate emergency IST. Every online processor has private TSS/IST stacks while sharing the immutable IDT. The timer handler performs only a tick increment and Local APIC EOI; it does not allocate, log, or take heap locks.

## Deferred work

- Per-device I/O APIC routing and interrupt ownership
- MSI/MSI-X allocation and interrupt remapping
- Per-CPU timer state and deadline timers
- TSC-deadline mode and invariant-TSC timekeeping
- Power-management ACPI AML execution
- Physical-hardware quirk handling
