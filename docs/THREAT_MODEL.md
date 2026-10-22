# Initial Threat Model

## Security objective

Doxxer is intended to become a privacy-focused desktop operating system with a deliberately small attack surface. This document covers the architectural direction; the first boot prototype does not yet enforce the full model.

## Prioritized attackers

1. A remote attacker attempting to exploit network-facing code.
2. A malicious or compromised user application attempting privilege escalation or unauthorized data access.
3. Malformed boot-time inputs intended to corrupt privileged kernel state.

## Trusted computing base

The current prototype trusts the CPU, QEMU/firmware, Limine, the kernel image, and the local build toolchain. The kernel performs strict validation of Limine responses before use. Third-party dependencies are pinned to explicit Git commits.

## Current mitigations

- No network stack, user applications, dynamic modules, or general-purpose drivers.
- Freestanding build without the hosted C++ runtime.
- Exceptions and RTTI disabled.
- Entropy-seeded stack protector after a minimal unprotected entry shim.
- Separate RX, R, and RW ELF load segments; no writable-executable load segment.
- Non-executable stack declaration.
- Bounds-checked framebuffer writes and fail-closed boot validation.
- Memory-map validation before allocator startup; reserved and non-usable regions are never admitted to the allocator.
- Separate DMA32 and normal allocation zones, aligned contiguous allocation, double-free rejection, and lock-protected allocator metadata.
- Physical pages are wiped both when allocated and when returned, limiting cross-subsystem data remnants.
- New address spaces enforce NX by default and reject writable-executable mappings; unmapped guard pages remain non-present.
- Page-table operations reject non-canonical addresses, misalignment, duplicate mappings, and invalid huge-page operations.
- The active kernel address space uses supervisor-only, NX stacks with unmapped guards on both ends.
- A private GDT/TSS/IDT routes exceptions through known assembly frames and dedicated IST stacks; double fault, NMI, and machine check use the emergency IST.
- Boot probes exercise a breakpoint and a real guard-page fault, including recovery and verification that exception frames landed on the intended IST.
- Fatal exceptions report vector, error code, CR2, control state, and general registers before halting with interrupts disabled.
- Dynamic allocations are zeroed on allocation and release, protected by entropy-derived metadata and tail canaries, and delayed through a bounded quarantine.
- Slab pages and page-backed allocations have unmapped guards; released large objects are immediately unmapped so stale access faults.
- ACPI root and child tables are checksum-validated and bounded before MADT/HPET fields are accepted; malformed entry lengths, duplicate critical tables, invalid interrupt overrides, and oversized tables fail closed.
- Interrupt-controller MMIO is remapped supervisor-only, non-executable, writable, and cache-disabled instead of being accessed through an arbitrary inherited alias.
- The legacy PIC is fully masked and every I/O APIC redirection entry begins masked. Only the private periodic Local APIC timer is enabled in this milestone.
- Timer delivery is tested through the real IDT/IST path against an independent HPET deadline before boot is considered successful.
- Each secondary processor receives separate guarded kernel, exception, and emergency stacks plus a private GDT/TSS. A CPU cannot accidentally share another CPU's busy TSS or exception stack.
- CPU-local identity is rooted at a kernel-controlled GS base and cross-checked against the Local APIC ID in the IPI path. Processor startup and IPI acknowledgement both use bounded HPET deadlines.
- Secondary processors execute only bounded scheduler-owned run-to-completion tasks and otherwise remain in an interruptible halt loop; resumable or user-controlled threads do not exist yet.
- Kernel task dispatch uses bounded per-CPU queues and a fixed task pool rather than attacker-controlled dynamic queue growth. Every task executes on a dedicated supervisor-only NX stack with unmapped boundary guards, a keyed layout canary, and full stack wiping between uses.
- Task handles include generations to reject stale release/completion operations. Queue and lifecycle publication use locks plus acquire/release atomics, while IPI wakeups carry no caller-controlled function pointer.
- Kernel authority is represented by typed, rights-limited capabilities rather than ambient global handles. Derived capabilities cannot gain rights, and revoking any ancestor invalidates its entire descendant chain without a global scan.
- Capability tokens combine a slot, a 22-bit generation, and an entropy-keyed 36-bit authentication tag. Tokens are validated against their domain nonce, complete metadata, parent chain, object type, and required rights before use.
- Object access returns a pinned lease. Destruction fails while leases exist, preventing capability validation from becoming a time-of-check/time-of-use pointer race.
- Serial panic diagnostics followed by an interrupt-disabled halt.

## Out of scope for milestone 1

- Physical attackers and evil-maid attacks.
- Malicious firmware, hypervisor, bootloader, compiler, or hardware.
- Secure Boot, measured boot, TPM attestation, and disk encryption.
- Side-channel resistance.
- Isolation between applications, because user mode does not yet exist.
- Capability authentication is defense in depth for kernel handles, not a substitute for syscall-boundary isolation or cryptographic authentication across machines.

## Planned direction

Future milestones should rebuild inherited kernel mappings with section-granular permissions, add per-device interrupt routing and preemptive threads, ring-3 processes, capability-oriented resource access, signed updates, and a deliberately narrow network stack. Allocator hardening does not make memory-unsafe kernel code safe; detected corruption still requires a fail-closed caller policy. Each milestone must update this document before expanding the trusted computing base.
