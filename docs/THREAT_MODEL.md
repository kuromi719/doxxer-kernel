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
- Serial panic diagnostics followed by an interrupt-disabled halt.

## Out of scope for milestone 1

- Physical attackers and evil-maid attacks.
- Malicious firmware, hypervisor, bootloader, compiler, or hardware.
- Secure Boot, measured boot, TPM attestation, and disk encryption.
- Side-channel resistance.
- Isolation between applications, because user mode does not yet exist.

## Planned direction

Future milestones should add page-based W^X enforcement, exception handling, a physical and virtual memory manager, ring-3 processes, capability-oriented resource access, signed updates, and a deliberately narrow network stack. Each milestone must update this document before expanding the trusted computing base.
