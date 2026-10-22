# Ephemeral User-Memory Windows

Doxxer does not use the inherited broad physical direct map for normal runtime access to
user-owned pages. Instead, each processor receives one 4 KiB temporary slot in a dedicated
supervisor mapping window. The ELF loader, validated user-copy layer, and protection probes use
this interface whenever kernel code must inspect or modify user RAM.

A temporary mapping is created only after the physical page's owner and address-space isolation
domain have been validated. Creation adds a sealed mapping reference, preventing the allocator
from freeing or recycling the page while the window exists. The resulting alias is supervisor-only,
non-executable, and read-only unless the caller explicitly requests write access.

Interrupts remain disabled for the complete mapping lifetime so execution cannot migrate to a
different processor. A slot lock and active-state check reject nested or colliding use. Teardown
removes the PTE, invalidates the local TLB entry before reuse, releases the page pin, and restores
the previous interrupt state. If teardown cannot remove a mapping, the slot stays quarantined and
cannot be reused silently.

Boot-time enforcement creates and tears down a real window while preparing the SMEP probe. Boot
continues only when every temporary slot is idle and the successful map/unmap counters agree.

## Current boundary

Slot selection currently uses the processor's 8-bit initial APIC ID, matching the prototype's
QEMU/xAPIC target and its maximum of 256 slots. Supporting x2APIC systems with larger identities
requires switching slot selection to the kernel CPU-local index.

The firmware-created HHDM is still retained for early allocator bootstrap, page-table editing, and
explicit physical-memory self-tests. Eliminating that inherited broad alias requires Doxxer-owned
bootstrap page tables and separate short-lived page-table editing windows. The current mechanism
therefore reduces routine user-page exposure; it is not a claim that RAM is unreadable after
arbitrary kernel compromise or physical access.
