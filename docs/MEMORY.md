# Doxxer Memory Architecture

## Principles

Doxxer does not reproduce another operating system's allocator ABI. Its memory
subsystem is built around explicit ownership, narrow interfaces, deterministic
failure, and data-remanence protection. Policy is kept separate from page-table
mechanics so that later capability domains can receive independent address
spaces without weakening the physical allocator.

## Physical memory manager

The current allocator consumes Limine's normalized memory map and HHDM response.
Every input range is overflow-checked and rounded inward to complete 4 KiB pages.
Only `LIMINE_MEMMAP_USABLE` pages are admitted; bootloader-reclaimable and ACPI
memory stay reserved until an explicit later transition.

The HHDM translation helper remains available for valid non-managed physical
objects such as boot page tables and MMIO. Being direct-mapped does not make a
page allocator-owned; allocation and release still require managed-bitmap state.

Two independent bitmaps are stored inside a reserved usable-memory range:

- **managed:** the page belongs to an allocator-controlled usable range;
- **used:** the managed page currently has an owner.

Keeping these states separate makes invalid frees and attempts to release holes,
MMIO, firmware, or allocator metadata rejectable instead of silently corrupting
state. Bitmap sizing follows the highest usable RAM address rather than the
highest MMIO descriptor, preventing sparse firmware mappings from consuming
large amounts of metadata.

### Allocation policy

- The public unit is a 4 KiB physical page.
- Single-page and aligned contiguous allocations are supported.
- `DMA32` and `normal` zones are tracked independently.
- Unconstrained allocations prefer normal memory, preserving scarce DMA32 pages.
- Next-fit hints reduce repeated scans without hiding fragmentation.
- Metadata updates are protected by a spinlock for future SMP use.
- Pages are zeroed before handoff and wiped again before becoming reusable.
- Page zero, non-usable ranges, and allocator metadata can never be allocated.

### Boot-time invariants

The boot self-test verifies:

1. single-page allocation;
2. aligned contiguous allocation;
3. explicit DMA32 and normal-zone boundaries when those zones exist;
4. zero-filled delivery;
5. invalid-alignment rejection;
6. double-free rejection; and
7. exact free/allocated accounting restoration.

A failed invariant takes the serial panic path and halts before the kernel is
declared ready.

## Virtual memory manager

The x86_64 virtual memory manager owns complete four-level page-table trees for
future processes and protected kernel domains. Virtual mappings use the physical
manager as a mechanism, while higher layers decide ownership and capability
policy.

Current invariants and capabilities:

- mappings are non-executable by default;
- writable-executable mappings are rejected rather than silently weakened;
- canonical addresses, physical-address width, and alignment are validated;
- both 4 KiB and aligned 2 MiB mappings are supported;
- supervisor/user, global, execute, write, and cache policy are explicit;
- missing pages naturally act as guard pages;
- duplicate maps and repeated unmaps fail deterministically;
- empty intermediate tables are pruned and returned to the physical allocator;
- complete inactive address spaces can be destroyed without freeing leaf data;
- new spaces inherit a shared, immutable kernel half while owning only their lower-half tables;
- public mapping operations cannot mutate the shared kernel half;
- address-space identifiers retain a validated 12-bit PCID for later activation;
- active-space edits perform local `invlpg` invalidation; and
- page-table operations are lock-protected in preparation for SMP.

The boot self-test builds an isolated address space, checks W^X and unknown-flag
rejection, translates offset addresses through both page sizes, validates a
non-present guard page, temporarily activates the new CR3 and verifies a real
hardware alias, restores the boot address space, changes permissions, unmaps both
mappings, destroys the page-table tree, and verifies exact physical-page
accounting restoration.

The kernel now activates an owned PML4 whose upper half inherits the immutable
boot mappings and whose lower half contains supervisor-only runtime and
exception stacks. Every 64 KiB stack is non-executable and isolated between an
unmapped lower and upper guard page. The boot stack is abandoned after the new
GDT, TSS, IDT, and fault probes are validated.

The next memory milestone will reconstruct the inherited upper half with
Doxxer-owned section-granular mappings and layer a small kernel heap on virtual
mappings. PCID activation and SMP TLB shootdowns remain disabled until CPU
discovery and inter-processor interrupt support exist.
