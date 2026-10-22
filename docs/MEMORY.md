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

## Planned virtual memory layer

The next memory milestone will add an x86_64 page-table owner with:

- NX-by-default mappings and explicit read/write/execute permissions;
- canonical-address and overflow validation;
- 4 KiB pages with optional 2 MiB promotion for suitable immutable ranges;
- recursive or direct-map page-table editing without ambient raw pointers;
- address-space identifiers prepared for PCID support;
- TLB invalidation APIs that can later grow into SMP shootdowns;
- guard pages around kernel stacks and sensitive allocator regions; and
- a small kernel heap layered on virtual mappings rather than physical addresses.

Virtual mappings will use the physical manager as a mechanism, while higher
layers decide ownership and capability policy.
