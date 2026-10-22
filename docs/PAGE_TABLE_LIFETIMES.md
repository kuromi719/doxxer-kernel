# Page-Table Graph Lifetimes

Doxxer treats its paging structures as a reference-counted graph rather than a collection of
unrelated allocator pages. The root PML4 of an address space is owned directly by that address
space. Every present, non-huge parent entry that points at a Doxxer-managed child table owns one
sealed reference to the child.

## Invariants

- A newly allocated child table is pinned before its parent entry becomes present.
- A parent entry is cleared before its child reference is released.
- A child is returned to the physical allocator only after its final graph reference is gone.
- Failed reference release leaks the now-unreachable table rather than risking reuse while linked.
- Each process that copies a shared supervisor-window PML4 entry acquires an independent reference.
- Detaching a process releases only its copies; the owner later tears down and frees the shared tree.
- Root PML4 pages are not graph-referenced because their `AddressSpace` object owns them directly.
- Page-table and allocator-metadata owners cannot pass through the ordinary supervisor leaf-mapping
  API. This prevents structural references from being confused with leaf mapping references.

The physical allocator seals the per-page reference count together with owner, domain, generation,
and allocation state. `free_page` fails while any graph reference remains. The VMM boot self-test
builds a real address space, attempts to free a linked PDPT, requires rejection, destroys all test
spaces, and then requires exact page and reference accounting restoration.

## Shared supervisor windows

The protection, per-CPU, scheduler, and temporary-access windows are shared at the PML4 boundary.
The kernel address space owns their lower tables. Child address spaces cannot mutate these reserved
PML4 slots, but each copied slot still pins the shared PDPT. This makes teardown order explicit and
prevents a child from freeing a table that another address space can still reach.

## Current boundary

The upper-half mappings inherited from Limine are not allocator-managed Doxxer table trees, so they
are not included in this ledger. Page-table inspection and editing also still use the firmware HHDM
through the narrow `direct_map_page_table` interface. A later milestone must construct fully
Doxxer-owned bootstrap mappings and bounded page-table editing windows before the inherited direct
map can be removed.

Reference counting prevents lifecycle reuse bugs; it does not make page tables immutable against
arbitrary code already executing with kernel privilege. SMP-safe remote TLB invalidation is also a
separate requirement before address spaces may execute concurrently on multiple processors.
