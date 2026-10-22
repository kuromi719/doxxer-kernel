# Memory Isolation

Doxxer's physical allocator maintains a dedicated shadow ledger alongside its allocation bitmaps.
The ledger is placed in allocator-reserved RAM and is never eligible for allocation. Each physical
page has an owner class, a monotonically changing generation, mirrored allocation state, and a
boot-secret-derived integrity seal. Allocation, mapping, and release paths validate the shadow state
under the allocator lock and fail closed on a mismatch.

Current owner classes separate page tables, heap pages, supervisor stacks, user images, user stacks,
user data, IOMMU tables, and test pages. Callers must provide the expected owner when mapping or
freeing a page. This blocks cross-subsystem confused-free and direct-map mistakes. User mappings are
accepted only for user-owned pages; executable user mappings are accepted only for image pages.
Kernel heap, page-table, IOMMU, and stack pages therefore cannot be exposed through the user mapping
API. User-copy operations likewise reject physical pages outside the user-owner set.

User-owned pages also carry a nonzero address-space isolation domain inside the sealed entry. The
VMM, image loader, user-stack code, user-copy layer, direct-access path, and release path require an
exact domain match. Two processes therefore cannot exchange physical pages merely because both
pages have the same broad owner class. Domain identifiers are monotonic and fail closed on
exhaustion instead of being reused within the same boot.

Pages are zeroed both before allocation is returned and before release. The shadow generation is
advanced on every state transition so stale ownership observations cannot silently match a later
allocation. Self-tests verify zeroing, zone behavior, wrong-owner rejection, double-free rejection,
and allocation-accounting restoration.

This is defense in depth against memory-lifecycle bugs and cross-subsystem confusion; it is not a
claim that software can make RAM unreadable to a CPU already executing fully compromised kernel
code. The current prototype also trusts its firmware-created bootstrap page tables until Doxxer
switches to its own tables. Later milestones should remove the broad bootstrap direct map, use
short-lived per-CPU mapping windows, add guard pages to more object classes, and enable hardware RAM
encryption and measured boot on platforms that provide them.
