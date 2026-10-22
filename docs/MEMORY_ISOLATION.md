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
VMM, image loader, user-stack code, user-copy layer, temporary-access path, and release path require
an exact domain match. Two processes therefore cannot exchange physical pages merely because both
pages have the same broad owner class. Domain identifiers are monotonic and fail closed on
exhaustion instead of being reused within the same boot.

The ledger additionally seals a per-page mapping-reference count. VMM mapping retains both user
and managed supervisor pages, unmapping releases them, and the allocator refuses to free any page
with a live reference. This prevents stale page-table entries from observing a page after it has
been recycled for a different object or domain. Address-space destruction requires an empty user
half rather than silently dissolving mappings, and managed user pages cannot be inserted through
the general supervisor mapping path. Non-leaf page-table edges use a separate global reference
class: publishing a parent entry pins the managed child table, removing the entry releases it, and
every copied supervisor-window root contributes its own reference. Page-table and metadata pages
are rejected by the ordinary supervisor leaf-mapping path, keeping structural and leaf references
type-separated. No public physical-memory API exposes a broad-direct-map pointer for user or
general kernel-owned pages.

Pages are zeroed both before allocation is returned and before release. The shadow generation is
advanced on every state transition so stale ownership observations cannot silently match a later
allocation. Self-tests verify zeroing, zone behavior, wrong-owner rejection, double-free rejection,
and allocation-accounting restoration.

This is defense in depth against memory-lifecycle bugs and cross-subsystem confusion; it is not a
claim that software can make RAM unreadable to a CPU already executing fully compromised kernel
code. The runtime loader, user-copy layer, and privilege probes now access user-owned RAM through
short-lived per-CPU supervisor-only NX windows. The current prototype still trusts its
firmware-created bootstrap page tables and uses their broad direct map for allocator bootstrap and
page-table editing. See `PAGE_TABLE_LIFETIMES.md` for the current graph invariant. Later milestones
should replace those mappings with Doxxer-owned bootstrap tables and dedicated editing windows, add
guard pages to more object classes, and enable hardware RAM encryption and measured boot on
platforms that provide them.
