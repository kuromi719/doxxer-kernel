# User Memory Access

User-memory helpers translate through an explicit address space and a per-CPU ephemeral mapping
window. The kernel never directly dereferences an untrusted virtual address and normal runtime
copies do not expose the page through the inherited broad physical direct map.

- The null region below 64 KiB and the canonical kernel half are always rejected.
- Ranges are overflow checked and individually bounded to 1 MiB.
- Every crossed page is queried and must carry the user bit.
- Writes require writable mappings and instruction fetch validation requires executable mappings.
- Copy operations handle page boundaries and use the physical address returned by the page-table
  query, including its in-page offset.
- Each page-sized access is exposed through a supervisor-only, NX alias, pinned for the mapping
  lifetime, locally invalidated on removal, and writable only for copy-to-user or zero operations.

The self-test copies across two pages, removes write permission from the second page, verifies that
reads still work, and checks null, kernel-half, overflow, and oversized-range rejection.

The syscall layer consumes these helpers through a process-bound gateway. A live address-space
lease carries the exact capability domain of its process, and lease validation checks the process
cookie, address-space identity, domain generation, lifecycle state, and pin count before accepting
a user request. The complete request is copied into kernel storage before dispatch, and the fully
initialized response is copied back only through a writable user mapping.
