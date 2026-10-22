# User Memory Access

User-memory helpers translate through an explicit address space and the kernel's physical direct
map. The kernel never directly dereferences an untrusted virtual address.

- The null region below 64 KiB and the canonical kernel half are always rejected.
- Ranges are overflow checked and individually bounded to 1 MiB.
- Every crossed page is queried and must carry the user bit.
- Writes require writable mappings and instruction fetch validation requires executable mappings.
- Copy operations handle page boundaries and use the physical address returned by the page-table
  query, including its in-page offset.

The self-test copies across two pages, removes write permission from the second page, verifies that
reads still work, and checks null, kernel-half, overflow, and oversized-range rejection.
