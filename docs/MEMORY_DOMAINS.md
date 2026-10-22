# Address-Space Memory Domains

Doxxer binds every user-owned physical page to exactly one address-space isolation domain. A domain
is a monotonically assigned 32-bit identifier stored in the physical allocator's sealed shadow
ledger. Domain zero is reserved for kernel-owned memory, and user pages cannot be allocated into it.
Identifiers are never reused during a boot; exhaustion fails address-space creation instead of
wrapping to a stale identity.

The domain is checked independently at every security-sensitive boundary:

- creation and release of user image, stack, and data pages;
- insertion or permission changes in user page tables;
- ELF image population and teardown;
- user stack construction and destruction;
- validated user-memory copies and execute-range checks;
- absence of a public broad-direct-map accessor for user-owned pages.

Every successful user mapping also pins each physical page through a reference counter stored inside
the sealed shadow entry. Unmapping releases the pin. A mapped page cannot be freed, reclassified, or
reused, closing the stale-page-table alias that would otherwise let an old virtual address observe a
later owner's data. Multiple aliases are counted independently, counter overflow fails closed, and
an address space cannot be destroyed while user mappings remain. User/supervisor classification
cannot be changed through the permission-update operation.

The general supervisor mapping API rejects managed user-owned pages, and the physical allocator
does not publish a broad-direct-map accessor for them. Kernel code that knows a physical address
therefore cannot bypass the supported domain checks by requesting a persistent supervisor alias.

Owner class and domain are separate invariants. For example, a `user_data` page owned by process A
still cannot be mapped, copied, directly accessed, or released through process B's address space.
The domain is included in the boot-keyed shadow seal, so changing it without updating the protected
metadata is detected as an integrity failure.

Boot self-tests allocate two independent address spaces and verify that cross-domain page mapping,
supervisor-alias insertion, direct access, and release all fail while the owning domain retains
access. They also prove that a live mapping blocks release and that the page becomes releasable only
after its final mapping reference is removed. Runtime user-page access additionally requires a
domain-checked ephemeral supervisor window. Pages continue to be zeroed on both allocation and
release.

Memory domains prevent accidental or confused-deputy cross-process RAM reuse through supported
kernel APIs. They do not protect against arbitrary code execution in the kernel or physical attacks.
The inherited broad direct map remains a bootstrap and page-table-editing dependency. Routine
user-page access has moved to short-lived per-CPU windows; removing the remaining inherited alias
requires Doxxer-owned bootstrap page tables.
