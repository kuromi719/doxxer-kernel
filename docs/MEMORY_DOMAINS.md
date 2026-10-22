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
- kernel direct-map access to user-owned physical pages.

Owner class and domain are separate invariants. For example, a `user_data` page owned by process A
still cannot be mapped, copied, directly accessed, or released through process B's address space.
The domain is included in the boot-keyed shadow seal, so changing it without updating the protected
metadata is detected as an integrity failure.

Boot self-tests allocate two independent address spaces and verify that cross-domain page mapping,
direct access, and release all fail while the owning domain retains access. Pages continue to be
zeroed on both allocation and release.

Memory domains prevent accidental or confused-deputy cross-process RAM reuse through supported
kernel APIs. They do not protect against arbitrary code execution in the kernel or physical attacks.
Removing the inherited broad direct map and replacing it with short-lived mapping windows remains a
separate hardening milestone.
