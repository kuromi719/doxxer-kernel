# Hardened Kernel Heap

## Layout

The heap owns a fixed 64 MiB lower-half virtual arena in the active Doxxer
address space. Its bitmap and allocation records are statically bounded, so the
allocator never recursively allocates metadata.

Small allocations use seven slab classes: 16, 32, 64, 128, 256, 512, and 1024
bytes. Each slab has one mapped 4 KiB data page between two unmapped guard pages.
Requests larger than 1024 bytes, or requiring alignment above 16 bytes, use
individually mapped pages with their own lower and upper guards. A single request
is currently limited to 8 MiB.

All heap mappings are supervisor-only, writable, and non-executable. The heap
does not expose physical addresses and does not create writable-executable
mappings.

## Corruption resistance

- Every live block has a header and tail canary derived from boot entropy, its
  virtual address, size class, and allocation state.
- Slab metadata has a separate keyed canary and is range-checked before use.
- Interior pointers, invalid alignment, unknown pointers, corrupted canaries,
  and double frees are rejected deterministically.
- Slab payloads are wiped through volatile stores when allocated and released.
- Freed slab objects enter a 64-entry FIFO quarantine before reuse. Their zeroed
  payload and free-state canary are revalidated when the quarantine expires.
- Released large allocations are wiped and immediately unmapped. Their virtual
  ranges remain reserved in quarantine so use-after-free access faults rather
  than aliasing a new object.
- Allocation accounting records live objects, requested bytes, committed slab
  and large pages, quarantine occupancy, and unexpected corruption events.

The current API reports invalid frees and corruption to its caller instead of
silently continuing. Security-sensitive subsystems should escalate these
failures to the kernel panic path. Global C++ `new`, `new[]`, `delete`, and
`delete[]` are connected to this API and panic on exhaustion or an invalid
release, providing fail-closed semantics for ordinary kernel objects.

## Boot validation

The boot self-test covers every slab class, page-backed aligned allocation,
zero-on-allocation, zero-on-free, slab growth, quarantine eviction, invalid
alignment, maximum-size rejection, keyed tail-canary corruption, double-free
rejection, the global C++ allocation path, guard presence, mapping permissions,
deterministic mixed-size allocation/free stress, and final live-allocation
accounting.

The allocator is lock-protected, but per-CPU caches and interrupt-safe locking
remain deferred until SMP and external interrupts are enabled.
