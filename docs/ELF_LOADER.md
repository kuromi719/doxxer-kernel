# Hardened ELF64 Loader

The ELF loader accepts a deliberately strict subset of x86_64 static executables and maps them
into an explicit address space.

- ELF64, little-endian, x86_64 `ET_EXEC` images only.
- At most 16 program headers and 128 mapped image pages.
- Loadable segments must be readable, page-aligned, bounded in the input, and in the user half.
- Writable-executable segments and overlapping pages are rejected.
- The entry point must lie inside an executable load segment.
- Pages are allocated zeroed, staged writable and non-executable, populated, then protected with
  their final W^X permissions.
- Segment bytes are populated through a short-lived supervisor-only, NX per-CPU mapping rather
  than through the inherited broad physical direct map.
- Any failure rolls back every page-table mapping and physical allocation.

The boot test loads synthetic code and data segments, verifies permissions and zero-filled BSS,
rejects a W+X image, and unloads without leaving mappings behind.
