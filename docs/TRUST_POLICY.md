# Doxxer Image Trust Policy

Doxxer uses a closed-by-default executable admission model. Executable bytes are not accepted merely
because they are structurally valid ELF64. The loader first copies the complete bounded input into
kernel-owned memory, computes its SHA-256 digest, and asks the kernel image policy to authorize that
exact snapshot.

## Policy lifecycle

1. The policy begins in an enrollment phase during trusted early boot.
2. Trusted image digests are enrolled into a fixed-capacity table.
3. The policy is sealed exactly once before user execution becomes possible.
4. After sealing, enrollment and duplicate mutation attempts are rejected permanently.
5. Only exact digest matches can reach ELF parsing and W^X mapping.

The trusted table is fixed-size and uses no attacker-controlled allocation. Digest comparisons process
all bytes and authorization checks every enrolled entry. The ELF loader separately enforces its size,
layout, address-range, entry-point, and W^X invariants; a trusted digest does not bypass format safety.

## Current trust boundary

This milestone proves the fail-closed kernel mechanism using boot-time enrolled test images. It does
not yet prove firmware, bootloader, or kernel authenticity. Production enrollment will be replaced by
an offline-signed Doxxer system manifest verified against a public key compiled into the kernel, then
anchored to UEFI Secure Boot and measured boot. Until that chain exists, “closed” means the runtime
loader rejects unknown executable content—not that compromised firmware or physical hardware is
impossible.
