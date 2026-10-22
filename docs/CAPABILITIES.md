# Capability Security Model

## Objective

Doxxer is capability-first: possessing an explicit capability is the prerequisite for operating on a kernel object. Subsystems should not gain authority merely because they run inside a shared process or know a global object number. This model is established before user mode so later syscalls can validate the same invariants at the privilege boundary.

The current registry is intentionally bounded to 16 domains, 64 objects, and 64 capability slots per domain. Exhaustion is reported instead of triggering hidden allocation or eviction.

## Token structure

A capability token is an opaque 64-bit value containing:

- 6-bit capability slot
- 22-bit reuse generation
- 36-bit keyed authentication tag

The tag covers the domain nonce and all security-relevant entry metadata: slot and generation, object identity and generation, object type, rights, and derivation parent. Its key is derived from boot entropy. A modified or cross-domain token therefore fails validation before object access.

The tag is a kernel hardening mechanism, not a network cryptographic primitive. Security does not rely on secrecy alone: all metadata, generations, ancestry, rights, type, and object lifetime are independently validated.

## Rights and attenuation

Defined rights are `inspect`, `read`, `write`, `signal`, `wait`, `map`, `derive`, `transfer`, and `administer`. Unknown or empty right sets are rejected.

A trusted kernel subsystem may grant a root capability. Derivation requires the parent's `derive` right and can only preserve or remove existing rights. It cannot change the referenced object or type. Derivation ancestry is bounded, preventing malicious cycles or unbounded validation work.

Cross-domain delegation separately requires the `transfer` right. The receiving domain gets only
the requested subset of the sender's rights, and the delegated entry retains a generation-checked
ancestry link to its source.

## Revocation

Each child records its parent's domain, slot, and generation. Revoking a capability invalidates
that slot and advances its generation. Descendants then fail ancestry validation because the
recorded parent generation no longer exists. This provides recursive revocation without scanning
every domain entry, including when ancestry crosses domain boundaries.

Slot reuse cannot revive an old token: generations advance and the keyed tag changes. Recreating a domain also rotates its nonce, invalidating every token from the earlier incarnation.

## Object lifetime

Objects have independent generational handles. Successful capability acquisition creates a pinned lease and increments the object's lease count under the registry lock. An object cannot be unregistered while any lease exists. Lease release validates object identity and generation before decrementing the pin.

This prevents a common time-of-check/time-of-use failure where a capability resolves to a pointer that is freed and reused before the caller operates on it.

## Boot validation

The self-test exercises:

- Typed acquisition with an allowed right
- Rejection of missing administrator authority
- Rights attenuation and attempted amplification
- Parent revocation invalidating a child
- Stale-token rejection after slot reuse
- Token inequality across generations
- Object destruction blocked by a live lease
- Object-generation invalidation after destruction
- Domain-generation invalidation after teardown
- Cross-domain attenuation and source-revocation propagation

Every negative test must be rejected before the capability model is declared online.

## Deferred work

- Per-process domain ownership and syscall copying
- Revocation notifications for queued or blocked receivers
- Object-specific policy adapters
- Audit identities and structured denial telemetry
- Scalable registries beyond the fixed prototype limits
- Revocation notifications for blocked waiters
