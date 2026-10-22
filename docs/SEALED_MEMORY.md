# Authenticated Sealed Memory

Doxxer provides a bounded kernel vault for secrets that must remain encrypted while idle. The vault
currently exposes 32 generation-safe records of up to 1024 bytes each. It does not allocate while
holding its lock and never stores a persistent plaintext copy.

## Construction

- Independent 256-bit encryption and authentication keys are derived from Limine boot entropy with
  domain-separated SHA-256 labels.
- Records use ChaCha20 with a boot-unique 96-bit nonce and monotonically increasing 64-bit counter.
- Encrypt-then-MAC uses HMAC-SHA-256 over the slot, generation, exact length, nonce, and ciphertext.
- Authentication is checked in constant time before decryption. A failed check zeros the caller's
  destination and returns no length.
- Destroying a record explicitly wipes its nonce, ciphertext, and tag before advancing its
  generation, so stale handles cannot reopen a recycled slot.
- Temporary keys, hash state, stream blocks, tags, and plaintext self-test buffers are explicitly
  zeroed through volatile stores.

Boot tests use published RFC ChaCha20 and HMAC-SHA-256 vectors, verify a round trip, corrupt stored
ciphertext, require authentication failure and output zeroization, then verify stale-handle
rejection after destruction.

## Security boundary

Software sealing protects registered secrets while they are idle in the vault. Data must briefly
exist in CPU registers, caches, and an explicitly supplied working buffer while an authorized
kernel component uses it. Therefore this mechanism does **not** claim that every live RAM byte is
always ciphertext. Transparent protection against physical RAM probing requires supported hardware
memory encryption (for example AMD SME or Intel TME), platform firmware enablement, and later
attestation. Doxxer will fail closed for workloads that request that stronger policy when the
hardware capability is unavailable.
