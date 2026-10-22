# Shadow Memory Regions

Doxxer materializes an authenticated sealed secret only inside a short-lived supervisor region.
Each region has a dedicated non-executable data page, unmapped guard pages on both sides, and a
separate non-executable shadow page. The shadow page is normally read-only and records addressable
bytes at a 1:16 scale; the unused tail remains poisoned. Kernel components use bounded read/write
operations which consult this shadow state before accessing the working page.

The region table is generation-safe and protected by a boot-keyed integrity seal covering the slot,
generation, exact secret size, state, and both physical-page identities. Physical pages use distinct
`secret_working` and `shadow_region` owners in the allocator's sealed page ledger. Neither owner is
eligible for user mapping. Closing a region poisons its shadow, explicitly wipes the full working
page, removes both mappings, releases the physical pages, and advances the generation so a stale
handle cannot access a reused slot.

The boot self-test verifies sealed-to-shadow materialization, bounded access, poisoned-tail
rejection, resealing after an authorized update, stale-handle rejection, mapping cleanup, and exact
physical/reference-count restoration.

## Security boundary

Shadow regions provide spatial and temporal validation around the brief plaintext working set. They
do not encrypt bytes while the CPU is actively operating on them and they are not compiler-wide
memory-safety instrumentation. Persistent secrets remain in the authenticated sealed-memory vault;
callers should open a region only for the shortest required interval and reseal or close it
immediately. Hardware memory encryption is still required to make active RAM transparently
ciphertext against physical probing.
