# Service Registry

The service registry maps a small validated name to an existing provider capability. It does not
create ambient authority: resolution delegates only the rights explicitly offered by the provider.

- Names contain 1-31 lowercase ASCII letters, digits, dots, or hyphens.
- Duplicate names and malformed names are rejected.
- Publishing requires an inspectable source capability carrying `transfer`.
- Offered rights cannot exceed the source capability and never include `transfer` automatically.
- Resolution creates a cross-domain delegated capability, preserving revocation ancestry.
- Withdrawal is capability-gated and invalidates the registration object generation.

The fixed registry holds 32 services and performs no dynamic allocation. A dead or revoked
provider source naturally makes subsequent resolution fail closed.
