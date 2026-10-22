# Syscall ABI Foundation

The first Doxxer syscall contract is a versioned, pointer-free request envelope. It remains
separate from production x86_64 entry assembly. Boot now verifies a single-shot CPL3-to-kernel
`SYSCALL` transition, but that probe deliberately does not expose this dispatcher to user code.

## Contract

- Every request carries ABI version 1, a call number, zeroed flags, four scalar arguments, and an
  optional 64-byte inline payload.
- The dispatcher never dereferences caller-provided addresses. A later entry layer must copy the
  fixed request into kernel memory before dispatch.
- Capability tokens remain opaque scalar arguments and every object operation revalidates type,
  rights, ancestry, generation, and lifetime.
- Responses are completely initialized before dispatch and expose only four scalar results plus a
  bounded inline payload.
- Unknown flags, versions, numbers, oversized payloads, and unavailable authority fail closed.

## Calls

ABI 1 supports feature discovery, IPC send/receive, event signal/try-wait, and process
inspect/terminate. Empty queues and authorization failures deliberately share a coarse result at
this layer to reduce accidental object-existence disclosure.

The dispatcher boot self-test exercises all supported object families plus invalid version, flag,
and call number rejection. The architecture probe independently validates hardware privilege
entry, selector state, user RIP/RSP capture, CR3 restoration, and MSR restoration. Per-CPU syscall
stacks, request copying, canonical return validation, and scheduler integration remain required
before exposing this dispatcher to ring 3.
