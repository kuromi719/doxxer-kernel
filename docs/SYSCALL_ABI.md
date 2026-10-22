# Syscall ABI Foundation

The first Doxxer syscall contract is a versioned, pointer-free request envelope. It is deliberately
separate from the future x86_64 `SYSCALL/SYSRET` entry assembly.

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

The boot self-test exercises all supported object families plus invalid version, flag, and call
number rejection. Hardware privilege transition, user-copy recovery, and per-thread syscall state
remain required before exposing this dispatcher to ring 3.
