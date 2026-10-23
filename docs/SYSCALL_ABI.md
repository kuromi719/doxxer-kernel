# Syscall ABI Foundation

The first Doxxer syscall contract is a versioned, pointer-free request envelope. It remains
separate from production x86_64 entry assembly. Boot now verifies a single-shot CPL3-to-kernel
`SYSCALL` transition and dispatches a fixed `abi_info` request through the real user-copy gateway.

## Contract

- Every request carries ABI version 1, a call number, zeroed flags, four scalar arguments, and an
  optional 64-byte inline payload.
- The dispatcher never dereferences caller-provided addresses. The user gateway copies the fixed
  request into kernel memory before dispatch.
- Capability tokens remain opaque scalar arguments and every object operation revalidates type,
  rights, ancestry, generation, and lifetime.
- Responses are completely initialized before dispatch and expose only four scalar results plus a
  bounded inline payload.
- Unknown flags, versions, numbers, oversized payloads, and unavailable authority fail closed.
- The user gateway accepts only a live process address-space lease and uses the capability domain
  stored in that same validated process object; callers cannot supply an unrelated domain beside
  an address space.
- Complete request and response structures cross the boundary only through the page-aware
  user-copy layer. The dispatcher never receives a user pointer, and overlapping request/response
  ranges are safe because the request is snapshotted before dispatch.
- A read-only/unmapped response or invalid request range rejects the operation without a direct
  kernel dereference. Copy failures have dedicated accounting.

## Calls

ABI 1 supports feature discovery, IPC send/receive, event signal/try-wait, and process
inspect/terminate. Empty queues and authorization failures deliberately share a coarse result at
this layer to reduce accidental object-existence disclosure.

The dispatcher boot self-test exercises all supported object families plus invalid version, flag,
and call number rejection. It also constructs two real user pages in a child process, copies an
`abi_info` request through the temporary mapping window, dispatches it under the child capability
domain, copies the initialized response back, and rejects read-only and non-canonical ranges. The
architecture probes validate hardware privilege entry, selector state, user RIP/RSP capture, CR3
restoration, the same process-bound copy gateway, response contents, and MSR restoration. After SMP
startup, a deadline-bounded rendezvous installs and reads back the runtime syscall MSRs on every
online CPU. A second two-call probe exercises `SWAPGS`, a CPU-local guarded syscall stack, process
binding, canonical/mapping/flag return validation, and an actual fixed-selector `IRETQ` return to
user code. The probe also resumes from a validated user-origin invalid-opcode exception through a
`SWAPGS`-safe interrupt entry before making its second syscall. Its binding is owned by the
scheduler and accepts only an execute-authorized, exclusive user-thread execution lease whose
process address space remains pinned. Binding is single-owner per CPU,
requires interrupts disabled, and is released by a same-CPU generation-tagged handle; duplicate
and forged-generation operations are rejected. Persistent user-thread dispatch and general process
fault termination remain required before allowing arbitrary long-lived ring-3 callers.
