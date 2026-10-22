# Capability IPC

Doxxer IPC channels are fixed-capacity kernel objects. They provide a deliberately small,
allocation-free message transport for future system services.

## Invariants

- A channel contains eight FIFO messages with at most 64 payload bytes each.
- Sender, receiver, and administrator endpoints are separate capabilities.
- Every operation resolves a typed capability lease before touching a channel.
- Full and empty queues fail immediately; no unbounded waiting or allocation occurs.
- Destroying a channel invalidates its registered object generation, so all surviving endpoint
  tokens become stale.
- Payload tail bytes are cleared and consumed slots are zeroed.

Blocking waits and capability transfer are intentionally separate mechanisms. This keeps channel
ownership, scheduling, and authority delegation auditable rather than hiding them in one API.
