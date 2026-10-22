# Capability Events

Events are bounded synchronization objects intended to connect IPC readiness to the scheduler
without granting unrelated authority.

- Signaling, waiting, and administration use independent typed capabilities.
- Auto-reset events consume one pending signal; manual-reset events remain signaled until reset.
- The current API is non-blocking. A failed wait never spins while holding a kernel lock.
- Event destruction invalidates the registered object generation and every stale endpoint.
- The registry has a fixed capacity of 32 events and performs no runtime allocation.

A later scheduler milestone can park tasks on events while retaining these object and authority
semantics.
