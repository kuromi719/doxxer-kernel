# User Thread Contexts

User-thread objects own the validated state required for scheduled ring-3 execution. The runtime
hardware probe now acquires an ordinary user-thread execution lease and consumes that object's
entry point, guarded stack, pinned process address space, and capability identity when entering
CPL3. General persistent application scheduling is not implemented yet.

- Creation requires a process control capability with `map` authority.
- The entry point must already be mapped user-executable in the process address space.
- Each thread receives eight writable, non-executable stack pages and one unmapped lower guard
  page in a deterministic non-overlapping region.
- Initial RFLAGS enables interrupts while reserved privilege-sensitive state remains clear.
- Ring-3 selectors are fixed to the installed user code and data GDT entries.
- A live thread pins its process address space, so process destruction fails until all thread
  stacks and mappings are released.
- Inspection, administration, and execution remain separate capability checks.
- Acquiring an execution lease requires `execute` authority and atomically transitions the thread
  from `ready` to `running`. A second execution lease is rejected.
- The lease pins thread identity, generation, immutable initial register context, and the exact
  process-space lease. Mutated or stale lease copies fail validation and cannot release the real
  execution.
- Successful release returns the thread to `ready`; termination and destruction remain blocked
  while an execution lease is active.
- If the owning process exits concurrently, the lease identity remains valid only long enough for
  deterministic unbind/release; new CPU binding and syscall dispatch still require a ready process.

The scheduler binds the typed execution lease to one CPU while interrupts are disabled. The
runtime probe enters with the thread's own RIP/RSP, crosses two syscalls and one user exception,
then unbinds and releases the lease before destroying the thread. Remaining work is resumable
context save/restore, preemption, migration, blocking, and process-level fault termination.
