# User Thread Contexts

User-thread objects prepare the state required for scheduled ring-3 execution. Separately, the
architecture boot probe now executes a fixed instruction sequence at CPL3 and crosses back through
the processor's `SYSCALL` path; ordinary thread objects are not scheduled yet.

- Creation requires a process control capability with `map` authority.
- The entry point must already be mapped user-executable in the process address space.
- Each thread receives eight writable, non-executable stack pages and one unmapped lower guard
  page in a deterministic non-overlapping region.
- Initial RFLAGS enables interrupts while reserved privilege-sensitive state remains clear.
- Ring-3 selectors are fixed to the installed user code and data GDT entries.
- A live thread pins its process address space, so process destruction fails until all thread
  stacks and mappings are released.
- Inspection and administration remain separate capability checks.

The next architecture layer must consume these validated contexts from the scheduler, replace the
single-shot probe state with per-CPU syscall state, copy request envelopes through the validated
user-copy layer, dispatch them, and return with a hardened `SYSRETQ`/`IRETQ` decision.
