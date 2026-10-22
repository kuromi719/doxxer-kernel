# User Thread Contexts

User-thread objects prepare the state required for a future ring-3 transition without yet
executing untrusted instructions.

- Creation requires a process control capability with `map` authority.
- The entry point must already be mapped user-executable in the process address space.
- Each thread receives eight writable, non-executable stack pages and one unmapped lower guard
  page in a deterministic non-overlapping region.
- Initial RFLAGS enables interrupts while reserved privilege-sensitive state remains clear.
- Ring-3 selectors are fixed to the installed user code and data GDT entries.
- A live thread pins its process address space, so process destruction fails until all thread
  stacks and mappings are released.
- Inspection and administration remain separate capability checks.

The next architecture layer can consume the validated context for `IRETQ` entry and connect it to
the scheduler and syscall return path.
