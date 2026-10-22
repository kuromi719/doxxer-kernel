# Ring-3 Transition Probe

Doxxer performs a real, bounded hardware privilege-boundary test before declaring the kernel ready.
The probe is intentionally separate from production thread scheduling, but it now exercises the
same process-bound copy gateway and ABI dispatcher intended for the runtime entry path.

## Sequence

1. Create a capability domain, process, pinned address-space lease, and isolation domain.
2. Allocate `user_image`, `user_stack`, request, and response pages.
3. Write a fixed instruction sequence through the per-CPU temporary user-memory window.
4. Publish the image as user/read/execute and the stack as user/read/write/NX.
5. Save `EFER`, `STAR`, `LSTAR`, and `FMASK`, then install a boot-only syscall target.
6. Switch CR3 and enter CPL3 with `IRETQ`, with interrupts disabled.
7. User code reads CS and SS, loads request/response pointers plus a nonce, and executes `SYSCALL`.
8. The assembly target clears AC, records RAX/RCX/R11/RSP and selectors, restores kernel CR3 and
   stack state, then invokes the syscall copy gateway on the kernel stack.
9. The gateway validates the process lease, copies an `abi_info` request from user RAM, dispatches
   it under the process capability domain, and copies the initialized response back.
10. Return to the exact kernel continuation without executing `SYSRETQ`, restore every modified
   MSR, verify the response, nonce, CPL3 selectors, post-syscall RIP, stack bounds, RFLAGS, and
   kernel CR3, then destroy all objects and require exact physical/reference counts.

The bytes after `SYSCALL` contain `UD2`; reaching them means the kernel entry path failed to take
control and will halt through the exception path rather than silently continuing.

## Security boundary

The probe establishes that the configured page tables, GDT selectors, NX/user permissions,
`IRETQ`, `SYSCALL`, user-copy, process-domain binding, and ABI dispatch machinery work together on
the boot CPU. It exposes only a fixed `abi_info` request from fixed probe code, does not run
arbitrary applications, and does not constitute a scheduler.

Dedicated per-CPU guarded syscall stacks are provisioned during SMP startup and verified on every
processor. After SMP startup a second hardware probe binds a live process lease into the BSP's
CPU-local state, enters user mode with an empty user GS base, executes the production-style
`SWAPGS` entry, switches immediately to the guarded syscall stack, validates user RIP/RSP/RFLAGS,
dispatches through the process copy gateway, and returns through a fixed-selector `IRETQ` frame.
User code then performs a second syscall, proving that the return path really resumed CPL3.

Between the two syscalls the probe executes `UD2`. The common interrupt entry detects the saved
CPL3 selector and performs `SWAPGS` before C++ dispatch touches CPU-local state. The registered
policy validates the bound process lease, selector pair, instruction and stack mappings, RFLAGS,
and exact fault RIP before skipping the fixed two-byte probe instruction. A matching `SWAPGS`
before `IRETQ` restores the empty user GS base, and the second syscall proves user execution
resumed after exception delivery.

The entry path deliberately uses `IRETQ` rather than the more fragile `SYSRETQ` fast path. Invalid
canonical state, forbidden privilege flags, a missing CPU-local process binding, or an invalid
executable/stack mapping fail closed before return. The boot probe restores all modified MSRs and
requires exact page/reference accounting. A serialized rendezvous installs and reads back the
production `EFER.SCE`, `STAR`, `LSTAR`, and `FMASK` state on every online processor before this
probe runs. Remaining runtime work includes scheduler-owned binding for arbitrary user threads,
general process fault termination/notification, and preemption rules.
