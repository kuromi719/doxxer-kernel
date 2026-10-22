# Ring-3 Transition Probe

Doxxer performs a real, bounded hardware privilege-boundary test before declaring the kernel ready.
The probe is intentionally separate from production thread scheduling and syscall dispatch.

## Sequence

1. Create a fresh address space and isolation domain.
2. Allocate one `user_image` page and one `user_stack` page.
3. Write a fixed instruction sequence through the per-CPU temporary user-memory window.
4. Publish the image as user/read/execute and the stack as user/read/write/NX.
5. Save `EFER`, `STAR`, `LSTAR`, and `FMASK`, then install a boot-only syscall target.
6. Switch CR3 and enter CPL3 with `IRETQ`, with interrupts disabled.
7. User code reads CS and SS, loads a nonce, and executes `SYSCALL`.
8. The assembly target clears AC, records RAX/RCX/R11/RSP and selectors, restores kernel CR3 and
   stack state, and returns to the exact kernel continuation without executing `SYSRETQ`.
9. Restore every modified MSR, verify the nonce, CPL3 selectors, post-syscall RIP, stack bounds,
   RFLAGS, and kernel CR3, then destroy the mappings and require exact physical/reference counts.

The bytes after `SYSCALL` contain `UD2`; reaching them means the kernel entry path failed to take
control and will halt through the exception path rather than silently continuing.

## Security boundary

The probe establishes that the configured page tables, GDT selectors, NX/user permissions,
`IRETQ`, and `SYSCALL` machinery work together on the boot CPU. It does not expose the syscall ABI,
does not run arbitrary applications, and does not constitute a scheduler.

A production entry path still requires per-CPU syscall stacks and state, `SWAPGS` discipline,
request copying through validated user-memory windows, capability-domain binding, canonical return
checks, signal/exception delivery, preemption rules, and an audited `SYSRETQ` versus `IRETQ`
return policy. The boot-only LSTAR is removed and the original MSR state restored immediately.
