# Kernel Task Scheduler

## Scope

This milestone introduces bounded cross-CPU kernel task dispatch, not a general preemptive thread scheduler. A task is a short run-to-completion function with one opaque argument. It cannot sleep, migrate, block on user resources, or retain its execution stack after returning.

The deliberately narrow model establishes safe execution and queueing invariants before ring-3 processes and full context switching increase the attack surface.

## Task isolation

The scheduler owns a fixed pool of 64 task slots. Each slot has a permanently reserved 32 KiB supervisor-only, non-executable stack. Unmapped pages border both sides of each stack. The mapped region is wiped before and after every execution, and a layout-derived canary at the lower boundary is checked before completion is published.

Task handles contain a slot and generation. Releasing a completed task advances the generation, so an old handle cannot observe or release a later occupant of the same slot.

## Per-CPU queues

Every online processor owns a bounded FIFO run queue. Queue operations are protected by independent spinlocks, limiting contention and preventing unbounded allocation from submission paths. Tasks are assigned round-robin across secondary processors; a uniprocessor system uses the bootstrap processor and pumps its queue directly.

Secondary processors idle with the interruptible `sti; hlt` pattern. Submission sends a fixed reschedule IPI; the interrupt handler only acknowledges the Local APIC. The worker loop, never the interrupt handler, removes and executes work. This keeps arbitrary callbacks outside interrupt context.

Task state transitions are monotonic for one generation:

```text
FREE -> QUEUED -> RUNNING -> COMPLETE|FAILED -> FREE(new generation)
```

Acquire/release atomics publish task descriptors and results. Only a successful compare-exchange from `QUEUED` to `RUNNING` grants execution ownership.

## User execution context ownership

The scheduler is the sole high-level owner of the process context installed for the runtime
syscall and user-exception paths. A binding accepts a typed, currently valid
`AddressSpaceLease`; arbitrary pointers and stale process leases cannot be installed as a
CPU-local syscall context.

Binding and unbinding require interrupts to be disabled, which pins the operation to the current
processor until a future scheduler supplies an explicit migration protocol. Each CPU permits one
active binding. The returned binding handle records the processor and a nonzero generation;
teardown succeeds only on the same CPU and only when the handle, scheduler record, and low-level
GS-backed context all agree. Duplicate binds, forged generations, stale handles, and cross-CPU
unbind attempts fail closed without replacing the active context.

The architecture-specific SMP layer remains a narrow mechanism for publishing the pointer in the
CPU-local record. Runtime ring-3 probes and future dispatch code must use the scheduler interface,
so process-lease validation and lifecycle accounting cannot be bypassed by ordinary callers.

## Validation

The boot self-test submits multiple tasks explicitly targeted to every online processor. Each task validates its CPU-local index and contributes to per-CPU counters and a deterministic checksum. Boot requires:

- Every submitted handle to reach completion before an HPET deadline
- The expected task count on every CPU
- No CPU-affinity mismatch
- An exact aggregate checksum
- Zero stack-canary failures
- Successful generation-checked release of every handle
- Successful typed user-context bind and same-CPU unbind
- Rejection of duplicate binding and a forged-generation teardown handle

Smoke coverage runs the scheduler with 1, 4, and 8 virtual processors, including 128 MiB and 5 GiB memory configurations.

## Deferred work

- Saved register contexts and resumable kernel threads
- Preemption and per-CPU scheduling timers
- Priorities, deadlines, affinity masks, and work stealing
- Blocking primitives and priority inheritance
- Scheduler-aware TLB shootdowns
- Persistent user-thread dispatch and address-space activation
- User-context migration and process-level fault termination
- XSAVE/FPU context ownership
