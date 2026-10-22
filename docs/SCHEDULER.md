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

## Validation

The boot self-test submits multiple tasks explicitly targeted to every online processor. Each task validates its CPU-local index and contributes to per-CPU counters and a deterministic checksum. Boot requires:

- Every submitted handle to reach completion before an HPET deadline
- The expected task count on every CPU
- No CPU-affinity mismatch
- An exact aggregate checksum
- Zero stack-canary failures
- Successful generation-checked release of every handle

Smoke coverage runs the scheduler with 1, 4, and 8 virtual processors, including 128 MiB and 5 GiB memory configurations.

## Deferred work

- Saved register contexts and resumable kernel threads
- Preemption and per-CPU scheduling timers
- Priorities, deadlines, affinity masks, and work stealing
- Blocking primitives and priority inheritance
- Scheduler-aware TLB shootdowns
- User-process address-space activation
- XSAVE/FPU context ownership
