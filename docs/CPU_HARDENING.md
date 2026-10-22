# CPU Hardening Policy

Doxxer treats the processor's privilege-enforcement controls as mandatory platform requirements,
not optional performance features. Boot stops unless every processor exposes and enables the
required x86_64 controls.

The bootstrap processor and every secondary processor independently enable and verify:

- `CR0.WP`, so supervisor writes cannot bypass read-only page permissions;
- `EFER.NXE`, so non-executable mappings are enforced;
- SMEP, preventing supervisor execution from user mappings;
- SMAP, preventing accidental supervisor access through user virtual aliases;
- UMIP, preventing ring-3 descriptor and machine-state disclosure;
- `CR4.TSD`, preventing unprivileged timestamp-counter reads;
- global-page support for kernel mappings.

Unprivileged `RDPMC` and FSGSBASE instructions remain disabled. FSGSBASE stays disabled until the
future syscall and `SWAPGS` transition code has a formally reviewed state machine. Interrupt entry
executes `CLAC` before entering C++ so an inherited access-control flag cannot leave SMAP bypassed
inside a handler.

When CPUID advertises the architectural speculation-control MSRs, each processor enables IBRS,
STIBP, and SSBD as available and issues an IBPB during initialization. The written state is read back
during the per-CPU verification pass.

The boot self-test also walks the live mappings covering the kernel requests, text, read-only data,
data, and BSS ranges. It requires RX text, read-only/NX constants, RW/NX mutable state, and no user
access to any kernel image page. A mismatch stops boot before application execution or device-driver
startup. A separate hardware probe maps a user-owned page into the active address space, accesses it
from supervisor mode with AC clear, and requires the expected present-page fault; this verifies that
SMAP is enforcing rather than merely reporting an enabled control bit.
An independent execution probe maps a one-instruction user image and requires a supervisor
instruction-fetch page fault, proving that SMEP enforcement is live as well.

These controls reduce privilege-crossing and speculative-execution attack surface. They do not by
themselves prove freedom from CPU errata, microarchitectural leakage, malicious firmware, or
compromised silicon. Platform-specific mitigations and updateable microcode policy remain future
work.
