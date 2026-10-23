.section .text
.code64

.extern doxxer_ring3_probe_active
.extern doxxer_ring3_probe_kernel_rsp
.extern doxxer_ring3_probe_kernel_cr3
.extern doxxer_ring3_probe_resume
.extern doxxer_ring3_probe_rax
.extern doxxer_ring3_probe_rcx
.extern doxxer_ring3_probe_r11
.extern doxxer_ring3_probe_rsp
.extern doxxer_ring3_probe_cs
.extern doxxer_ring3_probe_ss
.extern doxxer_ring3_probe_request
.extern doxxer_ring3_probe_response
.extern doxxer_ring3_probe_status
.extern doxxer_ring3_probe_dispatch
.extern doxxer_runtime_probe_active
.extern doxxer_runtime_probe_kernel_rsp
.extern doxxer_runtime_probe_kernel_cr3
.extern doxxer_runtime_probe_resume
.extern doxxer_runtime_syscall_dispatch
.extern doxxer_runtime_syscall_panic

.equ DOXXER_CPU_SYSCALL_STACK_TOP, 136
.equ DOXXER_CPU_SYSCALL_CONTEXT, 144
.equ DOXXER_CPU_SYSCALL_USER_RSP, 152
.equ DOXXER_RUNTIME_PROBE_COMPLETE, 0x44585250524F4245
.equ DOXXER_RUNTIME_PROBE_FATAL, 0x445852464154414C

.global doxxer_enter_ring3_probe
.type doxxer_enter_ring3_probe, @function
doxxer_enter_ring3_probe:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, doxxer_ring3_probe_kernel_rsp(%rip)
    movq %cr3, %rax
    movq %rax, doxxer_ring3_probe_kernel_cr3(%rip)
    leaq .Lring3_probe_resume(%rip), %rax
    movq %rax, doxxer_ring3_probe_resume(%rip)
    movq $1, doxxer_ring3_probe_active(%rip)
    cli
    movq %rdi, %cr3
    pushq $0x1b
    pushq %rdx
    pushq $0x2
    pushq $0x23
    pushq %rsi
    iretq

.Lring3_probe_resume:
    movq $0, doxxer_ring3_probe_active(%rip)
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq

.global doxxer_ring3_syscall_probe_entry
.type doxxer_ring3_syscall_probe_entry, @function
doxxer_ring3_syscall_probe_entry:
    clac
    cli
    cmpq $1, doxxer_ring3_probe_active(%rip)
    jne .Lring3_probe_fatal
    movq %rax, doxxer_ring3_probe_rax(%rip)
    movq %rcx, doxxer_ring3_probe_rcx(%rip)
    movq %r11, doxxer_ring3_probe_r11(%rip)
    movq %rsp, doxxer_ring3_probe_rsp(%rip)
    movq %r8, doxxer_ring3_probe_cs(%rip)
    movq %r9, doxxer_ring3_probe_ss(%rip)
    movq %rdi, doxxer_ring3_probe_request(%rip)
    movq %rsi, doxxer_ring3_probe_response(%rip)
    movq doxxer_ring3_probe_kernel_cr3(%rip), %rax
    movq %rax, %cr3
    movq doxxer_ring3_probe_kernel_rsp(%rip), %rsp
    subq $8, %rsp
    movq doxxer_ring3_probe_request(%rip), %rdi
    movq doxxer_ring3_probe_response(%rip), %rsi
    callq doxxer_ring3_probe_dispatch
    movq %rax, doxxer_ring3_probe_status(%rip)
    addq $8, %rsp
    movq doxxer_ring3_probe_resume(%rip), %rax
    jmpq *%rax

.Lring3_probe_fatal:
    cli
1:
    hlt
    jmp 1b

.global doxxer_enter_runtime_ring3_probe
.type doxxer_enter_runtime_ring3_probe, @function
doxxer_enter_runtime_ring3_probe:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, doxxer_runtime_probe_kernel_rsp(%rip)
    movq %cr3, %rax
    movq %rax, doxxer_runtime_probe_kernel_cr3(%rip)
    leaq .Lruntime_probe_resume(%rip), %rax
    movq %rax, doxxer_runtime_probe_resume(%rip)
    movq $1, doxxer_runtime_probe_active(%rip)
    cli
    movq %rdi, %cr3
    swapgs
    pushq $0x1b
    pushq %rdx
    pushq $0x2
    pushq $0x23
    pushq %rsi
    iretq

.Lruntime_probe_resume:
    movq $0, doxxer_runtime_probe_active(%rip)
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq

.global doxxer_runtime_syscall_entry
.type doxxer_runtime_syscall_entry, @function
doxxer_runtime_syscall_entry:
    swapgs
    clac
    cli
    movq %rsp, %gs:DOXXER_CPU_SYSCALL_USER_RSP
    movq %gs:DOXXER_CPU_SYSCALL_STACK_TOP, %rsp
    cmpq $0, %rsp
    je .Lruntime_syscall_fatal
    cmpq $0, %gs:DOXXER_CPU_SYSCALL_CONTEXT
    je .Lruntime_syscall_fatal

    /* Construct a fixed-selector IRET frame, then preserve non-result registers. */
    pushq $0x1b
    pushq %gs:DOXXER_CPU_SYSCALL_USER_RSP
    pushq %r11
    pushq $0x23
    pushq %rcx
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rdx
    pushq %r10
    pushq %r8
    pushq %r9
    pushq %rsi
    pushq %rdi

    movq %gs:DOXXER_CPU_SYSCALL_CONTEXT, %rdi
    movq 0(%rsp), %rsi
    movq 8(%rsp), %rdx
    movq 96(%rsp), %rcx
    movq 120(%rsp), %r8
    movq 112(%rsp), %r9
    subq $8, %rsp
    callq doxxer_runtime_syscall_dispatch
    addq $8, %rsp

    movabsq $DOXXER_RUNTIME_PROBE_COMPLETE, %r10
    cmpq %r10, %rax
    je .Lruntime_probe_complete
    movabsq $DOXXER_RUNTIME_PROBE_FATAL, %r10
    cmpq %r10, %rax
    je .Lruntime_syscall_fatal

    popq %rdi
    popq %rsi
    popq %r9
    popq %r8
    popq %r10
    popq %rdx
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    swapgs
    iretq

.Lruntime_probe_complete:
    cmpq $1, doxxer_runtime_probe_active(%rip)
    jne .Lruntime_syscall_fatal
    movq doxxer_runtime_probe_kernel_cr3(%rip), %rax
    movq %rax, %cr3
    movq doxxer_runtime_probe_kernel_rsp(%rip), %rsp
    movq doxxer_runtime_probe_resume(%rip), %rax
    jmpq *%rax

.Lruntime_syscall_fatal:
    /* The user CR3 does not own all kernel supervisor windows. Panic and its
       timer/graphics path must run on the saved kernel page table and stack. */
    movq doxxer_runtime_probe_kernel_cr3(%rip), %rax
    testq %rax, %rax
    je .Lruntime_fatal_halt
    movq %rax, %cr3
    movq doxxer_runtime_probe_kernel_rsp(%rip), %rsp
    testq %rsp, %rsp
    je .Lruntime_fatal_halt
    subq $8, %rsp
    callq doxxer_runtime_syscall_panic
.Lruntime_fatal_halt:
    cli
2:  hlt
    jmp 2b

/* Copied verbatim into the read/execute segment of the built-in user ELF.
   All branches are intra-image; there are no kernel relocations or pointers. */
.section .rodata.desktop_user,"a",@progbits
.global doxxer_desktop_program_start
.global doxxer_desktop_program_end
doxxer_desktop_program_start:
    movabsq $0x0000000000900000, %rdi
    movabsq $0x0000000000910000, %rsi
.Ldesktop_heartbeat:
    syscall
    testq %rax, %rax
    jne .Ldesktop_bad_response
    movl $0x00040000, %ecx
.Ldesktop_pause:
    pause
    loop .Ldesktop_pause
    jmp .Ldesktop_heartbeat
.Ldesktop_bad_response:
    ud2
doxxer_desktop_program_end:

.section .note.GNU-stack,"",@progbits
