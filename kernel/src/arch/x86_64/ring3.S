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

.section .note.GNU-stack,"",@progbits
