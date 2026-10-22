.section .text
.code64
.extern doxxer_exception_dispatch
.extern doxxer_fault_resume_rip

.altmacro
.macro DOXXER_ISR vector
.global doxxer_isr_\vector
.type doxxer_isr_\vector, @function
doxxer_isr_\vector:
.if (\vector != 8) && (\vector != 10) && (\vector != 11) && (\vector != 12) && (\vector != 13) && (\vector != 14) && (\vector != 17) && (\vector != 21) && (\vector != 29) && (\vector != 30)
    pushq $0
.endif
    pushq $\vector
    jmp doxxer_isr_common
.endm

.set doxxer_vector, 0
.rept 256
DOXXER_ISR %doxxer_vector
.set doxxer_vector, doxxer_vector + 1
.endr

.type doxxer_isr_common, @function
doxxer_isr_common:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    cld
    movq %rsp, %rdi
    call doxxer_exception_dispatch
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rsi
    popq %rdi
    popq %rbp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp
    iretq

.global doxxer_guard_page_probe
.type doxxer_guard_page_probe, @function
doxxer_guard_page_probe:
    leaq .Lguard_recovered(%rip), %rax
    movq %rax, doxxer_fault_resume_rip(%rip)
    movq (%rdi), %rax
    xorl %eax, %eax
    retq
.Lguard_recovered:
    movl $1, %eax
    retq

.global doxxer_run_on_stack
.type doxxer_run_on_stack, @function
doxxer_run_on_stack:
    movq %rdi, %rsp
    andq $-16, %rsp
    xorq %rbp, %rbp
    callq *%rsi
.Lstack_returned:
    cli
    hlt
    jmp .Lstack_returned

.global doxxer_run_on_cpu_stack
.type doxxer_run_on_cpu_stack, @function
doxxer_run_on_cpu_stack:
    cli
    movq %rdi, %cr3
    movq %rsi, %rsp
    andq $-16, %rsp
    xorq %rbp, %rbp
    movq %rcx, %rdi
    callq *%rdx
.Lcpu_stack_returned:
    cli
    hlt
    jmp .Lcpu_stack_returned

.section .rodata
.align 8
.global doxxer_isr_table
.type doxxer_isr_table, @object

.macro DOXXER_ISR_POINTER vector
    .quad doxxer_isr_\vector
.endm

doxxer_isr_table:
.set doxxer_vector, 0
.rept 256
DOXXER_ISR_POINTER %doxxer_vector
.set doxxer_vector, doxxer_vector + 1
.endr
.size doxxer_isr_table, . - doxxer_isr_table

.section .note.GNU-stack,"",@progbits
