.section .text
.code64

.global doxxer_execute_task_stack
.type doxxer_execute_task_stack, @function
doxxer_execute_task_stack:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, %r12
    movq %rdi, %rsp
    andq $-16, %rsp
    xorq %rbp, %rbp
    movq %rdx, %rdi
    callq *%rsi
    movq %r12, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq

.section .note.GNU-stack,"",@progbits
