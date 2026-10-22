#pragma once

#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::interrupts {
struct ExceptionFrame {
    u64 r15;
    u64 r14;
    u64 r13;
    u64 r12;
    u64 r11;
    u64 r10;
    u64 r9;
    u64 r8;
    u64 rsi;
    u64 rdi;
    u64 rbp;
    u64 rdx;
    u64 rcx;
    u64 rbx;
    u64 rax;
    u64 vector;
    u64 error_code;
    u64 rip;
    u64 cs;
    u64 rflags;
    u64 rsp;
    u64 ss;
};

using Handler = void (*)(ExceptionFrame& frame);

void initialize();
bool self_test(u64 guard_address, u64 exception_stack_bottom, u64 exception_stack_top);
bool register_handler(u8 vector, Handler handler);
void enable();
void disable();
bool enabled();
}

extern "C" void doxxer_exception_dispatch(doxxer::arch::x86_64::interrupts::ExceptionFrame* frame);
