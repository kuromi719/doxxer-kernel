#include <doxxer/arch/x86_64/interrupts.hpp>

#include <doxxer/log.hpp>
#include <doxxer/platform.hpp>

extern "C" void* doxxer_isr_table[256];
extern "C" doxxer::u64 doxxer_guard_page_probe(doxxer::u64 address);
extern "C" doxxer::u64 doxxer_fault_resume_rip = 0;

namespace doxxer::arch::x86_64::interrupts {
namespace {
constexpr u16 kKernelCodeSelector = 0x08;
constexpr u8 kInterruptGate = 0x8E;
constexpr u8 kExceptionIst = 1;
constexpr u8 kEmergencyIst = 2;

struct [[gnu::packed]] IdtEntry {
    u16 offset_low;
    u16 selector;
    u8 ist;
    u8 attributes;
    u16 offset_middle;
    u32 offset_high;
    u32 reserved;
};

struct [[gnu::packed]] DescriptorTablePointer {
    u16 limit;
    u64 base;
};

static_assert(sizeof(IdtEntry) == 16);
static_assert(sizeof(DescriptorTablePointer) == 10);

alignas(16) IdtEntry idt[256]{};
Handler handlers[256]{};
volatile bool breakpoint_probe_active = false;
volatile bool breakpoint_seen = false;
volatile bool page_fault_probe_active = false;
volatile bool page_fault_seen = false;
volatile u64 expected_fault_address = 0;
volatile u64 expected_stack_bottom = 0;
volatile u64 expected_stack_top = 0;
volatile bool frames_used_exception_stack = true;

u64 read_cr2() {
    u64 value = 0;
    asm volatile("mov %%cr2, %0" : "=r"(value));
    return value;
}

const char* exception_name(u64 vector) {
    switch (vector) {
    case 0:
        return "DIVIDE ERROR";
    case 1:
        return "DEBUG";
    case 2:
        return "NON-MASKABLE INTERRUPT";
    case 3:
        return "BREAKPOINT";
    case 4:
        return "OVERFLOW";
    case 5:
        return "BOUND RANGE EXCEEDED";
    case 6:
        return "INVALID OPCODE";
    case 7:
        return "DEVICE NOT AVAILABLE";
    case 8:
        return "DOUBLE FAULT";
    case 10:
        return "INVALID TSS";
    case 11:
        return "SEGMENT NOT PRESENT";
    case 12:
        return "STACK-SEGMENT FAULT";
    case 13:
        return "GENERAL PROTECTION FAULT";
    case 14:
        return "PAGE FAULT";
    case 16:
        return "X87 FLOATING-POINT EXCEPTION";
    case 17:
        return "ALIGNMENT CHECK";
    case 18:
        return "MACHINE CHECK";
    case 19:
        return "SIMD FLOATING-POINT EXCEPTION";
    case 20:
        return "VIRTUALIZATION EXCEPTION";
    case 21:
        return "CONTROL PROTECTION EXCEPTION";
    case 28:
        return "HYPERVISOR INJECTION EXCEPTION";
    case 29:
        return "VMM COMMUNICATION EXCEPTION";
    case 30:
        return "SECURITY EXCEPTION";
    default:
        return "UNEXPECTED INTERRUPT";
    }
}

void write_register(const char* name, u64 value) {
    log::write(name);
    log::write_hex(value);
    log::write(" ");
}

[[noreturn]] void fatal_exception(const ExceptionFrame& frame) {
    const u64 cr2 = read_cr2();
    log::error("CPU EXCEPTION");
    log::write("[EXCEPTION] VECTOR=");
    log::write_decimal(frame.vector);
    log::write(" NAME=");
    log::line(exception_name(frame.vector));
    write_register("[EXCEPTION] ERROR=", frame.error_code);
    write_register("RIP=", frame.rip);
    write_register("CS=", frame.cs);
    write_register("RFLAGS=", frame.rflags);
    log::write("\n");
    write_register("[EXCEPTION] RSP=", frame.rsp);
    write_register("SS=", frame.ss);
    write_register("CR2=", cr2);
    log::write("\n");
    write_register("[EXCEPTION] RAX=", frame.rax);
    write_register("RBX=", frame.rbx);
    write_register("RCX=", frame.rcx);
    write_register("RDX=", frame.rdx);
    log::write("\n");
    write_register("[EXCEPTION] RSI=", frame.rsi);
    write_register("RDI=", frame.rdi);
    write_register("RBP=", frame.rbp);
    log::write("\n");
    write_register("[EXCEPTION] R8=", frame.r8);
    write_register("R9=", frame.r9);
    write_register("R10=", frame.r10);
    write_register("R11=", frame.r11);
    log::write("\n");
    write_register("[EXCEPTION] R12=", frame.r12);
    write_register("R13=", frame.r13);
    write_register("R14=", frame.r14);
    write_register("R15=", frame.r15);
    log::write("\n");
    log::line("DOXXER_EXCEPTION");
    platform::halt();
}
}

void initialize() {
    for (u64 vector = 0; vector < 256; ++vector) {
        const u64 handler = reinterpret_cast<u64>(doxxer_isr_table[vector]);
        const bool emergency = vector == 2 || vector == 8 || vector == 18;
        idt[vector] = {
            .offset_low = static_cast<u16>(handler),
            .selector = kKernelCodeSelector,
            .ist = emergency ? kEmergencyIst : kExceptionIst,
            .attributes = kInterruptGate,
            .offset_middle = static_cast<u16>(handler >> 16U),
            .offset_high = static_cast<u32>(handler >> 32U),
            .reserved = 0,
        };
    }
    const DescriptorTablePointer pointer{
        .limit = static_cast<u16>(sizeof(idt) - 1),
        .base = reinterpret_cast<u64>(&idt[0]),
    };
    asm volatile("lidt %0" : : "m"(pointer) : "memory");
}

bool self_test(u64 guard_address, u64 exception_stack_bottom, u64 exception_stack_top) {
    DescriptorTablePointer active_idt{};
    asm volatile("sidt %0" : "=m"(active_idt));
    if (active_idt.base != reinterpret_cast<u64>(&idt[0]) || active_idt.limit != sizeof(idt) - 1) {
        return false;
    }

    expected_stack_bottom = exception_stack_bottom;
    expected_stack_top = exception_stack_top;
    frames_used_exception_stack = true;
    breakpoint_seen = false;
    breakpoint_probe_active = true;
    asm volatile("int3" : : : "memory");
    breakpoint_probe_active = false;
    if (!breakpoint_seen) {
        return false;
    }

    expected_fault_address = guard_address;
    page_fault_seen = false;
    page_fault_probe_active = true;
    const u64 recovered = doxxer_guard_page_probe(guard_address);
    page_fault_probe_active = false;
    expected_fault_address = 0;
    expected_stack_bottom = 0;
    expected_stack_top = 0;
    return recovered == 1 && page_fault_seen && frames_used_exception_stack;
}

bool register_handler(u8 vector, Handler handler) {
    if (vector < 32 || handler == nullptr || handlers[vector] != nullptr || enabled()) {
        return false;
    }
    handlers[vector] = handler;
    return true;
}

void enable() { asm volatile("sti" : : : "memory"); }

void disable() { asm volatile("cli" : : : "memory"); }

bool enabled() {
    u64 flags = 0;
    asm volatile("pushfq; popq %0" : "=r"(flags));
    return (flags & (1ULL << 9U)) != 0;
}

void dispatch(ExceptionFrame* frame) {
    if (frame == nullptr) {
        platform::halt();
    }
    if (breakpoint_probe_active || page_fault_probe_active) {
        const u64 frame_address = reinterpret_cast<u64>(frame);
        if (frame_address < expected_stack_bottom ||
            frame_address + sizeof(ExceptionFrame) > expected_stack_top) {
            frames_used_exception_stack = false;
        }
    }
    if (breakpoint_probe_active && frame->vector == 3) {
        breakpoint_seen = true;
        return;
    }
    if (page_fault_probe_active && frame->vector == 14 && read_cr2() == expected_fault_address &&
        (frame->error_code & 1U) == 0 && doxxer_fault_resume_rip != 0) {
        page_fault_seen = true;
        frame->rip = doxxer_fault_resume_rip;
        return;
    }
    if (frame->vector >= 32 && frame->vector < 256 && handlers[frame->vector] != nullptr) {
        handlers[frame->vector](*frame);
        return;
    }
    fatal_exception(*frame);
}
}

extern "C" void doxxer_exception_dispatch(doxxer::arch::x86_64::interrupts::ExceptionFrame* frame) {
    doxxer::arch::x86_64::interrupts::dispatch(frame);
}
