#include <doxxer/arch/x86_64/io.hpp>
#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/log.hpp>
#include <doxxer/platform.hpp>
#include <doxxer/types.hpp>

namespace doxxer::platform {
namespace {
u64 read_tsc() {
    u32 low = 0;
    u32 high = 0;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    return (static_cast<u64>(high) << 32U) | low;
}

void cpuid(u32 leaf, u32& eax, u32& ebx, u32& ecx, u32& edx) {
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                 : "a"(leaf), "c"(0));
}

u64 tsc_hz() {
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    cpuid(0, eax, ebx, ecx, edx);
    const u32 maximum_leaf = eax;
    if (maximum_leaf >= 0x15U) {
        cpuid(0x15U, eax, ebx, ecx, edx);
        if (eax != 0 && ebx != 0 && ecx != 0)
            return static_cast<u64>(ecx) * ebx / eax;
    }
    if (maximum_leaf >= 0x16U) {
        cpuid(0x16U, eax, ebx, ecx, edx);
        if (eax != 0) return static_cast<u64>(eax) * 1'000'000ULL;
    }
    // QEMU exposes an invariant virtual TSC; this fallback is only used when
    // frequency leaves are hidden and intentionally errs toward a longer wait.
    return 1'000'000'000ULL;
}
}

void delay_milliseconds(unsigned milliseconds) {
    const u64 ticks_per_millisecond = tsc_hz() / 1000U;
    const u64 start = read_tsc();
    const u64 duration = ticks_per_millisecond * milliseconds;
    while (read_tsc() - start < duration) asm volatile("pause");
}

[[noreturn]] void reboot() {
    asm volatile("cli");
    for (u32 spin = 0; spin < 100'000U; ++spin) {
        if ((arch::x86_64::in8(0x64) & 0x02U) == 0) break;
        asm volatile("pause");
    }
    arch::x86_64::out8(0x64, 0xFE);
    delay_milliseconds(100);
    struct [[gnu::packed]] InvalidIdt { u16 limit; u64 base; } invalid{0, 0};
    asm volatile("lidt %0; int3" : : "m"(invalid));
    halt();
}

[[noreturn]] void failure_recovery() {
    log::line("F5 TO REBOOT / AUTO RESTART IN 60");
    for (u32 remaining = 60; remaining > 0; --remaining) {
        graphics::draw_failure_countdown(remaining);
        const u64 deadline = read_tsc() + tsc_hz();
        while (read_tsc() < deadline) {
            if ((arch::x86_64::in8(0x64) & 0x01U) != 0) {
                const u8 scan_code = arch::x86_64::in8(0x60);
                if (scan_code == 0x3FU) reboot();
            }
            asm volatile("pause");
        }
    }
    reboot();
}

[[noreturn]] void halt() {
    asm volatile("cli");
    for (;;) {
        asm volatile("hlt");
    }
}

[[noreturn]] void test_success() {
#ifdef DOXXER_TEST_MODE
    arch::x86_64::out16(0x501, 0x10);
#endif
    halt();
}
}
