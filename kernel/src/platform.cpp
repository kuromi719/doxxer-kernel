#include <doxxer/arch/x86_64/io.hpp>
#include <doxxer/arch/x86_64/apic.hpp>
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

bool f5_pressed() {
    if ((arch::x86_64::in8(0x64) & 0x01U) == 0) return false;
    const u8 scan_code = arch::x86_64::in8(0x60);
    // initialize_restart_hotkey() explicitly enables 8042 Set-1 translation.
    // 0x03 is the Set-1 '2' key, not F5; accepting it rebooted on that key.
    return scan_code == 0x3FU;
}
}

bool initialize_restart_hotkey() {
    auto wait_input = []() -> bool {
        for (u32 spin = 0; spin < 100'000U; ++spin) {
            if ((arch::x86_64::in8(0x64) & 0x02U) == 0) return true;
            asm volatile("pause");
        }
        return false;
    };
    auto wait_output = []() -> bool {
        for (u32 spin = 0; spin < 100'000U; ++spin) {
            if ((arch::x86_64::in8(0x64) & 0x01U) != 0) return true;
            asm volatile("pause");
        }
        return false;
    };
    if (!wait_input()) return false;
    arch::x86_64::out8(0x64, 0xAD); // Disable port while programming.
    while ((arch::x86_64::in8(0x64) & 0x01U) != 0) (void)arch::x86_64::in8(0x60);
    if (!wait_input()) return false;
    arch::x86_64::out8(0x64, 0x20);
    if (!wait_output()) return false;
    u8 configuration = arch::x86_64::in8(0x60);
    configuration = static_cast<u8>((configuration & ~0x11U) | 0x40U);
    if (!wait_input()) return false;
    arch::x86_64::out8(0x64, 0x60);
    if (!wait_input()) return false;
    arch::x86_64::out8(0x60, configuration);
    if (!wait_input()) return false;
    arch::x86_64::out8(0x64, 0xAE);
    if (!wait_input()) return false;
    arch::x86_64::out8(0x60, 0xF4); // Enable keyboard scanning.
    if (!wait_output()) return false;
    return arch::x86_64::in8(0x60) == 0xFAU;
}

void poll_restart_hotkey() {
    if (f5_pressed()) reboot();
}

void delay_milliseconds(unsigned milliseconds) {
    const u64 reference_ticks =
        arch::x86_64::apic::reference_ticks_for_microseconds(
            static_cast<u64>(milliseconds) * 1000U);
    if (reference_ticks != 0) {
        const u64 start = arch::x86_64::apic::reference_counter();
        while (arch::x86_64::apic::reference_counter() - start < reference_ticks) {
            poll_restart_hotkey();
            asm volatile("pause");
        }
        return;
    }
    // Early boot precedes HPET discovery and must still be able to present
    // diagnostics. After APIC initialization the hardware reference clock
    // above is preferred over CPUID's sometimes inaccurate virtual TSC rate.
    const u64 ticks_per_millisecond = tsc_hz() / 1000U;
    const u64 start = read_tsc();
    const u64 duration = ticks_per_millisecond * milliseconds;
    while (read_tsc() - start < duration) {
        poll_restart_hotkey();
        asm volatile("pause");
    }
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
        delay_milliseconds(1000);
    }
    reboot();
}

[[noreturn]] void wait_for_restart() {
    for (;;) {
        if (f5_pressed()) reboot();
        // The calibrated local APIC timer wakes the BSP regularly, keeping the
        // logo idle loop efficient while still polling the PS/2 restart key.
        asm volatile("sti; hlt");
    }
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
