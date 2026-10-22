#include <doxxer/arch/x86_64/apic.hpp>

#include <doxxer/arch/x86_64/interrupts.hpp>
#include <doxxer/arch/x86_64/io.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>

namespace doxxer::arch::x86_64::apic {
namespace {
using memory::physical::kPageSize;
using memory::virtual_memory::MapFlags;

constexpr u32 kApicBaseMsr = 0x1B;
constexpr u64 kApicBaseMask = 0x000F'FFFF'FFFF'F000ULL;
constexpr u64 kLocalApicVirtual = 0x0000'5000'0000'0000ULL;
constexpr u64 kIoApicVirtual = 0x0000'5000'0010'0000ULL;
constexpr u64 kHpetVirtual = 0x0000'5000'0020'0000ULL;
constexpr u8 kTimerVector = 0xE0;
constexpr u8 kSpuriousVector = 0xFF;
constexpr u64 kCalibrationFemtoseconds = 10'000'000'000'000ULL;
constexpr u64 kTestTimeoutFemtoseconds = 250'000'000'000'000ULL;

volatile u32* local_apic = nullptr;
volatile u64* hpet_capabilities = nullptr;
volatile u64* hpet_configuration = nullptr;
volatile u64* hpet_counter = nullptr;
volatile u64 tick_count = 0;
u64 hpet_period_fs = 0;
u32 timer_period_us = 0;
u32 last_failure = 0;

u64 read_msr(u32 msr) {
    u32 low = 0;
    u32 high = 0;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return (static_cast<u64>(high) << 32U) | low;
}

void write_msr(u32 msr, u64 value) {
    asm volatile("wrmsr"
                 :
                 : "c"(msr), "a"(static_cast<u32>(value)), "d"(static_cast<u32>(value >> 32U))
                 : "memory");
}

bool cpu_has_apic() {
    u32 eax = 1;
    u32 ebx = 0;
    u32 ecx = 0;
    u32 edx = 0;
    asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : : "memory");
    return (edx & (1U << 9U)) != 0;
}

volatile u8* map_mmio(u64 physical_address, u64 virtual_base, usize required_size) {
    const u64 page = physical_address & ~(kPageSize - 1);
    const usize offset = static_cast<usize>(physical_address - page);
    if (required_size > kPageSize || offset > kPageSize - required_size) {
        return nullptr;
    }
    auto* space = memory::virtual_memory::active_address_space();
    if (space == nullptr || !memory::virtual_memory::map(*space, virtual_base, page,
                                                         MapFlags::write | MapFlags::global |
                                                             MapFlags::cache_disable)) {
        return nullptr;
    }
    return reinterpret_cast<volatile u8*>(virtual_base + offset);
}

u32 lapic_read(u32 offset) { return local_apic[offset / sizeof(u32)]; }

void lapic_write(u32 offset, u32 value) {
    local_apic[offset / sizeof(u32)] = value;
    static_cast<void>(lapic_read(0x20));
}

u32 ioapic_read(volatile u8* base, u8 reg) {
    *reinterpret_cast<volatile u32*>(base) = reg;
    return *reinterpret_cast<volatile u32*>(base + 0x10);
}

void ioapic_write(volatile u8* base, u8 reg, u32 value) {
    *reinterpret_cast<volatile u32*>(base) = reg;
    *reinterpret_cast<volatile u32*>(base + 0x10) = value;
}

void timer_handler(interrupts::ExceptionFrame&) {
    tick_count = tick_count + 1;
    lapic_write(0xB0, 0);
}

void spurious_handler(interrupts::ExceptionFrame&) {}

u64 hpet_read_counter() { return *hpet_counter; }

bool wait_hpet(u64 start, u64 femtoseconds) {
    const u64 delta = femtoseconds / hpet_period_fs;
    if (delta == 0) {
        return false;
    }
    while (hpet_read_counter() - start < delta) {
        asm volatile("pause");
    }
    return true;
}

bool initialize_hpet(u64 physical_address) {
    volatile u8* base = map_mmio(physical_address, kHpetVirtual, 0x100);
    if (base == nullptr) {
        return false;
    }
    hpet_capabilities = reinterpret_cast<volatile u64*>(base);
    hpet_configuration = reinterpret_cast<volatile u64*>(base + 0x10);
    hpet_counter = reinterpret_cast<volatile u64*>(base + 0xF0);
    const u64 capabilities = *hpet_capabilities;
    hpet_period_fs = capabilities >> 32U;
    if ((capabilities & (1ULL << 13U)) == 0 || hpet_period_fs == 0 ||
        hpet_period_fs > 100'000'000ULL) {
        return false;
    }
    *hpet_configuration = *hpet_configuration & ~1ULL;
    *hpet_counter = 0;
    *hpet_configuration = *hpet_configuration | 1ULL;
    return true;
}

bool mask_io_apics(const firmware::acpi::Topology& topology) {
    for (usize index = 0; index < topology.io_apic_count; ++index) {
        volatile u8* base =
            map_mmio(topology.io_apics[index].address, kIoApicVirtual + index * kPageSize, 0x20);
        if (base == nullptr) {
            return false;
        }
        const u32 version = ioapic_read(base, 1);
        const u32 maximum_entry = (version >> 16U) & 0xFFU;
        if (maximum_entry > 119) {
            return false;
        }
        for (u32 entry = 0; entry <= maximum_entry; ++entry) {
            const u8 low_register = static_cast<u8>(0x10 + entry * 2);
            ioapic_write(base, static_cast<u8>(low_register + 1), 0);
            ioapic_write(base, low_register, 1U << 16U);
        }
    }
    return true;
}

bool calibrate_timer() {
    lapic_write(0x320, 1U << 16U);
    lapic_write(0x3E0, 0x3);
    lapic_write(0x380, 0xFFFF'FFFFU);
    const u64 start = hpet_read_counter();
    if (!wait_hpet(start, kCalibrationFemtoseconds)) {
        return false;
    }
    const u32 elapsed = 0xFFFF'FFFFU - lapic_read(0x390);
    lapic_write(0x320, 1U << 16U);
    if (elapsed < 1000) {
        return false;
    }
    timer_period_us = 10'000;
    lapic_write(0x320, static_cast<u32>(kTimerVector) | (1U << 17U));
    lapic_write(0x380, elapsed);
    return true;
}
}

bool initialize(const firmware::acpi::Topology& topology) {
    interrupts::disable();
    last_failure = 0;
    tick_count = 0;
    if (!cpu_has_apic()) {
        last_failure = 1;
        return false;
    }
    u64 apic_msr = read_msr(kApicBaseMsr);
    if ((apic_msr & (1ULL << 10U)) != 0) {
        last_failure = 2;
        return false;
    }
    apic_msr |= 1ULL << 11U;
    write_msr(kApicBaseMsr, apic_msr);
    if ((apic_msr & kApicBaseMask) != (topology.local_apic_address & kApicBaseMask)) {
        last_failure = 3;
        return false;
    }
    volatile u8* lapic_base = map_mmio(topology.local_apic_address, kLocalApicVirtual, 0x400);
    if (lapic_base == nullptr) {
        last_failure = 4;
        return false;
    }
    local_apic = reinterpret_cast<volatile u32*>(lapic_base);
    if (static_cast<u8>(lapic_read(0x20) >> 24U) != topology.bootstrap_apic_id) {
        last_failure = 5;
        return false;
    }
    out8(0x21, 0xFF);
    out8(0xA1, 0xFF);
    lapic_write(0x80, 0);
    lapic_write(0x320, 1U << 16U);
    lapic_write(0x350, 1U << 16U);
    lapic_write(0x360, 1U << 16U);
    lapic_write(0x370, 1U << 16U);
    lapic_write(0xF0, (1U << 8U) | kSpuriousVector);
    if (!mask_io_apics(topology)) {
        last_failure = 6;
        return false;
    }
    if (!initialize_hpet(topology.hpet_address)) {
        last_failure = 7;
        return false;
    }
    if (!interrupts::register_handler(kTimerVector, timer_handler) ||
        !interrupts::register_handler(kSpuriousVector, spurious_handler)) {
        last_failure = 8;
        return false;
    }
    if (!calibrate_timer()) {
        last_failure = 9;
        return false;
    }
    return true;
}

bool timer_self_test() {
    const u64 initial_ticks = tick_count;
    const u64 start = hpet_read_counter();
    const u64 timeout_ticks = kTestTimeoutFemtoseconds / hpet_period_fs;
    interrupts::enable();
    while (tick_count - initial_ticks < 3) {
        if (hpet_read_counter() - start >= timeout_ticks) {
            interrupts::disable();
            last_failure = 10;
            return false;
        }
        asm volatile("pause");
    }
    return interrupts::enabled();
}

u64 timer_ticks() { return tick_count; }

u32 timer_period_microseconds() { return timer_period_us; }

u32 failure_code() { return last_failure; }
}
