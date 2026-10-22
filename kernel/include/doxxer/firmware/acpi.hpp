#pragma once

#include <limine.h>

#include <doxxer/types.hpp>

namespace doxxer::firmware::acpi {
constexpr usize kMaximumIoApics = 4;
constexpr usize kMaximumOverrides = 16;

struct IoApic {
    u8 id;
    u32 address;
    u32 global_interrupt_base;
};

struct InterruptOverride {
    u8 source;
    u32 global_interrupt;
    bool active_low;
    bool level_triggered;
};

struct Topology {
    u64 local_apic_address;
    u64 hpet_address;
    u32 enabled_processors;
    u8 bootstrap_apic_id;
    bool legacy_pic;
    IoApic io_apics[kMaximumIoApics];
    usize io_apic_count;
    InterruptOverride overrides[kMaximumOverrides];
    usize override_count;
};

bool initialize(const volatile limine_rsdp_response* response);
const Topology* topology();
u32 failure_code();
}
