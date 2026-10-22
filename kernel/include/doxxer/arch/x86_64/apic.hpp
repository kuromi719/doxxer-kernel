#pragma once

#include <doxxer/firmware/acpi.hpp>
#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::apic {
bool initialize(const firmware::acpi::Topology& topology);
bool initialize_secondary(u32 expected_apic_id);
u32 current_id();
void eoi();
bool send_ipi(u32 destination_apic_id, u8 vector);
u64 reference_counter();
u64 reference_ticks_for_microseconds(u64 microseconds);
bool timer_self_test();
u64 timer_ticks();
u32 timer_period_microseconds();
u32 failure_code();
}
