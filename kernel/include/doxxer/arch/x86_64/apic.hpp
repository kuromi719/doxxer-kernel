#pragma once

#include <doxxer/firmware/acpi.hpp>
#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::apic {
bool initialize(const firmware::acpi::Topology& topology);
bool timer_self_test();
u64 timer_ticks();
u32 timer_period_microseconds();
u32 failure_code();
}
