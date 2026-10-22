#pragma once

#include <limine.h>

#include <doxxer/firmware/acpi.hpp>
#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::smp {
bool initialize(const volatile limine_mp_response* response,
                const firmware::acpi::Topology& topology);
bool self_test();
u32 processor_count();
u32 online_processor_count();
u32 current_processor_id();
u32 current_apic_id();
u32 failure_code();
}
