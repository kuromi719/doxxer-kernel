#pragma once

#include <limine.h>

#include <doxxer/firmware/acpi.hpp>
#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::smp {
using WorkerEntry = void (*)();

bool initialize(const volatile limine_mp_response* response,
                const firmware::acpi::Topology& topology);
bool self_test();
u32 processor_count();
u32 online_processor_count();
u32 current_processor_id();
u32 current_apic_id();
u32 current_index();
u32 apic_id(u32 index);
bool current_syscall_stack(u64& stack_bottom, u64& stack_top);
bool bind_syscall_context(void* context);
bool unbind_syscall_context(void* context);
bool install_worker_entry(WorkerEntry entry);
u32 failure_code();
}
