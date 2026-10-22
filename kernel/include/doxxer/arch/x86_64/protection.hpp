#pragma once

#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::protection {
using KernelEntry = void (*)();
using CpuEntry = void (*)(void* argument);

bool initialize();
bool self_test();
bool on_kernel_stack();
[[noreturn]] void enter_kernel_stack(KernelEntry entry);
[[noreturn]] void enter_cpu_stack(u64 stack_top, CpuEntry entry, void* argument);
}
