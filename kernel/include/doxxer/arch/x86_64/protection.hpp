#pragma once

namespace doxxer::arch::x86_64::protection {
using KernelEntry = void (*)();

bool initialize();
bool self_test();
bool on_kernel_stack();
[[noreturn]] void enter_kernel_stack(KernelEntry entry);
}
