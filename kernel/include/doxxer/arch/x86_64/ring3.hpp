#pragma once

#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::ring3 {
bool self_test();
bool initialize_runtime();
bool runtime_self_test();
// Enroll the built-in, immutable user image before image_policy::seal().
bool enroll_desktop_image();
// Does not return: a validated first user syscall invokes on_ready, then the
// isolated task remains in ring 3. Any launch/runtime error invokes panic().
[[noreturn]] void launch_desktop_session(void (*on_ready)());
u32 failure_code();
}
