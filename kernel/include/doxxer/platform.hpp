#pragma once

namespace doxxer::platform {
bool initialize_restart_hotkey();
void poll_restart_hotkey();
void delay_milliseconds(unsigned milliseconds);
[[noreturn]] void reboot();
[[noreturn]] void failure_recovery();
[[noreturn]] void wait_for_restart();
[[noreturn]] void halt();
[[noreturn]] void test_success();
}
