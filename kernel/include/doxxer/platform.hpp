#pragma once

namespace doxxer::platform {
void delay_milliseconds(unsigned milliseconds);
[[noreturn]] void reboot();
[[noreturn]] void failure_recovery();
[[noreturn]] void halt();
[[noreturn]] void test_success();
}
