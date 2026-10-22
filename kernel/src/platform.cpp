#include <doxxer/arch/x86_64/io.hpp>
#include <doxxer/platform.hpp>

namespace doxxer::platform {
[[noreturn]] void halt() {
    asm volatile("cli");
    for (;;) {
        asm volatile("hlt");
    }
}

[[noreturn]] void test_success() {
#ifdef DOXXER_TEST_MODE
    arch::x86_64::out16(0x501, 0x10);
#endif
    halt();
}
}
