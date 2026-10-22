#include <doxxer/log.hpp>
#include <doxxer/panic.hpp>
#include <doxxer/platform.hpp>

namespace doxxer {
[[noreturn]] void panic(const char* reason) {
    log::error(reason == nullptr ? "UNKNOWN PANIC" : reason);
    log::line("DOXXER_PANIC");
    platform::halt();
}
}
