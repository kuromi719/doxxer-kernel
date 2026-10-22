#include <doxxer/boot/requests.hpp>
#include <doxxer/types.hpp>

extern "C" doxxer::uptr __stack_chk_guard = static_cast<doxxer::uptr>(0xD0CCE2A55EED1234ULL);
extern "C" [[noreturn]] void kernel_main();

extern "C" __attribute__((no_stack_protector)) [[noreturn]] void kmain() {
    using namespace doxxer;

    uptr guard = static_cast<uptr>(0xD0CCE2A55EED1234ULL);
    const volatile limine_entropy_response* response = boot::entropy_request.response;
    if (response != nullptr && response->values != nullptr && response->value_count > 0) {
        guard = static_cast<uptr>(response->values[0]);
        if (response->value_count > 1) {
            guard ^= static_cast<uptr>(response->values[1] << 1U);
        }
    }

    guard &= ~static_cast<uptr>(0xFFU);
    if (guard == 0) {
        guard = static_cast<uptr>(0xD0CCE2A55EED1200ULL);
    }
    __stack_chk_guard = guard;
    kernel_main();
}
