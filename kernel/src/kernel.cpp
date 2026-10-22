#include <doxxer/arch/x86_64/serial.hpp>
#include <doxxer/boot/requests.hpp>
#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/log.hpp>
#include <doxxer/panic.hpp>
#include <doxxer/platform.hpp>

extern "C" [[noreturn]] void kernel_main() {
    using namespace doxxer;

    if (!serial::initialize()) {
        platform::halt();
    }
    log::initialize();
    log::line("DOXXER_BOOT_START");
    log::success("SERIAL ONLINE");

    if (!LIMINE_BASE_REVISION_SUPPORTED(boot::base_revision)) {
        panic("UNSUPPORTED LIMINE BASE REVISION");
    }

    const volatile limine_entropy_response* entropy = boot::entropy_request.response;
    if (entropy == nullptr || entropy->values == nullptr || entropy->value_count == 0) {
        panic("BOOT ENTROPY UNAVAILABLE");
    }
    log::success("STACK GUARD SEEDED");

    const volatile limine_bootloader_info_response* bootloader =
        boot::bootloader_info_request.response;
    if (bootloader != nullptr && bootloader->name != nullptr) {
        log::write("[INFO] BOOTLOADER: ");
        log::write(bootloader->name);
        if (bootloader->version != nullptr) {
            log::write(" ");
            log::write(bootloader->version);
        }
        log::write("\n");
    }

    const volatile limine_framebuffer_response* framebuffer_response =
        boot::framebuffer_request.response;
    if (framebuffer_response == nullptr || framebuffer_response->framebuffers == nullptr
        || framebuffer_response->framebuffer_count == 0) {
        panic("FRAMEBUFFER UNAVAILABLE");
    }

    if (!graphics::initialize(framebuffer_response->framebuffers[0])) {
        panic("UNSUPPORTED FRAMEBUFFER");
    }
    graphics::draw_boot_banner();
    log::attach_framebuffer();
    log::success("FRAMEBUFFER ONLINE");
    log::success("KERNEL READY");
    log::line("DOXXER_BOOT_OK");

    platform::test_success();
}
