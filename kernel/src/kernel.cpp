#include <doxxer/arch/x86_64/protection.hpp>
#include <doxxer/arch/x86_64/serial.hpp>
#include <doxxer/boot/requests.hpp>
#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/log.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>
#include <doxxer/panic.hpp>
#include <doxxer/platform.hpp>

namespace {
[[noreturn]] void protected_kernel_main() {
    using namespace doxxer;

    if (!arch::x86_64::protection::on_kernel_stack()) {
        panic("KERNEL STACK TRANSITION FAILED");
    }
    log::success("GUARDED KERNEL STACK ACTIVE");

    const volatile limine_framebuffer_response* framebuffer_response =
        boot::framebuffer_request.response;
    if (framebuffer_response == nullptr || framebuffer_response->framebuffers == nullptr ||
        framebuffer_response->framebuffer_count == 0) {
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
}

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

    const volatile limine_memmap_response* memory_map = boot::memmap_request.response;
    const volatile limine_hhdm_response* hhdm = boot::hhdm_request.response;
    if (!memory::physical::initialize(memory_map, hhdm)) {
        panic("PHYSICAL MEMORY MANAGER INITIALIZATION FAILED");
    }
    if (!memory::physical::self_test()) {
        panic("PHYSICAL MEMORY MANAGER SELF-TEST FAILED");
    }
    const memory::physical::Statistics memory_stats = memory::physical::statistics();
    log::write("[INFO] PMM FREE PAGES: ");
    log::write_decimal(memory_stats.free_pages);
    log::write(" / METADATA PAGES: ");
    log::write_decimal(memory_stats.metadata_pages);
    log::write("\n");
    log::success("PMM ONLINE");

    if (!memory::virtual_memory::self_test()) {
        log::write("[ERROR] VMM SELF-TEST STAGE: ");
        log::write_decimal(memory::virtual_memory::self_test_failure());
        log::write("\n");
        panic("VIRTUAL MEMORY MANAGER SELF-TEST FAILED");
    }
    log::success("VMM ONLINE");

    if (!arch::x86_64::protection::initialize()) {
        panic("CPU PROTECTION INITIALIZATION FAILED");
    }
    log::success("GDT TSS IDT ONLINE");
    if (!arch::x86_64::protection::self_test()) {
        panic("CPU PROTECTION SELF-TEST FAILED");
    }
    log::success("EXCEPTION AND GUARD SELF-TEST PASSED");
    arch::x86_64::protection::enter_kernel_stack(protected_kernel_main);
}
