#include <doxxer/arch/x86_64/apic.hpp>
#include <doxxer/arch/x86_64/protection.hpp>
#include <doxxer/arch/x86_64/serial.hpp>
#include <doxxer/arch/x86_64/smp.hpp>
#include <doxxer/boot/requests.hpp>
#include <doxxer/firmware/acpi.hpp>
#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/log.hpp>
#include <doxxer/memory/heap.hpp>
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

    if (!memory::heap::initialize()) {
        panic("KERNEL HEAP INITIALIZATION FAILED");
    }
    if (!memory::heap::self_test()) {
        log::write("[ERROR] HEAP SELF-TEST STAGE: ");
        log::write_decimal(memory::heap::self_test_failure());
        log::write("\n");
        panic("KERNEL HEAP SELF-TEST FAILED");
    }
    const memory::heap::Statistics heap_stats = memory::heap::statistics();
    log::write("[INFO] HEAP COMMITTED PAGES: ");
    log::write_decimal(heap_stats.committed_pages);
    log::write(" / QUARANTINED OBJECTS: ");
    log::write_decimal(heap_stats.quarantined_objects);
    log::write("\n");
    log::success("HARDENED HEAP ONLINE");

    if (!firmware::acpi::initialize(boot::rsdp_request.response)) {
        log::write("[ERROR] ACPI FAILURE STAGE: ");
        log::write_decimal(firmware::acpi::failure_code());
        log::write("\n");
        panic("ACPI VALIDATION FAILED");
    }
    const firmware::acpi::Topology* topology = firmware::acpi::topology();
    if (topology == nullptr) {
        panic("ACPI TOPOLOGY UNAVAILABLE");
    }
    log::write("[INFO] ACPI PROCESSORS: ");
    log::write_decimal(topology->enabled_processors);
    log::write(" / IOAPICS: ");
    log::write_decimal(topology->io_apic_count);
    log::write("\n");
    log::success("ACPI TABLES VALIDATED");

    if (!arch::x86_64::apic::initialize(*topology)) {
        log::write("[ERROR] APIC FAILURE STAGE: ");
        log::write_decimal(arch::x86_64::apic::failure_code());
        log::write("\n");
        panic("APIC INITIALIZATION FAILED");
    }
    log::success("LOCAL APIC ONLINE");
    log::success("IOAPIC MASKED");
    if (!arch::x86_64::smp::initialize(boot::mp_request.response, *topology)) {
        log::write("[ERROR] SMP FAILURE STAGE: ");
        log::write_decimal(arch::x86_64::smp::failure_code());
        log::write("\n");
        panic("SMP INITIALIZATION FAILED");
    }
    log::write("[INFO] SMP PROCESSORS ONLINE: ");
    log::write_decimal(arch::x86_64::smp::online_processor_count());
    log::write(" / DISCOVERED: ");
    log::write_decimal(arch::x86_64::smp::processor_count());
    log::write("\n");
    log::success("PER-CPU RUNTIME ONLINE");
    if (!arch::x86_64::smp::self_test()) {
        log::write("[ERROR] SMP SELF-TEST STAGE: ");
        log::write_decimal(arch::x86_64::smp::failure_code());
        log::write("\n");
        panic("SMP IPI SELF-TEST FAILED");
    }
    log::success("SMP IPI SELF-TEST PASSED");
    if (!arch::x86_64::apic::timer_self_test()) {
        log::write("[ERROR] APIC TIMER FAILURE STAGE: ");
        log::write_decimal(arch::x86_64::apic::failure_code());
        log::write("\n");
        panic("APIC TIMER SELF-TEST FAILED");
    }
    log::write("[INFO] APIC TIMER PERIOD (US): ");
    log::write_decimal(arch::x86_64::apic::timer_period_microseconds());
    log::write(" / OBSERVED TICKS: ");
    log::write_decimal(arch::x86_64::apic::timer_ticks());
    log::write("\n");
    log::success("APIC TIMER ONLINE");

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
