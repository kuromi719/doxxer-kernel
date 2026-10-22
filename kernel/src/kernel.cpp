#include <doxxer/arch/x86_64/apic.hpp>
#include <doxxer/arch/x86_64/hardening.hpp>
#include <doxxer/arch/x86_64/iommu.hpp>
#include <doxxer/arch/x86_64/protection.hpp>
#include <doxxer/arch/x86_64/serial.hpp>
#include <doxxer/arch/x86_64/smp.hpp>
#include <doxxer/boot/requests.hpp>
#include <doxxer/firmware/acpi.hpp>
#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/ipc/channel.hpp>
#include <doxxer/loader/elf64.hpp>
#include <doxxer/log.hpp>
#include <doxxer/memory/heap.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/user_copy.hpp>
#include <doxxer/memory/virtual.hpp>
#include <doxxer/panic.hpp>
#include <doxxer/platform.hpp>
#include <doxxer/process/process.hpp>
#include <doxxer/scheduler/scheduler.hpp>
#include <doxxer/security/capability.hpp>
#include <doxxer/security/image_policy.hpp>
#include <doxxer/service/registry.hpp>
#include <doxxer/sync/event.hpp>
#include <doxxer/syscall/dispatcher.hpp>
#include <doxxer/thread/user_thread.hpp>

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

    if (!security::capability::initialize()) {
        panic("CAPABILITY REGISTRY INITIALIZATION FAILED");
    }
    if (!security::capability::self_test()) {
        log::write("[ERROR] CAPABILITY SELF-TEST STAGE: ");
        log::write_decimal(security::capability::failure_code());
        log::write("\n");
        panic("CAPABILITY SECURITY SELF-TEST FAILED");
    }
    const security::capability::Statistics capability_stats = security::capability::statistics();
    log::write("[INFO] CAPABILITY REJECTIONS VERIFIED: ");
    log::write_decimal(capability_stats.rejected_operations);
    log::write("\n");
    log::success("CAPABILITY SECURITY MODEL ONLINE");

    if (!ipc::initialize() || !ipc::self_test()) {
        log::write("[ERROR] IPC SELF-TEST STAGE: ");
        log::write_decimal(ipc::failure_code());
        log::write("\n");
        panic("CAPABILITY IPC SELF-TEST FAILED");
    }
    const ipc::Statistics ipc_stats = ipc::statistics();
    log::write("[INFO] IPC MESSAGES: ");
    log::write_decimal(ipc_stats.sent_messages);
    log::write(" SENT / ");
    log::write_decimal(ipc_stats.received_messages);
    log::write(" RECEIVED\n");
    log::success("CAPABILITY IPC ONLINE");

    if (!sync::event::initialize() || !sync::event::self_test()) {
        log::write("[ERROR] EVENT SELF-TEST STAGE: ");
        log::write_decimal(sync::event::failure_code());
        log::write("\n");
        panic("CAPABILITY EVENT SELF-TEST FAILED");
    }
    const sync::event::Statistics event_stats = sync::event::statistics();
    log::write("[INFO] EVENTS: ");
    log::write_decimal(event_stats.signals);
    log::write(" SIGNALS / ");
    log::write_decimal(event_stats.successful_waits);
    log::write(" WAITS\n");
    log::success("CAPABILITY EVENTS ONLINE");

    if (!process::initialize() || !process::self_test()) {
        log::write("[ERROR] PROCESS SELF-TEST STAGE: ");
        log::write_decimal(process::failure_code());
        log::write("\n");
        panic("PROCESS CONTAINER SELF-TEST FAILED");
    }
    const process::Statistics process_stats = process::statistics();
    log::write("[INFO] PROCESS LIFECYCLE: ");
    log::write_decimal(process_stats.created_processes);
    log::write(" CREATED / ");
    log::write_decimal(process_stats.destroyed_processes);
    log::write(" DESTROYED\n");
    log::success("ISOLATED PROCESS CONTAINERS ONLINE");

    if (!syscall::initialize() || !syscall::self_test()) {
        log::write("[ERROR] SYSCALL ABI SELF-TEST STAGE: ");
        log::write_decimal(syscall::failure_code());
        log::write("\n");
        panic("SYSCALL ABI SELF-TEST FAILED");
    }
    const syscall::Statistics syscall_stats = syscall::statistics();
    log::write("[INFO] SYSCALL ABI: ");
    log::write_decimal(syscall_stats.successful);
    log::write(" ACCEPTED / ");
    log::write_decimal(syscall_stats.rejected);
    log::write(" REJECTED\n");
    log::success("BOUNDED SYSCALL ABI ONLINE");

    if (!service::initialize() || !service::self_test()) {
        log::write("[ERROR] SERVICE REGISTRY SELF-TEST STAGE: ");
        log::write_decimal(service::failure_code());
        log::write("\n");
        panic("SERVICE REGISTRY SELF-TEST FAILED");
    }
    const service::Statistics service_stats = service::statistics();
    log::write("[INFO] SERVICE REGISTRY: ");
    log::write_decimal(service_stats.registrations);
    log::write(" PUBLISHED / ");
    log::write_decimal(service_stats.resolutions);
    log::write(" RESOLVED\n");
    log::success("CAPABILITY SERVICE REGISTRY ONLINE");

    if (!memory::user_copy::self_test()) {
        log::write("[ERROR] USER COPY SELF-TEST STAGE: ");
        log::write_decimal(memory::user_copy::failure_code());
        log::write("\n");
        panic("USER MEMORY COPY SELF-TEST FAILED");
    }
    const memory::user_copy::Statistics copy_stats = memory::user_copy::statistics();
    log::write("[INFO] USER COPY BYTES VERIFIED: ");
    log::write_decimal(copy_stats.bytes_copied);
    log::write("\n");
    log::success("VALIDATED USER MEMORY ACCESS ONLINE");

    if (!security::image_policy::initialize() || !security::image_policy::self_test()) {
        log::write("[ERROR] IMAGE POLICY SELF-TEST STAGE: ");
        log::write_decimal(security::image_policy::failure_code());
        log::write("\n");
        panic("IMAGE TRUST POLICY INITIALIZATION FAILED");
    }
    if (!loader::elf64::self_test()) {
        log::write("[ERROR] ELF64 LOADER SELF-TEST STAGE: ");
        log::write_decimal(loader::elf64::failure_code());
        log::write("\n");
        panic("ELF64 LOADER SELF-TEST FAILED");
    }
    const loader::elf64::Statistics loader_stats = loader::elf64::statistics();
    log::write("[INFO] ELF64 IMAGE PAGES VERIFIED: ");
    log::write_decimal(loader_stats.mapped_pages);
    log::write("\n");
    log::success("HARDENED ELF64 LOADER ONLINE");
    if (!security::image_policy::is_sealed()) {
        panic("IMAGE TRUST POLICY NOT SEALED");
    }
    const security::image_policy::Statistics image_policy_stats =
        security::image_policy::statistics();
    log::write("[INFO] TRUSTED IMAGE DIGESTS: ");
    log::write_decimal(image_policy_stats.trusted_images);
    log::write(" / REJECTIONS: ");
    log::write_decimal(image_policy_stats.rejected_images);
    log::write("\n");
    log::success("SEALED IMAGE TRUST POLICY ONLINE");

    if (!thread::user::initialize() || !thread::user::self_test()) {
        log::write("[ERROR] USER THREAD SELF-TEST STAGE: ");
        log::write_decimal(thread::user::failure_code());
        log::write("\n");
        panic("USER THREAD CONTEXT SELF-TEST FAILED");
    }
    const thread::user::Statistics thread_stats = thread::user::statistics();
    log::write("[INFO] USER THREAD LIFECYCLE: ");
    log::write_decimal(thread_stats.created_threads);
    log::write(" CREATED / ");
    log::write_decimal(thread_stats.destroyed_threads);
    log::write(" DESTROYED\n");
    log::success("GUARDED USER THREAD CONTEXTS ONLINE");

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

    if (!arch::x86_64::iommu::initialize(*topology) ||
        !arch::x86_64::iommu::self_test()) {
        log::write("[ERROR] IOMMU FAILURE STAGE: ");
        log::write_decimal(arch::x86_64::iommu::failure_code());
        log::write("\n");
        panic("DMA ISOLATION UNAVAILABLE");
    }
    const arch::x86_64::iommu::Statistics iommu_stats =
        arch::x86_64::iommu::statistics();
    log::write("[INFO] IOMMU UNITS: ");
    log::write_decimal(iommu_stats.enabled_units);
    log::write(" / DMA WIDTH: ");
    log::write_decimal(iommu_stats.dma_address_width);
    log::write(" / PCI COVERAGE: ");
    log::write_decimal(topology->dma_covered_functions);
    log::write("/");
    log::write_decimal(topology->pci_functions);
    log::write(" / BUS MASTER OFF: ");
    log::write_decimal(iommu_stats.quiesced_pci_functions);
    log::write("\n");
    log::success("DMA REMAPPING DEFAULT-DENY");
    log::success("DMA ROOT TABLES PINNED");

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
    const arch::x86_64::hardening::Statistics all_cpu_hardening =
        arch::x86_64::hardening::statistics();
    log::write("[INFO] HARDENED PROCESSORS VERIFIED: ");
    log::write_decimal(all_cpu_hardening.hardened_processors);
    log::write("\n");
    log::success("ALL CPU SECURITY STATE VERIFIED");
    log::success("SMP IPI SELF-TEST PASSED");
    if (!scheduler::initialize()) {
        log::write("[ERROR] SCHEDULER FAILURE STAGE: ");
        log::write_decimal(scheduler::failure_code());
        log::write("\n");
        panic("SCHEDULER INITIALIZATION FAILED");
    }
    log::success("PER-CPU SCHEDULER ONLINE");
    if (!scheduler::self_test()) {
        log::write("[ERROR] SCHEDULER SELF-TEST STAGE: ");
        log::write_decimal(scheduler::failure_code());
        log::write("\n");
        panic("SCHEDULER SELF-TEST FAILED");
    }
    const scheduler::Statistics scheduler_stats = scheduler::statistics();
    log::write("[INFO] SCHEDULER TASKS: ");
    log::write_decimal(scheduler_stats.completed);
    log::write(" COMPLETED / ");
    log::write_decimal(scheduler_stats.failed);
    log::write(" FAILED / CAPACITY ");
    log::write_decimal(scheduler_stats.capacity);
    log::write("\n");
    log::success("CROSS-CPU TASK SELF-TEST PASSED");
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
    u64 memory_integrity_key = entropy->values[0] ^ 0x5348'4144'4F57'4D45ULL;
    if (entropy->value_count > 1) {
        const u64 second = entropy->values[1];
        memory_integrity_key ^= (second << 17U) | (second >> 47U);
    }
    if (memory_integrity_key == 0 ||
        !memory::physical::initialize(memory_map, hhdm, memory_integrity_key)) {
        panic("PHYSICAL MEMORY MANAGER INITIALIZATION FAILED");
    }
    if (!memory::physical::self_test()) {
        log::write("[ERROR] PMM SELF-TEST STAGE: ");
        log::write_decimal(memory::physical::self_test_failure());
        log::write("\n");
        panic("PHYSICAL MEMORY MANAGER SELF-TEST FAILED");
    }
    const memory::physical::Statistics memory_stats = memory::physical::statistics();
    log::write("[INFO] PMM FREE PAGES: ");
    log::write_decimal(memory_stats.free_pages);
    log::write(" / METADATA PAGES: ");
    log::write_decimal(memory_stats.metadata_pages);
    log::write(" / SHADOW BYTES: ");
    log::write_decimal(memory_stats.shadow_bytes);
    log::write(" / OWNER REJECTIONS: ");
    log::write_decimal(memory_stats.ownership_rejections);
    log::write(" / DOMAIN REJECTIONS: ");
    log::write_decimal(memory_stats.domain_rejections);
    log::write(" / MAPPING REJECTIONS: ");
    log::write_decimal(memory_stats.mapping_rejections);
    log::write("\n");
    log::success("PMM ONLINE");
    log::success("SEALED SHADOW PAGE LEDGER ONLINE");

    if (!memory::virtual_memory::self_test()) {
        log::write("[ERROR] VMM SELF-TEST STAGE: ");
        log::write_decimal(memory::virtual_memory::self_test_failure());
        log::write("\n");
        panic("VIRTUAL MEMORY MANAGER SELF-TEST FAILED");
    }
    log::success("VMM ONLINE");
    const memory::physical::Statistics isolated_memory_stats =
        memory::physical::statistics();
    log::write("[INFO] MEMORY DOMAIN REJECTIONS VERIFIED: ");
    log::write_decimal(isolated_memory_stats.domain_rejections);
    log::write("\n");
    log::success("CROSS-DOMAIN RAM ISOLATION VERIFIED");
    log::write("[INFO] USER PAGE PINS: ");
    log::write_decimal(isolated_memory_stats.user_mapping_references);
    log::write(" ACTIVE / ");
    log::write_decimal(isolated_memory_stats.mapping_rejections);
    log::write(" REJECTIONS\n");
    log::success("MAPPED USER PAGE LIFETIMES PINNED");
    log::success("USER HHDM ACCESS API SEALED");

    if (!arch::x86_64::protection::initialize()) {
        panic("CPU PROTECTION INITIALIZATION FAILED");
    }
    log::success("GDT TSS IDT ONLINE");
    if (!arch::x86_64::protection::self_test()) {
        panic("CPU PROTECTION SELF-TEST FAILED");
    }
    const arch::x86_64::hardening::Statistics hardening_stats =
        arch::x86_64::hardening::statistics();
    log::write("[INFO] CPU HARDENING: WP/NX/SMEP/SMAP/UMIP / CORES: ");
    log::write_decimal(hardening_stats.hardened_processors);
    log::write("\n");
    log::success("CPU PRIVILEGE BOUNDARIES LOCKED");
    log::success("KERNEL ELF PERMISSIONS VERIFIED");
    log::success("SMAP ENFORCEMENT PROBED");
    log::success("SMEP ENFORCEMENT PROBED");
    const memory::virtual_memory::TemporaryMappingStatistics temporary_stats =
        memory::virtual_memory::temporary_mapping_statistics();
    log::write("[INFO] TEMPORARY USER WINDOWS: ");
    log::write_decimal(temporary_stats.mappings);
    log::write(" MAPS / ");
    log::write_decimal(temporary_stats.unmappings);
    log::write(" UNMAPS / ");
    log::write_decimal(temporary_stats.failures);
    log::write(" FAILURES\n");
    log::success("EPHEMERAL USER MEMORY WINDOWS VERIFIED");
    const memory::physical::Statistics protected_memory_stats =
        memory::physical::statistics();
    log::write("[INFO] SUPERVISOR PAGE PINS: ");
    log::write_decimal(protected_memory_stats.supervisor_mapping_references);
    log::write(" ACTIVE\n");
    log::success("SUPERVISOR MAPPING LIFETIMES PINNED");
    log::success("SUPERVISOR STACK WINDOWS ISOLATED");
    log::success("EXCEPTION AND GUARD SELF-TEST PASSED");
    arch::x86_64::protection::enter_kernel_stack(protected_kernel_main);
}
