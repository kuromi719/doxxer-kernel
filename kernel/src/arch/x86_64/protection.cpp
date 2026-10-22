#include <doxxer/arch/x86_64/protection.hpp>

#include <doxxer/arch/x86_64/hardening.hpp>
#include <doxxer/arch/x86_64/interrupts.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>

extern "C" [[noreturn]] void
doxxer_run_on_stack(doxxer::u64 stack_top, doxxer::arch::x86_64::protection::KernelEntry entry);
extern "C" [[noreturn]] void
doxxer_run_on_cpu_stack(doxxer::u64 root_physical, doxxer::u64 stack_top,
                        doxxer::arch::x86_64::protection::CpuEntry entry, void* argument);
extern "C" char __requests_start[];
extern "C" char __requests_end[];
extern "C" char __text_start[];
extern "C" char __text_end[];
extern "C" char __rodata_start[];
extern "C" char __rodata_end[];
extern "C" char __data_start[];
extern "C" char __data_end[];
extern "C" char __bss_start[];
extern "C" char __bss_end[];

namespace doxxer::arch::x86_64::protection {
namespace {
using memory::physical::kPageSize;
using memory::virtual_memory::AddressSpace;
using memory::virtual_memory::MapFlags;

constexpr u64 kStackPages = 16;
constexpr u64 kKernelStackBase = 0x0000'7000'0000'0000ULL;
constexpr u64 kExceptionStackBase = 0x0000'7000'0010'0000ULL;
constexpr u64 kEmergencyStackBase = 0x0000'7000'0020'0000ULL;
constexpr u16 kTaskStateSelector = 0x28;

struct StackMapping {
    u64 virtual_base;
    u64 physical_base;
    u64 mapped_pages;

    u64 top() const { return virtual_base + (kStackPages + 1) * kPageSize; }
};

struct [[gnu::packed]] TaskStateSegment {
    u32 reserved0;
    u64 rsp0;
    u64 rsp1;
    u64 rsp2;
    u64 reserved1;
    u64 ist1;
    u64 ist2;
    u64 ist3;
    u64 ist4;
    u64 ist5;
    u64 ist6;
    u64 ist7;
    u64 reserved2;
    u16 reserved3;
    u16 io_map_base;
};

struct [[gnu::packed]] DescriptorTablePointer {
    u16 limit;
    u64 base;
};

static_assert(sizeof(TaskStateSegment) == 104);
static_assert(sizeof(DescriptorTablePointer) == 10);

AddressSpace kernel_space{};
StackMapping kernel_stack{kKernelStackBase, 0, 0};
StackMapping exception_stack{kExceptionStackBase, 0, 0};
StackMapping emergency_stack{kEmergencyStackBase, 0, 0};
alignas(16) u64 gdt[7]{};
alignas(16) TaskStateSegment tss{};
bool initialized = false;

bool map_stack(StackMapping& stack) {
    if (!memory::physical::allocate_contiguous(kStackPages, 1, stack.physical_base,
                                               memory::physical::PageOwner::kernel_stack)) {
        return false;
    }
    for (u64 index = 0; index < kStackPages; ++index) {
        const u64 virtual_address = stack.virtual_base + (index + 1) * kPageSize;
        const u64 physical_address = stack.physical_base + index * kPageSize;
        if (!memory::virtual_memory::map(kernel_space, virtual_address, physical_address,
                                         MapFlags::write)) {
            return false;
        }
        ++stack.mapped_pages;
    }
    return true;
}

void release_stack(StackMapping& stack) {
    for (u64 index = 0; index < stack.mapped_pages; ++index) {
        memory::virtual_memory::unmap(kernel_space, stack.virtual_base + (index + 1) * kPageSize);
    }
    if (stack.physical_base != 0) {
        memory::physical::free_contiguous(stack.physical_base, kStackPages,
                                          memory::physical::PageOwner::kernel_stack);
    }
    stack.physical_base = 0;
    stack.mapped_pages = 0;
}

void release_all() {
    release_stack(emergency_stack);
    release_stack(exception_stack);
    release_stack(kernel_stack);
    if (kernel_space.valid()) {
        memory::virtual_memory::destroy(kernel_space);
    }
}

void install_gdt() {
    tss.rsp0 = kernel_stack.top();
    tss.ist1 = exception_stack.top();
    tss.ist2 = emergency_stack.top();
    tss.io_map_base = sizeof(TaskStateSegment);

    gdt[0] = 0;
    gdt[1] = 0x00AF'9A00'0000'FFFFULL;
    gdt[2] = 0x00CF'9200'0000'FFFFULL;
    gdt[3] = 0x00CF'F200'0000'FFFFULL;
    gdt[4] = 0x00AF'FA00'0000'FFFFULL;

    const u64 base = reinterpret_cast<u64>(&tss);
    constexpr u64 limit = sizeof(TaskStateSegment) - 1;
    gdt[5] = (limit & 0xFFFFU) | ((base & 0xFF'FFFFU) << 16U) | (0x89ULL << 40U) |
             (((limit >> 16U) & 0xFU) << 48U) | (((base >> 24U) & 0xFFU) << 56U);
    gdt[6] = base >> 32U;

    const DescriptorTablePointer pointer{
        .limit = static_cast<u16>(sizeof(gdt) - 1),
        .base = reinterpret_cast<u64>(&gdt[0]),
    };
    asm volatile("lgdt %0\n\t"
                 "pushq $0x08\n\t"
                 "leaq 1f(%%rip), %%rax\n\t"
                 "pushq %%rax\n\t"
                 "lretq\n\t"
                 "1:\n\t"
                 "movw $0x10, %%ax\n\t"
                 "movw %%ax, %%ds\n\t"
                 "movw %%ax, %%es\n\t"
                 "movw %%ax, %%ss\n\t"
                 "xorw %%ax, %%ax\n\t"
                 "movw %%ax, %%fs\n\t"
                 "movw %%ax, %%gs\n\t"
                 :
                 : "m"(pointer)
                 : "rax", "memory");

    const u16 task_selector = kTaskStateSelector;
    asm volatile("ltr %0" : : "r"(task_selector) : "memory");
}

bool stack_layout_valid(const StackMapping& stack) {
    memory::virtual_memory::Mapping mapping{};
    if (memory::virtual_memory::query(kernel_space, stack.virtual_base, mapping) ||
        memory::virtual_memory::query(kernel_space, stack.top(), mapping)) {
        return false;
    }
    for (u64 index = 0; index < kStackPages; ++index) {
        if (!memory::virtual_memory::query(kernel_space,
                                           stack.virtual_base + (index + 1) * kPageSize, mapping) ||
            mapping.physical_address != stack.physical_base + index * kPageSize ||
            !memory::virtual_memory::has_flag(mapping.flags, MapFlags::write) ||
            memory::virtual_memory::has_flag(mapping.flags, MapFlags::execute) ||
            memory::virtual_memory::has_flag(mapping.flags, MapFlags::user)) {
            return false;
        }
    }
    return true;
}

bool descriptor_state_valid() {
    u16 code_selector = 0;
    u16 stack_selector = 0;
    u16 task_selector = 0;
    asm volatile("mov %%cs, %0" : "=r"(code_selector));
    asm volatile("mov %%ss, %0" : "=r"(stack_selector));
    asm volatile("str %0" : "=r"(task_selector));
    return code_selector == 0x08 && stack_selector == 0x10 && task_selector == kTaskStateSelector;
}

bool region_permissions_valid(const char* start, const char* end, bool writable,
                              bool executable) {
    const u64 first = reinterpret_cast<u64>(start) & ~(kPageSize - 1);
    const u64 limit = reinterpret_cast<u64>(end);
    if (first == 0 || limit <= first) {
        return false;
    }
    for (u64 address = first; address < limit; address += kPageSize) {
        memory::virtual_memory::Mapping mapping{};
        if (!memory::virtual_memory::query(kernel_space, address, mapping) ||
            memory::virtual_memory::has_flag(mapping.flags, MapFlags::user) ||
            memory::virtual_memory::has_flag(mapping.flags, MapFlags::write) != writable ||
            memory::virtual_memory::has_flag(mapping.flags, MapFlags::execute) != executable) {
            return false;
        }
    }
    return true;
}

bool kernel_image_permissions_valid() {
    return region_permissions_valid(__requests_start, __requests_end, true, false) &&
           region_permissions_valid(__text_start, __text_end, false, true) &&
           region_permissions_valid(__rodata_start, __rodata_end, false, false) &&
           region_permissions_valid(__data_start, __data_end, true, false) &&
           region_permissions_valid(__bss_start, __bss_end, true, false);
}

bool smap_enforcement_valid() {
    constexpr u64 kProbeAddress = 0x0000'6000'0000'0000ULL;
    u64 physical_address = 0;
    if (!memory::physical::allocate_page(physical_address,
                                         memory::physical::PageOwner::user_data,
                                         memory::physical::Zone::any,
                                         kernel_space.isolation_domain())) {
        return false;
    }
    bool mapped = memory::virtual_memory::map(kernel_space, kProbeAddress, physical_address,
                                               MapFlags::user | MapFlags::write);
    bool valid = mapped && interrupts::probe_page_fault(
                               kProbeAddress, true, exception_stack.virtual_base + kPageSize,
                               exception_stack.top());
    if (mapped && !memory::virtual_memory::unmap(kernel_space, kProbeAddress)) {
        valid = false;
    }
    if (!memory::physical::free_page(physical_address,
                                     memory::physical::PageOwner::user_data,
                                     kernel_space.isolation_domain())) {
        valid = false;
    }
    return valid;
}

bool smep_enforcement_valid() {
    constexpr u64 kProbeAddress = 0x0000'6100'0000'0000ULL;
    u64 physical_address = 0;
    if (!memory::physical::allocate_page(physical_address,
                                         memory::physical::PageOwner::user_image,
                                         memory::physical::Zone::any,
                                         kernel_space.isolation_domain())) {
        return false;
    }
    memory::virtual_memory::TemporaryMapping temporary{};
    if (!memory::virtual_memory::map_temporary_user(kernel_space, physical_address, true,
                                                    temporary)) {
        (void)memory::physical::free_page(physical_address,
                                          memory::physical::PageOwner::user_image,
                                          kernel_space.isolation_domain());
        return false;
    }
    auto* code = static_cast<u8*>(temporary.address);
    code[0] = 0xC3;
    if (!memory::virtual_memory::unmap_temporary_user(temporary)) {
        return false;
    }
    bool mapped = memory::virtual_memory::map(kernel_space, kProbeAddress, physical_address,
                                               MapFlags::user | MapFlags::execute);
    bool valid = mapped && interrupts::probe_execution_fault(
                               kProbeAddress, exception_stack.virtual_base + kPageSize,
                               exception_stack.top());
    if (mapped && !memory::virtual_memory::unmap(kernel_space, kProbeAddress)) {
        valid = false;
    }
    if (!memory::physical::free_page(physical_address,
                                     memory::physical::PageOwner::user_image,
                                     kernel_space.isolation_domain())) {
        valid = false;
    }
    return valid;
}

bool supervisor_windows_valid() {
    constexpr u64 kDynamicProbe = 0x0000'7200'FF00'0000ULL;
    AddressSpace process_space{};
    memory::virtual_memory::Mapping inherited{};
    const u64 stack_address = kernel_stack.virtual_base + kPageSize;
    if (!memory::virtual_memory::create(process_space, 4095)) {
        return false;
    }

    bool valid = memory::virtual_memory::query(process_space, stack_address, inherited) &&
                 !memory::virtual_memory::has_flag(inherited.flags, MapFlags::user) &&
                 !memory::physical::free_page(inherited.physical_address,
                                              memory::physical::PageOwner::kernel_stack) &&
                 !memory::virtual_memory::map(process_space, kernel_stack.virtual_base,
                                              inherited.physical_address, MapFlags::write) &&
                 !memory::virtual_memory::unmap(process_space, stack_address) &&
                 !memory::virtual_memory::protect(process_space, stack_address, MapFlags::write);

    u64 probe_page = 0;
    bool probe_mapped = false;
    if (!memory::physical::allocate_page(probe_page, memory::physical::PageOwner::test)) {
        valid = false;
    } else if (!memory::virtual_memory::map(kernel_space, kDynamicProbe, probe_page,
                                            MapFlags::write)) {
        valid = false;
    } else {
        probe_mapped = true;
        memory::virtual_memory::Mapping dynamic_mapping{};
        valid = memory::virtual_memory::query(process_space, kDynamicProbe, dynamic_mapping) &&
                dynamic_mapping.physical_address == probe_page &&
                !memory::virtual_memory::has_flag(dynamic_mapping.flags, MapFlags::user) && valid;
    }

    if (probe_mapped) {
        const bool unmapped = memory::virtual_memory::unmap(kernel_space, kDynamicProbe);
        valid = unmapped && valid;
        if (unmapped) {
            probe_mapped = false;
            memory::virtual_memory::Mapping removed{};
            valid = !memory::virtual_memory::query(process_space, kDynamicProbe, removed) && valid;
        }
    }
    if (probe_page != 0 && !probe_mapped) {
        valid = memory::physical::free_page(probe_page, memory::physical::PageOwner::test) && valid;
    }
    valid = memory::virtual_memory::destroy(process_space) && valid;
    valid = memory::virtual_memory::query(kernel_space, stack_address, inherited) && valid;
    return valid;
}
}

bool initialize() {
    if (initialized) {
        return false;
    }
    asm volatile("cli" : : : "memory");
    if (!memory::virtual_memory::create(kernel_space) || !map_stack(kernel_stack) ||
        !map_stack(exception_stack) || !map_stack(emergency_stack)) {
        release_all();
        return false;
    }
    if (!memory::virtual_memory::activate(kernel_space)) {
        return false;
    }
    install_gdt();
    interrupts::initialize();
    if (!hardening::initialize_boot_processor()) {
        return false;
    }
    initialized = true;
    return true;
}

bool self_test() {
    if (!initialized || !stack_layout_valid(kernel_stack) ||
        !stack_layout_valid(exception_stack) || !stack_layout_valid(emergency_stack) ||
        !descriptor_state_valid() || !hardening::verify_current_processor() ||
        !kernel_image_permissions_valid() || !smap_enforcement_valid() ||
        !smep_enforcement_valid() || !memory::virtual_memory::temporary_windows_idle()) {
        return false;
    }
    if (!supervisor_windows_valid()) {
        return false;
    }
    return interrupts::self_test(kernel_stack.virtual_base,
                                 exception_stack.virtual_base + kPageSize, exception_stack.top());
}

bool on_kernel_stack() {
    u64 stack_pointer = 0;
    asm volatile("mov %%rsp, %0" : "=r"(stack_pointer));
    return initialized && stack_pointer >= kernel_stack.virtual_base + kPageSize &&
           stack_pointer < kernel_stack.top();
}

[[noreturn]] void enter_kernel_stack(KernelEntry entry) {
    if (!initialized || entry == nullptr) {
        for (;;) {
            asm volatile("cli; hlt");
        }
    }
    doxxer_run_on_stack(kernel_stack.top(), entry);
}

[[noreturn]] void enter_cpu_stack(u64 stack_top, CpuEntry entry, void* argument) {
    if (!initialized || stack_top == 0 || entry == nullptr) {
        for (;;) {
            asm volatile("cli; hlt");
        }
    }
    doxxer_run_on_cpu_stack(kernel_space.root_physical(), stack_top, entry, argument);
}
}
