#include <doxxer/arch/x86_64/smp.hpp>

#include <doxxer/arch/x86_64/apic.hpp>
#include <doxxer/arch/x86_64/hardening.hpp>
#include <doxxer/arch/x86_64/interrupts.hpp>
#include <doxxer/arch/x86_64/protection.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>

extern "C" doxxer::uptr __stack_chk_guard;

namespace doxxer::arch::x86_64::smp {
namespace {
using memory::physical::kPageSize;
using memory::virtual_memory::MapFlags;

constexpr usize kMaximumProcessors = 64;
constexpr u64 kStackPages = 8;
constexpr u64 kCpuArenaBase = 0x0000'7200'0000'0000ULL;
constexpr u64 kCpuArenaStride = 0x0100'0000ULL;
constexpr u64 kExceptionStackOffset = 0x0010'0000ULL;
constexpr u64 kEmergencyStackOffset = 0x0020'0000ULL;
constexpr u64 kSyscallStackOffset = 0x0030'0000ULL;
constexpr u64 kStartupTimeoutMicroseconds = 1'000'000;
constexpr u64 kIpiTimeoutMicroseconds = 250'000;
constexpr u16 kTaskStateSelector = 0x28;
constexpr u8 kProbeVector = 0xE1;
constexpr u32 kGsBaseMsr = 0xC000'0101U;
constexpr u32 kKernelGsBaseMsr = 0xC000'0102U;
constexpr u64 kSyscallStackCanary = 0x4458'5359'5343'414EULL;

enum class CpuStatus : u32 {
    offline = 0,
    launching = 1,
    online = 2,
    failed = 3,
};

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

struct alignas(64) CpuState {
    CpuState* self;
    u32 index;
    u32 processor_id;
    u32 apic_id;
    u32 status;
    u32 ipi_probes;
    StackMapping kernel_stack;
    StackMapping exception_stack;
    StackMapping emergency_stack;
    StackMapping syscall_stack;
    u64 syscall_stack_canary;
    u64 syscall_stack_top;
    void* syscall_context;
    u64 syscall_user_rsp;
    alignas(16) u64 gdt[7];
    alignas(16) TaskStateSegment tss;
};

static_assert(sizeof(TaskStateSegment) == 104);
static_assert(sizeof(DescriptorTablePointer) == 10);
static_assert(__builtin_offsetof(CpuState, syscall_stack_top) == 136);
static_assert(__builtin_offsetof(CpuState, syscall_context) == 144);
static_assert(__builtin_offsetof(CpuState, syscall_user_rsp) == 152);

alignas(64) CpuState cpus[kMaximumProcessors]{};
u32 discovered_processors = 0;
u32 last_failure = 0;
bool initialized = false;
WorkerEntry worker_entry = nullptr;

void write_gs_base(CpuState* cpu) {
    const u64 value = reinterpret_cast<u64>(cpu);
    asm volatile("wrmsr"
                 :
                 : "c"(kGsBaseMsr), "a"(static_cast<u32>(value)),
                   "d"(static_cast<u32>(value >> 32U))
                 : "memory");
}

void clear_kernel_gs_base() {
    asm volatile("wrmsr"
                 :
                 : "c"(kKernelGsBaseMsr), "a"(0U), "d"(0U)
                 : "memory");
}

CpuState* current_cpu() {
    CpuState* cpu = nullptr;
    asm volatile("movq %%gs:0, %0" : "=r"(cpu));
    return cpu;
}

[[noreturn]] void halt_cpu() {
    for (;;) {
        asm volatile("cli; hlt");
    }
}

bool map_stack(StackMapping& stack, u64 virtual_base) {
    stack.virtual_base = virtual_base;
    if (!memory::physical::allocate_contiguous(kStackPages, 1, stack.physical_base,
                                               memory::physical::PageOwner::kernel_stack)) {
        return false;
    }
    auto* space = memory::virtual_memory::active_address_space();
    if (space == nullptr) {
        return false;
    }
    for (u64 index = 0; index < kStackPages; ++index) {
        if (!memory::virtual_memory::map(*space, virtual_base + (index + 1) * kPageSize,
                                         stack.physical_base + index * kPageSize,
                                         MapFlags::write)) {
            return false;
        }
        ++stack.mapped_pages;
    }
    return true;
}

bool prepare_cpu_stacks(CpuState& cpu, usize index) {
    const u64 base = kCpuArenaBase + index * kCpuArenaStride;
    return map_stack(cpu.kernel_stack, base) &&
           map_stack(cpu.exception_stack, base + kExceptionStackOffset) &&
           map_stack(cpu.emergency_stack, base + kEmergencyStackOffset) &&
           map_stack(cpu.syscall_stack, base + kSyscallStackOffset);
}

bool prepare_boot_syscall_stack(CpuState& cpu, usize index) {
    const u64 base = kCpuArenaBase + index * kCpuArenaStride;
    return map_stack(cpu.syscall_stack, base + kSyscallStackOffset);
}

u64 syscall_stack_canary(const CpuState& cpu) {
    return kSyscallStackCanary ^ (static_cast<u64>(cpu.index) << 32U) ^
           cpu.syscall_stack.physical_base ^ static_cast<u64>(__stack_chk_guard);
}

void initialize_syscall_stack(CpuState& cpu) {
    auto* words = reinterpret_cast<volatile u64*>(cpu.syscall_stack.virtual_base + kPageSize);
    constexpr u64 word_count = (kStackPages * kPageSize) / sizeof(u64);
    for (u64 index = 0; index < word_count; ++index) {
        words[index] = 0;
    }
    cpu.syscall_stack_canary = syscall_stack_canary(cpu);
    cpu.syscall_stack_top = cpu.syscall_stack.top();
    cpu.syscall_context = nullptr;
    cpu.syscall_user_rsp = 0;
    words[0] = cpu.syscall_stack_canary;
}

bool syscall_stack_intact(const CpuState& cpu) {
    if (cpu.syscall_stack.mapped_pages != kStackPages ||
        cpu.syscall_stack.virtual_base == 0 || cpu.syscall_stack.physical_base == 0 ||
        cpu.syscall_stack_canary != syscall_stack_canary(cpu)) {
        return false;
    }
    const auto* bottom = reinterpret_cast<const volatile u64*>(
        cpu.syscall_stack.virtual_base + kPageSize);
    return *bottom == cpu.syscall_stack_canary;
}

void install_descriptors(CpuState& cpu) {
    cpu.tss.rsp0 = cpu.kernel_stack.top();
    cpu.tss.ist1 = cpu.exception_stack.top();
    cpu.tss.ist2 = cpu.emergency_stack.top();
    cpu.tss.io_map_base = sizeof(TaskStateSegment);

    cpu.gdt[0] = 0;
    cpu.gdt[1] = 0x00AF'9A00'0000'FFFFULL;
    cpu.gdt[2] = 0x00CF'9200'0000'FFFFULL;
    cpu.gdt[3] = 0x00CF'F200'0000'FFFFULL;
    cpu.gdt[4] = 0x00AF'FA00'0000'FFFFULL;
    const u64 base = reinterpret_cast<u64>(&cpu.tss);
    constexpr u64 limit = sizeof(TaskStateSegment) - 1;
    cpu.gdt[5] = (limit & 0xFFFFU) | ((base & 0xFF'FFFFU) << 16U) | (0x89ULL << 40U) |
                 (((limit >> 16U) & 0xFU) << 48U) | (((base >> 24U) & 0xFFU) << 56U);
    cpu.gdt[6] = base >> 32U;

    const DescriptorTablePointer pointer{
        .limit = static_cast<u16>(sizeof(cpu.gdt) - 1),
        .base = reinterpret_cast<u64>(&cpu.gdt[0]),
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
    const u16 selector = kTaskStateSelector;
    asm volatile("ltr %0" : : "r"(selector) : "memory");
    interrupts::load();
}

void probe_handler(interrupts::ExceptionFrame&) {
    CpuState* cpu = current_cpu();
    if (cpu != nullptr && cpu->self == cpu && cpu->index < discovered_processors &&
        cpu->apic_id == apic::current_id() && syscall_stack_intact(*cpu)) {
        __atomic_add_fetch(&cpu->ipi_probes, 1U, __ATOMIC_RELAXED);
    }
    apic::eoi();
}

[[noreturn]] void secondary_main(void* argument) {
    auto* cpu = static_cast<CpuState*>(argument);
    install_descriptors(*cpu);
    if (!hardening::initialize_secondary_processor()) {
        __atomic_store_n(&cpu->status, static_cast<u32>(CpuStatus::failed), __ATOMIC_RELEASE);
        halt_cpu();
    }
    write_gs_base(cpu);
    clear_kernel_gs_base();
    if (!apic::initialize_secondary(cpu->apic_id)) {
        __atomic_store_n(&cpu->status, static_cast<u32>(CpuStatus::failed), __ATOMIC_RELEASE);
        halt_cpu();
    }
    __atomic_store_n(&cpu->status, static_cast<u32>(CpuStatus::online), __ATOMIC_RELEASE);
    interrupts::enable();
    for (;;) {
        WorkerEntry entry = __atomic_load_n(&worker_entry, __ATOMIC_ACQUIRE);
        if (entry != nullptr) {
            entry();
            __atomic_store_n(&cpu->status, static_cast<u32>(CpuStatus::failed), __ATOMIC_RELEASE);
            halt_cpu();
        }
        asm volatile("hlt");
    }
}

extern "C" __attribute__((no_stack_protector)) [[noreturn]] void
doxxer_secondary_entry(limine_mp_info* info) {
    if (info == nullptr || info->extra_argument >= discovered_processors) {
        halt_cpu();
    }
    CpuState& cpu = cpus[info->extra_argument];
    if (cpu.processor_id != info->processor_id || cpu.apic_id != info->lapic_id) {
        __atomic_store_n(&cpu.status, static_cast<u32>(CpuStatus::failed), __ATOMIC_RELEASE);
        halt_cpu();
    }
    protection::enter_cpu_stack(cpu.kernel_stack.top(), secondary_main, &cpu);
}

bool deadline_reached(u64 start, u64 timeout_microseconds) {
    const u64 ticks = apic::reference_ticks_for_microseconds(timeout_microseconds);
    return ticks == 0 || apic::reference_counter() - start >= ticks;
}
}

bool initialize(const volatile limine_mp_response* response,
                const firmware::acpi::Topology& topology) {
    initialized = false;
    last_failure = 0;
    if (response == nullptr || response->cpus == nullptr || response->cpu_count == 0 ||
        response->cpu_count > kMaximumProcessors ||
        (response->flags & LIMINE_MP_RESPONSE_X86_64_X2APIC) != 0) {
        last_failure = 1;
        return false;
    }
    if (response->cpu_count != topology.enabled_processors ||
        response->bsp_lapic_id != topology.bootstrap_apic_id) {
        last_failure = 2;
        return false;
    }
    discovered_processors = static_cast<u32>(response->cpu_count);
    bool bsp_found = false;
    CpuState* bsp = nullptr;
    for (u32 index = 0; index < discovered_processors; ++index) {
        limine_mp_info* info = response->cpus[index];
        if (info == nullptr || info->lapic_id > 0xFF) {
            last_failure = 3;
            return false;
        }
        for (u32 previous = 0; previous < index; ++previous) {
            if (cpus[previous].apic_id == info->lapic_id ||
                cpus[previous].processor_id == info->processor_id) {
                last_failure = 4;
                return false;
            }
        }
        cpus[index].self = &cpus[index];
        cpus[index].index = index;
        cpus[index].processor_id = info->processor_id;
        cpus[index].apic_id = info->lapic_id;
        cpus[index].ipi_probes = 0;
        if (info->lapic_id == response->bsp_lapic_id) {
            bsp_found = true;
            bsp = &cpus[index];
            cpus[index].status = static_cast<u32>(CpuStatus::online);
            if (!prepare_boot_syscall_stack(cpus[index], index)) {
                last_failure = 5;
                return false;
            }
        } else {
            cpus[index].status = static_cast<u32>(CpuStatus::launching);
            if (!prepare_cpu_stacks(cpus[index], index)) {
                last_failure = 5;
                return false;
            }
        }
        initialize_syscall_stack(cpus[index]);
    }
    if (!bsp_found || !interrupts::register_handler(kProbeVector, probe_handler)) {
        last_failure = 6;
        return false;
    }
    write_gs_base(bsp);
    clear_kernel_gs_base();

    for (u32 index = 0; index < discovered_processors; ++index) {
        limine_mp_info* info = response->cpus[index];
        if (info->lapic_id == response->bsp_lapic_id) {
            continue;
        }
        __atomic_store_n(&info->extra_argument, static_cast<u64>(index), __ATOMIC_RELAXED);
        __atomic_store_n(&info->goto_address, doxxer_secondary_entry, __ATOMIC_RELEASE);
    }

    const u64 start = apic::reference_counter();
    while (online_processor_count() != discovered_processors) {
        for (u32 index = 0; index < discovered_processors; ++index) {
            if (__atomic_load_n(&cpus[index].status, __ATOMIC_ACQUIRE) ==
                static_cast<u32>(CpuStatus::failed)) {
                last_failure = 7;
                return false;
            }
        }
        if (deadline_reached(start, kStartupTimeoutMicroseconds)) {
            last_failure = 8;
            return false;
        }
        asm volatile("pause");
    }
    initialized = true;
    return true;
}

bool self_test() {
    if (!initialized) {
        last_failure = 9;
        return false;
    }
    CpuState* bsp = current_cpu();
    if (bsp == nullptr || bsp->self != bsp || bsp->index >= discovered_processors ||
        bsp->apic_id != apic::current_id() || !syscall_stack_intact(*bsp) ||
        !hardening::verify_current_processor() ||
        hardening::statistics().hardened_processors != discovered_processors) {
        last_failure = 12;
        return false;
    }
    auto* active_space = memory::virtual_memory::active_address_space();
    if (active_space == nullptr) {
        last_failure = 13;
        return false;
    }
    memory::virtual_memory::Mapping mapping{};
    for (u32 index = 0; index < discovered_processors; ++index) {
        const StackMapping& stack = cpus[index].syscall_stack;
        if (!syscall_stack_intact(cpus[index]) ||
            memory::virtual_memory::query(*active_space, stack.virtual_base, mapping) ||
            memory::virtual_memory::query(*active_space, stack.top(), mapping)) {
            last_failure = 13;
            return false;
        }
        for (u64 page = 0; page < kStackPages; ++page) {
            if (!memory::virtual_memory::query(*active_space,
                                               stack.virtual_base + (page + 1) * kPageSize,
                                               mapping) ||
                mapping.physical_address != stack.physical_base + page * kPageSize ||
                !memory::virtual_memory::has_flag(mapping.flags, MapFlags::write) ||
                memory::virtual_memory::has_flag(mapping.flags, MapFlags::execute) ||
                memory::virtual_memory::has_flag(mapping.flags, MapFlags::user)) {
                last_failure = 13;
                return false;
            }
        }
    }
    u32 before[kMaximumProcessors]{};
    const u32 bsp_id = apic::current_id();
    for (u32 index = 0; index < discovered_processors; ++index) {
        before[index] = __atomic_load_n(&cpus[index].ipi_probes, __ATOMIC_RELAXED);
        if (cpus[index].apic_id != bsp_id && !apic::send_ipi(cpus[index].apic_id, kProbeVector)) {
            last_failure = 10;
            return false;
        }
    }
    const u64 start = apic::reference_counter();
    for (;;) {
        bool complete = true;
        for (u32 index = 0; index < discovered_processors; ++index) {
            if (cpus[index].apic_id != bsp_id &&
                __atomic_load_n(&cpus[index].ipi_probes, __ATOMIC_ACQUIRE) == before[index]) {
                complete = false;
            }
        }
        if (complete) {
            return true;
        }
        if (deadline_reached(start, kIpiTimeoutMicroseconds)) {
            last_failure = 11;
            return false;
        }
        asm volatile("pause");
    }
}

u32 processor_count() { return discovered_processors; }

u32 online_processor_count() {
    u32 count = 0;
    for (u32 index = 0; index < discovered_processors; ++index) {
        if (__atomic_load_n(&cpus[index].status, __ATOMIC_ACQUIRE) ==
            static_cast<u32>(CpuStatus::online)) {
            ++count;
        }
    }
    return count;
}

u32 current_processor_id() {
    CpuState* cpu = current_cpu();
    return cpu == nullptr || cpu->self != cpu ? 0xFFFF'FFFFU : cpu->processor_id;
}

u32 current_apic_id() {
    CpuState* cpu = current_cpu();
    return cpu == nullptr || cpu->self != cpu ? 0xFFFF'FFFFU : cpu->apic_id;
}

u32 current_index() {
    CpuState* cpu = current_cpu();
    return cpu == nullptr || cpu->self != cpu ? 0xFFFF'FFFFU : cpu->index;
}

u32 apic_id(u32 index) {
    return index >= discovered_processors ? 0xFFFF'FFFFU : cpus[index].apic_id;
}

bool current_syscall_stack(u64& stack_bottom, u64& stack_top) {
    stack_bottom = 0;
    stack_top = 0;
    CpuState* cpu = current_cpu();
    if (!initialized || cpu == nullptr || cpu->self != cpu ||
        cpu->index >= discovered_processors || !syscall_stack_intact(*cpu)) {
        return false;
    }
    stack_bottom = cpu->syscall_stack.virtual_base + kPageSize;
    stack_top = cpu->syscall_stack.top();
    return true;
}

bool bind_syscall_context(void* context) {
    CpuState* cpu = current_cpu();
    if (!initialized || context == nullptr || cpu == nullptr || cpu->self != cpu ||
        cpu->index >= discovered_processors || !syscall_stack_intact(*cpu) ||
        cpu->syscall_stack_top != cpu->syscall_stack.top() ||
        __atomic_load_n(&cpu->syscall_context, __ATOMIC_ACQUIRE) != nullptr) {
        return false;
    }
    cpu->syscall_user_rsp = 0;
    __atomic_store_n(&cpu->syscall_context, context, __ATOMIC_RELEASE);
    return true;
}

bool unbind_syscall_context(void* context) {
    CpuState* cpu = current_cpu();
    if (!initialized || context == nullptr || cpu == nullptr || cpu->self != cpu ||
        cpu->index >= discovered_processors ||
        __atomic_load_n(&cpu->syscall_context, __ATOMIC_ACQUIRE) != context) {
        return false;
    }
    __atomic_store_n(&cpu->syscall_context, nullptr, __ATOMIC_RELEASE);
    cpu->syscall_user_rsp = 0;
    return syscall_stack_intact(*cpu);
}

bool install_worker_entry(WorkerEntry entry) {
    if (!initialized || entry == nullptr ||
        __atomic_load_n(&worker_entry, __ATOMIC_ACQUIRE) != nullptr) {
        return false;
    }
    __atomic_store_n(&worker_entry, entry, __ATOMIC_RELEASE);
    const u32 bsp_id = apic::current_id();
    for (u32 index = 0; index < discovered_processors; ++index) {
        if (cpus[index].apic_id != bsp_id && !apic::send_ipi(cpus[index].apic_id, kProbeVector)) {
            return false;
        }
    }
    return true;
}

u32 failure_code() { return last_failure; }
}
