#include <doxxer/arch/x86_64/ring3.hpp>

#include <doxxer/arch/x86_64/interrupts.hpp>
#include <doxxer/arch/x86_64/smp.hpp>
#include <doxxer/loader/elf64.hpp>
#include <doxxer/log.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/user_copy.hpp>
#include <doxxer/memory/virtual.hpp>
#include <doxxer/process/process.hpp>
#include <doxxer/panic.hpp>
#include <doxxer/platform.hpp>
#include <doxxer/scheduler/scheduler.hpp>
#include <doxxer/security/capability.hpp>
#include <doxxer/security/image_policy.hpp>
#include <doxxer/syscall/dispatcher.hpp>
#include <doxxer/thread/user_thread.hpp>

extern "C" void doxxer_enter_ring3_probe(doxxer::u64 root_physical,
                                           doxxer::u64 user_instruction,
                                           doxxer::u64 user_stack);
extern "C" void doxxer_enter_runtime_ring3_probe(doxxer::u64 root_physical,
                                                   doxxer::u64 user_instruction,
                                                   doxxer::u64 user_stack);
extern "C" void doxxer_ring3_syscall_probe_entry();
extern "C" void doxxer_runtime_syscall_entry();
extern "C" const doxxer::u8 doxxer_desktop_program_start[];
extern "C" const doxxer::u8 doxxer_desktop_program_end[];

extern "C" {
volatile doxxer::u64 doxxer_ring3_probe_active = 0;
volatile doxxer::u64 doxxer_ring3_probe_kernel_rsp = 0;
volatile doxxer::u64 doxxer_ring3_probe_kernel_cr3 = 0;
volatile doxxer::u64 doxxer_ring3_probe_resume = 0;
volatile doxxer::u64 doxxer_ring3_probe_rax = 0;
volatile doxxer::u64 doxxer_ring3_probe_rcx = 0;
volatile doxxer::u64 doxxer_ring3_probe_r11 = 0;
volatile doxxer::u64 doxxer_ring3_probe_rsp = 0;
volatile doxxer::u64 doxxer_ring3_probe_cs = 0;
volatile doxxer::u64 doxxer_ring3_probe_ss = 0;
volatile doxxer::u64 doxxer_ring3_probe_request = 0;
volatile doxxer::u64 doxxer_ring3_probe_response = 0;
volatile doxxer::u64 doxxer_ring3_probe_status = 0;
volatile doxxer::u64 doxxer_runtime_probe_active = 0;
volatile doxxer::u64 doxxer_runtime_probe_kernel_rsp = 0;
volatile doxxer::u64 doxxer_runtime_probe_kernel_cr3 = 0;
volatile doxxer::u64 doxxer_runtime_probe_resume = 0;
}

namespace doxxer::arch::x86_64::ring3 {
namespace {
constexpr u32 kMsrEfer = 0xC000'0080U;
constexpr u32 kMsrStar = 0xC000'0081U;
constexpr u32 kMsrLstar = 0xC000'0082U;
constexpr u32 kMsrFmask = 0xC000'0084U;
constexpr u32 kMsrKernelGsBase = 0xC000'0102U;
constexpr u64 kEferSyscallEnable = 1ULL;
constexpr u64 kKernelStar = (0x13ULL << 48U) | (0x08ULL << 32U);
constexpr u64 kMaskedUserFlags = (1ULL << 8U) | (1ULL << 9U) | (1ULL << 10U) |
                                 (1ULL << 18U);
constexpr u64 kUserCode = 0x0000'0000'0040'0000ULL;
constexpr u64 kUserStackBase = 0x0000'0000'0080'0000ULL;
constexpr u64 kUserRequest = 0x0000'0000'0090'0000ULL;
constexpr u64 kUserResponse = 0x0000'0000'0091'0000ULL;
constexpr u64 kProbeMagic = 0x4458'5233'5359'5343ULL;
constexpr u64 kRuntimeFinishRequest = 0x4458'525F'4649'4E49ULL;
constexpr u64 kRuntimeProbeComplete = 0x4458'5250'524F'4245ULL;
constexpr u64 kRuntimeProbeFatal = 0x4458'5246'4154'414CULL;
constexpr usize kRuntimeFirstReturnOffset = 22;
constexpr usize kRuntimeUserFaultOffset = 27;
constexpr usize kRuntimeSecondReturnOffset = 44;
constexpr usize kSyscallOffset = 44;
constexpr usize kAfterSyscallOffset = kSyscallOffset + 2;
constexpr usize kDesktopImageSize = 0x2000;
constexpr usize kDesktopCodeOffset = 0x1000;
struct DesktopElfHeader {
    u8 identity[16]; u16 type; u16 machine; u32 version; u64 entry;
    u64 program_header_offset; u64 section_header_offset; u32 flags;
    u16 header_size; u16 program_header_size; u16 program_header_count;
    u16 section_header_size; u16 section_header_count; u16 section_name_index;
};
struct DesktopProgramHeader {
    u32 type; u32 flags; u64 offset; u64 virtual_address;
    u64 physical_address; u64 file_size; u64 memory_size; u64 alignment;
};
static_assert(sizeof(DesktopElfHeader) == 64 && sizeof(DesktopProgramHeader) == 56);
alignas(8) u8 desktop_image[kDesktopImageSize]{};
bool desktop_image_enrolled = false;
bool desktop_session_active = false;
bool desktop_session_started = false;
void (*desktop_ready_callback)() = nullptr;
process::AddressSpaceLease* desktop_session_lease = nullptr;
u64 desktop_user_calls = 0;
u32 last_failure = 0;
process::AddressSpaceLease* active_probe_lease = nullptr;
u64 runtime_probe_calls = 0;
u64 runtime_first_rip = 0;
u64 runtime_first_rsp = 0;
u64 runtime_first_rflags = 0;
u64 runtime_user_exceptions = 0;
u64 runtime_user_fault_rip = 0;
u64 runtime_user_fault_rsp = 0;
u32 runtime_cpu_installs = 0;
bool runtime_initialized = false;

u64 reject_runtime_entry(u32 code, u64 user_rip) {
    log::write("[ERROR] USER SESSION DISPATCH REJECT CODE ");
    log::write_decimal(code);
    log::write(" RIP ");
    log::write_hex(user_rip);
    log::write("\n");
    return kRuntimeProbeFatal;
}

bool prepare_desktop_image() {
    const usize code_size = static_cast<usize>(doxxer_desktop_program_end -
                                                doxxer_desktop_program_start);
    if (code_size == 0 || code_size > memory::physical::kPageSize) return false;
    auto* header = reinterpret_cast<DesktopElfHeader*>(desktop_image);
    header->identity[0] = 0x7f; header->identity[1] = 'E';
    header->identity[2] = 'L'; header->identity[3] = 'F';
    header->identity[4] = 2; header->identity[5] = 1; header->identity[6] = 1;
    header->type = 2; header->machine = 62; header->version = 1;
    header->entry = kUserCode; header->program_header_offset = sizeof(*header);
    header->header_size = sizeof(*header);
    header->program_header_size = sizeof(DesktopProgramHeader);
    header->program_header_count = 1;
    auto* program = reinterpret_cast<DesktopProgramHeader*>(
        desktop_image + sizeof(DesktopElfHeader));
    *program = {.type = 1, .flags = 5, .offset = kDesktopCodeOffset,
                .virtual_address = kUserCode, .physical_address = 0,
                .file_size = code_size, .memory_size = code_size,
                .alignment = memory::physical::kPageSize};
    for (usize index = 0; index < code_size; ++index) {
        desktop_image[kDesktopCodeOffset + index] = doxxer_desktop_program_start[index];
    }
    return true;
}

u64 read_msr(u32 index) {
    u32 low = 0;
    u32 high = 0;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(index));
    return static_cast<u64>(low) | (static_cast<u64>(high) << 32U);
}

void write_msr(u32 index, u64 value) {
    asm volatile("wrmsr" : : "c"(index), "a"(static_cast<u32>(value)),
                 "d"(static_cast<u32>(value >> 32U)) : "memory");
}

void clear_observations() {
    doxxer_ring3_probe_active = 0;
    doxxer_ring3_probe_kernel_rsp = 0;
    doxxer_ring3_probe_kernel_cr3 = 0;
    doxxer_ring3_probe_resume = 0;
    doxxer_ring3_probe_rax = 0;
    doxxer_ring3_probe_rcx = 0;
    doxxer_ring3_probe_r11 = 0;
    doxxer_ring3_probe_rsp = 0;
    doxxer_ring3_probe_cs = 0;
    doxxer_ring3_probe_ss = 0;
    doxxer_ring3_probe_request = 0;
    doxxer_ring3_probe_response = 0;
    doxxer_ring3_probe_status = 0;
    active_probe_lease = nullptr;
}

bool syscall_supported() {
    u32 eax = 0x8000'0000U;
    u32 ebx = 0;
    u32 ecx = 0;
    u32 edx = 0;
    asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
    if (eax < 0x8000'0001U) {
        return false;
    }
    eax = 0x8000'0001U;
    ecx = 0;
    asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
    return (edx & (1U << 11U)) != 0;
}

bool valid_runtime_return(process::AddressSpaceLease& lease, u64 user_rip, u64 user_rsp,
                          u64 user_rflags) {
    constexpr u64 kMinimumUserAddress = 0x1'0000ULL;
    constexpr u64 kMaximumUserAddress = 0x0000'7FFF'FFFF'FFFFULL;
    constexpr u64 kForbiddenFlags = (3ULL << 12U) | (1ULL << 14U) | (1ULL << 17U) |
                                    (1ULL << 19U) | (1ULL << 20U);
    return process::validate_address_space_lease(lease) &&
           user_rip >= kMinimumUserAddress && user_rip <= kMaximumUserAddress &&
           user_rsp > kMinimumUserAddress && user_rsp <= kMaximumUserAddress &&
           (user_rflags & 0x2U) != 0 && (user_rflags & kForbiddenFlags) == 0 &&
           memory::user_copy::validate_range(*lease.space, user_rip, 1,
                                              memory::user_copy::Access::execute) &&
           memory::user_copy::validate_range(*lease.space, user_rsp - 1, 1,
                                              memory::user_copy::Access::read);
}

bool install_runtime_cpu() {
    if (!syscall_supported() || read_msr(kMsrKernelGsBase) != 0) {
        return false;
    }
    const u64 efer = read_msr(kMsrEfer);
    write_msr(kMsrStar, kKernelStar);
    write_msr(kMsrLstar, reinterpret_cast<u64>(&doxxer_runtime_syscall_entry));
    write_msr(kMsrFmask, kMaskedUserFlags);
    write_msr(kMsrEfer, efer | kEferSyscallEnable);
    const bool valid = (read_msr(kMsrEfer) & kEferSyscallEnable) != 0 &&
                       read_msr(kMsrStar) == kKernelStar &&
                       read_msr(kMsrLstar) == reinterpret_cast<u64>(&doxxer_runtime_syscall_entry) &&
                       read_msr(kMsrFmask) == kMaskedUserFlags &&
                       read_msr(kMsrKernelGsBase) == 0;
    if (valid) {
        __atomic_add_fetch(&runtime_cpu_installs, 1U, __ATOMIC_RELAXED);
    }
    return valid;
}

bool handle_runtime_user_exception(interrupts::ExceptionFrame& frame, u64 fault_address) {
    auto* execution = static_cast<thread::user::ExecutionLease*>(
        arch::x86_64::smp::current_syscall_context());
    if (doxxer_runtime_probe_active != 1 || execution == nullptr ||
        !thread::user::validate_execution_lease(*execution) ||
        execution->address_space == nullptr || frame.vector != 6 ||
        frame.error_code != 0 || frame.cs != 0x23 || frame.ss != 0x1B || fault_address != 0 ||
        frame.rip != kUserCode + kRuntimeUserFaultOffset || runtime_user_exceptions != 0 ||
        !valid_runtime_return(*execution->address_space, frame.rip, frame.rsp, frame.rflags)) {
        return false;
    }
    runtime_user_exceptions = 1;
    runtime_user_fault_rip = frame.rip;
    runtime_user_fault_rsp = frame.rsp;
    frame.rip += 2;
    return true;
}

u64 read_cr3() {
    u64 value = 0;
    asm volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}
}

extern "C" u64 doxxer_ring3_probe_dispatch(u64 user_request, u64 user_response) {
    if (active_probe_lease == nullptr) {
        return static_cast<u64>(syscall::Status::denied_or_unavailable);
    }
    return static_cast<u64>(
        syscall::dispatch_user(*active_probe_lease, user_request, user_response));
}

extern "C" u64 doxxer_runtime_syscall_dispatch(void* context, u64 user_request,
                                                u64 user_response, u64 user_rip,
                                                u64 user_rsp, u64 user_rflags) {
    if (context == nullptr) {
        return reject_runtime_entry(1, user_rip);
    }
    auto& execution = *static_cast<thread::user::ExecutionLease*>(context);
    if (!thread::user::validate_execution_lease(execution) ||
        execution.address_space == nullptr ||
        !valid_runtime_return(*execution.address_space, user_rip, user_rsp, user_rflags)) {
        return reject_runtime_entry(2, user_rip);
    }
    if (desktop_session_active) {
        if (desktop_session_lease == nullptr || execution.address_space == nullptr ||
            desktop_session_lease->space != execution.address_space->space ||
            user_request != kUserRequest || user_response != kUserResponse ||
            user_rip != kUserCode + 22 || desktop_user_calls == static_cast<u64>(-1)) {
            return reject_runtime_entry(3, user_rip);
        }
        const syscall::Status status = syscall::dispatch_user(*execution.address_space,
                                                                user_request, user_response);
        if (status != syscall::Status::ok) return reject_runtime_entry(4, user_rip);
        ++desktop_user_calls;
        if (desktop_user_calls == 16) {
            log::line("DOXXER_USER_HEARTBEAT_16");
        }
        if (!desktop_session_started) {
            syscall::Response response{};
            if (!memory::user_copy::copy_from_user(*execution.address_space->space, &response,
                                                    kUserResponse, sizeof(response)) ||
                response.status != syscall::Status::ok ||
                response.values[0] != syscall::kAbiVersion ||
                response.values[1] != ipc::kMaximumPayloadSize ||
                desktop_ready_callback == nullptr) {
                return reject_runtime_entry(5, user_rip);
            }
            desktop_session_started = true;
            log::line("DOXXER_USER_SESSION_STARTED");
            desktop_ready_callback();
        }
        platform::poll_restart_hotkey();
        return static_cast<u64>(status);
    }
    ++runtime_probe_calls;
    if (doxxer_runtime_probe_active == 1 && user_request == kRuntimeFinishRequest &&
        user_response == 0 && runtime_probe_calls == 2 &&
        user_rip == kUserCode + kRuntimeSecondReturnOffset) {
        return kRuntimeProbeComplete;
    }
    if (runtime_probe_calls != 1 || user_rip != kUserCode + kRuntimeFirstReturnOffset) {
        return kRuntimeProbeFatal;
    }
    runtime_first_rip = user_rip;
    runtime_first_rsp = user_rsp;
    runtime_first_rflags = user_rflags;
    return static_cast<u64>(
        syscall::dispatch_user(*execution.address_space, user_request, user_response));
}

extern "C" [[noreturn]] void doxxer_runtime_syscall_panic() {
    panic("USER SYSCALL BOUNDARY VIOLATION");
}

bool enroll_desktop_image() {
    if (desktop_image_enrolled || !prepare_desktop_image() ||
        !security::image_policy::enroll(desktop_image, sizeof(desktop_image))) {
        return false;
    }
    desktop_image_enrolled = true;
    return true;
}

[[noreturn]] void launch_desktop_session(void (*on_ready)()) {
    // The current single-task ring-3 transition is cooperative. Stop the BSP
    // APIC timer before binding a user context; preemption needs a scheduler
    // that can save and restore complete user register/CR3 state.
    arch::x86_64::interrupts::disable();
    if (!runtime_initialized || !desktop_image_enrolled || !security::image_policy::is_sealed() ||
        on_ready == nullptr || desktop_session_active ||
        arch::x86_64::interrupts::enabled()) {
        panic("USER SESSION PRECONDITION FAILED");
    }
    security::capability::DomainHandle manager{};
    process::CreateResult child{};
    process::AddressSpaceLease lease{};
    loader::elf64::Image image{};
    thread::user::CreateResult user_thread{};
    thread::user::ExecutionLease execution{};
    scheduler::UserContextBinding binding{};
    u64 request_page = 0;
    u64 response_page = 0;
    if (!security::capability::create_domain(manager) ||
        !process::create(manager, "doxxer-desktop", child) ||
        !process::acquire_address_space(manager, child.control, lease) ||
        !loader::elf64::load(*lease.space, desktop_image, sizeof(desktop_image), image)) {
        panic("USER SESSION IMAGE LOAD FAILED");
    }
    const auto domain = lease.space->isolation_domain();
    if (!memory::physical::allocate_page(request_page, memory::physical::PageOwner::user_data,
                                         memory::physical::Zone::any, domain) ||
        !memory::physical::allocate_page(response_page, memory::physical::PageOwner::user_data,
                                         memory::physical::Zone::any, domain) ||
        !memory::virtual_memory::map(*lease.space, kUserRequest, request_page,
                                     memory::virtual_memory::MapFlags::user |
                                         memory::virtual_memory::MapFlags::write) ||
        !memory::virtual_memory::map(*lease.space, kUserResponse, response_page,
                                     memory::virtual_memory::MapFlags::user |
                                         memory::virtual_memory::MapFlags::write) ||
        !thread::user::create(manager, child.control, image.entry_point, user_thread) ||
        !thread::user::acquire_execution(manager, user_thread.control, execution)) {
        panic("USER SESSION MEMORY OR THREAD FAILED");
    }
    syscall::Request request{};
    request.abi_version = syscall::kAbiVersion;
    request.number = syscall::Number::abi_info;
    if (!memory::user_copy::copy_to_user(*lease.space, kUserRequest, &request,
                                         sizeof(request)) ||
        !scheduler::bind_user_context(execution, binding)) {
        panic("USER SESSION ABI BIND FAILED");
    }
    desktop_ready_callback = on_ready;
    desktop_session_lease = &lease;
    desktop_session_started = false;
    desktop_user_calls = 0;
    desktop_session_active = true;
    doxxer_enter_runtime_ring3_probe(lease.space->root_physical(), execution.context.rip,
                                     execution.context.rsp);
    panic("USER SESSION RETURNED WITHOUT EXIT");
}

bool self_test() {
    last_failure = 0;
    clear_observations();
    if (!syscall_supported()) {
        last_failure = 1;
        return false;
    }
    const memory::physical::Statistics before = memory::physical::statistics();
    const u64 expected_kernel_cr3 = read_cr3();
    security::capability::DomainHandle manager{};
    process::CreateResult child{};
    process::AddressSpaceLease probe_lease{};
    u64 code_page = 0;
    u64 stack_page = 0;
    u64 request_page = 0;
    u64 response_page = 0;
    bool manager_created = false;
    bool process_created = false;
    bool lease_acquired = false;
    bool code_allocated = false;
    bool stack_allocated = false;
    bool request_allocated = false;
    bool response_allocated = false;
    bool code_mapped = false;
    bool stack_mapped = false;
    bool request_mapped = false;
    bool response_mapped = false;
    memory::physical::IsolationDomain domain = memory::physical::kKernelDomain;
    syscall::Response response{};

    manager_created = security::capability::create_domain(manager);
    process_created = manager_created && process::create(manager, "ring3-probe", child);
    lease_acquired = process_created &&
                     process::acquire_address_space(manager, child.control, probe_lease);
    if (!lease_acquired || !process::validate_address_space_lease(probe_lease)) {
        last_failure = 2;
        goto cleanup;
    }
    domain = probe_lease.space->isolation_domain();
    code_allocated = memory::physical::allocate_page(
        code_page, memory::physical::PageOwner::user_image, memory::physical::Zone::any, domain);
    stack_allocated = memory::physical::allocate_page(
        stack_page, memory::physical::PageOwner::user_stack, memory::physical::Zone::any, domain);
    request_allocated = memory::physical::allocate_page(
        request_page, memory::physical::PageOwner::user_data, memory::physical::Zone::any, domain);
    response_allocated = memory::physical::allocate_page(
        response_page, memory::physical::PageOwner::user_data, memory::physical::Zone::any, domain);
    if (!code_allocated || !stack_allocated || !request_allocated || !response_allocated) {
        last_failure = 3;
        goto cleanup;
    }

    {
        memory::virtual_memory::TemporaryMapping code_alias{};
        if (!memory::virtual_memory::map_temporary_user(*probe_lease.space, code_page, true,
                                                        code_alias)) {
            last_failure = 4;
            goto cleanup;
        }
        // mov %cs,%ax; movzx %ax,%r8d; mov %ss,%ax; movzx %ax,%r9d;
        // movabs $request,%rdi; movabs $response,%rsi; movabs $magic,%rax; syscall; ud2
        const u8 program[] = {0x66, 0x8C, 0xC8, 0x44, 0x0F, 0xB7, 0xC0, 0x66,
                              0x8C, 0xD0, 0x44, 0x0F, 0xB7, 0xC8, 0x48, 0xBF,
                              0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x48, 0xBE, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x48, 0xB8, 0x43, 0x53, 0x59, 0x53,
                              0x33, 0x52, 0x58, 0x44, 0x0F, 0x05, 0x0F, 0x0B};
        auto* destination = static_cast<u8*>(code_alias.address);
        for (usize index = 0; index < sizeof(program); ++index) {
            destination[index] = program[index];
        }
        if (!memory::virtual_memory::unmap_temporary_user(code_alias)) {
            last_failure = 5;
            goto cleanup;
        }
    }

    code_mapped = memory::virtual_memory::map(
        *probe_lease.space, kUserCode, code_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::execute);
    stack_mapped = memory::virtual_memory::map(
        *probe_lease.space, kUserStackBase, stack_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::write);
    request_mapped = memory::virtual_memory::map(
        *probe_lease.space, kUserRequest, request_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::write);
    response_mapped = memory::virtual_memory::map(
        *probe_lease.space, kUserResponse, response_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::write);
    if (!code_mapped || !stack_mapped || !request_mapped || !response_mapped) {
        last_failure = 6;
        goto cleanup;
    }

    {
        syscall::Request request{};
        request.abi_version = syscall::kAbiVersion;
        request.number = syscall::Number::abi_info;
        if (!memory::user_copy::copy_to_user(*probe_lease.space, kUserRequest, &request,
                                             sizeof(request))) {
            last_failure = 7;
            goto cleanup;
        }
    }

    {
        const u64 old_efer = read_msr(kMsrEfer);
        const u64 old_star = read_msr(kMsrStar);
        const u64 old_lstar = read_msr(kMsrLstar);
        const u64 old_fmask = read_msr(kMsrFmask);
        write_msr(kMsrStar, kKernelStar);
        write_msr(kMsrLstar, reinterpret_cast<u64>(&doxxer_ring3_syscall_probe_entry));
        write_msr(kMsrFmask, kMaskedUserFlags);
        write_msr(kMsrEfer, old_efer | kEferSyscallEnable);

        active_probe_lease = &probe_lease;
        doxxer_enter_ring3_probe(probe_lease.space->root_physical(), kUserCode,
                                 kUserStackBase + memory::physical::kPageSize - 16);
        active_probe_lease = nullptr;

        write_msr(kMsrStar, old_star);
        write_msr(kMsrLstar, old_lstar);
        write_msr(kMsrFmask, old_fmask);
        write_msr(kMsrEfer, old_efer);
    }

    if (doxxer_ring3_probe_active != 0 || read_cr3() != expected_kernel_cr3 ||
        doxxer_ring3_probe_kernel_cr3 != expected_kernel_cr3 ||
        doxxer_ring3_probe_rax != kProbeMagic ||
        doxxer_ring3_probe_rcx != kUserCode + kAfterSyscallOffset ||
        (doxxer_ring3_probe_r11 & 2U) == 0 ||
        doxxer_ring3_probe_rsp < kUserStackBase ||
        doxxer_ring3_probe_rsp >= kUserStackBase + memory::physical::kPageSize ||
        doxxer_ring3_probe_cs != 0x23 || doxxer_ring3_probe_ss != 0x1B) {
        last_failure = 8;
    }
    if (last_failure == 0 &&
        (doxxer_ring3_probe_request != kUserRequest ||
         doxxer_ring3_probe_response != kUserResponse ||
         doxxer_ring3_probe_status != static_cast<u64>(syscall::Status::ok) ||
         !memory::user_copy::copy_from_user(*probe_lease.space, &response, kUserResponse,
                                            sizeof(response)) ||
         response.status != syscall::Status::ok ||
         response.values[0] != syscall::kAbiVersion ||
         response.values[1] != ipc::kMaximumPayloadSize)) {
        last_failure = 9;
    }

cleanup:
    active_probe_lease = nullptr;
    if (response_mapped &&
        !memory::virtual_memory::unmap(*probe_lease.space, kUserResponse) &&
        last_failure == 0) {
        last_failure = 10;
    }
    if (request_mapped &&
        !memory::virtual_memory::unmap(*probe_lease.space, kUserRequest) &&
        last_failure == 0) {
        last_failure = 11;
    }
    if (stack_mapped && !memory::virtual_memory::unmap(*probe_lease.space, kUserStackBase) &&
        last_failure == 0) {
        last_failure = 12;
    }
    if (code_mapped && !memory::virtual_memory::unmap(*probe_lease.space, kUserCode) &&
        last_failure == 0) {
        last_failure = 13;
    }
    if (response_allocated &&
        !memory::physical::free_page(response_page, memory::physical::PageOwner::user_data,
                                     domain) &&
        last_failure == 0) {
        last_failure = 14;
    }
    if (request_allocated &&
        !memory::physical::free_page(request_page, memory::physical::PageOwner::user_data,
                                     domain) &&
        last_failure == 0) {
        last_failure = 15;
    }
    if (stack_allocated &&
        !memory::physical::free_page(stack_page, memory::physical::PageOwner::user_stack,
                                     domain) &&
        last_failure == 0) {
        last_failure = 16;
    }
    if (code_allocated &&
        !memory::physical::free_page(code_page, memory::physical::PageOwner::user_image,
                                     domain) &&
        last_failure == 0) {
        last_failure = 17;
    }
    if (lease_acquired) {
        process::release_address_space(probe_lease);
        lease_acquired = false;
    }
    if (process_created &&
        (!process::terminate(manager, child.control, 0) ||
         !process::destroy(manager, child.control)) &&
        last_failure == 0) {
        last_failure = 18;
    }
    if (manager_created && !security::capability::destroy_domain(manager) &&
        last_failure == 0) {
        last_failure = 19;
    }
    const memory::physical::Statistics after = memory::physical::statistics();
    if (last_failure == 0 &&
        (after.free_pages != before.free_pages ||
         after.allocated_pages != before.allocated_pages ||
         after.user_mapping_references != before.user_mapping_references ||
         after.supervisor_mapping_references != before.supervisor_mapping_references ||
         after.page_table_references != before.page_table_references)) {
        last_failure = 20;
    }
    clear_observations();
    return last_failure == 0;
}

bool initialize_runtime() {
    if (runtime_initialized || !syscall_supported() ||
        arch::x86_64::smp::processor_count() == 0) {
        last_failure = 100;
        return false;
    }
    runtime_cpu_installs = 0;
    if (!interrupts::register_user_exception_handler(handle_runtime_user_exception) ||
        !arch::x86_64::smp::run_on_all(install_runtime_cpu) ||
        runtime_cpu_installs != arch::x86_64::smp::processor_count()) {
        last_failure = 100;
        return false;
    }
    runtime_initialized = true;
    return true;
}

bool runtime_self_test() {
    last_failure = 0;
    runtime_probe_calls = 0;
    runtime_first_rip = 0;
    runtime_first_rsp = 0;
    runtime_first_rflags = 0;
    runtime_user_exceptions = 0;
    runtime_user_fault_rip = 0;
    runtime_user_fault_rsp = 0;
    doxxer_runtime_probe_active = 0;
    doxxer_runtime_probe_kernel_rsp = 0;
    doxxer_runtime_probe_kernel_cr3 = 0;
    doxxer_runtime_probe_resume = 0;
    if (!runtime_initialized || !syscall_supported() ||
        arch::x86_64::smp::current_index() == 0xFFFF'FFFFU) {
        last_failure = 101;
        return false;
    }

    const memory::physical::Statistics before = memory::physical::statistics();
    const u64 expected_kernel_cr3 = read_cr3();
    security::capability::DomainHandle manager{};
    process::CreateResult child{};
    process::AddressSpaceLease lease{};
    thread::user::CreateResult user_thread{};
    thread::user::ExecutionLease execution{};
    memory::physical::IsolationDomain domain = memory::physical::kKernelDomain;
    u64 code_page = 0;
    u64 request_page = 0;
    u64 response_page = 0;
    bool manager_created = false;
    bool process_created = false;
    bool lease_acquired = false;
    bool thread_created = false;
    bool execution_acquired = false;
    scheduler::UserContextBinding context_binding{};
    bool code_allocated = false;
    bool request_allocated = false;
    bool response_allocated = false;
    bool code_mapped = false;
    bool request_mapped = false;
    bool response_mapped = false;
    bool msrs_installed = false;
    u64 old_efer = 0;
    u64 old_star = 0;
    u64 old_lstar = 0;
    u64 old_fmask = 0;
    syscall::Response response{};
    u64 user_stack_pointer = 0;

    manager_created = security::capability::create_domain(manager);
    process_created = manager_created && process::create(manager, "runtime-syscall", child);
    lease_acquired = process_created &&
                     process::acquire_address_space(manager, child.control, lease);
    if (!lease_acquired || !process::validate_address_space_lease(lease)) {
        last_failure = 102;
        goto cleanup;
    }
    domain = lease.space->isolation_domain();
    code_allocated = memory::physical::allocate_page(
        code_page, memory::physical::PageOwner::user_image, memory::physical::Zone::any, domain);
    request_allocated = memory::physical::allocate_page(
        request_page, memory::physical::PageOwner::user_data, memory::physical::Zone::any, domain);
    response_allocated = memory::physical::allocate_page(
        response_page, memory::physical::PageOwner::user_data, memory::physical::Zone::any, domain);
    if (!code_allocated || !request_allocated || !response_allocated) {
        last_failure = 103;
        goto cleanup;
    }

    {
        memory::virtual_memory::TemporaryMapping code_alias{};
        if (!memory::virtual_memory::map_temporary_user(*lease.space, code_page, true,
                                                        code_alias)) {
            last_failure = 104;
            goto cleanup;
        }
        // First syscall dispatches abi_info and returns through IRETQ. The second proves that
        // return succeeded and asks the boot-only harness to resume the kernel continuation.
        const u8 program[] = {
            0x48, 0xBF, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xBE, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0F, 0x05, 0x48, 0x85, 0xC0, 0x75, 0x11, 0x0F, 0x0B,
            0x48, 0xBF, 0x49, 0x4E, 0x49, 0x46, 0x5F, 0x52, 0x58, 0x44,
            0x48, 0x31, 0xF6, 0x0F, 0x05, 0x0F, 0x0B,
        };
        auto* destination = static_cast<u8*>(code_alias.address);
        for (usize index = 0; index < sizeof(program); ++index) {
            destination[index] = program[index];
        }
        if (!memory::virtual_memory::unmap_temporary_user(code_alias)) {
            last_failure = 105;
            goto cleanup;
        }
    }

    code_mapped = memory::virtual_memory::map(
        *lease.space, kUserCode, code_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::execute);
    request_mapped = memory::virtual_memory::map(
        *lease.space, kUserRequest, request_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::write);
    response_mapped = memory::virtual_memory::map(
        *lease.space, kUserResponse, response_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::write);
    if (!code_mapped || !request_mapped || !response_mapped) {
        last_failure = 106;
        goto cleanup;
    }
    thread_created = thread::user::create(manager, child.control, kUserCode, user_thread);
    execution_acquired =
        thread_created && thread::user::acquire_execution(manager, user_thread.control, execution);
    if (!execution_acquired || !thread::user::validate_execution_lease(execution) ||
        execution.address_space == nullptr || execution.address_space->space != lease.space) {
        last_failure = 106;
        goto cleanup;
    }
    user_stack_pointer = execution.context.rsp;
    {
        syscall::Request request{};
        request.abi_version = syscall::kAbiVersion;
        request.number = syscall::Number::abi_info;
        if (!memory::user_copy::copy_to_user(*lease.space, kUserRequest, &request,
                                             sizeof(request))) {
            last_failure = 107;
            goto cleanup;
        }
    }

    if (!valid_runtime_return(lease, kUserCode, user_stack_pointer, 0x2) ||
        valid_runtime_return(lease, 0xFFFF'8000'0000'0000ULL, user_stack_pointer, 0x2) ||
        valid_runtime_return(lease, kUserCode, 0, 0x2) ||
        valid_runtime_return(lease, kUserCode, user_stack_pointer, 0x3002)) {
        last_failure = 108;
        goto cleanup;
    }
    if (!scheduler::bind_user_context(execution, context_binding) ||
        read_msr(kMsrKernelGsBase) != 0) {
        last_failure = 108;
        goto cleanup;
    }
    old_efer = read_msr(kMsrEfer);
    old_star = read_msr(kMsrStar);
    old_lstar = read_msr(kMsrLstar);
    old_fmask = read_msr(kMsrFmask);
    write_msr(kMsrStar, (static_cast<u64>(0x13) << 48U) |
                            (static_cast<u64>(0x08) << 32U));
    write_msr(kMsrLstar, reinterpret_cast<u64>(&doxxer_runtime_syscall_entry));
    write_msr(kMsrFmask, kMaskedUserFlags);
    write_msr(kMsrEfer, old_efer | kEferSyscallEnable);
    msrs_installed = true;

    doxxer_enter_runtime_ring3_probe(lease.space->root_physical(), execution.context.rip,
                                     user_stack_pointer);

    write_msr(kMsrStar, old_star);
    write_msr(kMsrLstar, old_lstar);
    write_msr(kMsrFmask, old_fmask);
    write_msr(kMsrEfer, old_efer);
    msrs_installed = false;

    if (read_cr3() != expected_kernel_cr3 || read_msr(kMsrKernelGsBase) != 0 ||
        runtime_probe_calls != 2 || runtime_first_rip != kUserCode + kRuntimeFirstReturnOffset ||
        runtime_user_exceptions != 1 ||
        runtime_user_fault_rip != kUserCode + kRuntimeUserFaultOffset ||
        runtime_user_fault_rsp != runtime_first_rsp ||
        runtime_first_rsp != user_stack_pointer ||
        (runtime_first_rflags & kMaskedUserFlags) != 0 ||
        !memory::user_copy::copy_from_user(*lease.space, &response, kUserResponse,
                                           sizeof(response)) ||
        response.status != syscall::Status::ok || response.values[0] != syscall::kAbiVersion ||
        response.values[1] != ipc::kMaximumPayloadSize) {
        last_failure = 109;
    }

cleanup:
    if (msrs_installed) {
        write_msr(kMsrStar, old_star);
        write_msr(kMsrLstar, old_lstar);
        write_msr(kMsrFmask, old_fmask);
        write_msr(kMsrEfer, old_efer);
    }
    if (context_binding.active && !scheduler::unbind_user_context(context_binding) &&
        last_failure == 0) {
        last_failure = 110;
    }
    if (execution_acquired && !context_binding.active &&
        !thread::user::release_execution(execution) && last_failure == 0) {
        last_failure = 110;
    }
    if (thread_created && !execution.active &&
        (!thread::user::terminate(manager, user_thread.control, 0) ||
         !thread::user::destroy(manager, user_thread.control)) &&
        last_failure == 0) {
        last_failure = 110;
    }
    if (response_mapped && !memory::virtual_memory::unmap(*lease.space, kUserResponse) &&
        last_failure == 0) {
        last_failure = 111;
    }
    if (request_mapped && !memory::virtual_memory::unmap(*lease.space, kUserRequest) &&
        last_failure == 0) {
        last_failure = 112;
    }
    if (code_mapped && !memory::virtual_memory::unmap(*lease.space, kUserCode) &&
        last_failure == 0) {
        last_failure = 114;
    }
    if (response_allocated &&
        !memory::physical::free_page(response_page, memory::physical::PageOwner::user_data,
                                     domain) &&
        last_failure == 0) {
        last_failure = 115;
    }
    if (request_allocated &&
        !memory::physical::free_page(request_page, memory::physical::PageOwner::user_data,
                                     domain) &&
        last_failure == 0) {
        last_failure = 116;
    }
    if (code_allocated &&
        !memory::physical::free_page(code_page, memory::physical::PageOwner::user_image,
                                     domain) &&
        last_failure == 0) {
        last_failure = 118;
    }
    if (lease_acquired) {
        process::release_address_space(lease);
    }
    if (process_created &&
        (!process::terminate(manager, child.control, 0) ||
         !process::destroy(manager, child.control)) &&
        last_failure == 0) {
        last_failure = 119;
    }
    if (manager_created && !security::capability::destroy_domain(manager) &&
        last_failure == 0) {
        last_failure = 120;
    }
    const memory::physical::Statistics after = memory::physical::statistics();
    if (last_failure == 0 &&
        (after.free_pages != before.free_pages ||
         after.allocated_pages != before.allocated_pages ||
         after.user_mapping_references != before.user_mapping_references ||
         after.supervisor_mapping_references != before.supervisor_mapping_references ||
         after.page_table_references != before.page_table_references)) {
        last_failure = 121;
    }
    doxxer_runtime_probe_active = 0;
    return last_failure == 0;
}

u32 failure_code() { return last_failure; }
}
