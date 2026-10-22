#include <doxxer/arch/x86_64/ring3.hpp>

#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>

extern "C" void doxxer_enter_ring3_probe(doxxer::u64 root_physical,
                                           doxxer::u64 user_instruction,
                                           doxxer::u64 user_stack);
extern "C" void doxxer_ring3_syscall_probe_entry();

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
}

namespace doxxer::arch::x86_64::ring3 {
namespace {
constexpr u32 kMsrEfer = 0xC000'0080U;
constexpr u32 kMsrStar = 0xC000'0081U;
constexpr u32 kMsrLstar = 0xC000'0082U;
constexpr u32 kMsrFmask = 0xC000'0084U;
constexpr u64 kEferSyscallEnable = 1ULL;
constexpr u64 kKernelStar = (0x13ULL << 48U) | (0x08ULL << 32U);
constexpr u64 kMaskedUserFlags = (1ULL << 8U) | (1ULL << 9U) | (1ULL << 10U) |
                                 (1ULL << 18U);
constexpr u64 kUserCode = 0x0000'0000'0040'0000ULL;
constexpr u64 kUserStackBase = 0x0000'0000'0080'0000ULL;
constexpr u64 kProbeMagic = 0x4458'5233'5359'5343ULL;
constexpr usize kSyscallOffset = 24;
constexpr usize kAfterSyscallOffset = kSyscallOffset + 2;
u32 last_failure = 0;

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

u64 read_cr3() {
    u64 value = 0;
    asm volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}
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
    memory::virtual_memory::AddressSpace probe_space{};
    u64 code_page = 0;
    u64 stack_page = 0;
    bool space_created = false;
    bool code_allocated = false;
    bool stack_allocated = false;
    bool code_mapped = false;
    bool stack_mapped = false;

    space_created = memory::virtual_memory::create(probe_space, 0);
    if (!space_created) {
        last_failure = 2;
        return false;
    }
    const memory::physical::IsolationDomain domain = probe_space.isolation_domain();
    code_allocated = memory::physical::allocate_page(
        code_page, memory::physical::PageOwner::user_image, memory::physical::Zone::any, domain);
    stack_allocated = memory::physical::allocate_page(
        stack_page, memory::physical::PageOwner::user_stack, memory::physical::Zone::any, domain);
    if (!code_allocated || !stack_allocated) {
        last_failure = 3;
        goto cleanup;
    }

    {
        memory::virtual_memory::TemporaryMapping code_alias{};
        if (!memory::virtual_memory::map_temporary_user(probe_space, code_page, true,
                                                        code_alias)) {
            last_failure = 4;
            goto cleanup;
        }
        // mov %cs,%ax; movzx %ax,%r8d; mov %ss,%ax; movzx %ax,%r9d;
        // movabs $magic,%rax; syscall; ud2
        const u8 program[] = {0x66, 0x8C, 0xC8, 0x44, 0x0F, 0xB7, 0xC0, 0x66,
                              0x8C, 0xD0, 0x44, 0x0F, 0xB7, 0xC8, 0x48, 0xB8,
                              0x43, 0x53, 0x59, 0x53, 0x33, 0x52, 0x58, 0x44,
                              0x0F, 0x05, 0x0F, 0x0B};
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
        probe_space, kUserCode, code_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::execute);
    stack_mapped = memory::virtual_memory::map(
        probe_space, kUserStackBase, stack_page,
        memory::virtual_memory::MapFlags::user | memory::virtual_memory::MapFlags::write);
    if (!code_mapped || !stack_mapped) {
        last_failure = 6;
        goto cleanup;
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

        doxxer_enter_ring3_probe(probe_space.root_physical(), kUserCode,
                                 kUserStackBase + memory::physical::kPageSize - 16);

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
        last_failure = 7;
    }

cleanup:
    if (stack_mapped && !memory::virtual_memory::unmap(probe_space, kUserStackBase) &&
        last_failure == 0) {
        last_failure = 8;
    }
    if (code_mapped && !memory::virtual_memory::unmap(probe_space, kUserCode) &&
        last_failure == 0) {
        last_failure = 9;
    }
    if (stack_allocated &&
        !memory::physical::free_page(stack_page, memory::physical::PageOwner::user_stack,
                                     domain) &&
        last_failure == 0) {
        last_failure = 10;
    }
    if (code_allocated &&
        !memory::physical::free_page(code_page, memory::physical::PageOwner::user_image,
                                     domain) &&
        last_failure == 0) {
        last_failure = 11;
    }
    if (space_created && !memory::virtual_memory::destroy(probe_space) && last_failure == 0) {
        last_failure = 12;
    }
    const memory::physical::Statistics after = memory::physical::statistics();
    if (last_failure == 0 &&
        (after.free_pages != before.free_pages ||
         after.allocated_pages != before.allocated_pages ||
         after.user_mapping_references != before.user_mapping_references ||
         after.supervisor_mapping_references != before.supervisor_mapping_references ||
         after.page_table_references != before.page_table_references)) {
        last_failure = 13;
    }
    clear_observations();
    return last_failure == 0;
}

u32 failure_code() { return last_failure; }
}
