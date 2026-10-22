#include <doxxer/arch/x86_64/hardening.hpp>

namespace doxxer::arch::x86_64::hardening {
namespace {
constexpr u32 kEferMsr = 0xC000'0080U;
constexpr u32 kSpecControlMsr = 0x0000'0048U;
constexpr u32 kPredictionCommandMsr = 0x0000'0049U;
constexpr u64 kEferNoExecute = 1ULL << 11U;
constexpr u64 kCr0MonitorCoprocessor = 1ULL << 1U;
constexpr u64 kCr0NumericError = 1ULL << 5U;
constexpr u64 kCr0WriteProtect = 1ULL << 16U;
constexpr u64 kCr4TimestampDisable = 1ULL << 2U;
constexpr u64 kCr4PageGlobalEnable = 1ULL << 7U;
constexpr u64 kCr4PerformanceCounterEnable = 1ULL << 8U;
constexpr u64 kCr4Umip = 1ULL << 11U;
constexpr u64 kCr4Fsgsbase = 1ULL << 16U;
constexpr u64 kCr4Smep = 1ULL << 20U;
constexpr u64 kCr4Smap = 1ULL << 21U;

struct CpuId {
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
};

u32 hardened_processors = 0;
u32 last_failure = 0;
u32 boot_initialized = 0;
u32 speculation_controls_active = 0;

CpuId cpuid(u32 leaf, u32 subleaf = 0) {
    CpuId result{};
    asm volatile("cpuid"
                 : "=a"(result.eax), "=b"(result.ebx), "=c"(result.ecx), "=d"(result.edx)
                 : "a"(leaf), "c"(subleaf)
                 : "memory");
    return result;
}

u64 read_cr0() {
    u64 value = 0;
    asm volatile("mov %%cr0, %0" : "=r"(value));
    return value;
}

u64 read_cr4() {
    u64 value = 0;
    asm volatile("mov %%cr4, %0" : "=r"(value));
    return value;
}

void write_cr0(u64 value) { asm volatile("mov %0, %%cr0" : : "r"(value) : "memory"); }

void write_cr4(u64 value) { asm volatile("mov %0, %%cr4" : : "r"(value) : "memory"); }

u64 read_msr(u32 index) {
    u32 low = 0;
    u32 high = 0;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(index) : "memory");
    return static_cast<u64>(low) | (static_cast<u64>(high) << 32U);
}

void write_msr(u32 index, u64 value) {
    asm volatile("wrmsr"
                 :
                 : "c"(index), "a"(static_cast<u32>(value)),
                   "d"(static_cast<u32>(value >> 32U))
                 : "memory");
}

bool feature_requirements(u32& speculation_bits, bool& issue_ibpb) {
    const CpuId basic = cpuid(0);
    const CpuId extended = cpuid(0x8000'0000U);
    if (basic.eax < 7 || extended.eax < 0x8000'0001U) {
        __atomic_store_n(&last_failure, 1U, __ATOMIC_RELEASE);
        return false;
    }
    const CpuId leaf1 = cpuid(1);
    const CpuId leaf7 = cpuid(7, 0);
    const CpuId extended1 = cpuid(0x8000'0001U);
    const bool msr = (leaf1.edx & (1U << 5U)) != 0;
    const bool pge = (leaf1.edx & (1U << 13U)) != 0;
    const bool nx = (extended1.edx & (1U << 20U)) != 0;
    const bool smep = (leaf7.ebx & (1U << 7U)) != 0;
    const bool smap = (leaf7.ebx & (1U << 20U)) != 0;
    const bool umip = (leaf7.ecx & (1U << 2U)) != 0;
    if (!msr || !pge || !nx || !smep || !smap || !umip) {
        __atomic_store_n(&last_failure, 2U, __ATOMIC_RELEASE);
        return false;
    }

    speculation_bits = 0;
    issue_ibpb = false;
    if ((leaf7.edx & (1U << 26U)) != 0) {
        speculation_bits |= 1U;
        issue_ibpb = true;
    }
    if ((leaf7.edx & (1U << 27U)) != 0) {
        speculation_bits |= 1U << 1U;
    }
    if ((leaf7.edx & (1U << 31U)) != 0) {
        speculation_bits |= 1U << 2U;
    }
    return true;
}

bool harden_current() {
    u32 speculation_bits = 0;
    bool issue_ibpb = false;
    if (!feature_requirements(speculation_bits, issue_ibpb)) {
        return false;
    }

    u64 efer = read_msr(kEferMsr);
    efer |= kEferNoExecute;
    write_msr(kEferMsr, efer);

    u64 cr0 = read_cr0();
    cr0 |= kCr0MonitorCoprocessor | kCr0NumericError | kCr0WriteProtect;
    write_cr0(cr0);

    u64 cr4 = read_cr4();
    cr4 |= kCr4TimestampDisable | kCr4PageGlobalEnable | kCr4Umip | kCr4Smep | kCr4Smap;
    cr4 &= ~(kCr4PerformanceCounterEnable | kCr4Fsgsbase);
    write_cr4(cr4);
    asm volatile("clac" : : : "memory");

    if (speculation_bits != 0) {
        write_msr(kSpecControlMsr, speculation_bits);
        if (issue_ibpb) {
            write_msr(kPredictionCommandMsr, 1);
        }
        __atomic_store_n(&speculation_controls_active, 1U, __ATOMIC_RELEASE);
    }

    if (!verify_current_processor()) {
        __atomic_store_n(&last_failure, 3U, __ATOMIC_RELEASE);
        return false;
    }
    __atomic_add_fetch(&hardened_processors, 1U, __ATOMIC_RELEASE);
    return true;
}
}

bool initialize_boot_processor() {
    if (__atomic_load_n(&boot_initialized, __ATOMIC_ACQUIRE) != 0 || !harden_current()) {
        return false;
    }
    __atomic_store_n(&boot_initialized, 1U, __ATOMIC_RELEASE);
    return true;
}

bool initialize_secondary_processor() {
    if (__atomic_load_n(&boot_initialized, __ATOMIC_ACQUIRE) == 0) {
        __atomic_store_n(&last_failure, 4U, __ATOMIC_RELEASE);
        return false;
    }
    return harden_current();
}

bool verify_current_processor() {
    u32 speculation_bits = 0;
    bool issue_ibpb = false;
    if (!feature_requirements(speculation_bits, issue_ibpb)) {
        return false;
    }
    const u64 cr0 = read_cr0();
    const u64 cr4 = read_cr4();
    const u64 efer = read_msr(kEferMsr);
    const u64 required_cr0 = kCr0MonitorCoprocessor | kCr0NumericError | kCr0WriteProtect;
    const u64 required_cr4 = kCr4TimestampDisable | kCr4PageGlobalEnable | kCr4Umip | kCr4Smep |
                             kCr4Smap;
    const bool speculation_valid =
        speculation_bits == 0 ||
        (read_msr(kSpecControlMsr) & speculation_bits) == speculation_bits;
    return (cr0 & required_cr0) == required_cr0 && (cr4 & required_cr4) == required_cr4 &&
           (cr4 & (kCr4PerformanceCounterEnable | kCr4Fsgsbase)) == 0 &&
           (efer & kEferNoExecute) != 0 && speculation_valid;
}

Statistics statistics() {
    const u64 cr0 = read_cr0();
    const u64 cr4 = read_cr4();
    const u64 efer = read_msr(kEferMsr);
    return {
        .hardened_processors = __atomic_load_n(&hardened_processors, __ATOMIC_ACQUIRE),
        .write_protect = (cr0 & kCr0WriteProtect) != 0,
        .no_execute = (efer & kEferNoExecute) != 0,
        .smep = (cr4 & kCr4Smep) != 0,
        .smap = (cr4 & kCr4Smap) != 0,
        .umip = (cr4 & kCr4Umip) != 0,
        .user_timestamps_disabled = (cr4 & kCr4TimestampDisable) != 0,
        .user_fsgsbase_disabled = (cr4 & kCr4Fsgsbase) == 0,
        .speculation_controls =
            __atomic_load_n(&speculation_controls_active, __ATOMIC_ACQUIRE) != 0,
    };
}

u32 failure_code() { return __atomic_load_n(&last_failure, __ATOMIC_ACQUIRE); }
}
