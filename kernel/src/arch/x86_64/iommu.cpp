#include <doxxer/arch/x86_64/iommu.hpp>

#include <doxxer/arch/x86_64/io.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>

namespace doxxer::arch::x86_64::iommu {
namespace {
using memory::physical::kPageSize;
using memory::virtual_memory::MapFlags;

constexpr u64 kRegisterVirtualBase = 0x0000'5000'0040'0000ULL;
constexpr u32 kVersion = 0x00;
constexpr u32 kCapability = 0x08;
constexpr u32 kGlobalCommand = 0x18;
constexpr u32 kGlobalStatus = 0x1C;
constexpr u32 kRootTableAddress = 0x20;
constexpr u32 kTranslationEnable = 1U << 31U;
constexpr u32 kSetRootTablePointer = 1U << 30U;
constexpr u32 kWaitIterations = 10'000'000;
constexpr u64 kRootAddressMask = 0xFFFF'FFFF'FFFF'F000ULL;

struct RootEntry {
    u64 low;
    u64 high;
};

struct Unit {
    volatile u8* registers;
    u64 register_virtual;
    u64 root_physical;
    u32 version;
    u64 capability;
    bool enabled;
};

static_assert(sizeof(RootEntry) * 256 == kPageSize);

Unit units[firmware::acpi::kMaximumIommus]{};
usize unit_count = 0;
u8 address_width = 0;
u32 quiesced_functions = 0;
u32 last_failure = 0;
bool initialized = false;

u32 read32(const Unit& unit, u32 offset) {
    return *reinterpret_cast<volatile u32*>(unit.registers + offset);
}

u64 read64(const Unit& unit, u32 offset) {
    return *reinterpret_cast<volatile u64*>(unit.registers + offset);
}

void write32(const Unit& unit, u32 offset, u32 value) {
    *reinterpret_cast<volatile u32*>(unit.registers + offset) = value;
    asm volatile("mfence" : : : "memory");
}

void write64(const Unit& unit, u32 offset, u64 value) {
    *reinterpret_cast<volatile u64*>(unit.registers + offset) = value;
    asm volatile("mfence" : : : "memory");
}

bool wait_status(const Unit& unit, u32 mask, bool set) {
    for (u32 iteration = 0; iteration < kWaitIterations; ++iteration) {
        if (((read32(unit, kGlobalStatus) & mask) != 0) == set) {
            return true;
        }
        asm volatile("pause");
    }
    return false;
}

bool root_is_empty(u64 root_physical) {
    const auto* root = static_cast<const RootEntry*>(
        memory::physical::direct_map_owned(root_physical, memory::physical::PageOwner::iommu));
    if (root == nullptr) {
        return false;
    }
    u64 aggregate = 0;
    for (usize index = 0; index < 256; ++index) {
        aggregate |= root[index].low | root[index].high;
    }
    return aggregate == 0;
}

u32 pci_read32(u8 bus, u8 device, u8 function, u8 offset) {
    const u32 address = 0x8000'0000U | (static_cast<u32>(bus) << 16U) |
                        (static_cast<u32>(device) << 11U) |
                        (static_cast<u32>(function) << 8U) | (offset & 0xFCU);
    arch::x86_64::out32(0xCF8, address);
    return arch::x86_64::in32(0xCFC);
}

bool quiesce_pci(u32 expected_functions) {
    quiesced_functions = 0;
    for (u16 bus = 0; bus < 256; ++bus) {
        for (u8 device = 0; device < 32; ++device) {
            if ((pci_read32(static_cast<u8>(bus), device, 0, 0) & 0xFFFFU) == 0xFFFFU) {
                continue;
            }
            const u32 header = pci_read32(static_cast<u8>(bus), device, 0, 0x0C);
            const u8 function_count = ((header >> 16U) & 0x80U) != 0 ? 8 : 1;
            for (u8 function = 0; function < function_count; ++function) {
                if ((pci_read32(static_cast<u8>(bus), device, function, 0) & 0xFFFFU) ==
                    0xFFFFU) {
                    continue;
                }
                const u32 classes =
                    pci_read32(static_cast<u8>(bus), device, function, 0x08);
                const bool host_bridge = (classes >> 24U) == 0x06U &&
                                         ((classes >> 16U) & 0xFFU) == 0;
                if (host_bridge) {
                    continue;
                }
                const u32 command_status =
                    pci_read32(static_cast<u8>(bus), device, function, 0x04);
                const u32 address = 0x8000'0000U | (static_cast<u32>(bus) << 16U) |
                                    (static_cast<u32>(device) << 11U) |
                                    (static_cast<u32>(function) << 8U) | 0x04U;
                arch::x86_64::out32(0xCF8, address);
                arch::x86_64::out16(0xCFC, static_cast<u16>(command_status & ~0x4U));
                if ((pci_read32(static_cast<u8>(bus), device, function, 0x04) & 0x4U) != 0) {
                    return false;
                }
                ++quiesced_functions;
            }
        }
    }
    return quiesced_functions == expected_functions;
}

bool pci_bus_masters_disabled(u32 expected_functions) {
    u32 verified = 0;
    for (u16 bus = 0; bus < 256; ++bus) {
        for (u8 device = 0; device < 32; ++device) {
            if ((pci_read32(static_cast<u8>(bus), device, 0, 0) & 0xFFFFU) == 0xFFFFU) {
                continue;
            }
            const u32 header = pci_read32(static_cast<u8>(bus), device, 0, 0x0C);
            const u8 function_count = ((header >> 16U) & 0x80U) != 0 ? 8 : 1;
            for (u8 function = 0; function < function_count; ++function) {
                if ((pci_read32(static_cast<u8>(bus), device, function, 0) & 0xFFFFU) ==
                    0xFFFFU) {
                    continue;
                }
                const u32 classes =
                    pci_read32(static_cast<u8>(bus), device, function, 0x08);
                const bool host_bridge = (classes >> 24U) == 0x06U &&
                                         ((classes >> 16U) & 0xFFU) == 0;
                if (host_bridge) {
                    continue;
                }
                if ((pci_read32(static_cast<u8>(bus), device, function, 0x04) & 0x4U) != 0) {
                    return false;
                }
                ++verified;
            }
        }
    }
    return verified == expected_functions;
}

bool flush_root_table(u64 root_physical) {
    u32 eax = 1;
    u32 ebx = 0;
    u32 ecx = 0;
    u32 edx = 0;
    asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : : "memory");
    const u32 line_size = ((ebx >> 8U) & 0xFFU) * 8U;
    auto* root = static_cast<u8*>(
        memory::physical::direct_map_owned(root_physical, memory::physical::PageOwner::iommu));
    if ((edx & (1U << 19U)) == 0 || line_size < 16 || line_size > 256 ||
        (line_size & (line_size - 1U)) != 0 || root == nullptr) {
        return false;
    }
    for (u32 offset = 0; offset < kPageSize; offset += line_size) {
        asm volatile("clflush (%0)" : : "r"(root + offset) : "memory");
    }
    asm volatile("mfence" : : : "memory");
    return true;
}

void release_all() {
    auto* space = memory::virtual_memory::active_address_space();
    while (unit_count != 0) {
        --unit_count;
        Unit& unit = units[unit_count];
        if (unit.registers != nullptr && unit.enabled) {
            write32(unit, kGlobalCommand, 0);
            (void)wait_status(unit, kTranslationEnable, false);
        }
        if (space != nullptr && unit.register_virtual != 0) {
            (void)memory::virtual_memory::unmap(*space, unit.register_virtual);
        }
        if (unit.root_physical != 0) {
            (void)memory::physical::free_page(unit.root_physical,
                                              memory::physical::PageOwner::iommu);
        }
        unit = {};
    }
    address_width = 0;
    quiesced_functions = 0;
    initialized = false;
}

bool initialize_unit(const firmware::acpi::Iommu& description, usize index) {
    auto* space = memory::virtual_memory::active_address_space();
    if (space == nullptr || (!description.include_all && description.scope_count == 0) ||
        description.pci_segment != 0) {
        return false;
    }
    Unit& unit = units[index];
    unit.register_virtual = kRegisterVirtualBase + index * kPageSize;
    if (!memory::virtual_memory::map(*space, unit.register_virtual, description.register_address,
                                     MapFlags::write | MapFlags::global |
                                         MapFlags::cache_disable)) {
        return false;
    }
    unit.registers = reinterpret_cast<volatile u8*>(unit.register_virtual);
    unit.version = read32(unit, kVersion);
    unit.capability = read64(unit, kCapability);
    if (unit.version == 0 || unit.version == 0xFFFF'FFFFU || unit.capability == static_cast<u64>(-1)) {
        return false;
    }
    if (!memory::physical::allocate_page(unit.root_physical,
                                         memory::physical::PageOwner::iommu) ||
        !root_is_empty(unit.root_physical) || !flush_root_table(unit.root_physical)) {
        return false;
    }
    write64(unit, kRootTableAddress, unit.root_physical & kRootAddressMask);
    write32(unit, kGlobalCommand, kSetRootTablePointer);
    if (!wait_status(unit, kSetRootTablePointer, true)) {
        return false;
    }
    write32(unit, kGlobalCommand, kTranslationEnable);
    if (!wait_status(unit, kTranslationEnable, true)) {
        return false;
    }
    unit.enabled = true;
    return true;
}
}

bool initialize(const firmware::acpi::Topology& topology) {
    last_failure = 0;
    if (initialized || topology.iommu_count == 0 ||
        topology.iommu_count > firmware::acpi::kMaximumIommus ||
        topology.dma_address_width < 32 || topology.dma_address_width > 64) {
        last_failure = 1;
        return false;
    }
    address_width = topology.dma_address_width;
    if (!quiesce_pci(topology.pci_functions)) {
        last_failure = 2;
        release_all();
        return false;
    }
    for (usize index = 0; index < topology.iommu_count; ++index) {
        unit_count = index + 1;
        if (!initialize_unit(topology.iommus[index], index)) {
            last_failure = static_cast<u32>(10 + index);
            release_all();
            return false;
        }
    }
    initialized = true;
    return true;
}

bool self_test() {
    if (!initialized || unit_count == 0 ||
        !pci_bus_masters_disabled(quiesced_functions)) {
        last_failure = 30;
        return false;
    }
    for (usize index = 0; index < unit_count; ++index) {
        const Unit& unit = units[index];
        if (!unit.enabled || (read32(unit, kGlobalStatus) & kTranslationEnable) == 0 ||
            (read64(unit, kRootTableAddress) & kRootAddressMask) != unit.root_physical ||
            !root_is_empty(unit.root_physical)) {
            last_failure = static_cast<u32>(31 + index);
            return false;
        }
    }
    return true;
}

Statistics statistics() {
    return {
        .enabled_units = static_cast<u32>(unit_count),
        .quiesced_pci_functions = quiesced_functions,
        .dma_address_width = address_width,
        .default_deny = initialized,
    };
}

u32 failure_code() { return last_failure; }
}
