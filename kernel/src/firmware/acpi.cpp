#include <doxxer/firmware/acpi.hpp>

#include <doxxer/arch/x86_64/io.hpp>
#include <doxxer/memory/physical.hpp>

namespace doxxer::firmware::acpi {
namespace {
constexpr u32 kMaximumTableLength = 1024 * 1024;
constexpr usize kMaximumRootEntries = 256;

struct [[gnu::packed]] Rsdp {
    char signature[8];
    u8 checksum;
    char oem_id[6];
    u8 revision;
    u32 rsdt_address;
    u32 length;
    u64 xsdt_address;
    u8 extended_checksum;
    u8 reserved[3];
};

struct [[gnu::packed]] SdtHeader {
    char signature[4];
    u32 length;
    u8 revision;
    u8 checksum;
    char oem_id[6];
    char oem_table_id[8];
    u32 oem_revision;
    u32 creator_id;
    u32 creator_revision;
};

struct [[gnu::packed]] Madt {
    SdtHeader header;
    u32 local_apic_address;
    u32 flags;
};

struct [[gnu::packed]] GenericAddress {
    u8 address_space;
    u8 bit_width;
    u8 bit_offset;
    u8 access_size;
    u64 address;
};

struct [[gnu::packed]] Hpet {
    SdtHeader header;
    u32 event_timer_block_id;
    GenericAddress base;
    u8 hpet_number;
    u16 minimum_tick;
    u8 page_protection;
};

struct [[gnu::packed]] Dmar {
    SdtHeader header;
    u8 host_address_width;
    u8 flags;
    u8 reserved[10];
};

struct [[gnu::packed]] DmarStructure {
    u16 type;
    u16 length;
};

struct [[gnu::packed]] DmarHardwareUnit {
    DmarStructure header;
    u8 flags;
    u8 reserved;
    u16 segment;
    u64 register_address;
};

struct [[gnu::packed]] DmarDeviceScope {
    u8 type;
    u8 length;
    u16 reserved;
    u8 enumeration_id;
    u8 start_bus;
};

static_assert(sizeof(Rsdp) == 36);
static_assert(sizeof(SdtHeader) == 36);
static_assert(sizeof(Madt) == 44);
static_assert(sizeof(Hpet) == 56);
static_assert(sizeof(Dmar) == 48);
static_assert(sizeof(DmarHardwareUnit) == 16);
static_assert(sizeof(DmarDeviceScope) == 6);

Topology discovered{};
bool ready = false;
u32 last_failure = 0;
u64 dma_scope_bitmap[1024]{};

u32 pci_read32(u8 bus, u8 device, u8 function, u8 offset) {
    const u32 address = 0x8000'0000U | (static_cast<u32>(bus) << 16U) |
                        (static_cast<u32>(device) << 11U) |
                        (static_cast<u32>(function) << 8U) | (offset & 0xFCU);
    arch::x86_64::out32(0xCF8, address);
    return arch::x86_64::in32(0xCFC);
}

u16 bdf_index(u8 bus, u8 device, u8 function) {
    return static_cast<u16>((static_cast<u16>(bus) << 8U) |
                            (static_cast<u16>(device) << 3U) | function);
}

void mark_bdf(u8 bus, u8 device, u8 function) {
    const u16 index = bdf_index(bus, device, function);
    dma_scope_bitmap[index / 64U] |= 1ULL << (index % 64U);
}

bool bdf_marked(u8 bus, u8 device, u8 function) {
    const u16 index = bdf_index(bus, device, function);
    return (dma_scope_bitmap[index / 64U] & (1ULL << (index % 64U))) != 0;
}

bool pci_present(u8 bus, u8 device, u8 function) {
    return (pci_read32(bus, device, function, 0) & 0xFFFFU) != 0xFFFFU;
}

bool pci_bridge(u8 bus, u8 device, u8 function, u8& secondary, u8& subordinate) {
    const u32 classes = pci_read32(bus, device, function, 0x08);
    if ((classes >> 24U) != 0x06U || ((classes >> 16U) & 0xFFU) != 0x04U) {
        return false;
    }
    const u32 buses = pci_read32(bus, device, function, 0x18);
    secondary = static_cast<u8>(buses >> 8U);
    subordinate = static_cast<u8>(buses >> 16U);
    return secondary != 0 && subordinate >= secondary;
}

bool add_dma_scope(const DmarDeviceScope* scope) {
    if (scope == nullptr || scope->length < sizeof(DmarDeviceScope) + 2 ||
        (scope->length - sizeof(DmarDeviceScope)) % 2 != 0) {
        return false;
    }
    if (scope->type != 1 && scope->type != 2) {
        return scope->type == 3 || scope->type == 4;
    }
    const auto* path = reinterpret_cast<const u8*>(scope) + sizeof(DmarDeviceScope);
    const usize path_count = (scope->length - sizeof(DmarDeviceScope)) / 2;
    u8 bus = scope->start_bus;
    for (usize index = 0; index < path_count; ++index) {
        const u8 device = path[index * 2];
        const u8 function = path[index * 2 + 1];
        if (device >= 32 || function >= 8 || !pci_present(bus, device, function)) {
            return false;
        }
        if (index + 1 < path_count) {
            u8 secondary = 0;
            u8 subordinate = 0;
            if (!pci_bridge(bus, device, function, secondary, subordinate)) {
                return false;
            }
            bus = secondary;
            continue;
        }
        mark_bdf(bus, device, function);
        if (scope->type == 2) {
            u8 secondary = 0;
            u8 subordinate = 0;
            if (!pci_bridge(bus, device, function, secondary, subordinate)) {
                return false;
            }
            for (u16 child_bus = secondary; child_bus <= subordinate; ++child_bus) {
                for (u8 child_device = 0; child_device < 32; ++child_device) {
                    for (u8 child_function = 0; child_function < 8; ++child_function) {
                        mark_bdf(static_cast<u8>(child_bus), child_device, child_function);
                    }
                }
            }
        }
    }
    return true;
}

bool pci_dma_coverage_valid() {
    discovered.pci_functions = 0;
    discovered.dma_covered_functions = 0;
    for (u16 bus = 0; bus < 256; ++bus) {
        for (u8 device = 0; device < 32; ++device) {
            if (!pci_present(static_cast<u8>(bus), device, 0)) {
                continue;
            }
            const u32 header = pci_read32(static_cast<u8>(bus), device, 0, 0x0C);
            const u8 function_count = ((header >> 16U) & 0x80U) != 0 ? 8 : 1;
            for (u8 function = 0; function < function_count; ++function) {
                if (!pci_present(static_cast<u8>(bus), device, function)) {
                    continue;
                }
                const u32 classes = pci_read32(static_cast<u8>(bus), device, function, 0x08);
                const bool host_bridge = (classes >> 24U) == 0x06U &&
                                         ((classes >> 16U) & 0xFFU) == 0;
                if (host_bridge) {
                    continue;
                }
                ++discovered.pci_functions;
                if (!bdf_marked(static_cast<u8>(bus), device, function)) {
                    last_failure = 0x1'0000U | bdf_index(static_cast<u8>(bus), device, function);
                    return false;
                }
                ++discovered.dma_covered_functions;
            }
        }
    }
    return discovered.pci_functions != 0 &&
           discovered.pci_functions == discovered.dma_covered_functions;
}

bool signature_is(const char* value, const char* expected, usize length) {
    for (usize index = 0; index < length; ++index) {
        if (value[index] != expected[index]) {
            return false;
        }
    }
    return true;
}

bool checksum_valid(const void* address, usize length) {
    const auto* bytes = static_cast<const volatile u8*>(address);
    u8 sum = 0;
    for (usize index = 0; index < length; ++index) {
        sum = static_cast<u8>(sum + bytes[index]);
    }
    return sum == 0;
}

const SdtHeader* table_at(u64 physical_address) {
    if (physical_address == 0) {
        return nullptr;
    }
    return static_cast<const SdtHeader*>(memory::physical::direct_map(physical_address));
}

bool table_valid(const SdtHeader* table) {
    return table != nullptr && table->length >= sizeof(SdtHeader) &&
           table->length <= kMaximumTableLength && checksum_valid(table, table->length);
}

u8 current_apic_id() {
    u32 eax = 1;
    u32 ebx = 0;
    u32 ecx = 0;
    u32 edx = 0;
    asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : : "memory");
    return static_cast<u8>(ebx >> 24U);
}

bool add_override(u8 source, u32 global_interrupt, u16 flags) {
    const u16 polarity = flags & 0x3U;
    const u16 trigger = (flags >> 2U) & 0x3U;
    if (source >= 16 || polarity == 2 || trigger == 2 ||
        discovered.override_count >= kMaximumOverrides) {
        return false;
    }
    for (usize index = 0; index < discovered.override_count; ++index) {
        if (discovered.overrides[index].source == source) {
            return false;
        }
    }
    discovered.overrides[discovered.override_count++] = {
        .source = source,
        .global_interrupt = global_interrupt,
        .active_low = polarity == 3,
        .level_triggered = trigger == 3,
    };
    return true;
}

bool parse_madt(const Madt* madt) {
    if (madt == nullptr || madt->header.length < sizeof(Madt)) {
        last_failure = 41;
        return false;
    }
    discovered.local_apic_address = madt->local_apic_address;
    discovered.legacy_pic = (madt->flags & 1U) != 0;
    const u8 bsp_id = current_apic_id();
    bool bootstrap_found = false;
    const auto* cursor = reinterpret_cast<const u8*>(madt) + sizeof(Madt);
    const auto* end = reinterpret_cast<const u8*>(madt) + madt->header.length;
    while (cursor < end) {
        if (static_cast<usize>(end - cursor) < 2) {
            last_failure = 42;
            return false;
        }
        const u8 type = cursor[0];
        const u8 length = cursor[1];
        if (length < 2 || static_cast<usize>(end - cursor) < length) {
            last_failure = 43;
            return false;
        }
        if (type == 0) {
            if (length != 8) {
                last_failure = 44;
                return false;
            }
            const u8 apic_id = cursor[3];
            const u32 flags = *reinterpret_cast<const u32*>(cursor + 4);
            if ((flags & 1U) != 0) {
                ++discovered.enabled_processors;
                if (apic_id == bsp_id) {
                    bootstrap_found = true;
                    discovered.bootstrap_apic_id = apic_id;
                }
            }
        } else if (type == 1) {
            if (length != 12 || discovered.io_apic_count >= kMaximumIoApics) {
                last_failure = 45;
                return false;
            }
            discovered.io_apics[discovered.io_apic_count++] = {
                .id = cursor[2],
                .address = *reinterpret_cast<const u32*>(cursor + 4),
                .global_interrupt_base = *reinterpret_cast<const u32*>(cursor + 8),
            };
        } else if (type == 2) {
            if (length != 10 || cursor[2] != 0 ||
                !add_override(cursor[3], *reinterpret_cast<const u32*>(cursor + 4),
                              *reinterpret_cast<const u16*>(cursor + 8))) {
                last_failure = 46;
                return false;
            }
        } else if (type == 5) {
            if (length != 12) {
                last_failure = 47;
                return false;
            }
            discovered.local_apic_address = *reinterpret_cast<const u64*>(cursor + 4);
        }
        cursor += length;
    }
    if (discovered.local_apic_address == 0 || discovered.enabled_processors == 0 ||
        discovered.io_apic_count == 0 || !bootstrap_found) {
        last_failure = 48;
        return false;
    }
    return true;
}

bool parse_dmar(const Dmar* dmar) {
    if (dmar == nullptr || dmar->header.length < sizeof(Dmar) ||
        dmar->host_address_width < 31 || dmar->host_address_width > 63) {
        last_failure = 55;
        return false;
    }
    discovered.dma_address_width = static_cast<u8>(dmar->host_address_width + 1U);
    discovered.dma_interrupt_remapping = (dmar->flags & 1U) != 0;
    const auto* cursor = reinterpret_cast<const u8*>(dmar) + sizeof(Dmar);
    const auto* end = reinterpret_cast<const u8*>(dmar) + dmar->header.length;
    while (cursor < end) {
        if (static_cast<usize>(end - cursor) < sizeof(DmarStructure)) {
            last_failure = 56;
            return false;
        }
        const auto* structure = reinterpret_cast<const DmarStructure*>(cursor);
        if (structure->length < sizeof(DmarStructure) ||
            static_cast<usize>(end - cursor) < structure->length) {
            last_failure = 57;
            return false;
        }
        if (structure->type == 0) {
            if (structure->length < sizeof(DmarHardwareUnit) ||
                discovered.iommu_count >= kMaximumIommus) {
                last_failure = 58;
                return false;
            }
            const auto* unit = reinterpret_cast<const DmarHardwareUnit*>(cursor);
            if (unit->segment != 0 || unit->register_address == 0 ||
                unit->register_address % memory::physical::kPageSize != 0) {
                last_failure = 59;
                return false;
            }
            for (usize index = 0; index < discovered.iommu_count; ++index) {
                if (discovered.iommus[index].register_address == unit->register_address) {
                    last_failure = 60;
                    return false;
                }
            }
            const bool unit_include_all = (unit->flags & 1U) != 0;
            Iommu& description = discovered.iommus[discovered.iommu_count++];
            description = {
                .register_address = unit->register_address,
                .pci_segment = unit->segment,
                .include_all = unit_include_all,
                .scope_count = 0,
            };
            if (unit_include_all) {
                for (u64& bits : dma_scope_bitmap) {
                    bits = static_cast<u64>(-1);
                }
            } else {
                const auto* scope_cursor = cursor + sizeof(DmarHardwareUnit);
                const auto* structure_end = cursor + structure->length;
                while (scope_cursor < structure_end) {
                    if (static_cast<usize>(structure_end - scope_cursor) <
                        sizeof(DmarDeviceScope)) {
                        last_failure = 63;
                        return false;
                    }
                    const auto* scope = reinterpret_cast<const DmarDeviceScope*>(scope_cursor);
                    if (scope->length > static_cast<usize>(structure_end - scope_cursor) ||
                        !add_dma_scope(scope)) {
                        last_failure = 64;
                        return false;
                    }
                    ++description.scope_count;
                    scope_cursor += scope->length;
                }
            }
        }
        cursor += structure->length;
    }
    if (discovered.iommu_count == 0) {
        last_failure = 61;
        return false;
    }
    if (!pci_dma_coverage_valid()) {
        if (last_failure == 0) {
            last_failure = 65;
        }
        return false;
    }
    return true;
}

bool parse_root(const SdtHeader* root, bool xsdt) {
    if (!table_valid(root) || !signature_is(root->signature, xsdt ? "XSDT" : "RSDT", 4)) {
        last_failure = 49;
        return false;
    }
    const usize entry_size = xsdt ? sizeof(u64) : sizeof(u32);
    const usize payload = root->length - sizeof(SdtHeader);
    if (payload % entry_size != 0 || payload / entry_size > kMaximumRootEntries) {
        last_failure = 50;
        return false;
    }
    const auto* entries = reinterpret_cast<const u8*>(root) + sizeof(SdtHeader);
    const Madt* madt = nullptr;
    const Hpet* hpet = nullptr;
    const Dmar* dmar = nullptr;
    for (usize index = 0; index < payload / entry_size; ++index) {
        const u64 address = xsdt ? reinterpret_cast<const u64*>(entries)[index]
                                 : reinterpret_cast<const u32*>(entries)[index];
        const SdtHeader* table = table_at(address);
        if (!table_valid(table)) {
            last_failure = 51;
            return false;
        }
        if (signature_is(table->signature, "APIC", 4)) {
            if (madt != nullptr) {
                last_failure = 52;
                return false;
            }
            madt = reinterpret_cast<const Madt*>(table);
        } else if (signature_is(table->signature, "HPET", 4)) {
            if (hpet != nullptr || table->length < sizeof(Hpet)) {
                last_failure = 53;
                return false;
            }
            hpet = reinterpret_cast<const Hpet*>(table);
        } else if (signature_is(table->signature, "DMAR", 4)) {
            if (dmar != nullptr || table->length < sizeof(Dmar)) {
                last_failure = 62;
                return false;
            }
            dmar = reinterpret_cast<const Dmar*>(table);
        }
    }
    if (!parse_madt(madt) || !parse_dmar(dmar) || hpet == nullptr || hpet->base.address_space != 0 ||
        hpet->base.address == 0 || hpet->base.bit_offset != 0) {
        if (last_failure == 0) {
            last_failure = 54;
        }
        return false;
    }
    discovered.hpet_address = hpet->base.address;
    return true;
}
}

bool initialize(const volatile limine_rsdp_response* response) {
    ready = false;
    last_failure = 0;
    discovered = {};
    for (u64& bits : dma_scope_bitmap) {
        bits = 0;
    }
    if (response == nullptr || response->address == nullptr) {
        last_failure = 1;
        return false;
    }
    const auto* rsdp = static_cast<const Rsdp*>(response->address);
    if (!signature_is(rsdp->signature, "RSD PTR ", 8) || !checksum_valid(rsdp, 20)) {
        last_failure = 2;
        return false;
    }
    const SdtHeader* root = nullptr;
    bool xsdt = false;
    if (rsdp->revision >= 2) {
        if (rsdp->length < sizeof(Rsdp) || rsdp->length > 4096 ||
            !checksum_valid(rsdp, rsdp->length) || rsdp->xsdt_address == 0) {
            last_failure = 3;
            return false;
        }
        root = table_at(rsdp->xsdt_address);
        xsdt = true;
    } else {
        root = table_at(rsdp->rsdt_address);
    }
    if (!parse_root(root, xsdt)) {
        if (last_failure == 0) {
            last_failure = 4;
        }
        return false;
    }
    ready = true;
    return true;
}

const Topology* topology() { return ready ? &discovered : nullptr; }

u32 failure_code() { return last_failure; }
}
