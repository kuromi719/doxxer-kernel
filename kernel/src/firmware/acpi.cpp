#include <doxxer/firmware/acpi.hpp>

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

static_assert(sizeof(Rsdp) == 36);
static_assert(sizeof(SdtHeader) == 36);
static_assert(sizeof(Madt) == 44);
static_assert(sizeof(Hpet) == 56);

Topology discovered{};
bool ready = false;
u32 last_failure = 0;

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
        }
    }
    if (!parse_madt(madt) || hpet == nullptr || hpet->base.address_space != 0 ||
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
