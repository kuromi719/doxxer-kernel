#include <doxxer/memory/shadow_regions.hpp>

#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>
#include <doxxer/sync/spinlock.hpp>

extern "C" doxxer::uptr __stack_chk_guard;

namespace doxxer::memory::shadow_regions {
namespace {
using virtual_memory::AddressSpace;
using virtual_memory::MapFlags;

constexpr u16 kMaximumRegions = 32;
constexpr usize kGranuleBytes = 16;
constexpr u8 kPoisoned = 0xFD;
constexpr u64 kDataBase = 0x0000'6800'0000'0000ULL;
constexpr u64 kShadowBase = 0x0000'6900'0000'0000ULL;
constexpr u64 kDataStride = 3 * physical::kPageSize;
constexpr u64 kShadowStride = 2 * physical::kPageSize;

struct Region {
    u64 seal;
    u64 data_physical;
    u64 shadow_physical;
    u32 generation = 1;
    u16 size;
    bool active;
};

sync::SpinLock regions_lock{};
Region regions[kMaximumRegions]{};
AddressSpace* address_space = nullptr;
u64 integrity_key = 0;
u64 opened_regions = 0;
u64 closed_regions = 0;
u64 rejected_accesses = 0;
u64 resealed_regions = 0;
u32 active_regions = 0;
u32 last_failure = 0;
bool initialized = false;

u64 mix(u64 value) {
    value ^= value >> 30U;
    value *= 0xBF58'476D'1CE4'E5B9ULL;
    value ^= value >> 27U;
    value *= 0x94D0'49BB'1331'11EBULL;
    return value ^ (value >> 31U);
}

u64 data_address(u16 slot) {
    return kDataBase + static_cast<u64>(slot) * kDataStride + physical::kPageSize;
}

u64 shadow_address(u16 slot) {
    return kShadowBase + static_cast<u64>(slot) * kShadowStride;
}

u64 region_seal(u16 slot, const Region& region) {
    return mix(integrity_key ^ (static_cast<u64>(slot) << 48U) ^
               (static_cast<u64>(region.generation) << 16U) ^ region.size ^
               region.data_physical ^ (region.shadow_physical << 1U) ^
               (region.active ? 0xD058'5348'4144'4F57ULL : 0));
}

void secure_zero(void* pointer, usize size) {
    auto* bytes = static_cast<volatile u8*>(pointer);
    for (usize index = 0; index < size; ++index) {
        bytes[index] = 0;
    }
    asm volatile("" : : : "memory");
}

void copy_bytes(void* destination, const void* source, usize size) {
    auto* output = static_cast<u8*>(destination);
    const auto* input = static_cast<const u8*>(source);
    for (usize index = 0; index < size; ++index) {
        output[index] = input[index];
    }
}

u32 next_generation(u32 generation) {
    ++generation;
    return generation == 0 ? 1 : generation;
}

bool mapping_matches(u64 address, u64 physical_address, bool writable) {
    virtual_memory::Mapping mapping{};
    return virtual_memory::query(*address_space, address, mapping) &&
           mapping.physical_address == physical_address &&
           virtual_memory::has_flag(mapping.flags, MapFlags::write) == writable &&
           !virtual_memory::has_flag(mapping.flags, MapFlags::execute) &&
           !virtual_memory::has_flag(mapping.flags, MapFlags::user);
}

bool guard_absent(u64 address) {
    virtual_memory::Mapping mapping{};
    return !virtual_memory::query(*address_space, address, mapping);
}

bool region_valid(u16 slot, const Region& region) {
    if (!initialized || slot >= kMaximumRegions || !region.active || region.size == 0 ||
        region.size > security::sealed_memory::kMaximumSecretBytes ||
        region.data_physical == 0 || region.shadow_physical == 0 ||
        region.seal != region_seal(slot, region)) {
        return false;
    }
    physical::PageOwner data_owner{};
    physical::PageOwner shadow_owner{};
    const u64 data = data_address(slot);
    const u64 shadow = shadow_address(slot);
    return physical::owner_of(region.data_physical, data_owner) &&
           physical::owner_of(region.shadow_physical, shadow_owner) &&
           data_owner == physical::PageOwner::secret_working &&
           shadow_owner == physical::PageOwner::shadow_region &&
           mapping_matches(data, region.data_physical, true) &&
           mapping_matches(shadow, region.shadow_physical, false) &&
           guard_absent(data - physical::kPageSize) &&
           guard_absent(data + physical::kPageSize) &&
           guard_absent(shadow + physical::kPageSize);
}

bool access_allowed(u16 slot, const Region& region, usize offset, usize size) {
    if (!region_valid(slot, region) || size == 0 || offset >= region.size ||
        size > static_cast<usize>(region.size) - offset) {
        return false;
    }
    const auto* shadow = reinterpret_cast<const volatile u8*>(shadow_address(slot));
    for (usize byte = offset; byte < offset + size; ++byte) {
        const u8 state = shadow[byte / kGranuleBytes];
        if (state == kPoisoned || (state != 0 && byte % kGranuleBytes >= state)) {
            return false;
        }
    }
    return true;
}

bool initialize_shadow(u16 slot, usize size) {
    const u64 address = shadow_address(slot);
    auto* shadow = reinterpret_cast<volatile u8*>(address);
    for (usize index = 0; index < physical::kPageSize; ++index) {
        shadow[index] = kPoisoned;
    }
    const usize full_granules = size / kGranuleBytes;
    const usize remainder = size % kGranuleBytes;
    for (usize index = 0; index < full_granules; ++index) {
        shadow[index] = 0;
    }
    if (remainder != 0) {
        shadow[full_granules] = static_cast<u8>(remainder);
    }
    return virtual_memory::protect(*address_space, address, MapFlags::none);
}

bool poison_shadow(u16 slot) {
    const u64 address = shadow_address(slot);
    if (!virtual_memory::protect(*address_space, address, MapFlags::write)) {
        return false;
    }
    auto* shadow = reinterpret_cast<volatile u8*>(address);
    for (usize index = 0; index < physical::kPageSize; ++index) {
        shadow[index] = kPoisoned;
    }
    return virtual_memory::protect(*address_space, address, MapFlags::none);
}

bool release_region(u16 slot, Region& region) {
    bool success = region_valid(slot, region);
    if (mapping_matches(shadow_address(slot), region.shadow_physical, false)) {
        success = poison_shadow(slot) && success;
    }
    if (mapping_matches(data_address(slot), region.data_physical, true)) {
        secure_zero(reinterpret_cast<void*>(data_address(slot)), physical::kPageSize);
    } else {
        success = false;
    }
    virtual_memory::Mapping mapping{};
    if (!virtual_memory::query(*address_space, shadow_address(slot), mapping) ||
        !virtual_memory::unmap(*address_space, shadow_address(slot))) {
        success = false;
    }
    if (!virtual_memory::query(*address_space, data_address(slot), mapping) ||
        !virtual_memory::unmap(*address_space, data_address(slot))) {
        success = false;
    }
    if (!physical::free_page(region.shadow_physical, physical::PageOwner::shadow_region)) {
        success = false;
    }
    if (!physical::free_page(region.data_physical, physical::PageOwner::secret_working)) {
        success = false;
    }
    region.data_physical = 0;
    region.shadow_physical = 0;
    region.size = 0;
    region.active = false;
    region.generation = next_generation(region.generation);
    region.seal = region_seal(slot, region);
    if (active_regions != 0) {
        --active_regions;
    }
    ++closed_regions;
    return success;
}

bool same_bytes(const u8* left, const u8* right, usize size) {
    u8 difference = 0;
    for (usize index = 0; index < size; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}
}

bool initialize() {
    sync::LockGuard guard(regions_lock);
    if (initialized) {
        return false;
    }
    address_space = virtual_memory::active_address_space();
    if (address_space == nullptr || !address_space->valid()) {
        address_space = nullptr;
        return false;
    }
    virtual_memory::Mapping mapping{};
    for (u16 slot = 0; slot < kMaximumRegions; ++slot) {
        const u64 data = data_address(slot);
        const u64 shadow = shadow_address(slot);
        if (virtual_memory::query(*address_space, data - physical::kPageSize, mapping) ||
            virtual_memory::query(*address_space, data, mapping) ||
            virtual_memory::query(*address_space, data + physical::kPageSize, mapping) ||
            virtual_memory::query(*address_space, shadow, mapping) ||
            virtual_memory::query(*address_space, shadow + physical::kPageSize, mapping)) {
            address_space = nullptr;
            return false;
        }
    }
    integrity_key = mix(static_cast<u64>(__stack_chk_guard) ^ address_space->root_physical() ^
                        kDataBase ^ kShadowBase);
    if (integrity_key == 0) {
        integrity_key = 0xD058'5348'4144'4F57ULL;
    }
    for (u16 slot = 0; slot < kMaximumRegions; ++slot) {
        regions[slot].seal = region_seal(slot, regions[slot]);
    }
    initialized = true;
    return true;
}

bool open_sealed(security::sealed_memory::Handle sealed, Handle& handle) {
    handle = {};
    sync::LockGuard guard(regions_lock);
    if (!initialized) {
        ++rejected_accesses;
        return false;
    }
    u16 slot = kMaximumRegions;
    for (u16 index = 0; index < kMaximumRegions; ++index) {
        if (!regions[index].active) {
            slot = index;
            break;
        }
    }
    if (slot == kMaximumRegions) {
        ++rejected_accesses;
        return false;
    }
    Region& region = regions[slot];
    u64 data_physical = 0;
    u64 shadow_physical = 0;
    const u64 data = data_address(slot);
    const u64 shadow = shadow_address(slot);
    if (!physical::allocate_page(data_physical, physical::PageOwner::secret_working) ||
        !physical::allocate_page(shadow_physical, physical::PageOwner::shadow_region) ||
        !virtual_memory::map(*address_space, data, data_physical, MapFlags::write) ||
        !virtual_memory::map(*address_space, shadow, shadow_physical, MapFlags::write)) {
        if (shadow_physical != 0) {
            virtual_memory::Mapping mapping{};
            if (virtual_memory::query(*address_space, shadow, mapping)) {
                (void)virtual_memory::unmap(*address_space, shadow);
            }
            (void)physical::free_page(shadow_physical, physical::PageOwner::shadow_region);
        }
        if (data_physical != 0) {
            virtual_memory::Mapping mapping{};
            if (virtual_memory::query(*address_space, data, mapping)) {
                (void)virtual_memory::unmap(*address_space, data);
            }
            (void)physical::free_page(data_physical, physical::PageOwner::secret_working);
        }
        ++rejected_accesses;
        return false;
    }

    usize opened_size = 0;
    if (!security::sealed_memory::open(sealed, reinterpret_cast<void*>(data),
                                       security::sealed_memory::kMaximumSecretBytes,
                                       opened_size) ||
        opened_size == 0 || opened_size > security::sealed_memory::kMaximumSecretBytes ||
        !initialize_shadow(slot, opened_size)) {
        secure_zero(reinterpret_cast<void*>(data), physical::kPageSize);
        (void)virtual_memory::unmap(*address_space, shadow);
        (void)virtual_memory::unmap(*address_space, data);
        (void)physical::free_page(shadow_physical, physical::PageOwner::shadow_region);
        (void)physical::free_page(data_physical, physical::PageOwner::secret_working);
        ++rejected_accesses;
        return false;
    }
    region.data_physical = data_physical;
    region.shadow_physical = shadow_physical;
    region.size = static_cast<u16>(opened_size);
    region.active = true;
    region.seal = region_seal(slot, region);
    handle = {.slot = slot, .generation = region.generation};
    ++opened_regions;
    ++active_regions;
    return true;
}

bool read(Handle handle, usize offset, void* destination, usize size) {
    if (destination == nullptr || size == 0) {
        sync::LockGuard guard(regions_lock);
        ++rejected_accesses;
        return false;
    }
    sync::LockGuard guard(regions_lock);
    if (handle.slot >= kMaximumRegions || regions[handle.slot].generation != handle.generation ||
        !access_allowed(handle.slot, regions[handle.slot], offset, size)) {
        if (size <= security::sealed_memory::kMaximumSecretBytes) {
            secure_zero(destination, size);
        }
        ++rejected_accesses;
        return false;
    }
    copy_bytes(destination,
               reinterpret_cast<const void*>(data_address(handle.slot) + offset), size);
    return true;
}

bool write(Handle handle, usize offset, const void* source, usize size) {
    if (source == nullptr || size == 0) {
        sync::LockGuard guard(regions_lock);
        ++rejected_accesses;
        return false;
    }
    sync::LockGuard guard(regions_lock);
    if (handle.slot >= kMaximumRegions || regions[handle.slot].generation != handle.generation ||
        !access_allowed(handle.slot, regions[handle.slot], offset, size)) {
        ++rejected_accesses;
        return false;
    }
    copy_bytes(reinterpret_cast<void*>(data_address(handle.slot) + offset), source, size);
    return true;
}

bool reseal(Handle handle, security::sealed_memory::Handle& sealed) {
    sealed = {};
    sync::LockGuard guard(regions_lock);
    if (handle.slot >= kMaximumRegions || regions[handle.slot].generation != handle.generation ||
        !region_valid(handle.slot, regions[handle.slot]) ||
        !security::sealed_memory::seal(reinterpret_cast<const void*>(data_address(handle.slot)),
                                       regions[handle.slot].size, sealed)) {
        ++rejected_accesses;
        return false;
    }
    ++resealed_regions;
    return true;
}

bool close(Handle& handle) {
    sync::LockGuard guard(regions_lock);
    if (handle.slot >= kMaximumRegions || regions[handle.slot].generation != handle.generation ||
        !region_valid(handle.slot, regions[handle.slot])) {
        ++rejected_accesses;
        return false;
    }
    const bool success = release_region(handle.slot, regions[handle.slot]);
    handle = {};
    return success;
}

bool self_test() {
    last_failure = 1;
    if (!initialized) {
        return false;
    }
    constexpr u8 original[] = {0x44, 0x4F, 0x58, 0x58, 0x45, 0x52, 0x2D, 0x53,
                               0x48, 0x41, 0x44, 0x4F, 0x57, 0x2D, 0x52, 0x41,
                               0x4D, 0x2D, 0x54, 0x45, 0x53, 0x54};
    constexpr u8 replacement[] = {0x53, 0x45, 0x41, 0x4C, 0x45, 0x44};
    security::sealed_memory::Handle source{};
    security::sealed_memory::Handle updated{};
    Handle region{};
    Handle stale{};
    u8 output[sizeof(original)]{};
    usize output_size = 0;
    const physical::Statistics before = physical::statistics();
    if (!security::sealed_memory::seal(original, sizeof(original), source) ||
        !open_sealed(source, region)) {
        return false;
    }
    stale = region;

    last_failure = 2;
    if (!read(region, 0, output, sizeof(original)) ||
        !same_bytes(original, output, sizeof(original))) {
        return false;
    }
    for (u8& byte : output) {
        byte = 0xA5;
    }
    if (read(region, sizeof(original), output, 1) || output[0] != 0 ||
        write(region, sizeof(original) - 2, replacement, sizeof(replacement))) {
        return false;
    }

    last_failure = 3;
    if (!write(region, 0, replacement, sizeof(replacement)) || !reseal(region, updated) ||
        !close(region) || read(stale, 0, output, 1) || output[0] != 0) {
        return false;
    }

    last_failure = 4;
    secure_zero(output, sizeof(output));
    if (!security::sealed_memory::open(updated, output, sizeof(output), output_size) ||
        output_size != sizeof(original) ||
        !same_bytes(output, replacement, sizeof(replacement))) {
        return false;
    }
    for (usize index = sizeof(replacement); index < sizeof(original); ++index) {
        if (output[index] != original[index]) {
            return false;
        }
    }
    secure_zero(output, sizeof(output));

    last_failure = 5;
    if (!security::sealed_memory::destroy(source) ||
        !security::sealed_memory::destroy(updated)) {
        return false;
    }
    const physical::Statistics after = physical::statistics();
    if (active_regions != 0 || after.free_pages != before.free_pages ||
        after.allocated_pages != before.allocated_pages ||
        after.supervisor_mapping_references != before.supervisor_mapping_references) {
        return false;
    }
    last_failure = 0;
    return true;
}

Statistics statistics() {
    sync::LockGuard guard(regions_lock);
    return {
        .opened_regions = opened_regions,
        .closed_regions = closed_regions,
        .rejected_accesses = rejected_accesses,
        .resealed_regions = resealed_regions,
        .active_regions = active_regions,
        .capacity = kMaximumRegions,
    };
}

u32 failure_code() { return last_failure; }
}
