#include <doxxer/memory/user_copy.hpp>

#include <doxxer/memory/physical.hpp>

namespace doxxer::memory::user_copy {
namespace {
constexpr u64 kMinimumUserAddress = 0x1'0000ULL;
constexpr u64 kMaximumUserAddress = 0x0000'7FFF'FFFF'FFFFULL;
constexpr usize kMaximumCopyLength = 1024 * 1024;
u64 copies_from_user = 0;
u64 copies_to_user = 0;
u64 bytes_copied = 0;
u64 rejected_operations = 0;
u32 last_failure = 0;

void reject() { __atomic_add_fetch(&rejected_operations, 1ULL, __ATOMIC_RELAXED); }

bool range_bounds(u64 address, usize length) {
    if (length == 0) {
        return address >= kMinimumUserAddress && address <= kMaximumUserAddress;
    }
    if (length > kMaximumCopyLength || address < kMinimumUserAddress ||
        address > kMaximumUserAddress || static_cast<u64>(length - 1) >
                                          kMaximumUserAddress - address) {
        return false;
    }
    return true;
}

bool mapping_allows(const virtual_memory::Mapping& mapping, Access access) {
    if (!virtual_memory::has_flag(mapping.flags, virtual_memory::MapFlags::user)) {
        return false;
    }
    if (access == Access::write &&
        !virtual_memory::has_flag(mapping.flags, virtual_memory::MapFlags::write)) {
        return false;
    }
    if (access == Access::execute &&
        !virtual_memory::has_flag(mapping.flags, virtual_memory::MapFlags::execute)) {
        return false;
    }
    return true;
}

bool copy_bytes(virtual_memory::AddressSpace& space, u64 user_address, u8* kernel_buffer,
                usize length, bool to_user) {
    usize copied = 0;
    while (copied < length) {
        virtual_memory::Mapping mapping{};
        const u64 current = user_address + copied;
        if (!virtual_memory::query(space, current, mapping) ||
            !mapping_allows(mapping, to_user ? Access::write : Access::read)) {
            return false;
        }
        const usize page_remaining =
            static_cast<usize>(physical::kPageSize - (current & (physical::kPageSize - 1)));
        const usize chunk = (length - copied) < page_remaining ? (length - copied) : page_remaining;
        auto* user_bytes = static_cast<u8*>(physical::direct_map(mapping.physical_address));
        if (user_bytes == nullptr) {
            return false;
        }
        for (usize index = 0; index < chunk; ++index) {
            if (to_user) {
                user_bytes[index] = kernel_buffer[copied + index];
            } else {
                kernel_buffer[copied + index] = user_bytes[index];
            }
        }
        copied += chunk;
    }
    return true;
}

bool equal_bytes(const u8* left, const u8* right, usize length) {
    for (usize index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}
}

bool validate_range(virtual_memory::AddressSpace& space, u64 user_address, usize length,
                    Access access) {
    if (!space.valid() || !range_bounds(user_address, length)) {
        reject();
        return false;
    }
    if (length == 0) {
        return true;
    }
    u64 current = user_address;
    const u64 end = user_address + length;
    while (current < end) {
        virtual_memory::Mapping mapping{};
        if (!virtual_memory::query(space, current, mapping) || !mapping_allows(mapping, access)) {
            reject();
            return false;
        }
        const u64 next_page = (current & ~(physical::kPageSize - 1)) + physical::kPageSize;
        current = next_page < end ? next_page : end;
    }
    return true;
}

bool copy_from_user(virtual_memory::AddressSpace& space, void* destination, u64 user_source,
                    usize length) {
    if ((length != 0 && destination == nullptr) ||
        !validate_range(space, user_source, length, Access::read) ||
        !copy_bytes(space, user_source, static_cast<u8*>(destination), length, false)) {
        reject();
        return false;
    }
    __atomic_add_fetch(&copies_from_user, 1ULL, __ATOMIC_RELAXED);
    __atomic_add_fetch(&bytes_copied, static_cast<u64>(length), __ATOMIC_RELAXED);
    return true;
}

bool copy_to_user(virtual_memory::AddressSpace& space, u64 user_destination, const void* source,
                  usize length) {
    if ((length != 0 && source == nullptr) ||
        !validate_range(space, user_destination, length, Access::write) ||
        !copy_bytes(space, user_destination, const_cast<u8*>(static_cast<const u8*>(source)),
                    length, true)) {
        reject();
        return false;
    }
    __atomic_add_fetch(&copies_to_user, 1ULL, __ATOMIC_RELAXED);
    __atomic_add_fetch(&bytes_copied, static_cast<u64>(length), __ATOMIC_RELAXED);
    return true;
}

bool zero_user(virtual_memory::AddressSpace& space, u64 user_destination, usize length) {
    if (!validate_range(space, user_destination, length, Access::write)) {
        reject();
        return false;
    }
    usize cleared = 0;
    while (cleared < length) {
        virtual_memory::Mapping mapping{};
        const u64 current = user_destination + cleared;
        if (!virtual_memory::query(space, current, mapping)) {
            reject();
            return false;
        }
        const usize page_remaining =
            static_cast<usize>(physical::kPageSize - (current & (physical::kPageSize - 1)));
        const usize chunk = (length - cleared) < page_remaining ? (length - cleared) : page_remaining;
        auto* bytes = static_cast<u8*>(physical::direct_map(mapping.physical_address));
        if (bytes == nullptr) {
            reject();
            return false;
        }
        for (usize index = 0; index < chunk; ++index) {
            bytes[index] = 0;
        }
        cleared += chunk;
    }
    __atomic_add_fetch(&copies_to_user, 1ULL, __ATOMIC_RELAXED);
    __atomic_add_fetch(&bytes_copied, static_cast<u64>(length), __ATOMIC_RELAXED);
    return true;
}

bool self_test() {
    last_failure = 0;
    virtual_memory::AddressSpace space{};
    u64 first_page = 0;
    u64 second_page = 0;
    constexpr u64 kUserBase = 0x40'0000ULL;
    if (!virtual_memory::create(space, 31) || !physical::allocate_page(first_page) ||
        !physical::allocate_page(second_page) ||
        !virtual_memory::map(space, kUserBase, first_page,
                             virtual_memory::MapFlags::user |
                                 virtual_memory::MapFlags::write) ||
        !virtual_memory::map(space, kUserBase + physical::kPageSize, second_page,
                             virtual_memory::MapFlags::user |
                                 virtual_memory::MapFlags::write)) {
        last_failure = 1;
        return false;
    }
    u8 source[32]{};
    u8 destination[32]{};
    for (usize index = 0; index < sizeof(source); ++index) {
        source[index] = static_cast<u8>(index ^ 0xD0U);
    }
    const u64 crossing_address = kUserBase + physical::kPageSize - 16;
    if (!copy_to_user(space, crossing_address, source, sizeof(source)) ||
        !copy_from_user(space, destination, crossing_address, sizeof(destination)) ||
        !equal_bytes(source, destination, sizeof(source))) {
        last_failure = 2;
        return false;
    }
    if (!virtual_memory::protect(space, kUserBase + physical::kPageSize,
                                 virtual_memory::MapFlags::user) ||
        copy_to_user(space, crossing_address, source, sizeof(source)) ||
        !copy_from_user(space, destination, crossing_address, sizeof(destination))) {
        last_failure = 3;
        return false;
    }
    if (validate_range(space, 0, 1, Access::read) ||
        validate_range(space, 0xFFFF'8000'0000'0000ULL, 1, Access::read) ||
        validate_range(space, kMaximumUserAddress - 3, 8, Access::read) ||
        validate_range(space, kUserBase, kMaximumCopyLength + 1, Access::read)) {
        last_failure = 4;
        return false;
    }
    if (!virtual_memory::unmap(space, kUserBase) ||
        !virtual_memory::unmap(space, kUserBase + physical::kPageSize) ||
        !physical::free_page(first_page) || !physical::free_page(second_page) ||
        !virtual_memory::destroy(space)) {
        last_failure = 5;
        return false;
    }
    return true;
}

Statistics statistics() {
    return {
        .copies_from_user = __atomic_load_n(&copies_from_user, __ATOMIC_RELAXED),
        .copies_to_user = __atomic_load_n(&copies_to_user, __ATOMIC_RELAXED),
        .bytes_copied = __atomic_load_n(&bytes_copied, __ATOMIC_RELAXED),
        .rejected_operations = __atomic_load_n(&rejected_operations, __ATOMIC_RELAXED),
    };
}

u32 failure_code() { return last_failure; }
}
