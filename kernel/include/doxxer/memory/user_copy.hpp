#pragma once

#include <doxxer/memory/virtual.hpp>
#include <doxxer/types.hpp>

namespace doxxer::memory::user_copy {
enum class Access : u8 {
    read,
    write,
    execute,
};

struct Statistics {
    u64 copies_from_user;
    u64 copies_to_user;
    u64 bytes_copied;
    u64 rejected_operations;
};

bool validate_range(virtual_memory::AddressSpace& space, u64 user_address, usize length,
                    Access access);
bool copy_from_user(virtual_memory::AddressSpace& space, void* destination, u64 user_source,
                    usize length);
bool copy_to_user(virtual_memory::AddressSpace& space, u64 user_destination, const void* source,
                  usize length);
bool zero_user(virtual_memory::AddressSpace& space, u64 user_destination, usize length);
bool self_test();
Statistics statistics();
u32 failure_code();
}
