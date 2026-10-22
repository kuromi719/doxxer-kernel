#pragma once

#include <doxxer/security/sealed_memory.hpp>
#include <doxxer/types.hpp>

namespace doxxer::memory::shadow_regions {
struct Handle {
    u16 slot;
    u32 generation;
};

struct Statistics {
    u64 opened_regions;
    u64 closed_regions;
    u64 rejected_accesses;
    u64 resealed_regions;
    u32 active_regions;
    u32 capacity;
};

bool initialize();
bool open_sealed(security::sealed_memory::Handle sealed, Handle& region);
bool read(Handle region, usize offset, void* destination, usize size);
bool write(Handle region, usize offset, const void* source, usize size);
bool reseal(Handle region, security::sealed_memory::Handle& sealed);
bool close(Handle& region);
bool self_test();
Statistics statistics();
u32 failure_code();
}
