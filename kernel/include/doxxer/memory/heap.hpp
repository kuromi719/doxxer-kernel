#pragma once

#include <doxxer/types.hpp>

namespace doxxer::memory::heap {
struct Statistics {
    u64 allocated_objects;
    u64 requested_bytes;
    u64 committed_pages;
    u64 slab_pages;
    u64 large_pages;
    u64 quarantined_objects;
    u64 corruption_events;
};

bool initialize();
bool ready();
void* allocate(usize size, usize alignment = 16);
bool deallocate(void* pointer);
usize usable_size(const void* pointer);
Statistics statistics();
bool validate();
bool self_test();
u32 self_test_failure();
}
