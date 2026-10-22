#pragma once

#include <doxxer/memory/virtual.hpp>
#include <doxxer/types.hpp>

namespace doxxer::loader::elf64 {
constexpr usize kMaximumImagePages = 128;

struct Page {
    u64 virtual_address;
    u64 physical_address;
    memory::virtual_memory::MapFlags final_flags;
};

struct Image {
    bool loaded;
    u64 entry_point;
    usize page_count;
    Page pages[kMaximumImagePages];
};

struct Statistics {
    u64 loaded_images;
    u64 unloaded_images;
    u64 mapped_pages;
    u64 rejected_images;
};

bool load(memory::virtual_memory::AddressSpace& space, const void* data, usize size,
          Image& image);
bool unload(memory::virtual_memory::AddressSpace& space, Image& image);
bool self_test();
Statistics statistics();
u32 failure_code();
}
