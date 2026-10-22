#pragma once

#include <doxxer/types.hpp>

struct limine_hhdm_response;
struct limine_memmap_response;

namespace doxxer::memory::physical {
inline constexpr u64 kPageSize = 4096;
inline constexpr u64 kDma32Limit = 0x1'0000'0000ULL;

enum class Zone : u8 {
    any,
    dma32,
    normal,
};

struct Statistics {
    u64 discovered_usable_pages;
    u64 managed_pages;
    u64 allocated_pages;
    u64 free_pages;
    u64 metadata_pages;
    u64 dma32_free_pages;
    u64 normal_free_pages;
};

bool initialize(const volatile limine_memmap_response* memory_map,
                const volatile limine_hhdm_response* hhdm);
bool ready();
bool allocate_page(u64& physical_address, Zone zone = Zone::any);
bool allocate_contiguous(u64 page_count, u64 alignment_pages, u64& physical_address,
                         Zone zone = Zone::any);
bool free_page(u64 physical_address);
bool free_contiguous(u64 physical_address, u64 page_count);
void* direct_map(u64 physical_address);
Statistics statistics();
bool self_test();
}
