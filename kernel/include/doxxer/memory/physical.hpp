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

enum class PageOwner : u8 {
    free = 0,
    reserved,
    metadata,
    page_table,
    kernel_heap,
    kernel_stack,
    user_image,
    user_stack,
    user_data,
    iommu,
    test,
};

struct Statistics {
    u64 discovered_usable_pages;
    u64 managed_pages;
    u64 allocated_pages;
    u64 free_pages;
    u64 metadata_pages;
    u64 dma32_free_pages;
    u64 normal_free_pages;
    u64 shadow_bytes;
    u64 integrity_failures;
    u64 ownership_rejections;
};

bool initialize(const volatile limine_memmap_response* memory_map,
                const volatile limine_hhdm_response* hhdm, u64 integrity_key);
bool ready();
bool allocate_page(u64& physical_address, PageOwner owner, Zone zone = Zone::any);
bool allocate_contiguous(u64 page_count, u64 alignment_pages, u64& physical_address,
                         PageOwner owner, Zone zone = Zone::any);
bool free_page(u64 physical_address, PageOwner owner);
bool free_contiguous(u64 physical_address, u64 page_count, PageOwner owner);
void* direct_map_owned(u64 physical_address, PageOwner owner);
void* direct_map_user(u64 physical_address);
void* direct_map_page_table(u64 physical_address);
void* direct_map_firmware(u64 physical_address);
bool owner_of(u64 physical_address, PageOwner& owner);
bool user_mapping_allowed(u64 physical_address, u64 page_count, bool executable);
Statistics statistics();
bool self_test();
}
