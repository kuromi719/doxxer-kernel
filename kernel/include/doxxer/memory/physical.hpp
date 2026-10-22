#pragma once

#include <doxxer/types.hpp>

struct limine_hhdm_response;
struct limine_memmap_response;

namespace doxxer::memory::physical {
inline constexpr u64 kPageSize = 4096;
inline constexpr u64 kDma32Limit = 0x1'0000'0000ULL;
using IsolationDomain = u32;
inline constexpr IsolationDomain kKernelDomain = 0;

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
    u64 domain_rejections;
    u64 mapping_rejections;
    u64 user_mapping_references;
    u64 supervisor_mapping_references;
    u64 page_table_references;
};

bool initialize(const volatile limine_memmap_response* memory_map,
                const volatile limine_hhdm_response* hhdm, u64 integrity_key);
bool ready();
bool allocate_page(u64& physical_address, PageOwner owner, Zone zone = Zone::any,
                   IsolationDomain domain = kKernelDomain);
bool allocate_contiguous(u64 page_count, u64 alignment_pages, u64& physical_address,
                         PageOwner owner, Zone zone = Zone::any,
                         IsolationDomain domain = kKernelDomain);
bool free_page(u64 physical_address, PageOwner owner,
               IsolationDomain domain = kKernelDomain);
bool free_contiguous(u64 physical_address, u64 page_count, PageOwner owner,
                     IsolationDomain domain = kKernelDomain);
void* direct_map_page_table(u64 physical_address);
void* direct_map_firmware(u64 physical_address);
bool owner_of(u64 physical_address, PageOwner& owner);
bool user_mapping_allowed(u64 physical_address, u64 page_count, bool executable,
                          IsolationDomain domain);
bool retain_user_mapping(u64 physical_address, u64 page_count, bool executable,
                         IsolationDomain domain);
bool release_user_mapping(u64 physical_address, u64 page_count, IsolationDomain domain);
bool retain_supervisor_mapping(u64 physical_address, u64 page_count);
bool release_supervisor_mapping(u64 physical_address, u64 page_count);
bool retain_page_table_reference(u64 physical_address);
bool release_page_table_reference(u64 physical_address);
Statistics statistics();
bool self_test();
u32 self_test_failure();
}
