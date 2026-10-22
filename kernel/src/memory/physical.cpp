#include <doxxer/memory/physical.hpp>

#include <doxxer/sync/spinlock.hpp>
#include <limine.h>

extern "C" void* memset(void* destination, int value, doxxer::usize count);

namespace doxxer::memory::physical {
namespace {
struct Bitmap {
    u8* bytes = nullptr;
    u64 bit_count = 0;

    bool get(u64 index) const {
        return index < bit_count && (bytes[index / 8] & static_cast<u8>(1U << (index % 8))) != 0;
    }

    void set(u64 index, bool value) {
        if (index >= bit_count) {
            return;
        }
        const u8 mask = static_cast<u8>(1U << (index % 8));
        if (value) {
            bytes[index / 8] |= mask;
        } else {
            bytes[index / 8] &= static_cast<u8>(~mask);
        }
    }
};

struct ShadowEntry {
    u64 seal;
    u32 generation;
    IsolationDomain domain;
    PageOwner owner;
    u8 managed;
    u8 used;
    u8 reserved;
};

static_assert(sizeof(ShadowEntry) == 24);

struct State {
    Bitmap used{};
    Bitmap managed{};
    ShadowEntry* shadow = nullptr;
    u64 shadow_key = 0;
    u64 shadow_bytes = 0;
    u64 integrity_failures = 0;
    u64 ownership_rejections = 0;
    u64 domain_rejections = 0;
    u64 hhdm_offset = 0;
    u64 page_count = 0;
    u64 discovered_usable_pages = 0;
    u64 managed_pages = 0;
    u64 allocated_pages = 0;
    u64 free_pages = 0;
    u64 metadata_pages = 0;
    u64 dma32_free_pages = 0;
    u64 normal_free_pages = 0;
    u64 dma32_hint = 1;
    u64 normal_hint = kDma32Limit / kPageSize;
    bool initialized = false;
    sync::SpinLock lock{};
};

State state{};
constexpr u64 kMaximumMemoryMapEntries = 4096;

constexpr u64 align_down(u64 value, u64 alignment) { return value & ~(alignment - 1); }

constexpr u64 align_up(u64 value, u64 alignment) {
    if (value > static_cast<u64>(-1) - (alignment - 1)) {
        return static_cast<u64>(-1);
    }
    return align_down(value + alignment - 1, alignment);
}

constexpr bool power_of_two(u64 value) { return value != 0 && (value & (value - 1)) == 0; }

u64 bitmap_bytes(u64 pages) { return (pages + 7) / 8; }

u64 mix64(u64 value) {
    value ^= value >> 30U;
    value *= 0xBF58'476D'1CE4'E5B9ULL;
    value ^= value >> 27U;
    value *= 0x94D0'49BB'1331'11EBULL;
    return value ^ (value >> 31U);
}

u64 shadow_seal(u64 page, const ShadowEntry& entry) {
    const u64 state_bits = static_cast<u64>(entry.generation) |
                           (static_cast<u64>(entry.owner) << 32U) |
                           (static_cast<u64>(entry.managed) << 40U) |
                           (static_cast<u64>(entry.used) << 48U);
    return mix64(state.shadow_key ^ (page * 0x9E37'79B9'7F4A'7C15ULL) ^ state_bits ^
                 (static_cast<u64>(entry.domain) * 0xD6E8'FEB8'6659'FD93ULL));
}

bool shadow_valid(u64 page) {
    if (state.shadow == nullptr || page >= state.page_count) {
        return false;
    }
    const ShadowEntry& entry = state.shadow[page];
    return entry.reserved == 0 && entry.generation != 0 &&
           entry.seal == shadow_seal(page, entry) &&
           (entry.managed != 0) == state.managed.get(page) &&
           (entry.used != 0) == state.used.get(page);
}

void set_page_state(u64 page, bool managed, bool used, PageOwner owner,
                    IsolationDomain domain = kKernelDomain) {
    if (page >= state.page_count || state.shadow == nullptr) {
        return;
    }
    state.managed.set(page, managed);
    state.used.set(page, used);
    ShadowEntry& entry = state.shadow[page];
    ++entry.generation;
    if (entry.generation == 0) {
        ++entry.generation;
    }
    entry.owner = owner;
    entry.domain = domain;
    entry.managed = managed ? 1 : 0;
    entry.used = used ? 1 : 0;
    entry.reserved = 0;
    entry.seal = shadow_seal(page, entry);
}

bool range_end(u64 base, u64 length, u64& end) {
    if (length > static_cast<u64>(-1) - base) {
        return false;
    }
    end = base + length;
    return true;
}

constexpr bool user_owner(PageOwner owner) {
    return owner == PageOwner::user_image || owner == PageOwner::user_stack ||
           owner == PageOwner::user_data;
}

constexpr bool allocatable_owner(PageOwner owner) {
    return owner == PageOwner::page_table || owner == PageOwner::kernel_heap ||
           owner == PageOwner::kernel_stack || owner == PageOwner::user_image ||
           owner == PageOwner::user_stack || owner == PageOwner::user_data ||
           owner == PageOwner::iommu || owner == PageOwner::test;
}

constexpr bool domain_valid(PageOwner owner, IsolationDomain domain) {
    return user_owner(owner) ? domain != kKernelDomain : domain == kKernelDomain;
}

bool is_available(u64 page) {
    if (!state.managed.get(page)) {
        return false;
    }
    if (!shadow_valid(page)) {
        ++state.integrity_failures;
        return false;
    }
    const ShadowEntry& entry = state.shadow[page];
    return !state.used.get(page) && entry.owner == PageOwner::free;
}

void account_available_page(u64 page, bool add) {
    const u64 physical = page * kPageSize;
    if (add) {
        ++state.free_pages;
    } else {
        --state.free_pages;
    }
    if (physical < kDma32Limit) {
        if (add) {
            ++state.dma32_free_pages;
        } else {
            --state.dma32_free_pages;
        }
    } else {
        if (add) {
            ++state.normal_free_pages;
        } else {
            --state.normal_free_pages;
        }
    }
}

void reserve_page(u64 page, PageOwner owner) {
    if (page >= state.page_count) {
        return;
    }
    if (state.managed.get(page)) {
        --state.managed_pages;
    }
    if (is_available(page)) {
        account_available_page(page, false);
    }
    set_page_state(page, false, true, owner);
}

void zone_bounds(Zone zone, u64& begin, u64& end) {
    const u64 dma_end =
        kDma32Limit / kPageSize < state.page_count ? kDma32Limit / kPageSize : state.page_count;
    if (zone == Zone::dma32) {
        begin = 1;
        end = dma_end;
    } else if (zone == Zone::normal) {
        begin = dma_end;
        end = state.page_count;
    } else {
        begin = 1;
        end = state.page_count;
    }
}

bool scan_range(u64 begin, u64 end, u64 count, u64 alignment, u64& found) {
    if (begin >= end || count > end - begin) {
        return false;
    }
    u64 candidate = align_up(begin, alignment);
    while (candidate < end && count <= end - candidate) {
        u64 offset = 0;
        for (; offset < count; ++offset) {
            if (!is_available(candidate + offset)) {
                break;
            }
        }
        if (offset == count) {
            found = candidate;
            return true;
        }
        candidate = align_up(candidate + offset + 1, alignment);
    }
    return false;
}

bool allocate_from_zone(Zone zone, u64 count, u64 alignment, PageOwner owner,
                        IsolationDomain domain, u64& first_page) {
    u64 begin = 0;
    u64 end = 0;
    zone_bounds(zone, begin, end);
    if (begin >= end) {
        return false;
    }

    u64& hint = zone == Zone::normal ? state.normal_hint : state.dma32_hint;
    if (hint < begin || hint >= end) {
        hint = begin;
    }

    if (!scan_range(hint, end, count, alignment, first_page) &&
        !scan_range(begin, hint, count, alignment, first_page)) {
        return false;
    }

    for (u64 index = 0; index < count; ++index) {
        set_page_state(first_page + index, true, true, owner, domain);
        account_available_page(first_page + index, false);
    }
    state.allocated_pages += count;
    hint = first_page + count < end ? first_page + count : begin;
    return true;
}

void secure_zero_pages(u64 first_page, u64 count) {
    auto* bytes =
        reinterpret_cast<void*>(static_cast<uptr>(state.hhdm_offset + first_page * kPageSize));
    memset(bytes, 0, static_cast<usize>(count * kPageSize));
}

bool verify_shadow_ledger() {
    sync::LockGuard guard(state.lock);
    for (u64 page = 0; page < state.page_count; ++page) {
        if (state.shadow[page].generation != 0 && !shadow_valid(page)) {
            ++state.integrity_failures;
            return false;
        }
    }
    return true;
}
}

bool initialize(const volatile limine_memmap_response* memory_map,
                const volatile limine_hhdm_response* hhdm, u64 integrity_key) {
    if (state.initialized || memory_map == nullptr || hhdm == nullptr ||
        memory_map->entries == nullptr || memory_map->entry_count == 0 ||
        memory_map->entry_count > kMaximumMemoryMapEntries || integrity_key == 0) {
        return false;
    }

    u64 highest_address = 0;
    u64 discovered_pages = 0;
    for (u64 index = 0; index < memory_map->entry_count; ++index) {
        const volatile limine_memmap_entry* entry = memory_map->entries[index];
        if (entry == nullptr) {
            return false;
        }
        u64 end = 0;
        if (!range_end(entry->base, entry->length, end)) {
            return false;
        }
        if (entry->type == LIMINE_MEMMAP_USABLE) {
            if (end > highest_address) {
                highest_address = end;
            }
            const u64 start = align_up(entry->base, kPageSize);
            const u64 usable_end = align_down(end, kPageSize);
            if (start < usable_end) {
                const u64 range_pages = (usable_end - start) / kPageSize;
                if (range_pages > static_cast<u64>(-1) - discovered_pages) {
                    return false;
                }
                discovered_pages += range_pages;
            }
        }
    }

    const u64 pages = align_up(highest_address, kPageSize) / kPageSize;
    if (pages == 0 || pages > static_cast<u64>(static_cast<usize>(-1)) * 8) {
        return false;
    }
    if (pages > static_cast<u64>(-1) / kPageSize ||
        hhdm->offset > static_cast<u64>(-1) - pages * kPageSize) {
        return false;
    }
    const u64 one_bitmap_bytes = bitmap_bytes(pages);
    if (one_bitmap_bytes > static_cast<u64>(-1) / 2 ||
        pages > static_cast<u64>(-1) / sizeof(ShadowEntry)) {
        return false;
    }
    const u64 shadow_offset = align_up(one_bitmap_bytes * 2, alignof(ShadowEntry));
    const u64 shadow_bytes = pages * sizeof(ShadowEntry);
    if (shadow_offset > static_cast<u64>(-1) - shadow_bytes) {
        return false;
    }
    const u64 metadata_bytes = shadow_offset + shadow_bytes;
    const u64 metadata_pages = align_up(metadata_bytes, kPageSize) / kPageSize;

    u64 metadata_physical = 0;
    bool metadata_found = false;
    for (u64 index = 0; index < memory_map->entry_count; ++index) {
        const volatile limine_memmap_entry* entry = memory_map->entries[index];
        if (entry->type != LIMINE_MEMMAP_USABLE) {
            continue;
        }
        u64 end = 0;
        if (!range_end(entry->base, entry->length, end)) {
            return false;
        }
        const u64 start = align_up(entry->base, kPageSize);
        const u64 usable_end = align_down(end, kPageSize);
        if (start < usable_end && metadata_pages <= (usable_end - start) / kPageSize) {
            metadata_physical = start;
            metadata_found = true;
            break;
        }
    }
    if (!metadata_found || hhdm->offset > static_cast<u64>(-1) - metadata_physical) {
        return false;
    }

    state.hhdm_offset = hhdm->offset;
    state.shadow_key = mix64(integrity_key ^ hhdm->offset ^ pages);
    if (state.shadow_key == 0) {
        return false;
    }
    state.page_count = pages;
    state.discovered_usable_pages = discovered_pages;
    state.metadata_pages = metadata_pages;
    auto* metadata_virtual =
        reinterpret_cast<u8*>(static_cast<uptr>(state.hhdm_offset + metadata_physical));
    state.used = Bitmap{metadata_virtual, pages};
    state.managed = Bitmap{metadata_virtual + one_bitmap_bytes, pages};
    state.shadow = reinterpret_cast<ShadowEntry*>(metadata_virtual + shadow_offset);
    state.shadow_bytes = shadow_bytes;
    memset(metadata_virtual, 0, static_cast<usize>(metadata_bytes));
    memset(metadata_virtual, 0xFF, static_cast<usize>(one_bitmap_bytes));

    for (u64 index = 0; index < memory_map->entry_count; ++index) {
        const volatile limine_memmap_entry* entry = memory_map->entries[index];
        if (entry->type != LIMINE_MEMMAP_USABLE) {
            continue;
        }
        u64 end = 0;
        if (!range_end(entry->base, entry->length, end)) {
            return false;
        }
        const u64 start_page = align_up(entry->base, kPageSize) / kPageSize;
        const u64 end_page = align_down(end, kPageSize) / kPageSize;
        for (u64 page = start_page; page < end_page; ++page) {
            if (!state.managed.get(page)) {
                set_page_state(page, true, false, PageOwner::free);
                ++state.managed_pages;
                account_available_page(page, true);
            }
        }
    }

    reserve_page(0, PageOwner::reserved);
    const u64 metadata_first_page = metadata_physical / kPageSize;
    for (u64 index = 0; index < metadata_pages; ++index) {
        reserve_page(metadata_first_page + index, PageOwner::metadata);
    }

    state.initialized = true;
    return true;
}

bool ready() { return state.initialized; }

bool allocate_page(u64& physical_address, PageOwner owner, Zone zone, IsolationDomain domain) {
    return allocate_contiguous(1, 1, physical_address, owner, zone, domain);
}

bool allocate_contiguous(u64 page_count, u64 alignment_pages, u64& physical_address,
                         PageOwner owner, Zone zone, IsolationDomain domain) {
    if (!state.initialized || page_count == 0 || !power_of_two(alignment_pages) ||
        page_count > static_cast<u64>(static_cast<usize>(-1)) / kPageSize ||
        !allocatable_owner(owner) || !domain_valid(owner, domain)) {
        if (!domain_valid(owner, domain)) {
            __atomic_add_fetch(&state.domain_rejections, 1ULL, __ATOMIC_RELAXED);
        }
        return false;
    }

    sync::LockGuard guard(state.lock);
    u64 first_page = 0;
    bool allocated = false;
    if (zone == Zone::any) {
        allocated = allocate_from_zone(Zone::normal, page_count, alignment_pages, owner, domain,
                                       first_page) ||
                    allocate_from_zone(Zone::dma32, page_count, alignment_pages, owner, domain,
                                       first_page);
    } else {
        allocated = allocate_from_zone(zone, page_count, alignment_pages, owner, domain,
                                       first_page);
    }
    if (!allocated) {
        return false;
    }

    secure_zero_pages(first_page, page_count);
    physical_address = first_page * kPageSize;
    return true;
}

bool free_page(u64 physical_address, PageOwner owner, IsolationDomain domain) {
    return free_contiguous(physical_address, 1, owner, domain);
}

bool free_contiguous(u64 physical_address, u64 page_count, PageOwner owner,
                     IsolationDomain domain) {
    if (!state.initialized || page_count == 0 || physical_address % kPageSize != 0) {
        return false;
    }
    const u64 first_page = physical_address / kPageSize;
    if (first_page >= state.page_count || page_count > state.page_count - first_page) {
        return false;
    }

    sync::LockGuard guard(state.lock);
    for (u64 index = 0; index < page_count; ++index) {
        const u64 page = first_page + index;
        if (!state.managed.get(page)) {
            ++state.ownership_rejections;
            return false;
        }
        if (!shadow_valid(page)) {
            ++state.integrity_failures;
            return false;
        }
        if (!state.used.get(page)) {
            ++state.ownership_rejections;
            return false;
        }
        if (state.shadow[page].owner != owner) {
            ++state.ownership_rejections;
            return false;
        }
        if (state.shadow[page].domain != domain) {
            __atomic_add_fetch(&state.domain_rejections, 1ULL, __ATOMIC_RELAXED);
            return false;
        }
    }

    secure_zero_pages(first_page, page_count);
    for (u64 index = 0; index < page_count; ++index) {
        const u64 page = first_page + index;
        set_page_state(page, true, false, PageOwner::free);
        account_available_page(page, true);
    }
    state.allocated_pages -= page_count;
    return true;
}

void* direct_map_owned(u64 physical_address, PageOwner owner, IsolationDomain domain) {
    if (!state.initialized || state.hhdm_offset > static_cast<u64>(-1) - physical_address) {
        return nullptr;
    }
    const u64 page = physical_address / kPageSize;
    sync::LockGuard guard(state.lock);
    if (page >= state.page_count || !state.managed.get(page) || !state.used.get(page) ||
        !shadow_valid(page)) {
        ++state.integrity_failures;
        return nullptr;
    }
    if (state.shadow[page].owner != owner) {
        ++state.ownership_rejections;
        return nullptr;
    }
    if (state.shadow[page].domain != domain) {
        __atomic_add_fetch(&state.domain_rejections, 1ULL, __ATOMIC_RELAXED);
        return nullptr;
    }
    return reinterpret_cast<void*>(static_cast<uptr>(state.hhdm_offset + physical_address));
}

void* direct_map_user(u64 physical_address, IsolationDomain domain) {
    if (!state.initialized || domain == kKernelDomain ||
        state.hhdm_offset > static_cast<u64>(-1) - physical_address) {
        if (domain == kKernelDomain) {
            __atomic_add_fetch(&state.domain_rejections, 1ULL, __ATOMIC_RELAXED);
        }
        return nullptr;
    }
    const u64 page = physical_address / kPageSize;
    sync::LockGuard guard(state.lock);
    if (page >= state.page_count || !state.managed.get(page) || !state.used.get(page) ||
        !shadow_valid(page)) {
        ++state.integrity_failures;
        return nullptr;
    }
    const PageOwner owner = state.shadow[page].owner;
    if (owner != PageOwner::user_image && owner != PageOwner::user_stack &&
        owner != PageOwner::user_data) {
        ++state.ownership_rejections;
        return nullptr;
    }
    if (state.shadow[page].domain != domain) {
        __atomic_add_fetch(&state.domain_rejections, 1ULL, __ATOMIC_RELAXED);
        return nullptr;
    }
    return reinterpret_cast<void*>(static_cast<uptr>(state.hhdm_offset + physical_address));
}

void* direct_map_page_table(u64 physical_address) {
    if (!state.initialized || state.hhdm_offset > static_cast<u64>(-1) - physical_address) {
        return nullptr;
    }
    const u64 page = physical_address / kPageSize;
    sync::LockGuard guard(state.lock);
    if (page >= state.page_count || !state.managed.get(page)) {
        return reinterpret_cast<void*>(static_cast<uptr>(state.hhdm_offset + physical_address));
    }
    if (!state.used.get(page) || !shadow_valid(page)) {
        ++state.integrity_failures;
        return nullptr;
    }
    if (state.shadow[page].owner != PageOwner::page_table) {
        ++state.ownership_rejections;
        return nullptr;
    }
    return reinterpret_cast<void*>(static_cast<uptr>(state.hhdm_offset + physical_address));
}

void* direct_map_firmware(u64 physical_address) {
    if (!state.initialized || state.hhdm_offset > static_cast<u64>(-1) - physical_address) {
        return nullptr;
    }
    const u64 page = physical_address / kPageSize;
    sync::LockGuard guard(state.lock);
    if (page < state.page_count && state.managed.get(page)) {
        return nullptr;
    }
    return reinterpret_cast<void*>(static_cast<uptr>(state.hhdm_offset + physical_address));
}

bool owner_of(u64 physical_address, PageOwner& owner) {
    if (!state.initialized) {
        return false;
    }
    const u64 page = physical_address / kPageSize;
    sync::LockGuard guard(state.lock);
    if (page >= state.page_count || !state.managed.get(page) || !state.used.get(page) ||
        !shadow_valid(page)) {
        ++state.integrity_failures;
        return false;
    }
    owner = state.shadow[page].owner;
    return true;
}

bool user_mapping_allowed(u64 physical_address, u64 page_count, bool executable,
                          IsolationDomain domain) {
    if (!state.initialized || domain == kKernelDomain || page_count == 0 ||
        physical_address % kPageSize != 0) {
        if (domain == kKernelDomain) {
            __atomic_add_fetch(&state.domain_rejections, 1ULL, __ATOMIC_RELAXED);
        }
        return false;
    }
    const u64 first_page = physical_address / kPageSize;
    if (first_page >= state.page_count || page_count > state.page_count - first_page) {
        return false;
    }
    sync::LockGuard guard(state.lock);
    for (u64 index = 0; index < page_count; ++index) {
        const u64 page = first_page + index;
        if (!state.managed.get(page) || !state.used.get(page) || !shadow_valid(page)) {
            ++state.integrity_failures;
            return false;
        }
        const PageOwner owner = state.shadow[page].owner;
        const bool user_owner = owner == PageOwner::user_image || owner == PageOwner::user_stack ||
                                owner == PageOwner::user_data;
        if (!user_owner || (executable && owner != PageOwner::user_image)) {
            ++state.ownership_rejections;
            return false;
        }
        if (state.shadow[page].domain != domain) {
            __atomic_add_fetch(&state.domain_rejections, 1ULL, __ATOMIC_RELAXED);
            return false;
        }
    }
    return true;
}

Statistics statistics() {
    if (!state.initialized) {
        return {};
    }
    sync::LockGuard guard(state.lock);
    return {
        .discovered_usable_pages = state.discovered_usable_pages,
        .managed_pages = state.managed_pages,
        .allocated_pages = state.allocated_pages,
        .free_pages = state.free_pages,
        .metadata_pages = state.metadata_pages,
        .dma32_free_pages = state.dma32_free_pages,
        .normal_free_pages = state.normal_free_pages,
        .shadow_bytes = state.shadow_bytes,
        .integrity_failures = state.integrity_failures,
        .ownership_rejections = state.ownership_rejections,
        .domain_rejections =
            __atomic_load_n(&state.domain_rejections, __ATOMIC_RELAXED),
    };
}

bool self_test() {
    if (!state.initialized) {
        return false;
    }
    const Statistics before = statistics();
    u64 single = 0;
    u64 run = 0;
    u64 dma32 = 0;
    u64 normal = 0;
    u64 domain_page = 0;
    bool single_allocated = false;
    bool run_allocated = false;
    bool dma32_allocated = false;
    bool normal_allocated = false;
    bool domain_page_allocated = false;
    const auto cleanup = [&]() {
        if (single_allocated) {
            free_page(single, PageOwner::test);
        }
        if (run_allocated) {
            free_contiguous(run, 3, PageOwner::test);
        }
        if (dma32_allocated) {
            free_page(dma32, PageOwner::test);
        }
        if (normal_allocated) {
            free_page(normal, PageOwner::test);
        }
        if (domain_page_allocated) {
            free_page(domain_page, PageOwner::user_data, 7);
        }
    };

    single_allocated = allocate_page(single, PageOwner::test);
    run_allocated = allocate_contiguous(3, 4, run, PageOwner::test);
    if (!single_allocated || !run_allocated || run % (4 * kPageSize) != 0 || single == run) {
        cleanup();
        return false;
    }

    if (before.dma32_free_pages != 0) {
        dma32_allocated = allocate_page(dma32, PageOwner::test, Zone::dma32);
        if (!dma32_allocated || dma32 >= kDma32Limit) {
            cleanup();
            return false;
        }
    }
    if (before.normal_free_pages != 0) {
        normal_allocated = allocate_page(normal, PageOwner::test, Zone::normal);
        if (!normal_allocated || normal < kDma32Limit) {
            cleanup();
            return false;
        }
    }

    u64 invalid_alignment_result = 0;
    if (allocate_contiguous(1, 3, invalid_alignment_result, PageOwner::test)) {
        cleanup();
        return false;
    }

    const auto zero_sampled = [](const u8* bytes) {
        if (bytes == nullptr) {
            return false;
        }
        for (u64 index = 0; index < kPageSize; index += 257) {
            if (bytes[index] != 0) {
                return false;
            }
        }
        return true;
    };
    if (!zero_sampled(static_cast<const u8*>(direct_map_owned(single, PageOwner::test))) ||
        !zero_sampled(static_cast<const u8*>(direct_map_owned(run, PageOwner::test))) ||
        direct_map_owned(single, PageOwner::kernel_heap) != nullptr ||
        free_page(single, PageOwner::kernel_heap)) {
        cleanup();
        return false;
    }

    u64 invalid_domain_page = 0;
    domain_page_allocated =
        allocate_page(domain_page, PageOwner::user_data, Zone::any, 7);
    if (!domain_page_allocated ||
        allocate_page(invalid_domain_page, PageOwner::user_data) ||
        direct_map_user(domain_page, 8) != nullptr ||
        free_page(domain_page, PageOwner::user_data, 8) ||
        !zero_sampled(static_cast<const u8*>(direct_map_user(domain_page, 7)))) {
        cleanup();
        return false;
    }

    cleanup();
    single_allocated = false;
    run_allocated = false;
    dma32_allocated = false;
    normal_allocated = false;
    domain_page_allocated = false;
    if (free_page(single, PageOwner::test)) {
        return false;
    }
    const Statistics after = statistics();
    return verify_shadow_ledger() && before.free_pages == after.free_pages &&
           before.allocated_pages == after.allocated_pages &&
           after.integrity_failures == before.integrity_failures &&
           after.ownership_rejections == before.ownership_rejections + 3 &&
           after.domain_rejections == before.domain_rejections + 3;
}
}
