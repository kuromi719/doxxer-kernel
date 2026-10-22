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

struct State {
    Bitmap used{};
    Bitmap managed{};
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

bool range_end(u64 base, u64 length, u64& end) {
    if (length > static_cast<u64>(-1) - base) {
        return false;
    }
    end = base + length;
    return true;
}

void set_managed(u64 page, bool value) { state.managed.set(page, value); }

void set_used(u64 page, bool value) { state.used.set(page, value); }

bool is_available(u64 page) { return state.managed.get(page) && !state.used.get(page); }

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

void reserve_page(u64 page) {
    if (page >= state.page_count) {
        return;
    }
    if (state.managed.get(page)) {
        --state.managed_pages;
    }
    if (is_available(page)) {
        account_available_page(page, false);
    }
    set_managed(page, false);
    set_used(page, true);
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

bool allocate_from_zone(Zone zone, u64 count, u64 alignment, u64& first_page) {
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
        set_used(first_page + index, true);
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
}

bool initialize(const volatile limine_memmap_response* memory_map,
                const volatile limine_hhdm_response* hhdm) {
    if (state.initialized || memory_map == nullptr || hhdm == nullptr ||
        memory_map->entries == nullptr || memory_map->entry_count == 0 ||
        memory_map->entry_count > kMaximumMemoryMapEntries) {
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
    if (one_bitmap_bytes > static_cast<u64>(-1) / 2) {
        return false;
    }
    const u64 metadata_bytes = one_bitmap_bytes * 2;
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
    state.page_count = pages;
    state.discovered_usable_pages = discovered_pages;
    state.metadata_pages = metadata_pages;
    auto* metadata_virtual =
        reinterpret_cast<u8*>(static_cast<uptr>(state.hhdm_offset + metadata_physical));
    state.used = Bitmap{metadata_virtual, pages};
    state.managed = Bitmap{metadata_virtual + one_bitmap_bytes, pages};
    memset(metadata_virtual, 0xFF, static_cast<usize>(one_bitmap_bytes));
    memset(metadata_virtual + one_bitmap_bytes, 0, static_cast<usize>(one_bitmap_bytes));

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
                set_managed(page, true);
                set_used(page, false);
                ++state.managed_pages;
                account_available_page(page, true);
            }
        }
    }

    reserve_page(0);
    const u64 metadata_first_page = metadata_physical / kPageSize;
    for (u64 index = 0; index < metadata_pages; ++index) {
        reserve_page(metadata_first_page + index);
    }

    state.initialized = true;
    return true;
}

bool ready() { return state.initialized; }

bool allocate_page(u64& physical_address, Zone zone) {
    return allocate_contiguous(1, 1, physical_address, zone);
}

bool allocate_contiguous(u64 page_count, u64 alignment_pages, u64& physical_address, Zone zone) {
    if (!state.initialized || page_count == 0 || !power_of_two(alignment_pages) ||
        page_count > static_cast<u64>(static_cast<usize>(-1)) / kPageSize) {
        return false;
    }

    sync::LockGuard guard(state.lock);
    u64 first_page = 0;
    bool allocated = false;
    if (zone == Zone::any) {
        allocated = allocate_from_zone(Zone::normal, page_count, alignment_pages, first_page) ||
                    allocate_from_zone(Zone::dma32, page_count, alignment_pages, first_page);
    } else {
        allocated = allocate_from_zone(zone, page_count, alignment_pages, first_page);
    }
    if (!allocated) {
        return false;
    }

    secure_zero_pages(first_page, page_count);
    physical_address = first_page * kPageSize;
    return true;
}

bool free_page(u64 physical_address) { return free_contiguous(physical_address, 1); }

bool free_contiguous(u64 physical_address, u64 page_count) {
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
        if (!state.managed.get(page) || !state.used.get(page)) {
            return false;
        }
    }

    secure_zero_pages(first_page, page_count);
    for (u64 index = 0; index < page_count; ++index) {
        const u64 page = first_page + index;
        set_used(page, false);
        account_available_page(page, true);
    }
    state.allocated_pages -= page_count;
    return true;
}

void* direct_map(u64 physical_address) {
    if (!state.initialized || physical_address / kPageSize >= state.page_count ||
        state.hhdm_offset > static_cast<u64>(-1) - physical_address) {
        return nullptr;
    }
    return reinterpret_cast<void*>(static_cast<uptr>(state.hhdm_offset + physical_address));
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
    bool single_allocated = false;
    bool run_allocated = false;
    bool dma32_allocated = false;
    bool normal_allocated = false;
    const auto cleanup = [&]() {
        if (single_allocated) {
            free_page(single);
        }
        if (run_allocated) {
            free_contiguous(run, 3);
        }
        if (dma32_allocated) {
            free_page(dma32);
        }
        if (normal_allocated) {
            free_page(normal);
        }
    };

    single_allocated = allocate_page(single);
    run_allocated = allocate_contiguous(3, 4, run);
    if (!single_allocated || !run_allocated || run % (4 * kPageSize) != 0 || single == run) {
        cleanup();
        return false;
    }

    if (before.dma32_free_pages != 0) {
        dma32_allocated = allocate_page(dma32, Zone::dma32);
        if (!dma32_allocated || dma32 >= kDma32Limit) {
            cleanup();
            return false;
        }
    }
    if (before.normal_free_pages != 0) {
        normal_allocated = allocate_page(normal, Zone::normal);
        if (!normal_allocated || normal < kDma32Limit) {
            cleanup();
            return false;
        }
    }

    u64 invalid_alignment_result = 0;
    if (allocate_contiguous(1, 3, invalid_alignment_result)) {
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
    if (!zero_sampled(static_cast<const u8*>(direct_map(single))) ||
        !zero_sampled(static_cast<const u8*>(direct_map(run)))) {
        cleanup();
        return false;
    }

    cleanup();
    single_allocated = false;
    run_allocated = false;
    dma32_allocated = false;
    normal_allocated = false;
    if (free_page(single)) {
        return false;
    }
    const Statistics after = statistics();
    return before.free_pages == after.free_pages && before.allocated_pages == after.allocated_pages;
}
}
