#include <doxxer/memory/virtual.hpp>

#include <doxxer/memory/physical.hpp>

namespace doxxer::memory::virtual_memory {
namespace {
using physical::kPageSize;

constexpr u64 kEntriesPerTable = 512;
constexpr u64 kPresent = 1ULL << 0U;
constexpr u64 kWritable = 1ULL << 1U;
constexpr u64 kUser = 1ULL << 2U;
constexpr u64 kCacheDisable = 1ULL << 4U;
constexpr u64 kHuge = 1ULL << 7U;
constexpr u64 kGlobal = 1ULL << 8U;
constexpr u64 kNoExecute = 1ULL << 63U;
constexpr u64 kAddressMask = 0x000F'FFFF'FFFF'F000ULL;
constexpr u64 kPcidMaximum = 4095;
u32 last_self_test_failure = 0;

struct alignas(4096) PageTable {
    u64 entries[kEntriesPerTable];
};

static_assert(sizeof(PageTable) == kPageSize);

constexpr u64 pml4_index(u64 address) { return (address >> 39U) & 0x1FFU; }
constexpr u64 pdpt_index(u64 address) { return (address >> 30U) & 0x1FFU; }
constexpr u64 pd_index(u64 address) { return (address >> 21U) & 0x1FFU; }
constexpr u64 pt_index(u64 address) { return (address >> 12U) & 0x1FFU; }

PageTable* table_from_physical(u64 physical_address) {
    return static_cast<PageTable*>(physical::direct_map(physical_address & kAddressMask));
}

bool table_empty(const PageTable* table) {
    if (table == nullptr) {
        return false;
    }
    for (u64 index = 0; index < kEntriesPerTable; ++index) {
        if ((table->entries[index] & kPresent) != 0) {
            return false;
        }
    }
    return true;
}

bool allocate_table(u64& physical_address, PageTable*& table) {
    if (!physical::allocate_page(physical_address)) {
        return false;
    }
    table = table_from_physical(physical_address);
    if (table == nullptr) {
        physical::free_page(physical_address);
        physical_address = 0;
        return false;
    }
    return true;
}

bool next_table(u64& entry, bool user, bool create_missing, PageTable*& table) {
    if ((entry & kPresent) != 0) {
        if ((entry & kHuge) != 0) {
            return false;
        }
        if (user) {
            entry |= kUser;
        }
        table = table_from_physical(entry);
        return table != nullptr;
    }
    if (!create_missing) {
        return false;
    }

    u64 physical_address = 0;
    if (!allocate_table(physical_address, table)) {
        return false;
    }
    entry = physical_address | kPresent | kWritable | (user ? kUser : 0);
    return true;
}

u64 leaf_flags(MapFlags flags, bool huge) {
    u64 result = kPresent;
    if (has_flag(flags, MapFlags::write)) {
        result |= kWritable;
    }
    if (has_flag(flags, MapFlags::user)) {
        result |= kUser;
    }
    if (has_flag(flags, MapFlags::global)) {
        result |= kGlobal;
    }
    if (has_flag(flags, MapFlags::cache_disable)) {
        result |= kCacheDisable;
    }
    if (!has_flag(flags, MapFlags::execute)) {
        result |= kNoExecute;
    }
    if (huge) {
        result |= kHuge;
    }
    return result;
}

MapFlags decode_flags(u64 entry) {
    MapFlags flags = MapFlags::none;
    if ((entry & kWritable) != 0) {
        flags = flags | MapFlags::write;
    }
    if ((entry & kNoExecute) == 0) {
        flags = flags | MapFlags::execute;
    }
    if ((entry & kUser) != 0) {
        flags = flags | MapFlags::user;
    }
    if ((entry & kGlobal) != 0) {
        flags = flags | MapFlags::global;
    }
    if ((entry & kCacheDisable) != 0) {
        flags = flags | MapFlags::cache_disable;
    }
    return flags;
}

bool flags_valid(MapFlags flags) {
    constexpr u8 known_flags = static_cast<u8>(MapFlags::write) |
                               static_cast<u8>(MapFlags::execute) |
                               static_cast<u8>(MapFlags::user) | static_cast<u8>(MapFlags::global) |
                               static_cast<u8>(MapFlags::cache_disable);
    return (static_cast<u8>(flags) & static_cast<u8>(~known_flags)) == 0 &&
           !(has_flag(flags, MapFlags::write) && has_flag(flags, MapFlags::execute));
}

u64 read_cr3() {
    u64 value = 0;
    asm volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}

u64 read_cr3_root() { return read_cr3() & kAddressMask; }

void write_cr3(u64 value) { asm volatile("mov %0, %%cr3" : : "r"(value) : "memory"); }

void invalidate_if_active(const AddressSpace& space, u64 virtual_address) {
    if (read_cr3_root() == space.root_physical()) {
        asm volatile("invlpg (%0)" : : "r"(virtual_address) : "memory");
    }
}

void prune_empty_path(AddressSpace& space, u64 virtual_address) {
    PageTable* pml4 = table_from_physical(space.root_physical());
    if (pml4 == nullptr) {
        return;
    }
    u64& pml4e = pml4->entries[pml4_index(virtual_address)];
    if ((pml4e & kPresent) == 0 || (pml4e & kHuge) != 0) {
        return;
    }
    PageTable* pdpt = table_from_physical(pml4e);
    if (pdpt == nullptr) {
        return;
    }
    u64& pdpte = pdpt->entries[pdpt_index(virtual_address)];
    if ((pdpte & kPresent) != 0 && (pdpte & kHuge) == 0) {
        PageTable* pd = table_from_physical(pdpte);
        if (pd != nullptr) {
            u64& pde = pd->entries[pd_index(virtual_address)];
            if ((pde & kPresent) != 0 && (pde & kHuge) == 0) {
                PageTable* pt = table_from_physical(pde);
                if (table_empty(pt)) {
                    const u64 physical_address = pde & kAddressMask;
                    pde = 0;
                    physical::free_page(physical_address);
                }
            }
            if (table_empty(pd)) {
                const u64 physical_address = pdpte & kAddressMask;
                pdpte = 0;
                physical::free_page(physical_address);
            }
        }
    }
    if (table_empty(pdpt)) {
        const u64 physical_address = pml4e & kAddressMask;
        pml4e = 0;
        physical::free_page(physical_address);
    }
}

bool destroy_table(PageTable* table, u8 level) {
    if (table == nullptr || level == 0) {
        return false;
    }
    bool success = true;
    if (level > 1) {
        for (u64 index = 0; index < kEntriesPerTable; ++index) {
            const u64 entry = table->entries[index];
            if ((entry & kPresent) == 0 || (entry & kHuge) != 0) {
                continue;
            }
            PageTable* child = table_from_physical(entry);
            if (!destroy_table(child, static_cast<u8>(level - 1))) {
                success = false;
            }
            const u64 child_physical = entry & kAddressMask;
            table->entries[index] = 0;
            if (!physical::free_page(child_physical)) {
                success = false;
            }
        }
    }
    return success;
}

bool destroy_user_half(PageTable* root) {
    if (root == nullptr) {
        return false;
    }
    bool success = true;
    for (u64 index = 0; index < kEntriesPerTable / 2; ++index) {
        const u64 entry = root->entries[index];
        if ((entry & kPresent) == 0 || (entry & kHuge) != 0) {
            continue;
        }
        PageTable* child = table_from_physical(entry);
        if (!destroy_table(child, 3)) {
            success = false;
        }
        root->entries[index] = 0;
        if (!physical::free_page(entry & kAddressMask)) {
            success = false;
        }
    }
    return success;
}

bool mutable_address(u64 virtual_address) {
    return is_canonical(virtual_address) && pml4_index(virtual_address) < kEntriesPerTable / 2;
}

bool query_unlocked(AddressSpace& space, u64 virtual_address, Mapping& mapping) {
    if (!space.valid() || !is_canonical(virtual_address)) {
        return false;
    }
    PageTable* pml4 = table_from_physical(space.root_physical());
    if (pml4 == nullptr) {
        return false;
    }
    PageTable* pdpt = nullptr;
    u64& pml4e = pml4->entries[pml4_index(virtual_address)];
    if (!next_table(pml4e, false, false, pdpt)) {
        return false;
    }
    PageTable* pd = nullptr;
    u64& pdpte = pdpt->entries[pdpt_index(virtual_address)];
    if (!next_table(pdpte, false, false, pd)) {
        return false;
    }
    const u64 pde = pd->entries[pd_index(virtual_address)];
    if ((pde & kPresent) == 0) {
        return false;
    }
    if ((pde & kHuge) != 0) {
        mapping = {
            .physical_address = (pde & kAddressMask) + (virtual_address & 0x1F'FFFFULL),
            .page_size = PageSize::size_2m,
            .flags = decode_flags(pde),
        };
        return true;
    }

    PageTable* pt = table_from_physical(pde);
    if (pt == nullptr) {
        return false;
    }
    const u64 pte = pt->entries[pt_index(virtual_address)];
    if ((pte & kPresent) == 0) {
        return false;
    }
    mapping = {
        .physical_address = (pte & kAddressMask) + (virtual_address & 0xFFFULL),
        .page_size = PageSize::size_4k,
        .flags = decode_flags(pte),
    };
    return true;
}
}

bool is_canonical(u64 virtual_address) {
    const u64 upper = virtual_address >> 48U;
    const bool sign = ((virtual_address >> 47U) & 1U) != 0;
    return sign ? upper == 0xFFFFU : upper == 0;
}

bool create(AddressSpace& space, u16 pcid) {
    if (space.valid() || pcid > kPcidMaximum) {
        return false;
    }
    u64 root_physical = 0;
    PageTable* root = nullptr;
    if (!allocate_table(root_physical, root)) {
        return false;
    }
    PageTable* active_root = table_from_physical(read_cr3_root());
    if (active_root == nullptr) {
        physical::free_page(root_physical);
        return false;
    }
    for (u64 index = kEntriesPerTable / 2; index < kEntriesPerTable; ++index) {
        root->entries[index] = active_root->entries[index];
    }
    space.root_physical_ = root_physical;
    space.pcid_ = pcid;
    return true;
}

bool destroy(AddressSpace& space) {
    if (!space.valid() || read_cr3_root() == space.root_physical()) {
        return false;
    }
    sync::LockGuard guard(space.lock_);
    PageTable* root = table_from_physical(space.root_physical());
    if (root == nullptr) {
        return false;
    }
    const u64 root_physical = space.root_physical();
    bool success = destroy_user_half(root);
    if (!physical::free_page(root_physical)) {
        success = false;
    }
    space.root_physical_ = 0;
    space.pcid_ = 0;
    return success;
}

bool activate(AddressSpace& space) {
    if (!space.valid() || space.pcid() != 0) {
        return false;
    }
    write_cr3(space.root_physical());
    return read_cr3_root() == space.root_physical();
}

bool map(AddressSpace& space, u64 virtual_address, u64 physical_address, MapFlags flags,
         PageSize page_size) {
    const u64 size = static_cast<u64>(page_size);
    if (!space.valid() || !mutable_address(virtual_address) || !flags_valid(flags) ||
        (page_size != PageSize::size_4k && page_size != PageSize::size_2m) ||
        virtual_address % size != 0 || physical_address % size != 0 ||
        (physical_address & ~kAddressMask) != 0) {
        return false;
    }

    sync::LockGuard guard(space.lock_);
    PageTable* pml4 = table_from_physical(space.root_physical());
    if (pml4 == nullptr) {
        return false;
    }
    const bool user = has_flag(flags, MapFlags::user);
    PageTable* pdpt = nullptr;
    u64& pml4e = pml4->entries[pml4_index(virtual_address)];
    if (!next_table(pml4e, user, true, pdpt)) {
        prune_empty_path(space, virtual_address);
        return false;
    }
    PageTable* pd = nullptr;
    u64& pdpte = pdpt->entries[pdpt_index(virtual_address)];
    if (!next_table(pdpte, user, true, pd)) {
        prune_empty_path(space, virtual_address);
        return false;
    }
    u64& pde = pd->entries[pd_index(virtual_address)];
    if (page_size == PageSize::size_2m) {
        if ((pde & kPresent) != 0) {
            return false;
        }
        pde = physical_address | leaf_flags(flags, true);
        invalidate_if_active(space, virtual_address);
        return true;
    }

    PageTable* pt = nullptr;
    if (!next_table(pde, user, true, pt)) {
        prune_empty_path(space, virtual_address);
        return false;
    }
    u64& pte = pt->entries[pt_index(virtual_address)];
    if ((pte & kPresent) != 0) {
        return false;
    }
    pte = physical_address | leaf_flags(flags, false);
    invalidate_if_active(space, virtual_address);
    return true;
}

bool unmap(AddressSpace& space, u64 virtual_address) {
    if (!space.valid() || !mutable_address(virtual_address) || virtual_address % kPageSize != 0) {
        return false;
    }
    sync::LockGuard guard(space.lock_);
    PageTable* pml4 = table_from_physical(space.root_physical());
    if (pml4 == nullptr) {
        return false;
    }
    PageTable* pdpt = nullptr;
    u64& pml4e = pml4->entries[pml4_index(virtual_address)];
    if (!next_table(pml4e, false, false, pdpt)) {
        return false;
    }
    PageTable* pd = nullptr;
    u64& pdpte = pdpt->entries[pdpt_index(virtual_address)];
    if (!next_table(pdpte, false, false, pd)) {
        return false;
    }
    u64& pde = pd->entries[pd_index(virtual_address)];
    if ((pde & kPresent) == 0) {
        return false;
    }
    if ((pde & kHuge) != 0) {
        if (virtual_address % static_cast<u64>(PageSize::size_2m) != 0) {
            return false;
        }
        pde = 0;
    } else {
        PageTable* pt = table_from_physical(pde);
        if (pt == nullptr) {
            return false;
        }
        u64& pte = pt->entries[pt_index(virtual_address)];
        if ((pte & kPresent) == 0) {
            return false;
        }
        pte = 0;
    }
    invalidate_if_active(space, virtual_address);
    prune_empty_path(space, virtual_address);
    return true;
}

bool protect(AddressSpace& space, u64 virtual_address, MapFlags flags) {
    if (!space.valid() || !mutable_address(virtual_address) || !flags_valid(flags) ||
        virtual_address % kPageSize != 0) {
        return false;
    }
    sync::LockGuard guard(space.lock_);
    PageTable* pml4 = table_from_physical(space.root_physical());
    if (pml4 == nullptr) {
        return false;
    }
    const bool user = has_flag(flags, MapFlags::user);
    PageTable* pdpt = nullptr;
    u64& pml4e = pml4->entries[pml4_index(virtual_address)];
    if (!next_table(pml4e, user, false, pdpt)) {
        return false;
    }
    PageTable* pd = nullptr;
    u64& pdpte = pdpt->entries[pdpt_index(virtual_address)];
    if (!next_table(pdpte, user, false, pd)) {
        return false;
    }
    u64& pde = pd->entries[pd_index(virtual_address)];
    if ((pde & kPresent) == 0) {
        return false;
    }
    if ((pde & kHuge) != 0) {
        if (virtual_address % static_cast<u64>(PageSize::size_2m) != 0) {
            return false;
        }
        pde = (pde & kAddressMask) | leaf_flags(flags, true);
    } else {
        PageTable* pt = table_from_physical(pde);
        if (pt == nullptr) {
            return false;
        }
        u64& pte = pt->entries[pt_index(virtual_address)];
        if ((pte & kPresent) == 0) {
            return false;
        }
        pte = (pte & kAddressMask) | leaf_flags(flags, false);
    }
    invalidate_if_active(space, virtual_address);
    return true;
}

bool query(AddressSpace& space, u64 virtual_address, Mapping& mapping) {
    sync::LockGuard guard(space.lock_);
    return query_unlocked(space, virtual_address, mapping);
}

bool self_test() {
    last_self_test_failure = 0;
    const physical::Statistics before = physical::statistics();
    AddressSpace space{};
    u64 page = 0;
    u64 large_run = 0;
    bool page_allocated = false;
    bool large_allocated = false;
    bool space_created = false;
    const auto cleanup = [&]() {
        if (space_created && space.valid()) {
            destroy(space);
        }
        if (page_allocated) {
            physical::free_page(page);
        }
        if (large_allocated) {
            physical::free_contiguous(large_run, 512);
        }
    };

    space_created = create(space, 17);
    page_allocated = physical::allocate_page(page);
    large_allocated = physical::allocate_contiguous(512, 512, large_run);
    if (!space_created || !page_allocated || !large_allocated || space.pcid() != 17) {
        last_self_test_failure = !space_created     ? 11
                                 : !page_allocated  ? 12
                                 : !large_allocated ? 13
                                                    : 14;
        cleanup();
        return false;
    }

    constexpr u64 small_virtual = 0x0000'0040'0000'0000ULL;
    constexpr u64 large_virtual = 0x0000'0050'0000'0000ULL;
    constexpr u64 guard_virtual = small_virtual + kPageSize;
    if (is_canonical(0x0000'8000'0000'0000ULL) || is_canonical(0xFFFF'0000'0000'0000ULL) ||
        map(space, 0xFFFF'8000'0000'0000ULL, page, MapFlags::none) ||
        map(space, guard_virtual, page, static_cast<MapFlags>(0x80)) ||
        !map(space, small_virtual, page, MapFlags::write | MapFlags::user) ||
        map(space, small_virtual, page, MapFlags::user) ||
        map(space, guard_virtual, page, MapFlags::write | MapFlags::execute, PageSize::size_4k) ||
        !map(space, large_virtual, large_run, MapFlags::user | MapFlags::execute,
             PageSize::size_2m)) {
        last_self_test_failure = 2;
        cleanup();
        return false;
    }

    Mapping small_mapping{};
    Mapping large_mapping{};
    Mapping guard_mapping{};
    if (!query(space, small_virtual + 123, small_mapping) ||
        small_mapping.physical_address != page + 123 ||
        small_mapping.page_size != PageSize::size_4k ||
        !has_flag(small_mapping.flags, MapFlags::write) ||
        has_flag(small_mapping.flags, MapFlags::execute) ||
        !query(space, large_virtual + 4096, large_mapping) ||
        large_mapping.physical_address != large_run + 4096 ||
        large_mapping.page_size != PageSize::size_2m ||
        !has_flag(large_mapping.flags, MapFlags::execute) ||
        query(space, guard_virtual, guard_mapping)) {
        last_self_test_failure = 3;
        cleanup();
        return false;
    }

    const u64 original_cr3 = read_cr3();
    write_cr3(space.root_physical());
    auto* hardware_alias = reinterpret_cast<volatile u64*>(static_cast<uptr>(small_virtual));
    constexpr u64 alias_probe = 0xD0'58'56'4D'4D'4F'4BULL;
    *hardware_alias = alias_probe;
    const u64 observed_probe = *hardware_alias;
    write_cr3(original_cr3);
    const auto* direct_page = static_cast<const volatile u64*>(physical::direct_map(page));
    if (observed_probe != alias_probe || direct_page == nullptr || *direct_page != alias_probe) {
        last_self_test_failure = 4;
        cleanup();
        return false;
    }

    if (!protect(space, small_virtual, MapFlags::user | MapFlags::execute) ||
        protect(space, small_virtual, MapFlags::write | MapFlags::execute) ||
        !query(space, small_virtual, small_mapping) ||
        has_flag(small_mapping.flags, MapFlags::write) ||
        !has_flag(small_mapping.flags, MapFlags::execute) || !unmap(space, small_virtual) ||
        unmap(space, small_virtual) || !unmap(space, large_virtual) ||
        query(space, large_virtual, large_mapping) ||
        map(space, 0x0001'0000'0000'0000ULL, page, MapFlags::none)) {
        last_self_test_failure = 5;
        cleanup();
        return false;
    }

    if (!destroy(space)) {
        last_self_test_failure = 6;
        cleanup();
        return false;
    }
    space_created = false;
    if (!physical::free_page(page) || !physical::free_contiguous(large_run, 512)) {
        last_self_test_failure = 7;
        return false;
    }
    page_allocated = false;
    large_allocated = false;
    const physical::Statistics after = physical::statistics();
    if (before.free_pages != after.free_pages || before.allocated_pages != after.allocated_pages) {
        last_self_test_failure = 8;
        return false;
    }
    return true;
}

u32 self_test_failure() { return last_self_test_failure; }
}
