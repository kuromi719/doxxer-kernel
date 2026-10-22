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
constexpr u64 kProtectionWindowIndex = 0xE0;
constexpr u64 kCpuWindowIndex = 0xE4;
constexpr u64 kTaskWindowIndex = 0xE8;
constexpr u64 kTemporaryWindowIndex = 0xEC;
constexpr u64 kTemporaryWindowBase = kTemporaryWindowIndex << 39U;
constexpr u16 kTemporarySlotCount = 256;
u32 last_self_test_failure = 0;
AddressSpace* active_space = nullptr;
sync::SpinLock supervisor_windows_lock{};
sync::SpinLock temporary_slot_locks[kTemporarySlotCount]{};
bool temporary_slot_active[kTemporarySlotCount]{};
u64 temporary_mappings = 0;
u64 temporary_unmappings = 0;
u64 temporary_failures = 0;
u64 next_isolation_domain = 1;

class ConditionalLockGuard final {
  public:
    explicit ConditionalLockGuard(sync::SpinLock* lock) : lock_(lock) {
        if (lock_ != nullptr) {
            lock_->lock();
        }
    }
    ~ConditionalLockGuard() {
        if (lock_ != nullptr) {
            lock_->unlock();
        }
    }
    ConditionalLockGuard(const ConditionalLockGuard&) = delete;
    ConditionalLockGuard& operator=(const ConditionalLockGuard&) = delete;

  private:
    sync::SpinLock* lock_;
};

struct alignas(4096) PageTable {
    u64 entries[kEntriesPerTable];
};

static_assert(sizeof(PageTable) == kPageSize);

constexpr u64 pml4_index(u64 address) { return (address >> 39U) & 0x1FFU; }
constexpr u64 pdpt_index(u64 address) { return (address >> 30U) & 0x1FFU; }
constexpr u64 pd_index(u64 address) { return (address >> 21U) & 0x1FFU; }
constexpr u64 pt_index(u64 address) { return (address >> 12U) & 0x1FFU; }
constexpr bool supervisor_window_index(u64 index) {
    return index == kProtectionWindowIndex || index == kCpuWindowIndex ||
           index == kTaskWindowIndex || index == kTemporaryWindowIndex;
}

u16 current_temporary_slot() {
    u32 eax = 1;
    u32 ebx = 0;
    u32 ecx = 0;
    u32 edx = 0;
    asm volatile("cpuid"
                 : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx)
                 :
                 : "memory");
    return static_cast<u16>(ebx >> 24U);
}

u64 disable_interrupts() {
    u64 rflags = 0;
    asm volatile("pushfq; popq %0; cli" : "=r"(rflags) : : "memory");
    return rflags;
}

void restore_interrupts(u64 rflags) {
    if ((rflags & (1ULL << 9U)) != 0) {
        asm volatile("sti" : : : "memory");
    }
}

PageTable* table_from_physical(u64 physical_address) {
    return static_cast<PageTable*>(physical::direct_map_page_table(physical_address & kAddressMask));
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
    if (!physical::allocate_page(physical_address, physical::PageOwner::page_table)) {
        return false;
    }
    table = table_from_physical(physical_address);
    if (table == nullptr) {
        physical::free_page(physical_address, physical::PageOwner::page_table);
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
                    physical::free_page(physical_address, physical::PageOwner::page_table);
                }
            }
            if (table_empty(pd)) {
                const u64 physical_address = pdpte & kAddressMask;
                pdpte = 0;
                physical::free_page(physical_address, physical::PageOwner::page_table);
            }
        }
    }
    if (table_empty(pdpt) && !supervisor_window_index(pml4_index(virtual_address))) {
        const u64 physical_address = pml4e & kAddressMask;
        pml4e = 0;
        physical::free_page(physical_address, physical::PageOwner::page_table);
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
            if (!physical::free_page(child_physical, physical::PageOwner::page_table)) {
                success = false;
            }
        }
    }
    return success;
}

bool table_contains_user_mapping(PageTable* table, u8 level) {
    if (table == nullptr || level == 0) {
        return true;
    }
    for (u64 index = 0; index < kEntriesPerTable; ++index) {
        const u64 entry = table->entries[index];
        if ((entry & kPresent) == 0) {
            continue;
        }
        if (level == 1 || (entry & kHuge) != 0) {
            if ((entry & kUser) != 0) {
                return true;
            }
            continue;
        }
        if (table_contains_user_mapping(table_from_physical(entry),
                                        static_cast<u8>(level - 1))) {
            return true;
        }
    }
    return false;
}

bool user_half_empty(PageTable* root, bool owns_supervisor_windows) {
    if (root == nullptr) {
        return false;
    }
    for (u64 index = 0; index < kEntriesPerTable / 2; ++index) {
        if (!owns_supervisor_windows && supervisor_window_index(index)) {
            continue;
        }
        const u64 entry = root->entries[index];
        if ((entry & kPresent) == 0) {
            continue;
        }
        if ((entry & kHuge) != 0 ||
            table_contains_user_mapping(table_from_physical(entry), 3)) {
            return false;
        }
    }
    return true;
}

bool destroy_user_half(PageTable* root, bool owns_supervisor_windows) {
    if (root == nullptr) {
        return false;
    }
    bool success = true;
    for (u64 index = 0; index < kEntriesPerTable / 2; ++index) {
        if (!owns_supervisor_windows && supervisor_window_index(index)) {
            root->entries[index] = 0;
            continue;
        }
        const u64 entry = root->entries[index];
        if ((entry & kPresent) == 0 || (entry & kHuge) != 0) {
            continue;
        }
        PageTable* child = table_from_physical(entry);
        if (!destroy_table(child, 3)) {
            success = false;
        }
        root->entries[index] = 0;
        if (!physical::free_page(entry & kAddressMask, physical::PageOwner::page_table)) {
            success = false;
        }
    }
    return success;
}

bool mutable_address(const AddressSpace& space, u64 virtual_address) {
    if (!is_canonical(virtual_address) ||
        pml4_index(virtual_address) >= kEntriesPerTable / 2) {
        return false;
    }
    return space.owns_supervisor_windows() ||
           !supervisor_window_index(pml4_index(virtual_address));
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
    sync::LockGuard supervisor_guard(supervisor_windows_lock);
    if (next_isolation_domain > 0xFFFF'FFFFULL) {
        return false;
    }
    const auto isolation_domain =
        static_cast<physical::IsolationDomain>(next_isolation_domain++);
    u64 root_physical = 0;
    PageTable* root = nullptr;
    if (!allocate_table(root_physical, root)) {
        return false;
    }
    PageTable* active_root = table_from_physical(read_cr3_root());
    if (active_root == nullptr) {
        physical::free_page(root_physical, physical::PageOwner::page_table);
        return false;
    }
    for (u64 index = kEntriesPerTable / 2; index < kEntriesPerTable; ++index) {
        root->entries[index] = active_root->entries[index];
    }
    const bool owns_supervisor_windows = active_space == nullptr;
    if (owns_supervisor_windows) {
        PageTable* window = nullptr;
        if (!next_table(root->entries[kProtectionWindowIndex], false, true, window) ||
            !next_table(root->entries[kCpuWindowIndex], false, true, window) ||
            !next_table(root->entries[kTaskWindowIndex], false, true, window) ||
            !next_table(root->entries[kTemporaryWindowIndex], false, true, window)) {
            destroy_user_half(root, true);
            physical::free_page(root_physical, physical::PageOwner::page_table);
            return false;
        }
    } else {
        root->entries[kProtectionWindowIndex] = active_root->entries[kProtectionWindowIndex];
        root->entries[kCpuWindowIndex] = active_root->entries[kCpuWindowIndex];
        root->entries[kTaskWindowIndex] = active_root->entries[kTaskWindowIndex];
        root->entries[kTemporaryWindowIndex] = active_root->entries[kTemporaryWindowIndex];
    }
    space.root_physical_ = root_physical;
    space.pcid_ = pcid;
    space.isolation_domain_ = isolation_domain;
    space.owns_supervisor_windows_ = owns_supervisor_windows;
    return true;
}

bool destroy(AddressSpace& space) {
    if (!space.valid() || read_cr3_root() == space.root_physical()) {
        return false;
    }
    sync::LockGuard supervisor_guard(supervisor_windows_lock);
    sync::LockGuard guard(space.lock_);
    PageTable* root = table_from_physical(space.root_physical());
    if (root == nullptr || !user_half_empty(root, space.owns_supervisor_windows_)) {
        return false;
    }
    const u64 root_physical = space.root_physical();
    bool success = destroy_user_half(root, space.owns_supervisor_windows_);
    if (!physical::free_page(root_physical, physical::PageOwner::page_table)) {
        success = false;
    }
    space.root_physical_ = 0;
    space.pcid_ = 0;
    space.isolation_domain_ = physical::kKernelDomain;
    space.owns_supervisor_windows_ = false;
    return success;
}

bool activate(AddressSpace& space) {
    if (!space.valid() || space.pcid() != 0) {
        return false;
    }
    write_cr3(space.root_physical());
    if (read_cr3_root() != space.root_physical()) {
        return false;
    }
    active_space = &space;
    return true;
}

AddressSpace* active_address_space() { return active_space; }

bool map(AddressSpace& space, u64 virtual_address, u64 physical_address, MapFlags flags,
         PageSize page_size) {
    const u64 size = static_cast<u64>(page_size);
    if (!space.valid() || !mutable_address(space, virtual_address) || !flags_valid(flags) ||
        (page_size != PageSize::size_4k && page_size != PageSize::size_2m) ||
        virtual_address % size != 0 || physical_address % size != 0 ||
        (physical_address & ~kAddressMask) != 0) {
        return false;
    }
    const bool user = has_flag(flags, MapFlags::user);
    const u64 mapped_pages = size / kPageSize;
    if ((user && !physical::retain_user_mapping(physical_address, mapped_pages,
                                                 has_flag(flags, MapFlags::execute),
                                                 space.isolation_domain())) ||
        (!user && !physical::retain_supervisor_mapping(physical_address, mapped_pages))) {
        return false;
    }
    const auto fail = [&]() {
        if (user) {
            (void)physical::release_user_mapping(physical_address, mapped_pages,
                                                 space.isolation_domain());
        } else {
            (void)physical::release_supervisor_mapping(physical_address, mapped_pages);
        }
        return false;
    };

    ConditionalLockGuard supervisor_guard(supervisor_window_index(pml4_index(virtual_address))
                                               ? &supervisor_windows_lock
                                               : nullptr);
    sync::LockGuard guard(space.lock_);
    PageTable* pml4 = table_from_physical(space.root_physical());
    if (pml4 == nullptr) {
        return fail();
    }
    PageTable* pdpt = nullptr;
    u64& pml4e = pml4->entries[pml4_index(virtual_address)];
    if (!next_table(pml4e, user, true, pdpt)) {
        prune_empty_path(space, virtual_address);
        return fail();
    }
    PageTable* pd = nullptr;
    u64& pdpte = pdpt->entries[pdpt_index(virtual_address)];
    if (!next_table(pdpte, user, true, pd)) {
        prune_empty_path(space, virtual_address);
        return fail();
    }
    u64& pde = pd->entries[pd_index(virtual_address)];
    if (page_size == PageSize::size_2m) {
        if ((pde & kPresent) != 0) {
            return fail();
        }
        pde = physical_address | leaf_flags(flags, true);
        invalidate_if_active(space, virtual_address);
        return true;
    }

    PageTable* pt = nullptr;
    if (!next_table(pde, user, true, pt)) {
        prune_empty_path(space, virtual_address);
        return fail();
    }
    u64& pte = pt->entries[pt_index(virtual_address)];
    if ((pte & kPresent) != 0) {
        return fail();
    }
    pte = physical_address | leaf_flags(flags, false);
    invalidate_if_active(space, virtual_address);
    return true;
}

bool unmap(AddressSpace& space, u64 virtual_address) {
    if (!space.valid() || !mutable_address(space, virtual_address) ||
        virtual_address % kPageSize != 0) {
        return false;
    }
    ConditionalLockGuard supervisor_guard(supervisor_window_index(pml4_index(virtual_address))
                                               ? &supervisor_windows_lock
                                               : nullptr);
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
        const u64 mapped_pages = static_cast<u64>(PageSize::size_2m) / kPageSize;
        const bool released = (pde & kUser) != 0
                                  ? physical::release_user_mapping(
                                        pde & kAddressMask, mapped_pages,
                                        space.isolation_domain())
                                  : physical::release_supervisor_mapping(
                                        pde & kAddressMask, mapped_pages);
        if (!released) {
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
        const bool released =
            (pte & kUser) != 0
                ? physical::release_user_mapping(pte & kAddressMask, 1,
                                                 space.isolation_domain())
                : physical::release_supervisor_mapping(pte & kAddressMask, 1);
        if (!released) {
            return false;
        }
        pte = 0;
    }
    invalidate_if_active(space, virtual_address);
    prune_empty_path(space, virtual_address);
    return true;
}

bool protect(AddressSpace& space, u64 virtual_address, MapFlags flags) {
    if (!space.valid() || !mutable_address(space, virtual_address) || !flags_valid(flags) ||
        virtual_address % kPageSize != 0) {
        return false;
    }
    ConditionalLockGuard supervisor_guard(supervisor_window_index(pml4_index(virtual_address))
                                               ? &supervisor_windows_lock
                                               : nullptr);
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
        if (user && !physical::user_mapping_allowed(
                        pde & kAddressMask,
                        static_cast<u64>(PageSize::size_2m) / kPageSize,
                        has_flag(flags, MapFlags::execute), space.isolation_domain())) {
            return false;
        }
        if (((pde & kUser) != 0) != user) {
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
        if (user && !physical::user_mapping_allowed(pte & kAddressMask, 1,
                                                     has_flag(flags, MapFlags::execute),
                                                     space.isolation_domain())) {
            return false;
        }
        if (((pte & kUser) != 0) != user) {
            return false;
        }
        pte = (pte & kAddressMask) | leaf_flags(flags, false);
    }
    invalidate_if_active(space, virtual_address);
    return true;
}

bool query(AddressSpace& space, u64 virtual_address, Mapping& mapping) {
    ConditionalLockGuard supervisor_guard(supervisor_window_index(pml4_index(virtual_address))
                                               ? &supervisor_windows_lock
                                               : nullptr);
    sync::LockGuard guard(space.lock_);
    return query_unlocked(space, virtual_address, mapping);
}

bool map_temporary_user(AddressSpace& owner_space, u64 physical_address, bool writable,
                        TemporaryMapping& mapping) {
    if (mapping.active || mapping.address != nullptr || !owner_space.valid() ||
        owner_space.isolation_domain() == physical::kKernelDomain || active_space == nullptr ||
        !active_space->valid() || !active_space->owns_supervisor_windows()) {
        __atomic_add_fetch(&temporary_failures, 1ULL, __ATOMIC_RELAXED);
        return false;
    }
    const u64 physical_page = physical_address & ~(kPageSize - 1);
    const u64 page_offset = physical_address & (kPageSize - 1);
    const u16 slot = current_temporary_slot();
    const u64 saved_rflags = disable_interrupts();
    sync::SpinLock& slot_lock = temporary_slot_locks[slot];
    if (__atomic_load_n(&temporary_slot_active[slot], __ATOMIC_ACQUIRE)) {
        __atomic_add_fetch(&temporary_failures, 1ULL, __ATOMIC_RELAXED);
        restore_interrupts(saved_rflags);
        return false;
    }
    slot_lock.lock();
    if (__atomic_load_n(&temporary_slot_active[slot], __ATOMIC_ACQUIRE) ||
        !physical::retain_user_mapping(physical_page, 1, false,
                                       owner_space.isolation_domain())) {
        __atomic_add_fetch(&temporary_failures, 1ULL, __ATOMIC_RELAXED);
        slot_lock.unlock();
        restore_interrupts(saved_rflags);
        return false;
    }

    const u64 virtual_address = kTemporaryWindowBase + static_cast<u64>(slot) * kPageSize;
    bool installed = false;
    {
        sync::LockGuard supervisor_guard(supervisor_windows_lock);
        sync::LockGuard space_guard(active_space->lock_);
        PageTable* pml4 = table_from_physical(active_space->root_physical());
        PageTable* pdpt = nullptr;
        PageTable* pd = nullptr;
        PageTable* pt = nullptr;
        if (pml4 != nullptr) {
            u64& pml4e = pml4->entries[pml4_index(virtual_address)];
            if (next_table(pml4e, false, true, pdpt)) {
                u64& pdpte = pdpt->entries[pdpt_index(virtual_address)];
                if (next_table(pdpte, false, true, pd)) {
                    u64& pde = pd->entries[pd_index(virtual_address)];
                    if (next_table(pde, false, true, pt)) {
                        u64& pte = pt->entries[pt_index(virtual_address)];
                        if ((pte & kPresent) == 0) {
                            pte = physical_page |
                                  leaf_flags(writable ? MapFlags::write : MapFlags::none, false);
                            invalidate_if_active(*active_space, virtual_address);
                            installed = true;
                        }
                    }
                }
            }
        }
        if (!installed) {
            prune_empty_path(*active_space, virtual_address);
        }
    }
    if (!installed) {
        (void)physical::release_user_mapping(physical_page, 1,
                                             owner_space.isolation_domain());
        __atomic_add_fetch(&temporary_failures, 1ULL, __ATOMIC_RELAXED);
        slot_lock.unlock();
        restore_interrupts(saved_rflags);
        return false;
    }

    __atomic_store_n(&temporary_slot_active[slot], true, __ATOMIC_RELEASE);
    __atomic_add_fetch(&temporary_mappings, 1ULL, __ATOMIC_RELAXED);
    mapping = {
        .address = reinterpret_cast<void*>(
            static_cast<uptr>(virtual_address + page_offset)),
        .address_space_cookie = active_space,
        .physical_page = physical_page,
        .domain = owner_space.isolation_domain(),
        .saved_rflags = saved_rflags,
        .slot = slot,
        .active = true,
    };
    return true;
}

bool unmap_temporary_user(TemporaryMapping& mapping) {
    if (!mapping.active || mapping.address == nullptr || mapping.address_space_cookie == nullptr ||
        mapping.slot >= kTemporarySlotCount || current_temporary_slot() != mapping.slot) {
        __atomic_add_fetch(&temporary_failures, 1ULL, __ATOMIC_RELAXED);
        return false;
    }
    auto* space = static_cast<AddressSpace*>(mapping.address_space_cookie);
    const u16 slot = mapping.slot;
    const u64 physical_page = mapping.physical_page;
    const physical::IsolationDomain domain = mapping.domain;
    const u64 saved_rflags = mapping.saved_rflags;
    const u64 virtual_address = kTemporaryWindowBase + static_cast<u64>(slot) * kPageSize;

    bool removed = false;
    if (__atomic_load_n(&temporary_slot_active[slot], __ATOMIC_ACQUIRE)) {
        sync::LockGuard supervisor_guard(supervisor_windows_lock);
        sync::LockGuard space_guard(space->lock_);
        PageTable* pml4 = table_from_physical(space->root_physical());
        PageTable* pdpt = nullptr;
        PageTable* pd = nullptr;
        PageTable* pt = nullptr;
        if (pml4 != nullptr) {
            u64& pml4e = pml4->entries[pml4_index(virtual_address)];
            if (next_table(pml4e, false, false, pdpt)) {
                u64& pdpte = pdpt->entries[pdpt_index(virtual_address)];
                if (next_table(pdpte, false, false, pd)) {
                    u64& pde = pd->entries[pd_index(virtual_address)];
                    if (next_table(pde, false, false, pt)) {
                        u64& pte = pt->entries[pt_index(virtual_address)];
                        if ((pte & (kPresent | kUser | kAddressMask)) ==
                            (kPresent | physical_page)) {
                            pte = 0;
                            invalidate_if_active(*space, virtual_address);
                            prune_empty_path(*space, virtual_address);
                            removed = true;
                        }
                    }
                }
            }
        }
    }
    if (!removed) {
        __atomic_add_fetch(&temporary_failures, 1ULL, __ATOMIC_RELAXED);
        mapping = {};
        temporary_slot_locks[slot].unlock();
        restore_interrupts(saved_rflags);
        return false;
    }
    __atomic_store_n(&temporary_slot_active[slot], false, __ATOMIC_RELEASE);
    const bool released = physical::release_user_mapping(physical_page, 1, domain);
    if (released) {
        __atomic_add_fetch(&temporary_unmappings, 1ULL, __ATOMIC_RELAXED);
    } else {
        __atomic_add_fetch(&temporary_failures, 1ULL, __ATOMIC_RELAXED);
    }
    mapping = {};
    temporary_slot_locks[slot].unlock();
    restore_interrupts(saved_rflags);
    return released;
}

TemporaryMappingStatistics temporary_mapping_statistics() {
    return {
        .mappings = __atomic_load_n(&temporary_mappings, __ATOMIC_RELAXED),
        .unmappings = __atomic_load_n(&temporary_unmappings, __ATOMIC_RELAXED),
        .failures = __atomic_load_n(&temporary_failures, __ATOMIC_RELAXED),
    };
}

bool temporary_windows_idle() {
    for (u16 slot = 0; slot < kTemporarySlotCount; ++slot) {
        if (__atomic_load_n(&temporary_slot_active[slot], __ATOMIC_ACQUIRE)) {
            return false;
        }
    }
    const TemporaryMappingStatistics current = temporary_mapping_statistics();
    return current.mappings != 0 && current.mappings == current.unmappings &&
           current.failures == 0;
}

bool self_test() {
    last_self_test_failure = 0;
    const physical::Statistics before = physical::statistics();
    AddressSpace space{};
    AddressSpace foreign_space{};
    physical::IsolationDomain space_domain = physical::kKernelDomain;
    u64 page = 0;
    u64 large_run = 0;
    u64 kernel_page = 0;
    u64 stack_page = 0;
    bool page_allocated = false;
    bool large_allocated = false;
    bool kernel_page_allocated = false;
    bool stack_page_allocated = false;
    bool space_created = false;
    bool foreign_space_created = false;
    const auto cleanup = [&]() {
        if (foreign_space_created && foreign_space.valid()) {
            destroy(foreign_space);
        }
        if (space_created && space.valid()) {
            destroy(space);
        }
        if (page_allocated) {
            physical::free_page(page, physical::PageOwner::user_image, space_domain);
        }
        if (large_allocated) {
            physical::free_contiguous(large_run, 512, physical::PageOwner::user_image,
                                      space_domain);
        }
        if (kernel_page_allocated) {
            physical::free_page(kernel_page, physical::PageOwner::kernel_heap);
        }
        if (stack_page_allocated) {
            physical::free_page(stack_page, physical::PageOwner::user_stack, space_domain);
        }
    };

    space_created = create(space, 17);
    foreign_space_created = create(foreign_space, 18);
    if (!space_created || !foreign_space_created ||
        space.isolation_domain() == physical::kKernelDomain ||
        foreign_space.isolation_domain() == physical::kKernelDomain ||
        space.isolation_domain() == foreign_space.isolation_domain()) {
        last_self_test_failure = 11;
        cleanup();
        return false;
    }
    space_domain = space.isolation_domain();
    page_allocated = physical::allocate_page(page, physical::PageOwner::user_image,
                                               physical::Zone::any, space_domain);
    large_allocated = physical::allocate_contiguous(512, 512, large_run,
                                                    physical::PageOwner::user_image,
                                                    physical::Zone::any, space_domain);
    kernel_page_allocated =
        physical::allocate_page(kernel_page, physical::PageOwner::kernel_heap);
    stack_page_allocated =
        physical::allocate_page(stack_page, physical::PageOwner::user_stack,
                                physical::Zone::any, space_domain);
    if (!space_created || !page_allocated || !large_allocated || !kernel_page_allocated ||
        !stack_page_allocated || space.pcid() != 17) {
        last_self_test_failure = !space_created     ? 11
                                 : !page_allocated  ? 12
                                 : !large_allocated ? 13
                                 : !kernel_page_allocated ? 14
                                 : !stack_page_allocated  ? 15
                                                          : 16;
        cleanup();
        return false;
    }

    constexpr u64 small_virtual = 0x0000'0040'0000'0000ULL;
    constexpr u64 large_virtual = 0x0000'0050'0000'0000ULL;
    constexpr u64 guard_virtual = small_virtual + kPageSize;
    constexpr u64 foreign_virtual = 0x0000'0060'0000'0000ULL;
    constexpr u64 kernel_virtual = 0x0000'0061'0000'0000ULL;
    if (is_canonical(0x0000'8000'0000'0000ULL) || is_canonical(0xFFFF'0000'0000'0000ULL) ||
        map(foreign_space, foreign_virtual, page, MapFlags::user) ||
        map(foreign_space, foreign_virtual, page, MapFlags::none) ||
        physical::free_page(page, physical::PageOwner::user_image,
                            foreign_space.isolation_domain()) ||
        map(space, 0xFFFF'8000'0000'0000ULL, page, MapFlags::none) ||
        map(space, guard_virtual, page, static_cast<MapFlags>(0x80)) ||
        map(space, guard_virtual, kernel_page, MapFlags::write | MapFlags::user) ||
        map(space, guard_virtual, stack_page, MapFlags::user | MapFlags::execute) ||
        !map(space, small_virtual, page, MapFlags::write | MapFlags::user) ||
        !map(space, kernel_virtual, kernel_page, MapFlags::write) ||
        map(space, small_virtual, page, MapFlags::user) ||
        map(space, guard_virtual, page, MapFlags::write | MapFlags::execute, PageSize::size_4k) ||
        !map(space, large_virtual, large_run, MapFlags::user | MapFlags::execute,
             PageSize::size_2m) ||
        physical::free_page(page, physical::PageOwner::user_image, space_domain) ||
        physical::free_page(kernel_page, physical::PageOwner::kernel_heap) ||
        destroy(space)) {
        last_self_test_failure = 2;
        cleanup();
        return false;
    }

    Mapping small_mapping{};
    Mapping large_mapping{};
    Mapping guard_mapping{};
    Mapping kernel_mapping{};
    if (!query(space, small_virtual + 123, small_mapping) ||
        small_mapping.physical_address != page + 123 ||
        small_mapping.page_size != PageSize::size_4k ||
        !has_flag(small_mapping.flags, MapFlags::write) ||
        has_flag(small_mapping.flags, MapFlags::execute) ||
        !query(space, large_virtual + 4096, large_mapping) ||
        large_mapping.physical_address != large_run + 4096 ||
        large_mapping.page_size != PageSize::size_2m ||
        !has_flag(large_mapping.flags, MapFlags::execute) ||
        !query(space, kernel_virtual, kernel_mapping) ||
        kernel_mapping.physical_address != kernel_page ||
        !has_flag(kernel_mapping.flags, MapFlags::write) ||
        has_flag(kernel_mapping.flags, MapFlags::execute) ||
        has_flag(kernel_mapping.flags, MapFlags::user) ||
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
    if (observed_probe != alias_probe) {
        last_self_test_failure = 4;
        cleanup();
        return false;
    }

    if (protect(space, small_virtual, MapFlags::none) ||
        !protect(space, small_virtual, MapFlags::user | MapFlags::execute) ||
        protect(space, small_virtual, MapFlags::write | MapFlags::execute) ||
        !query(space, small_virtual, small_mapping) ||
        has_flag(small_mapping.flags, MapFlags::write) ||
        !has_flag(small_mapping.flags, MapFlags::execute) || !unmap(space, small_virtual) ||
        unmap(space, small_virtual) || !unmap(space, large_virtual) ||
        !unmap(space, kernel_virtual) ||
        query(space, large_virtual, large_mapping) ||
        map(space, 0x0001'0000'0000'0000ULL, page, MapFlags::none)) {
        last_self_test_failure = 5;
        cleanup();
        return false;
    }

    if (!destroy(foreign_space) || !destroy(space)) {
        last_self_test_failure = 6;
        cleanup();
        return false;
    }
    foreign_space_created = false;
    space_created = false;
    if (!physical::free_page(page, physical::PageOwner::user_image, space_domain) ||
        !physical::free_contiguous(large_run, 512, physical::PageOwner::user_image,
                                   space_domain) ||
        !physical::free_page(kernel_page, physical::PageOwner::kernel_heap) ||
        !physical::free_page(stack_page, physical::PageOwner::user_stack, space_domain)) {
        last_self_test_failure = 7;
        return false;
    }
    page_allocated = false;
    large_allocated = false;
    kernel_page_allocated = false;
    stack_page_allocated = false;
    const physical::Statistics after = physical::statistics();
    if (before.free_pages != after.free_pages || before.allocated_pages != after.allocated_pages ||
        before.user_mapping_references != after.user_mapping_references ||
        after.mapping_rejections != before.mapping_rejections + 3 ||
        before.supervisor_mapping_references != after.supervisor_mapping_references) {
        last_self_test_failure = 8;
        return false;
    }
    return true;
}

u32 self_test_failure() { return last_self_test_failure; }
}
