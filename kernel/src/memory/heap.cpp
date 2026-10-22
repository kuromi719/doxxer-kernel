#include <doxxer/memory/heap.hpp>

#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>
#include <doxxer/sync/spinlock.hpp>

extern "C" doxxer::uptr __stack_chk_guard;
void* operator new(doxxer::usize size);
void operator delete(void* pointer) noexcept;

namespace doxxer::memory::heap {
namespace {
using virtual_memory::AddressSpace;
using virtual_memory::MapFlags;

constexpr u64 kArenaBase = 0x0000'6000'0000'0000ULL;
constexpr u64 kArenaPages = 16'384;
constexpr u64 kArenaBitmapWords = kArenaPages / 64;
constexpr u64 kGuardPages = 2;
constexpr u64 kSlabDataOffset = 128;
constexpr u64 kQuarantineCapacity = 64;
constexpr u64 kLargeRecordCount = 128;
constexpr u64 kMaximumAllocation = 8 * 1024 * 1024;
constexpr u64 kSlabMagic = 0xD058'534C'4142'3101ULL;
constexpr u64 kBlockMagic = 0xD058'424C'4F43'4B01ULL;
constexpr u64 kAllocatedTag = 0xA1'10'CA'7E'D0'58'00'01ULL;
constexpr u64 kFreedTag = 0xF4'EE'D0'00'D0'58'00'02ULL;
constexpr u64 kLargeTag = 0x1A'26'E0'00'D0'58'00'03ULL;
constexpr usize kClassSizes[] = {16, 32, 64, 128, 256, 512, 1024};
constexpr usize kClassCount = sizeof(kClassSizes) / sizeof(kClassSizes[0]);

enum class BlockState : u8 {
    allocated = 1,
    quarantined = 2,
    free = 3,
};

enum class LargeState : u8 {
    unused,
    allocated,
    quarantined,
};

enum class QuarantineKind : u8 {
    none,
    slab,
    large,
};

struct alignas(16) BlockHeader {
    u64 magic;
    u64 canary;
    u32 requested_size;
    u16 class_index;
    u8 state;
    u8 reserved;
};

struct alignas(16) SlabHeader {
    u64 magic;
    u64 canary;
    u64 physical_address;
    u64 next;
    u64 allocated_bitmap;
    u64 quarantined_bitmap;
    u32 class_index;
    u32 slot_size;
    u32 capacity;
    u32 arena_page;
};

struct LargeRecord {
    u64 virtual_address;
    u64 requested_size;
    u64 canary;
    u32 arena_page;
    u32 data_pages;
    LargeState state;
};

struct QuarantineEntry {
    QuarantineKind kind;
    u64 owner;
    u32 index;
};

static_assert(sizeof(BlockHeader) == 32);
static_assert(sizeof(SlabHeader) <= kSlabDataOffset);

sync::SpinLock heap_lock{};
AddressSpace* address_space = nullptr;
u64 secret = 0;
u64 arena_bitmap[kArenaBitmapWords]{};
u64 arena_mapped_bitmap[kArenaBitmapWords]{};
u64 slab_lists[kClassCount]{};
LargeRecord large_records[kLargeRecordCount]{};
QuarantineEntry quarantine[kQuarantineCapacity]{};
u64 quarantine_head = 0;
u64 quarantine_count = 0;
Statistics stats{};
bool initialized = false;
bool expected_corruption = false;
u64 expected_corruption_count = 0;
u32 last_self_test_failure = 0;

constexpr u64 align_up(u64 value, u64 alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

bool power_of_two(usize value) { return value != 0 && (value & (value - 1)) == 0; }

u64 mix(u64 value) {
    value ^= value >> 30U;
    value *= 0xBF58'476D'1CE4'E5B9ULL;
    value ^= value >> 27U;
    value *= 0x94D0'49BB'1331'11EBULL;
    return value ^ (value >> 31U);
}

u64 make_canary(u64 address, u64 tag) { return mix(secret ^ address ^ tag); }

void secure_zero(void* pointer, usize size) {
    auto* bytes = static_cast<volatile u8*>(pointer);
    for (usize index = 0; index < size; ++index) {
        bytes[index] = 0;
    }
    asm volatile("" : : : "memory");
}

bool bytes_are_zero(const void* pointer, usize size) {
    const auto* bytes = static_cast<const volatile u8*>(pointer);
    for (usize index = 0; index < size; ++index) {
        if (bytes[index] != 0) {
            return false;
        }
    }
    return true;
}

void write_u64(void* pointer, u64 value) {
    auto* bytes = static_cast<u8*>(pointer);
    for (usize index = 0; index < sizeof(value); ++index) {
        bytes[index] = static_cast<u8>(value >> (index * 8U));
    }
}

u64 read_u64(const void* pointer) {
    const auto* bytes = static_cast<const u8*>(pointer);
    u64 value = 0;
    for (usize index = 0; index < sizeof(value); ++index) {
        value |= static_cast<u64>(bytes[index]) << (index * 8U);
    }
    return value;
}

void note_corruption() {
    if (expected_corruption) {
        ++expected_corruption_count;
    } else {
        ++stats.corruption_events;
    }
}

bool arena_page_used(u64 page) { return (arena_bitmap[page / 64] & (1ULL << (page % 64))) != 0; }

bool arena_page_mapped(u64 page) {
    return (arena_mapped_bitmap[page / 64] & (1ULL << (page % 64))) != 0;
}

void set_arena_page(u64 page, bool used) {
    const u64 mask = 1ULL << (page % 64);
    if (used) {
        arena_bitmap[page / 64] |= mask;
    } else {
        arena_bitmap[page / 64] &= ~mask;
    }
}

void set_arena_page_mapped(u64 page, bool mapped) {
    const u64 mask = 1ULL << (page % 64);
    if (mapped) {
        arena_mapped_bitmap[page / 64] |= mask;
    } else {
        arena_mapped_bitmap[page / 64] &= ~mask;
    }
}

bool reserve_virtual(u64 page_count, u32& first_page) {
    if (page_count == 0 || page_count > kArenaPages) {
        return false;
    }
    for (u64 start = 0; start <= kArenaPages - page_count; ++start) {
        bool available = true;
        for (u64 offset = 0; offset < page_count; ++offset) {
            if (arena_page_used(start + offset)) {
                available = false;
                start += offset;
                break;
            }
        }
        if (!available) {
            continue;
        }
        for (u64 offset = 0; offset < page_count; ++offset) {
            set_arena_page(start + offset, true);
        }
        first_page = static_cast<u32>(start);
        return true;
    }
    return false;
}

void release_virtual(u32 first_page, u64 page_count) {
    if (static_cast<u64>(first_page) + page_count > kArenaPages) {
        note_corruption();
        return;
    }
    for (u64 offset = 0; offset < page_count; ++offset) {
        set_arena_page(static_cast<u64>(first_page) + offset, false);
    }
}

u64 virtual_from_page(u32 page) {
    return kArenaBase + static_cast<u64>(page) * physical::kPageSize;
}

usize class_index_for(usize size) {
    for (usize index = 0; index < kClassCount; ++index) {
        if (size <= kClassSizes[index]) {
            return index;
        }
    }
    return kClassCount;
}

BlockHeader* block_at(SlabHeader* slab, u64 index) {
    const u64 address =
        reinterpret_cast<u64>(slab) + kSlabDataOffset + index * static_cast<u64>(slab->slot_size);
    return reinterpret_cast<BlockHeader*>(address);
}

void* payload_of(BlockHeader* block) {
    return reinterpret_cast<void*>(reinterpret_cast<u64>(block) + sizeof(BlockHeader));
}

void* tail_of(BlockHeader* block, usize class_size) {
    return reinterpret_cast<void*>(reinterpret_cast<u64>(payload_of(block)) + class_size);
}

bool slab_address_valid(const SlabHeader* slab) {
    const u64 address = reinterpret_cast<u64>(slab);
    if (address < kArenaBase + physical::kPageSize ||
        address >= kArenaBase + kArenaPages * physical::kPageSize ||
        address % physical::kPageSize != 0) {
        return false;
    }
    return arena_page_mapped((address - kArenaBase) / physical::kPageSize);
}

bool slab_header_valid(const SlabHeader* slab, usize class_index) {
    return slab_address_valid(slab) && slab->magic == kSlabMagic &&
           slab->class_index == class_index && slab->class_index < kClassCount &&
           slab->capacity <= 64 && slab->capacity != 0 &&
           slab->slot_size ==
               align_up(sizeof(BlockHeader) + kClassSizes[class_index] + sizeof(u64), 16) &&
           slab->canary == make_canary(reinterpret_cast<u64>(slab), kSlabMagic);
}

bool allocated_block_valid(SlabHeader* slab, u64 index) {
    BlockHeader* block = block_at(slab, index);
    void* payload = payload_of(block);
    const usize class_size = kClassSizes[slab->class_index];
    return block->magic == kBlockMagic && block->class_index == slab->class_index &&
           block->state == static_cast<u8>(BlockState::allocated) && block->requested_size != 0 &&
           block->requested_size <= class_size &&
           block->canary == make_canary(reinterpret_cast<u64>(payload), kAllocatedTag) &&
           read_u64(tail_of(block, block->requested_size)) ==
               make_canary(reinterpret_cast<u64>(payload), kAllocatedTag ^ block->requested_size);
}

bool free_block_valid(SlabHeader* slab, u64 index, BlockState state) {
    BlockHeader* block = block_at(slab, index);
    void* payload = payload_of(block);
    const usize class_size = kClassSizes[slab->class_index];
    return block->magic == kBlockMagic && block->class_index == slab->class_index &&
           block->state == static_cast<u8>(state) && block->requested_size == 0 &&
           block->canary == make_canary(reinterpret_cast<u64>(payload), kFreedTag) &&
           read_u64(tail_of(block, class_size)) ==
               make_canary(reinterpret_cast<u64>(payload), kFreedTag ^ class_size) &&
           bytes_are_zero(payload, class_size);
}

SlabHeader* create_slab(usize class_index) {
    u32 arena_page = 0;
    if (!reserve_virtual(1 + kGuardPages, arena_page)) {
        return nullptr;
    }
    u64 physical_address = 0;
    if (!physical::allocate_page(physical_address, physical::PageOwner::kernel_heap)) {
        release_virtual(arena_page, 1 + kGuardPages);
        return nullptr;
    }
    const u64 virtual_address = virtual_from_page(arena_page + 1);
    if (!virtual_memory::map(*address_space, virtual_address, physical_address, MapFlags::write)) {
        physical::free_page(physical_address, physical::PageOwner::kernel_heap);
        release_virtual(arena_page, 1 + kGuardPages);
        return nullptr;
    }
    set_arena_page_mapped(static_cast<u64>(arena_page) + 1, true);

    auto* slab = reinterpret_cast<SlabHeader*>(virtual_address);
    slab->magic = kSlabMagic;
    slab->canary = make_canary(virtual_address, kSlabMagic);
    slab->physical_address = physical_address;
    slab->next = slab_lists[class_index];
    slab->allocated_bitmap = 0;
    slab->quarantined_bitmap = 0;
    slab->class_index = static_cast<u32>(class_index);
    slab->slot_size = static_cast<u32>(
        align_up(sizeof(BlockHeader) + kClassSizes[class_index] + sizeof(u64), 16));
    slab->capacity = static_cast<u32>((physical::kPageSize - kSlabDataOffset) / slab->slot_size);
    slab->arena_page = arena_page;
    slab_lists[class_index] = virtual_address;
    ++stats.committed_pages;
    ++stats.slab_pages;
    return slab;
}

void* allocate_from_slab(usize size, usize class_index) {
    SlabHeader* slab = reinterpret_cast<SlabHeader*>(slab_lists[class_index]);
    while (slab != nullptr) {
        if (!slab_header_valid(slab, class_index)) {
            note_corruption();
            return nullptr;
        }
        const u64 unavailable = slab->allocated_bitmap | slab->quarantined_bitmap;
        for (u64 index = 0; index < slab->capacity; ++index) {
            const u64 bit = 1ULL << index;
            if ((unavailable & bit) != 0) {
                continue;
            }
            BlockHeader* block = block_at(slab, index);
            if (block->magic != 0 && !free_block_valid(slab, index, BlockState::free)) {
                slab->quarantined_bitmap |= bit;
                note_corruption();
                continue;
            }
            void* payload = payload_of(block);
            const usize class_size = kClassSizes[class_index];
            secure_zero(payload, class_size);
            block->magic = kBlockMagic;
            block->canary = make_canary(reinterpret_cast<u64>(payload), kAllocatedTag);
            block->requested_size = static_cast<u32>(size);
            block->class_index = static_cast<u16>(class_index);
            block->state = static_cast<u8>(BlockState::allocated);
            block->reserved = 0;
            write_u64(tail_of(block, size),
                      make_canary(reinterpret_cast<u64>(payload), kAllocatedTag ^ size));
            slab->allocated_bitmap |= bit;
            ++stats.allocated_objects;
            stats.requested_bytes += size;
            return payload;
        }
        slab = reinterpret_cast<SlabHeader*>(slab->next);
    }
    slab = create_slab(class_index);
    return slab == nullptr ? nullptr : allocate_from_slab(size, class_index);
}

LargeRecord* find_large_record(const void* pointer, bool allocated_only) {
    const u64 address = reinterpret_cast<u64>(pointer);
    for (u64 index = 0; index < kLargeRecordCount; ++index) {
        LargeRecord& record = large_records[index];
        if (record.virtual_address == address &&
            (!allocated_only || record.state == LargeState::allocated)) {
            return &record;
        }
    }
    return nullptr;
}

u64 large_record_index(const LargeRecord* record) {
    return static_cast<u64>(record - &large_records[0]);
}

bool discard_large_mapping(LargeRecord& record, u32 mapped_pages) {
    bool success = true;
    for (u32 index = 0; index < mapped_pages; ++index) {
        const u64 virtual_address =
            record.virtual_address + static_cast<u64>(index) * physical::kPageSize;
        virtual_memory::Mapping mapping{};
        if (!virtual_memory::query(*address_space, virtual_address, mapping)) {
            success = false;
            continue;
        }
        if (!virtual_memory::unmap(*address_space, virtual_address)) {
            success = false;
            continue;
        }
        set_arena_page_mapped(static_cast<u64>(record.arena_page) + index + 1, false);
        if (!physical::free_page(mapping.physical_address & ~(physical::kPageSize - 1),
                                 physical::PageOwner::kernel_heap)) {
            success = false;
        }
    }
    return success;
}

void* allocate_large(usize size) {
    if (size > kMaximumAllocation || size > static_cast<usize>(-1) - sizeof(u64)) {
        return nullptr;
    }
    LargeRecord* record = nullptr;
    for (u64 index = 0; index < kLargeRecordCount; ++index) {
        if (large_records[index].state == LargeState::unused) {
            record = &large_records[index];
            break;
        }
    }
    if (record == nullptr) {
        return nullptr;
    }

    const u64 data_pages = (size + sizeof(u64) + physical::kPageSize - 1) / physical::kPageSize;
    u32 arena_page = 0;
    if (!reserve_virtual(data_pages + kGuardPages, arena_page)) {
        return nullptr;
    }
    record->virtual_address = virtual_from_page(arena_page + 1);
    record->requested_size = size;
    record->arena_page = arena_page;
    record->data_pages = static_cast<u32>(data_pages);
    record->state = LargeState::allocated;

    u32 mapped_pages = 0;
    for (; mapped_pages < record->data_pages; ++mapped_pages) {
        u64 physical_address = 0;
        const u64 virtual_address =
            record->virtual_address + static_cast<u64>(mapped_pages) * physical::kPageSize;
        if (!physical::allocate_page(physical_address, physical::PageOwner::kernel_heap) ||
            !virtual_memory::map(*address_space, virtual_address, physical_address,
                                 MapFlags::write)) {
            if (physical_address != 0) {
                physical::free_page(physical_address, physical::PageOwner::kernel_heap);
            }
            if (!discard_large_mapping(*record, mapped_pages)) {
                note_corruption();
                return nullptr;
            }
            release_virtual(arena_page, data_pages + kGuardPages);
            *record = {};
            return nullptr;
        }
        set_arena_page_mapped(static_cast<u64>(arena_page) + mapped_pages + 1, true);
    }
    record->canary = make_canary(record->virtual_address, kLargeTag ^ size);
    write_u64(reinterpret_cast<void*>(record->virtual_address + size), record->canary);
    ++stats.allocated_objects;
    stats.requested_bytes += size;
    stats.committed_pages += data_pages;
    stats.large_pages += data_pages;
    return reinterpret_cast<void*>(record->virtual_address);
}

bool locate_slab_block(const void* pointer, SlabHeader*& slab, u64& index) {
    const u64 address = reinterpret_cast<u64>(pointer);
    for (usize class_index = 0; class_index < kClassCount; ++class_index) {
        slab = reinterpret_cast<SlabHeader*>(slab_lists[class_index]);
        while (slab != nullptr) {
            if (!slab_header_valid(slab, class_index)) {
                note_corruption();
                return false;
            }
            const u64 first_payload =
                reinterpret_cast<u64>(slab) + kSlabDataOffset + sizeof(BlockHeader);
            const u64 slab_end = reinterpret_cast<u64>(slab) + physical::kPageSize;
            if (address >= first_payload && address < slab_end) {
                const u64 relative = address - first_payload;
                if (relative % slab->slot_size != 0) {
                    return false;
                }
                index = relative / slab->slot_size;
                return index < slab->capacity;
            }
            slab = reinterpret_cast<SlabHeader*>(slab->next);
        }
    }
    slab = nullptr;
    return false;
}

void evict_quarantine(const QuarantineEntry& entry) {
    if (entry.kind == QuarantineKind::slab) {
        auto* slab = reinterpret_cast<SlabHeader*>(entry.owner);
        if (!slab_address_valid(slab) || !slab_header_valid(slab, slab->class_index) ||
            entry.index >= slab->capacity) {
            note_corruption();
            return;
        }
        const u64 bit = 1ULL << entry.index;
        if ((slab->quarantined_bitmap & bit) == 0 ||
            !free_block_valid(slab, entry.index, BlockState::quarantined)) {
            note_corruption();
            return;
        }
        slab->quarantined_bitmap &= ~bit;
        block_at(slab, entry.index)->state = static_cast<u8>(BlockState::free);
    } else if (entry.kind == QuarantineKind::large) {
        if (entry.index >= kLargeRecordCount ||
            large_records[entry.index].state != LargeState::quarantined) {
            note_corruption();
            return;
        }
        LargeRecord& record = large_records[entry.index];
        release_virtual(record.arena_page, static_cast<u64>(record.data_pages) + kGuardPages);
        record = {};
    }
}

void quarantine_push(QuarantineEntry entry) {
    if (quarantine_count == kQuarantineCapacity) {
        evict_quarantine(quarantine[quarantine_head]);
        quarantine[quarantine_head] = entry;
        quarantine_head = (quarantine_head + 1) % kQuarantineCapacity;
    } else {
        const u64 position = (quarantine_head + quarantine_count) % kQuarantineCapacity;
        quarantine[position] = entry;
        ++quarantine_count;
    }
    stats.quarantined_objects = quarantine_count;
}

bool deallocate_slab(SlabHeader* slab, u64 index) {
    const u64 bit = 1ULL << index;
    if ((slab->allocated_bitmap & bit) == 0 || !allocated_block_valid(slab, index)) {
        note_corruption();
        return false;
    }
    BlockHeader* block = block_at(slab, index);
    const usize requested_size = block->requested_size;
    const usize class_size = kClassSizes[slab->class_index];
    void* payload = payload_of(block);
    secure_zero(payload, class_size);
    block->canary = make_canary(reinterpret_cast<u64>(payload), kFreedTag);
    block->requested_size = 0;
    block->state = static_cast<u8>(BlockState::quarantined);
    write_u64(tail_of(block, class_size),
              make_canary(reinterpret_cast<u64>(payload), kFreedTag ^ class_size));
    slab->allocated_bitmap &= ~bit;
    slab->quarantined_bitmap |= bit;
    --stats.allocated_objects;
    stats.requested_bytes -= requested_size;
    quarantine_push({QuarantineKind::slab, reinterpret_cast<u64>(slab), static_cast<u32>(index)});
    return true;
}

bool large_metadata_valid(const LargeRecord& record) {
    if (record.requested_size == 0 || record.requested_size > kMaximumAllocation ||
        record.data_pages == 0 ||
        static_cast<u64>(record.arena_page) + record.data_pages + kGuardPages > kArenaPages ||
        record.virtual_address != virtual_from_page(record.arena_page + 1) ||
        record.requested_size + sizeof(u64) >
            static_cast<u64>(record.data_pages) * physical::kPageSize) {
        return false;
    }
    return true;
}

bool large_record_valid(const LargeRecord& record) {
    if (record.state != LargeState::allocated || !large_metadata_valid(record) ||
        record.canary != make_canary(record.virtual_address, kLargeTag ^ record.requested_size)) {
        return false;
    }
    for (u32 index = 0; index < record.data_pages; ++index) {
        if (!arena_page_mapped(static_cast<u64>(record.arena_page) + index + 1)) {
            return false;
        }
        virtual_memory::Mapping mapping{};
        if (!virtual_memory::query(
                *address_space,
                record.virtual_address + static_cast<u64>(index) * physical::kPageSize, mapping) ||
            virtual_memory::has_flag(mapping.flags, MapFlags::execute) ||
            virtual_memory::has_flag(mapping.flags, MapFlags::user) ||
            !virtual_memory::has_flag(mapping.flags, MapFlags::write)) {
            return false;
        }
    }
    return read_u64(reinterpret_cast<const void*>(record.virtual_address +
                                                  record.requested_size)) == record.canary;
}

bool deallocate_large(LargeRecord& record) {
    if (!large_record_valid(record)) {
        note_corruption();
        return false;
    }
    const u64 requested_size = record.requested_size;
    secure_zero(reinterpret_cast<void*>(record.virtual_address),
                static_cast<usize>(record.data_pages) * physical::kPageSize);
    if (!discard_large_mapping(record, record.data_pages)) {
        note_corruption();
        return false;
    }
    --stats.allocated_objects;
    stats.requested_bytes -= requested_size;
    stats.committed_pages -= record.data_pages;
    stats.large_pages -= record.data_pages;
    record.state = LargeState::quarantined;
    quarantine_push({QuarantineKind::large, 0, static_cast<u32>(large_record_index(&record))});
    return true;
}

bool guards_absent(u32 arena_page, u32 data_pages) {
    virtual_memory::Mapping mapping{};
    return !virtual_memory::query(*address_space, virtual_from_page(arena_page), mapping) &&
           !virtual_memory::query(*address_space, virtual_from_page(arena_page + data_pages + 1),
                                  mapping);
}
}

bool initialize() {
    sync::LockGuard guard(heap_lock);
    if (initialized) {
        return false;
    }
    address_space = virtual_memory::active_address_space();
    if (address_space == nullptr || !address_space->valid()) {
        return false;
    }
    virtual_memory::Mapping mapping{};
    if (virtual_memory::query(*address_space, kArenaBase, mapping) ||
        virtual_memory::query(*address_space, kArenaBase + kArenaPages * physical::kPageSize - 1,
                              mapping)) {
        address_space = nullptr;
        return false;
    }
    secret =
        mix(static_cast<u64>(__stack_chk_guard) ^ kArenaBase ^ reinterpret_cast<u64>(&heap_lock));
    if (secret == 0) {
        secret = 0xD0'58'48'45'41'50'00'01ULL;
    }
    initialized = true;
    return true;
}

bool ready() { return initialized; }

void* allocate(usize size, usize alignment) {
    if (!initialized || size == 0 || !power_of_two(alignment) || alignment > physical::kPageSize) {
        return nullptr;
    }
    sync::LockGuard guard(heap_lock);
    const usize class_index = class_index_for(size);
    if (class_index < kClassCount && alignment <= 16) {
        return allocate_from_slab(size, class_index);
    }
    return allocate_large(size);
}

bool deallocate(void* pointer) {
    if (pointer == nullptr) {
        return true;
    }
    if (!initialized) {
        return false;
    }
    sync::LockGuard guard(heap_lock);
    SlabHeader* slab = nullptr;
    u64 index = 0;
    if (locate_slab_block(pointer, slab, index)) {
        return deallocate_slab(slab, index);
    }
    LargeRecord* record = find_large_record(pointer, true);
    if (record != nullptr) {
        return deallocate_large(*record);
    }
    note_corruption();
    return false;
}

usize usable_size(const void* pointer) {
    if (!initialized || pointer == nullptr) {
        return 0;
    }
    sync::LockGuard guard(heap_lock);
    SlabHeader* slab = nullptr;
    u64 index = 0;
    if (locate_slab_block(pointer, slab, index) &&
        (slab->allocated_bitmap & (1ULL << index)) != 0 && allocated_block_valid(slab, index)) {
        return block_at(slab, index)->requested_size;
    }
    LargeRecord* record = find_large_record(pointer, true);
    return record != nullptr && large_record_valid(*record) ? record->requested_size : 0;
}

Statistics statistics() {
    sync::LockGuard guard(heap_lock);
    return stats;
}

bool validate() {
    if (!initialized) {
        return false;
    }
    sync::LockGuard guard(heap_lock);
    for (usize class_index = 0; class_index < kClassCount; ++class_index) {
        auto* slab = reinterpret_cast<SlabHeader*>(slab_lists[class_index]);
        while (slab != nullptr) {
            if (!slab_header_valid(slab, class_index) || !guards_absent(slab->arena_page, 1)) {
                return false;
            }
            virtual_memory::Mapping mapping{};
            if (!virtual_memory::query(*address_space, reinterpret_cast<u64>(slab), mapping) ||
                mapping.physical_address != slab->physical_address ||
                virtual_memory::has_flag(mapping.flags, MapFlags::execute) ||
                virtual_memory::has_flag(mapping.flags, MapFlags::user) ||
                !virtual_memory::has_flag(mapping.flags, MapFlags::write) ||
                (slab->allocated_bitmap & slab->quarantined_bitmap) != 0) {
                return false;
            }
            for (u64 index = 0; index < slab->capacity; ++index) {
                const u64 bit = 1ULL << index;
                BlockHeader* block = block_at(slab, index);
                if ((slab->allocated_bitmap & bit) != 0) {
                    if (!allocated_block_valid(slab, index)) {
                        return false;
                    }
                } else if ((slab->quarantined_bitmap & bit) != 0) {
                    if (!free_block_valid(slab, index, BlockState::quarantined)) {
                        return false;
                    }
                } else if (block->magic != 0 && !free_block_valid(slab, index, BlockState::free)) {
                    return false;
                }
            }
            slab = reinterpret_cast<SlabHeader*>(slab->next);
        }
    }
    for (u64 index = 0; index < kLargeRecordCount; ++index) {
        const LargeRecord& record = large_records[index];
        if (record.state == LargeState::allocated &&
            (!large_record_valid(record) || !guards_absent(record.arena_page, record.data_pages))) {
            return false;
        }
        if (record.state == LargeState::quarantined) {
            if (!large_metadata_valid(record)) {
                return false;
            }
            for (u32 page = 0; page < record.data_pages; ++page) {
                if (arena_page_mapped(static_cast<u64>(record.arena_page) + page + 1)) {
                    return false;
                }
            }
            virtual_memory::Mapping mapping{};
            if (virtual_memory::query(*address_space, record.virtual_address, mapping)) {
                return false;
            }
        }
    }
    return true;
}

bool self_test() {
    last_self_test_failure = 1;
    if (!initialized) {
        return false;
    }
    const Statistics before = statistics();
    auto* small = static_cast<u8*>(allocate(24));
    auto* large = static_cast<u8*>(allocate(1500, 256));
    if (small == nullptr || large == nullptr || reinterpret_cast<u64>(small) % 16 != 0 ||
        reinterpret_cast<u64>(large) % 256 != 0 || usable_size(small) != 24 ||
        usable_size(large) != 1500 || !bytes_are_zero(small, 24) || !bytes_are_zero(large, 1500) ||
        allocate(8, 3) != nullptr || allocate(kMaximumAllocation + 1) != nullptr) {
        return false;
    }

    last_self_test_failure = 2;
    small[0] = 0xA5;
    large[1499] = 0x5A;
    small[24] ^= 1U;
    expected_corruption = true;
    expected_corruption_count = 0;
    const bool small_corruption_rejected = !deallocate(small);
    small[24] ^= 1U;
    large[1500] ^= 1U;
    const bool large_corruption_rejected = !deallocate(large);
    large[1500] ^= 1U;
    expected_corruption = false;
    if (!small_corruption_rejected || !large_corruption_rejected ||
        expected_corruption_count != 2 || !deallocate(small) || !bytes_are_zero(small, 32) ||
        !deallocate(large)) {
        return false;
    }

    last_self_test_failure = 3;
    expected_corruption = true;
    expected_corruption_count = 0;
    const bool double_free_rejected = !deallocate(small);
    expected_corruption = false;
    if (!double_free_rejected || expected_corruption_count != 1) {
        return false;
    }

    last_self_test_failure = 4;
    constexpr u64 cpp_probe_value = 0xD058'C0DE'BADC'0FFEULL;
    const Statistics before_cpp = statistics();
    auto* cpp_object = static_cast<u64*>(::operator new(sizeof(u64)));
    *cpp_object = cpp_probe_value;
    const Statistics during_cpp = statistics();
    if (*cpp_object != cpp_probe_value ||
        during_cpp.allocated_objects != before_cpp.allocated_objects + 1 ||
        during_cpp.requested_bytes != before_cpp.requested_bytes + sizeof(u64)) {
        return false;
    }
    ::operator delete(cpp_object);

    constexpr usize class_probes[] = {1, 17, 33, 65, 129, 257, 513, 1024};
    last_self_test_failure = 5;
    void* class_objects[sizeof(class_probes) / sizeof(class_probes[0])]{};
    for (usize index = 0; index < sizeof(class_probes) / sizeof(class_probes[0]); ++index) {
        class_objects[index] = allocate(class_probes[index]);
        if (class_objects[index] == nullptr ||
            reinterpret_cast<u64>(class_objects[index]) % 16 != 0 ||
            usable_size(class_objects[index]) < class_probes[index] ||
            !bytes_are_zero(class_objects[index], class_probes[index])) {
            return false;
        }
    }
    last_self_test_failure = 6;
    for (void*& object : class_objects) {
        if (!deallocate(object)) {
            return false;
        }
        object = nullptr;
    }

    last_self_test_failure = 7;
    void* objects[80]{};
    for (usize index = 0; index < 80; ++index) {
        objects[index] = allocate(8 + (index % 7));
        if (objects[index] == nullptr) {
            return false;
        }
    }
    last_self_test_failure = 8;
    for (void*& object : objects) {
        if (!deallocate(object)) {
            return false;
        }
        object = nullptr;
    }

    last_self_test_failure = 9;
    void* stress_objects[32]{};
    u64 random = secret ^ 0xD058'5354'5245'5353ULL;
    for (u64 step = 0; step < 256; ++step) {
        random ^= random << 13U;
        random ^= random >> 7U;
        random ^= random << 17U;
        const usize slot = static_cast<usize>(random % 32);
        if (stress_objects[slot] != nullptr) {
            if (!deallocate(stress_objects[slot])) {
                return false;
            }
            stress_objects[slot] = nullptr;
        } else {
            const usize size = static_cast<usize>((random >> 8U) % 2048) + 1;
            stress_objects[slot] = allocate(size);
            if (stress_objects[slot] == nullptr) {
                return false;
            }
        }
        if ((step % 32) == 31 && !validate()) {
            return false;
        }
    }
    for (void*& object : stress_objects) {
        if (object != nullptr && !deallocate(object)) {
            return false;
        }
        object = nullptr;
    }

    const Statistics after = statistics();
    last_self_test_failure = 10;
    if (after.allocated_objects != before.allocated_objects ||
        after.requested_bytes != before.requested_bytes ||
        after.corruption_events != before.corruption_events || !validate()) {
        return false;
    }
    last_self_test_failure = 0;
    return true;
}

u32 self_test_failure() { return last_self_test_failure; }
}
