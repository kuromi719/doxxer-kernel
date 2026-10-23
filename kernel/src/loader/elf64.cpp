#include <doxxer/loader/elf64.hpp>
#include <doxxer/arch/x86_64/ring3.hpp>

#include <doxxer/memory/heap.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/user_copy.hpp>
#include <doxxer/security/image_policy.hpp>

namespace doxxer::loader::elf64 {
namespace {
constexpr u32 kProgramLoad = 1;
constexpr u32 kFlagExecute = 1;
constexpr u32 kFlagWrite = 2;
constexpr u32 kFlagRead = 4;
constexpr u64 kMinimumUserAddress = 0x1'0000ULL;
constexpr u64 kMaximumUserAddress = 0x0000'7FFF'FFFF'FFFFULL;
constexpr u16 kMaximumProgramHeaders = 16;
constexpr usize kMaximumImageBytes = 2 * 1024 * 1024;

struct ElfHeader {
    u8 identity[16];
    u16 type;
    u16 machine;
    u32 version;
    u64 entry;
    u64 program_header_offset;
    u64 section_header_offset;
    u32 flags;
    u16 header_size;
    u16 program_header_size;
    u16 program_header_count;
    u16 section_header_size;
    u16 section_header_count;
    u16 section_name_index;
};

struct ProgramHeader {
    u32 type;
    u32 flags;
    u64 offset;
    u64 virtual_address;
    u64 physical_address;
    u64 file_size;
    u64 memory_size;
    u64 alignment;
};

static_assert(sizeof(ElfHeader) == 64);
static_assert(sizeof(ProgramHeader) == 56);

class Snapshot final {
  public:
    Snapshot() = default;
    ~Snapshot() {
        if (bytes_ != nullptr) {
            (void)memory::heap::deallocate(bytes_);
        }
    }
    Snapshot(const Snapshot&) = delete;
    Snapshot& operator=(const Snapshot&) = delete;

    bool capture(const void* source, usize size) {
        bytes_ = static_cast<u8*>(memory::heap::allocate(size, alignof(ElfHeader)));
        if (bytes_ == nullptr) {
            return false;
        }
        const auto* source_bytes = static_cast<const u8*>(source);
        for (usize index = 0; index < size; ++index) {
            bytes_[index] = source_bytes[index];
        }
        return true;
    }

    const u8* bytes() const { return bytes_; }

  private:
    u8* bytes_ = nullptr;
};

u64 loaded_images = 0;
u64 unloaded_images = 0;
u64 mapped_pages = 0;
u64 rejected_images = 0;
u32 last_failure = 0;

void reject() { __atomic_add_fetch(&rejected_images, 1ULL, __ATOMIC_RELAXED); }

bool add_overflows(u64 left, u64 right) { return right > static_cast<u64>(-1) - left; }

bool power_of_two(u64 value) { return value != 0 && (value & (value - 1)) == 0; }

u64 align_up(u64 value) {
    return (value + memory::physical::kPageSize - 1) & ~(memory::physical::kPageSize - 1);
}

bool header_valid(const ElfHeader& header, usize size) {
    if (header.identity[0] != 0x7F || header.identity[1] != 'E' ||
        header.identity[2] != 'L' || header.identity[3] != 'F' ||
        header.identity[4] != 2 || header.identity[5] != 1 || header.identity[6] != 1 ||
        header.type != 2 || header.machine != 62 || header.version != 1 ||
        header.header_size != sizeof(ElfHeader) ||
        header.program_header_size != sizeof(ProgramHeader) ||
        header.program_header_offset % alignof(ProgramHeader) != 0 ||
        header.program_header_count == 0 ||
        header.program_header_count > kMaximumProgramHeaders) {
        return false;
    }
    const u64 table_size = static_cast<u64>(header.program_header_count) * sizeof(ProgramHeader);
    return !add_overflows(header.program_header_offset, table_size) &&
           header.program_header_offset + table_size <= size;
}

bool segment_valid(const ProgramHeader& segment, usize file_size) {
    if (segment.type != kProgramLoad) {
        return true;
    }
    if (segment.memory_size == 0 || segment.file_size > segment.memory_size ||
        (segment.flags & ~(kFlagRead | kFlagWrite | kFlagExecute)) != 0 ||
        (segment.flags & kFlagRead) == 0 ||
        (segment.flags & (kFlagWrite | kFlagExecute)) == (kFlagWrite | kFlagExecute) ||
        segment.virtual_address % memory::physical::kPageSize != 0 ||
        segment.offset % memory::physical::kPageSize != 0 ||
        (segment.alignment != 0 &&
         (!power_of_two(segment.alignment) ||
          segment.virtual_address % segment.alignment != segment.offset % segment.alignment)) ||
        add_overflows(segment.offset, segment.file_size) ||
        segment.offset + segment.file_size > file_size ||
        add_overflows(segment.virtual_address, segment.memory_size) ||
        segment.virtual_address < kMinimumUserAddress ||
        segment.virtual_address + segment.memory_size - 1 > kMaximumUserAddress ||
        add_overflows(segment.memory_size, memory::physical::kPageSize - 1)) {
        return false;
    }
    return true;
}

memory::virtual_memory::MapFlags final_flags(u32 elf_flags) {
    auto flags = memory::virtual_memory::MapFlags::user;
    if ((elf_flags & kFlagWrite) != 0) {
        flags = flags | memory::virtual_memory::MapFlags::write;
    }
    if ((elf_flags & kFlagExecute) != 0) {
        flags = flags | memory::virtual_memory::MapFlags::execute;
    }
    return flags;
}

void rollback(memory::virtual_memory::AddressSpace& space, Image& image) {
    while (image.page_count != 0) {
        --image.page_count;
        const Page& page = image.pages[image.page_count];
        (void)memory::virtual_memory::unmap(space, page.virtual_address);
        (void)memory::physical::free_page(page.physical_address,
                                          memory::physical::PageOwner::user_image,
                                          space.isolation_domain());
        image.pages[image.page_count] = {};
    }
    image = {};
}

bool page_overlaps(const Image& image, u64 virtual_address) {
    for (usize index = 0; index < image.page_count; ++index) {
        if (image.pages[index].virtual_address == virtual_address) {
            return true;
        }
    }
    return false;
}

bool equal_bytes(const u8* left, const u8* right, usize length) {
    for (usize index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}
}

bool load(memory::virtual_memory::AddressSpace& space, const void* data, usize size,
          Image& image) {
    image = {};
    if (!space.valid() || data == nullptr || size < sizeof(ElfHeader) ||
        size > kMaximumImageBytes) {
        reject();
        return false;
    }
    Snapshot snapshot{};
    if (!snapshot.capture(data, size) ||
        !security::image_policy::authorize(snapshot.bytes(), size)) {
        reject();
        return false;
    }
    const u8* bytes = snapshot.bytes();
    const auto* header = reinterpret_cast<const ElfHeader*>(bytes);
    if (!header_valid(*header, size)) {
        reject();
        return false;
    }
    const auto* programs = reinterpret_cast<const ProgramHeader*>(
        bytes + static_cast<usize>(header->program_header_offset));
    usize required_pages = 0;
    bool entry_executable = false;
    for (u16 index = 0; index < header->program_header_count; ++index) {
        const ProgramHeader& segment = programs[index];
        if (!segment_valid(segment, size)) {
            reject();
            return false;
        }
        if (segment.type != kProgramLoad) {
            continue;
        }
        const u64 page_count = align_up(segment.memory_size) / memory::physical::kPageSize;
        if (page_count > kMaximumImagePages - required_pages) {
            reject();
            return false;
        }
        required_pages += static_cast<usize>(page_count);
        if ((segment.flags & kFlagExecute) != 0 && header->entry >= segment.virtual_address &&
            header->entry - segment.virtual_address < segment.memory_size) {
            entry_executable = true;
        }
    }
    if (required_pages == 0 || !entry_executable) {
        reject();
        return false;
    }

    for (u16 index = 0; index < header->program_header_count; ++index) {
        const ProgramHeader& segment = programs[index];
        if (segment.type != kProgramLoad) {
            continue;
        }
        const u64 segment_pages = align_up(segment.memory_size) / memory::physical::kPageSize;
        for (u64 page_index = 0; page_index < segment_pages; ++page_index) {
            const u64 virtual_address =
                segment.virtual_address + page_index * memory::physical::kPageSize;
            if (page_overlaps(image, virtual_address)) {
                rollback(space, image);
                reject();
                return false;
            }
            u64 physical_address = 0;
            if (!memory::physical::allocate_page(physical_address,
                                                 memory::physical::PageOwner::user_image,
                                                 memory::physical::Zone::any,
                                                 space.isolation_domain()) ||
                !memory::virtual_memory::map(
                    space, virtual_address, physical_address,
                    memory::virtual_memory::MapFlags::user |
                        memory::virtual_memory::MapFlags::write)) {
                if (physical_address != 0) {
                    (void)memory::physical::free_page(
                        physical_address, memory::physical::PageOwner::user_image,
                        space.isolation_domain());
                }
                rollback(space, image);
                reject();
                return false;
            }
            image.pages[image.page_count++] = {
                .virtual_address = virtual_address,
                .physical_address = physical_address,
                .final_flags = final_flags(segment.flags),
            };
            const u64 file_position = page_index * memory::physical::kPageSize;
            if (file_position < segment.file_size) {
                const u64 remaining = segment.file_size - file_position;
                const usize chunk = static_cast<usize>(
                    remaining < memory::physical::kPageSize ? remaining : memory::physical::kPageSize);
                memory::virtual_memory::TemporaryMapping temporary{};
                if (!memory::virtual_memory::map_temporary_user(
                        space, physical_address, true, temporary)) {
                    rollback(space, image);
                    reject();
                    return false;
                }
                auto* destination = static_cast<u8*>(temporary.address);
                const u8* source = bytes + static_cast<usize>(segment.offset + file_position);
                for (usize byte = 0; byte < chunk; ++byte) {
                    destination[byte] = source[byte];
                }
                if (!memory::virtual_memory::unmap_temporary_user(temporary)) {
                    rollback(space, image);
                    reject();
                    return false;
                }
            }
        }
    }
    for (usize index = 0; index < image.page_count; ++index) {
        if (!memory::virtual_memory::protect(space, image.pages[index].virtual_address,
                                             image.pages[index].final_flags)) {
            rollback(space, image);
            reject();
            return false;
        }
    }
    image.loaded = true;
    image.entry_point = header->entry;
    __atomic_add_fetch(&loaded_images, 1ULL, __ATOMIC_RELAXED);
    __atomic_add_fetch(&mapped_pages, static_cast<u64>(image.page_count), __ATOMIC_RELAXED);
    return true;
}

bool unload(memory::virtual_memory::AddressSpace& space, Image& image) {
    if (!space.valid() || !image.loaded || image.page_count == 0) {
        reject();
        return false;
    }
    bool success = true;
    while (image.page_count != 0) {
        --image.page_count;
        const Page page = image.pages[image.page_count];
        if (!memory::virtual_memory::unmap(space, page.virtual_address) ||
            !memory::physical::free_page(page.physical_address,
                                         memory::physical::PageOwner::user_image,
                                         space.isolation_domain())) {
            success = false;
        }
        image.pages[image.page_count] = {};
    }
    image = {};
    if (!success) {
        reject();
        return false;
    }
    __atomic_add_fetch(&unloaded_images, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool self_test() {
    last_failure = 0;
    alignas(8) u8 blob[0x3000]{};
    auto* header = reinterpret_cast<ElfHeader*>(blob);
    header->identity[0] = 0x7F;
    header->identity[1] = 'E';
    header->identity[2] = 'L';
    header->identity[3] = 'F';
    header->identity[4] = 2;
    header->identity[5] = 1;
    header->identity[6] = 1;
    header->type = 2;
    header->machine = 62;
    header->version = 1;
    header->entry = 0x40'0000;
    header->program_header_offset = sizeof(ElfHeader);
    header->header_size = sizeof(ElfHeader);
    header->program_header_size = sizeof(ProgramHeader);
    header->program_header_count = 2;
    auto* programs = reinterpret_cast<ProgramHeader*>(blob + sizeof(ElfHeader));
    programs[0] = {
        .type = kProgramLoad,
        .flags = kFlagRead | kFlagExecute,
        .offset = 0x1000,
        .virtual_address = 0x40'0000,
        .physical_address = 0,
        .file_size = 4,
        .memory_size = 4,
        .alignment = memory::physical::kPageSize,
    };
    programs[1] = {
        .type = kProgramLoad,
        .flags = kFlagRead | kFlagWrite,
        .offset = 0x2000,
        .virtual_address = 0x40'1000,
        .physical_address = 0,
        .file_size = 4,
        .memory_size = 32,
        .alignment = memory::physical::kPageSize,
    };
    const u8 code[4] = {0x31, 0xC0, 0xC3, 0x90};
    const u8 data[4] = {0x44, 0x4F, 0x58, 0x58};
    for (usize index = 0; index < 4; ++index) {
        blob[0x1000 + index] = code[index];
        blob[0x2000 + index] = data[index];
    }

    if (!security::image_policy::enroll(blob, sizeof(blob))) {
        last_failure = 7;
        return false;
    }
    programs[0].flags = kFlagRead | kFlagWrite | kFlagExecute;
    if (!security::image_policy::enroll(blob, sizeof(blob))) {
        last_failure = 8;
        return false;
    }
    programs[0].flags = kFlagRead | kFlagExecute;
    if (!arch::x86_64::ring3::enroll_desktop_image() ||
        !security::image_policy::seal() || !security::image_policy::is_sealed() ||
        security::image_policy::enroll(blob, sizeof(blob))) {
        last_failure = 9;
        return false;
    }

    memory::virtual_memory::AddressSpace space{};
    Image image{};
    if (!memory::virtual_memory::create(space, 32)) {
        last_failure = 10;
        return false;
    }
    blob[sizeof(blob) - 1] = 0xA5;
    if (load(space, blob, sizeof(blob), image)) {
        last_failure = 11;
        return false;
    }
    blob[sizeof(blob) - 1] = 0;
    if (!load(space, blob, sizeof(blob), image) ||
        image.entry_point != 0x40'0000 || image.page_count != 2) {
        last_failure = 1;
        return false;
    }
    memory::virtual_memory::Mapping code_mapping{};
    memory::virtual_memory::Mapping data_mapping{};
    if (!memory::virtual_memory::query(space, 0x40'0000, code_mapping) ||
        !memory::virtual_memory::query(space, 0x40'1000, data_mapping) ||
        !memory::virtual_memory::has_flag(code_mapping.flags,
                                          memory::virtual_memory::MapFlags::execute) ||
        memory::virtual_memory::has_flag(code_mapping.flags,
                                         memory::virtual_memory::MapFlags::write) ||
        !memory::virtual_memory::has_flag(data_mapping.flags,
                                          memory::virtual_memory::MapFlags::write) ||
        memory::virtual_memory::has_flag(data_mapping.flags,
                                         memory::virtual_memory::MapFlags::execute)) {
        last_failure = 2;
        return false;
    }
    u8 copied_code[4]{};
    u8 copied_data[8]{};
    if (!memory::user_copy::copy_from_user(space, copied_code, 0x40'0000,
                                            sizeof(copied_code)) ||
        !memory::user_copy::copy_from_user(space, copied_data, 0x40'1000,
                                            sizeof(copied_data)) ||
        !equal_bytes(copied_code, code, sizeof(code)) ||
        !equal_bytes(copied_data, data, sizeof(data)) || copied_data[4] != 0 ||
        memory::user_copy::copy_to_user(space, 0x40'0000, data, sizeof(data))) {
        last_failure = 3;
        return false;
    }
    if (!unload(space, image) || memory::virtual_memory::query(space, 0x40'0000, code_mapping)) {
        last_failure = 4;
        return false;
    }
    programs[0].flags = kFlagRead | kFlagWrite | kFlagExecute;
    if (load(space, blob, sizeof(blob), image)) {
        last_failure = 5;
        return false;
    }
    if (!memory::virtual_memory::destroy(space)) {
        last_failure = 6;
        return false;
    }
    return true;
}

Statistics statistics() {
    return {
        .loaded_images = __atomic_load_n(&loaded_images, __ATOMIC_RELAXED),
        .unloaded_images = __atomic_load_n(&unloaded_images, __ATOMIC_RELAXED),
        .mapped_pages = __atomic_load_n(&mapped_pages, __ATOMIC_RELAXED),
        .rejected_images = __atomic_load_n(&rejected_images, __ATOMIC_RELAXED),
    };
}

u32 failure_code() { return last_failure; }
}
