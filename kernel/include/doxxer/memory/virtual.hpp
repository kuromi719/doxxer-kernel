#pragma once

#include <doxxer/sync/spinlock.hpp>
#include <doxxer/types.hpp>

namespace doxxer::memory::virtual_memory {
enum class MapFlags : u8 {
    none = 0,
    write = 1U << 0U,
    execute = 1U << 1U,
    user = 1U << 2U,
    global = 1U << 3U,
    cache_disable = 1U << 4U,
};

constexpr MapFlags operator|(MapFlags left, MapFlags right) {
    return static_cast<MapFlags>(static_cast<u8>(left) | static_cast<u8>(right));
}

constexpr bool has_flag(MapFlags value, MapFlags flag) {
    return (static_cast<u8>(value) & static_cast<u8>(flag)) != 0;
}

enum class PageSize : u64 {
    size_4k = 4096,
    size_2m = 2 * 1024 * 1024,
};

struct Mapping {
    u64 physical_address;
    PageSize page_size;
    MapFlags flags;
};

class AddressSpace final {
  public:
    AddressSpace() = default;
    AddressSpace(const AddressSpace&) = delete;
    AddressSpace& operator=(const AddressSpace&) = delete;

    bool valid() const { return root_physical_ != 0; }
    u64 root_physical() const { return root_physical_; }
    u16 pcid() const { return pcid_; }
    bool owns_supervisor_windows() const { return owns_supervisor_windows_; }

  private:
    friend bool create(AddressSpace&, u16);
    friend bool destroy(AddressSpace&);
    friend bool map(AddressSpace&, u64, u64, MapFlags, PageSize);
    friend bool unmap(AddressSpace&, u64);
    friend bool protect(AddressSpace&, u64, MapFlags);
    friend bool query(AddressSpace&, u64, Mapping&);

    u64 root_physical_ = 0;
    u16 pcid_ = 0;
    bool owns_supervisor_windows_ = false;
    sync::SpinLock lock_{};
};

bool create(AddressSpace& space, u16 pcid = 0);
bool destroy(AddressSpace& space);
bool activate(AddressSpace& space);
AddressSpace* active_address_space();
bool map(AddressSpace& space, u64 virtual_address, u64 physical_address, MapFlags flags,
         PageSize page_size = PageSize::size_4k);
bool unmap(AddressSpace& space, u64 virtual_address);
bool protect(AddressSpace& space, u64 virtual_address, MapFlags flags);
bool query(AddressSpace& space, u64 virtual_address, Mapping& mapping);
bool is_canonical(u64 virtual_address);
bool self_test();
u32 self_test_failure();
}
