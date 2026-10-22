#include <doxxer/memory/heap.hpp>
#include <doxxer/panic.hpp>
#include <doxxer/types.hpp>

namespace {
void* allocate_or_panic(doxxer::usize size) {
    if (size == 0) {
        size = 1;
    }
    void* pointer = doxxer::memory::heap::allocate(size);
    if (pointer == nullptr) {
        doxxer::panic("KERNEL HEAP EXHAUSTED");
    }
    return pointer;
}

void release_or_panic(void* pointer) {
    if (!doxxer::memory::heap::deallocate(pointer)) {
        doxxer::panic("KERNEL HEAP CORRUPTION DETECTED");
    }
}
}

void* operator new(doxxer::usize size) { return allocate_or_panic(size); }

void* operator new[](doxxer::usize size) { return allocate_or_panic(size); }

void operator delete(void* pointer) noexcept { release_or_panic(pointer); }

void operator delete[](void* pointer) noexcept { release_or_panic(pointer); }

void operator delete(void* pointer, doxxer::usize) noexcept { release_or_panic(pointer); }

void operator delete[](void* pointer, doxxer::usize) noexcept { release_or_panic(pointer); }
