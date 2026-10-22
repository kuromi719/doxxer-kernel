#include <doxxer/panic.hpp>

extern "C" {
int __cxa_atexit(void (*)(void*), void*, void*) {
    return 0;
}

void __cxa_pure_virtual() {
    doxxer::panic("PURE VIRTUAL CALL");
}

void __cxa_deleted_virtual() {
    doxxer::panic("DELETED VIRTUAL CALL");
}

void* __dso_handle = nullptr;

__attribute__((no_stack_protector)) void __stack_chk_fail() {
    doxxer::panic("STACK CORRUPTION DETECTED");
}
}
