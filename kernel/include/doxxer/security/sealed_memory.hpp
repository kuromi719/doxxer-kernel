#pragma once

#include <doxxer/types.hpp>

namespace doxxer::security::sealed_memory {
inline constexpr usize kMaximumSecretBytes = 1024;

struct Handle {
    u16 slot;
    u32 generation;
};

struct Statistics {
    u64 sealed_objects;
    u64 opened_objects;
    u64 destroyed_objects;
    u64 authentication_failures;
    u64 rejected_operations;
    u32 capacity;
};

bool initialize(const volatile u64* entropy, usize entropy_words);
bool seal(const void* plaintext, usize size, Handle& handle);
bool open(Handle handle, void* plaintext, usize capacity, usize& size);
bool destroy(Handle handle);
bool self_test();
Statistics statistics();
u32 failure_code();
}
