#pragma once

#include <doxxer/types.hpp>

namespace doxxer::scheduler {
using TaskEntry = void (*)(void* argument);

struct TaskHandle {
    u32 slot;
    u32 generation;
};

struct Statistics {
    u64 submitted;
    u64 completed;
    u64 failed;
    u32 capacity;
};

bool initialize();
bool submit(TaskEntry entry, void* argument, TaskHandle& handle);
bool completed(TaskHandle handle);
bool release(TaskHandle handle);
bool pump_one();
bool self_test();
Statistics statistics();
u32 failure_code();
}
