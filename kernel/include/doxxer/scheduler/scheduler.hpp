#pragma once

#include <doxxer/thread/user_thread.hpp>
#include <doxxer/types.hpp>

namespace doxxer::scheduler {
using TaskEntry = void (*)(void* argument);

struct TaskHandle {
    u32 slot;
    u32 generation;
};

struct UserContextBinding {
    thread::user::ExecutionLease* execution;
    u32 cpu;
    u32 generation;
    bool active;
};

struct Statistics {
    u64 submitted;
    u64 completed;
    u64 failed;
    u64 user_context_binds;
    u64 user_context_rejections;
    u32 capacity;
};

bool initialize();
bool submit(TaskEntry entry, void* argument, TaskHandle& handle);
bool completed(TaskHandle handle);
bool release(TaskHandle handle);
bool pump_one();
bool bind_user_context(thread::user::ExecutionLease& execution, UserContextBinding& binding);
bool unbind_user_context(UserContextBinding& binding);
bool self_test();
Statistics statistics();
u32 failure_code();
}
