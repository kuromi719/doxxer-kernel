#pragma once

#include <doxxer/process/process.hpp>
#include <doxxer/security/capability.hpp>
#include <doxxer/types.hpp>

namespace doxxer::thread::user {
enum class State : u8 {
    ready = 1,
    exited = 2,
};

struct Handle {
    u16 slot;
    u32 generation;
};

struct Context {
    u64 r15;
    u64 r14;
    u64 r13;
    u64 r12;
    u64 rbp;
    u64 rbx;
    u64 rip;
    u64 rsp;
    u64 rflags;
    u64 fs_base;
    u16 code_selector;
    u16 stack_selector;
};

struct CreateResult {
    Handle handle;
    security::capability::Token control;
};

struct Info {
    u64 identifier;
    State state;
    u32 exit_code;
    Context context;
    u64 stack_guard;
    u64 stack_base;
    u64 stack_top;
};

struct Statistics {
    u32 active_threads;
    u64 created_threads;
    u64 destroyed_threads;
    u64 rejected_operations;
};

bool initialize();
bool create(security::capability::DomainHandle manager,
            security::capability::Token process_control, u64 entry_point,
            CreateResult& result);
bool inspect(security::capability::DomainHandle manager,
             security::capability::Token thread_control, Info& info);
bool terminate(security::capability::DomainHandle manager,
               security::capability::Token thread_control, u32 exit_code);
bool destroy(security::capability::DomainHandle manager,
             security::capability::Token thread_control);
bool self_test();
Statistics statistics();
u32 failure_code();
}
