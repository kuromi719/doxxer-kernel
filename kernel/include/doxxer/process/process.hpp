#pragma once

#include <doxxer/security/capability.hpp>
#include <doxxer/types.hpp>

namespace doxxer::process {
enum class State : u8 {
    ready = 1,
    exited = 2,
};

struct Handle {
    u16 slot;
    u32 generation;
};

struct CreateResult {
    Handle handle;
    security::capability::DomainHandle domain;
    security::capability::Token control;
};

struct Info {
    u64 identifier;
    State state;
    u32 exit_code;
    u64 address_space_root;
    u16 pcid;
    char name[24];
};

struct Statistics {
    u32 active_processes;
    u64 created_processes;
    u64 exited_processes;
    u64 destroyed_processes;
    u64 rejected_operations;
};

bool initialize();
bool create(security::capability::DomainHandle manager, const char* name, CreateResult& result);
bool inspect(security::capability::DomainHandle manager, security::capability::Token control,
             Info& info);
bool terminate(security::capability::DomainHandle manager, security::capability::Token control,
               u32 exit_code);
bool destroy(security::capability::DomainHandle manager, security::capability::Token control);
bool self_test();
Statistics statistics();
u32 failure_code();
}
