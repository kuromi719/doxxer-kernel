#pragma once

#include <doxxer/security/capability.hpp>
#include <doxxer/memory/virtual.hpp>
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
    memory::physical::IsolationDomain isolation_domain;
    char name[24];
};

struct Statistics {
    u32 active_processes;
    u64 created_processes;
    u64 exited_processes;
    u64 destroyed_processes;
    u64 rejected_operations;
};

struct AddressSpaceLease {
    memory::virtual_memory::AddressSpace* space;
    void* process_cookie;
    State state;
    bool active;
};

bool initialize();
bool create(security::capability::DomainHandle manager, const char* name, CreateResult& result);
bool inspect(security::capability::DomainHandle manager, security::capability::Token control,
             Info& info);
bool terminate(security::capability::DomainHandle manager, security::capability::Token control,
               u32 exit_code);
bool destroy(security::capability::DomainHandle manager, security::capability::Token control);
bool acquire_address_space(security::capability::DomainHandle manager,
                           security::capability::Token control, AddressSpaceLease& lease);
void release_address_space(AddressSpaceLease& lease);
bool self_test();
Statistics statistics();
u32 failure_code();
}
