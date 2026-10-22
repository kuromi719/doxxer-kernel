#pragma once

#include <doxxer/types.hpp>

namespace doxxer::security::capability {
enum class ObjectType : u16 {
    none = 0,
    kernel_service = 1,
    ipc_channel = 2,
    address_space = 3,
    task = 4,
    event = 5,
};

enum class Right : u32 {
    none = 0,
    inspect = 1U << 0U,
    read = 1U << 1U,
    write = 1U << 2U,
    signal = 1U << 3U,
    wait = 1U << 4U,
    map = 1U << 5U,
    derive = 1U << 6U,
    transfer = 1U << 7U,
    administer = 1U << 8U,
};

using Rights = u32;

constexpr Rights rights(Right value) { return static_cast<Rights>(value); }
constexpr Rights operator|(Right left, Right right) { return rights(left) | rights(right); }
constexpr Rights operator|(Rights left, Right right) { return left | rights(right); }

struct DomainHandle {
    u16 slot;
    u32 generation;
};

struct ObjectHandle {
    u16 slot;
    u32 generation;
};

struct Token {
    u64 value;
};

struct Lease {
    void* object;
    ObjectType type;
    Rights granted_rights;
    u16 object_slot;
    u32 object_generation;
    bool active;
};

struct Statistics {
    u32 active_domains;
    u32 active_objects;
    u32 active_capabilities;
    u32 active_leases;
    u64 rejected_operations;
};

bool initialize();
bool create_domain(DomainHandle& handle);
bool destroy_domain(DomainHandle handle);
bool register_object(ObjectType type, void* object, ObjectHandle& handle);
bool unregister_object(ObjectHandle handle);
bool grant(DomainHandle domain, ObjectHandle object, Rights granted_rights, Token& token);
bool derive(DomainHandle domain, Token parent, Rights reduced_rights, Token& token);
bool revoke(DomainHandle domain, Token token);
bool acquire(DomainHandle domain, Token token, ObjectType expected_type, Rights required_rights,
             Lease& lease);
void release(Lease& lease);
bool self_test();
Statistics statistics();
u32 failure_code();
}
