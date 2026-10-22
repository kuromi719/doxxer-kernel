#pragma once

#include <doxxer/security/capability.hpp>
#include <doxxer/types.hpp>

namespace doxxer::service {
struct RegistrationHandle {
    u16 slot;
    u32 generation;
};

struct Registration {
    RegistrationHandle handle;
    security::capability::Token control;
};

struct Statistics {
    u32 active_services;
    u64 registrations;
    u64 resolutions;
    u64 rejected_operations;
};

bool initialize();
bool publish(security::capability::DomainHandle provider, const char* name,
             security::capability::ObjectType type, security::capability::Token source,
             security::capability::Rights offered_rights, Registration& registration);
bool resolve(const char* name, security::capability::DomainHandle requester,
             security::capability::Rights requested_rights,
             security::capability::Token& delegated);
bool withdraw(security::capability::DomainHandle provider,
              security::capability::Token registration_control);
bool self_test();
Statistics statistics();
u32 failure_code();
}
