#pragma once

#include <doxxer/security/capability.hpp>
#include <doxxer/types.hpp>

namespace doxxer::sync::event {
struct Handle {
    u16 slot;
    u32 generation;
};

struct Endpoints {
    security::capability::Token signaler;
    security::capability::Token waiter;
    security::capability::Token administrator;
};

struct Statistics {
    u32 active_events;
    u32 signaled_events;
    u64 signals;
    u64 successful_waits;
    u64 rejected_operations;
};

bool initialize();
bool create(security::capability::DomainHandle owner, bool manual_reset, bool initially_signaled,
            Handle& handle, Endpoints& endpoints);
bool signal(security::capability::DomainHandle domain, security::capability::Token endpoint);
bool try_wait(security::capability::DomainHandle domain, security::capability::Token endpoint);
bool reset(security::capability::DomainHandle domain, security::capability::Token administrator);
bool destroy(security::capability::DomainHandle domain, security::capability::Token administrator);
bool self_test();
Statistics statistics();
u32 failure_code();
}
