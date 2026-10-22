#include <doxxer/sync/event.hpp>

#include <doxxer/sync/spinlock.hpp>

namespace doxxer::sync::event {
namespace {
constexpr u16 kMaximumEvents = 32;

struct Event {
    sync::SpinLock lock{};
    bool active = false;
    bool manual_reset = false;
    bool signaled = false;
    u32 generation = 1;
    security::capability::ObjectHandle object{};
};

sync::SpinLock registry_lock{};
Event events[kMaximumEvents]{};
bool initialized = false;
u64 signal_count = 0;
u64 successful_waits = 0;
u64 rejected_operations = 0;
u32 last_failure = 0;

void reject() { __atomic_add_fetch(&rejected_operations, 1ULL, __ATOMIC_RELAXED); }

u32 next_generation(u32 generation) {
    ++generation;
    return generation == 0 ? 1 : generation;
}

Event* acquire_event(security::capability::DomainHandle domain,
                     security::capability::Token token, security::capability::Rights rights,
                     security::capability::Lease& lease) {
    if (!security::capability::acquire(domain, token, security::capability::ObjectType::event,
                                       rights, lease)) {
        reject();
        return nullptr;
    }
    auto* event = static_cast<Event*>(lease.object);
    if (event == nullptr || !event->active) {
        security::capability::release(lease);
        reject();
        return nullptr;
    }
    return event;
}
}

bool initialize() {
    sync::LockGuard guard(registry_lock);
    if (initialized) {
        return false;
    }
    initialized = true;
    return true;
}

bool create(security::capability::DomainHandle owner, bool manual_reset, bool initially_signaled,
            Handle& handle, Endpoints& endpoints) {
    handle = {};
    endpoints = {};
    sync::LockGuard guard(registry_lock);
    if (!initialized) {
        reject();
        return false;
    }
    for (u16 index = 0; index < kMaximumEvents; ++index) {
        Event& event = events[index];
        if (event.active) {
            continue;
        }
        event.manual_reset = manual_reset;
        event.signaled = initially_signaled;
        if (!security::capability::register_object(security::capability::ObjectType::event, &event,
                                                   event.object)) {
            reject();
            return false;
        }
        const auto signal_rights = security::capability::Right::inspect |
                                   security::capability::Right::signal;
        const auto wait_rights = security::capability::Right::inspect |
                                 security::capability::Right::wait;
        const auto admin_rights = security::capability::Right::inspect |
                                  security::capability::Right::administer;
        if (!security::capability::grant(owner, event.object, signal_rights, endpoints.signaler) ||
            !security::capability::grant(owner, event.object, wait_rights, endpoints.waiter) ||
            !security::capability::grant(owner, event.object, admin_rights,
                                         endpoints.administrator)) {
            (void)security::capability::revoke(owner, endpoints.signaler);
            (void)security::capability::revoke(owner, endpoints.waiter);
            (void)security::capability::unregister_object(event.object);
            endpoints = {};
            reject();
            return false;
        }
        event.active = true;
        handle = {.slot = index, .generation = event.generation};
        return true;
    }
    reject();
    return false;
}

bool signal(security::capability::DomainHandle domain, security::capability::Token endpoint) {
    security::capability::Lease lease{};
    Event* event = acquire_event(
        domain, endpoint, security::capability::rights(security::capability::Right::signal), lease);
    if (event == nullptr) {
        return false;
    }
    {
        sync::LockGuard guard(event->lock);
        event->signaled = true;
    }
    security::capability::release(lease);
    __atomic_add_fetch(&signal_count, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool try_wait(security::capability::DomainHandle domain, security::capability::Token endpoint) {
    security::capability::Lease lease{};
    Event* event = acquire_event(
        domain, endpoint, security::capability::rights(security::capability::Right::wait), lease);
    if (event == nullptr) {
        return false;
    }
    bool success = false;
    {
        sync::LockGuard guard(event->lock);
        if (event->signaled) {
            success = true;
            if (!event->manual_reset) {
                event->signaled = false;
            }
        }
    }
    security::capability::release(lease);
    if (!success) {
        reject();
        return false;
    }
    __atomic_add_fetch(&successful_waits, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool reset(security::capability::DomainHandle domain,
           security::capability::Token administrator) {
    security::capability::Lease lease{};
    Event* event = acquire_event(domain, administrator,
                                 security::capability::rights(
                                     security::capability::Right::administer),
                                 lease);
    if (event == nullptr) {
        return false;
    }
    {
        sync::LockGuard guard(event->lock);
        event->signaled = false;
    }
    security::capability::release(lease);
    return true;
}

bool destroy(security::capability::DomainHandle domain,
             security::capability::Token administrator) {
    security::capability::Lease lease{};
    Event* event = acquire_event(domain, administrator,
                                 security::capability::rights(
                                     security::capability::Right::administer),
                                 lease);
    if (event == nullptr) {
        return false;
    }
    const security::capability::ObjectHandle object = event->object;
    {
        sync::LockGuard guard(event->lock);
        event->active = false;
        event->signaled = false;
        event->generation = next_generation(event->generation);
    }
    security::capability::release(lease);
    if (!security::capability::unregister_object(object)) {
        reject();
        return false;
    }
    return true;
}

bool self_test() {
    last_failure = 0;
    security::capability::DomainHandle domain{};
    Handle automatic{};
    Handle manual{};
    Endpoints automatic_endpoints{};
    Endpoints manual_endpoints{};
    if (!security::capability::create_domain(domain) ||
        !create(domain, false, false, automatic, automatic_endpoints) ||
        !create(domain, true, true, manual, manual_endpoints)) {
        last_failure = 1;
        return false;
    }
    if (try_wait(domain, automatic_endpoints.waiter) ||
        !signal(domain, automatic_endpoints.signaler) ||
        !try_wait(domain, automatic_endpoints.waiter) ||
        try_wait(domain, automatic_endpoints.waiter)) {
        last_failure = 2;
        return false;
    }
    if (!try_wait(domain, manual_endpoints.waiter) ||
        !try_wait(domain, manual_endpoints.waiter) ||
        !reset(domain, manual_endpoints.administrator) ||
        try_wait(domain, manual_endpoints.waiter)) {
        last_failure = 3;
        return false;
    }
    if (signal(domain, automatic_endpoints.waiter) ||
        reset(domain, automatic_endpoints.signaler)) {
        last_failure = 4;
        return false;
    }
    if (!destroy(domain, automatic_endpoints.administrator) ||
        signal(domain, automatic_endpoints.signaler) ||
        !destroy(domain, manual_endpoints.administrator) ||
        !security::capability::destroy_domain(domain)) {
        last_failure = 5;
        return false;
    }
    return true;
}

Statistics statistics() {
    Statistics result{
        .active_events = 0,
        .signaled_events = 0,
        .signals = __atomic_load_n(&signal_count, __ATOMIC_RELAXED),
        .successful_waits = __atomic_load_n(&successful_waits, __ATOMIC_RELAXED),
        .rejected_operations = __atomic_load_n(&rejected_operations, __ATOMIC_RELAXED),
    };
    for (auto& event : events) {
        sync::LockGuard guard(event.lock);
        if (event.active) {
            ++result.active_events;
            result.signaled_events += event.signaled ? 1U : 0U;
        }
    }
    return result;
}

u32 failure_code() { return last_failure; }
}
