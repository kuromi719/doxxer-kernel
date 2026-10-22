#include <doxxer/service/registry.hpp>

#include <doxxer/sync/spinlock.hpp>

namespace doxxer::service {
namespace {
constexpr u16 kMaximumServices = 32;
constexpr usize kMaximumNameLength = 31;

struct ServiceEntry {
    bool active = false;
    bool withdrawing = false;
    u32 generation = 1;
    char name[kMaximumNameLength + 1]{};
    security::capability::DomainHandle provider{};
    security::capability::Token source{};
    security::capability::ObjectType type = security::capability::ObjectType::none;
    security::capability::Rights offered_rights = 0;
    security::capability::ObjectHandle object{};
};

sync::SpinLock registry_lock{};
ServiceEntry services[kMaximumServices]{};
bool initialized = false;
u64 registration_count = 0;
u64 resolution_count = 0;
u64 rejected_operations = 0;
u32 last_failure = 0;

void reject() { __atomic_add_fetch(&rejected_operations, 1ULL, __ATOMIC_RELAXED); }

u32 next_generation(u32 generation) {
    ++generation;
    return generation == 0 ? 1 : generation;
}

bool valid_name_character(char value) {
    return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '.' ||
           value == '-';
}

bool copy_name(char (&destination)[kMaximumNameLength + 1], const char* source) {
    if (source == nullptr || source[0] == '\0') {
        return false;
    }
    usize index = 0;
    while (index < kMaximumNameLength && source[index] != '\0') {
        if (!valid_name_character(source[index])) {
            return false;
        }
        destination[index] = source[index];
        ++index;
    }
    if (source[index] != '\0') {
        return false;
    }
    destination[index] = '\0';
    for (++index; index <= kMaximumNameLength; ++index) {
        destination[index] = '\0';
    }
    return true;
}

bool names_equal(const char* left, const char* right) {
    if (right == nullptr) {
        return false;
    }
    for (usize index = 0; index <= kMaximumNameLength; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
        if (left[index] == '\0') {
            return true;
        }
    }
    return false;
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

bool publish(security::capability::DomainHandle provider, const char* name,
             security::capability::ObjectType type, security::capability::Token source,
             security::capability::Rights offered_rights, Registration& registration) {
    registration = {};
    char validated_name[kMaximumNameLength + 1]{};
    if (!copy_name(validated_name, name) || offered_rights == 0 ||
        (offered_rights & security::capability::rights(security::capability::Right::transfer)) !=
            0) {
        reject();
        return false;
    }
    security::capability::Lease source_lease{};
    if (!security::capability::acquire(
            provider, source, type,
            security::capability::rights(security::capability::Right::inspect), source_lease) ||
        (source_lease.granted_rights &
         security::capability::rights(security::capability::Right::transfer)) == 0 ||
        (offered_rights & ~source_lease.granted_rights) != 0) {
        if (source_lease.active) {
            security::capability::release(source_lease);
        }
        reject();
        return false;
    }
    security::capability::release(source_lease);

    sync::LockGuard guard(registry_lock);
    if (!initialized) {
        reject();
        return false;
    }
    ServiceEntry* available = nullptr;
    u16 available_slot = 0;
    for (u16 index = 0; index < kMaximumServices; ++index) {
        ServiceEntry& service = services[index];
        if (service.active && names_equal(service.name, validated_name)) {
            reject();
            return false;
        }
        if (!service.active && available == nullptr) {
            available = &service;
            available_slot = index;
        }
    }
    if (available == nullptr ||
        !security::capability::register_object(
            security::capability::ObjectType::service_registration, available,
            available->object)) {
        reject();
        return false;
    }
    const auto control_rights = security::capability::Right::inspect |
                                security::capability::Right::administer;
    if (!security::capability::grant(provider, available->object, control_rights,
                                     registration.control)) {
        (void)security::capability::unregister_object(available->object);
        reject();
        return false;
    }
    for (usize index = 0; index <= kMaximumNameLength; ++index) {
        available->name[index] = validated_name[index];
    }
    available->provider = provider;
    available->source = source;
    available->type = type;
    available->offered_rights = offered_rights;
    available->withdrawing = false;
    available->active = true;
    registration.handle = {.slot = available_slot, .generation = available->generation};
    __atomic_add_fetch(&registration_count, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool resolve(const char* name, security::capability::DomainHandle requester,
             security::capability::Rights requested_rights,
             security::capability::Token& delegated) {
    delegated = {};
    char validated_name[kMaximumNameLength + 1]{};
    if (!copy_name(validated_name, name) || requested_rights == 0) {
        reject();
        return false;
    }
    sync::LockGuard guard(registry_lock);
    for (ServiceEntry& service : services) {
        if (!service.active || service.withdrawing ||
            !names_equal(service.name, validated_name)) {
            continue;
        }
        if ((requested_rights & ~service.offered_rights) != 0 ||
            !security::capability::delegate(service.provider, service.source, requester,
                                            requested_rights, delegated)) {
            reject();
            return false;
        }
        __atomic_add_fetch(&resolution_count, 1ULL, __ATOMIC_RELAXED);
        return true;
    }
    reject();
    return false;
}

bool withdraw(security::capability::DomainHandle provider,
              security::capability::Token registration_control) {
    security::capability::Lease lease{};
    if (!security::capability::acquire(
            provider, registration_control,
            security::capability::ObjectType::service_registration,
            security::capability::rights(security::capability::Right::administer), lease)) {
        reject();
        return false;
    }
    auto* service = static_cast<ServiceEntry*>(lease.object);
    if (service == nullptr) {
        security::capability::release(lease);
        reject();
        return false;
    }
    const security::capability::ObjectHandle object = service->object;
    bool valid = false;
    {
        sync::LockGuard guard(registry_lock);
        if (service->active && !service->withdrawing) {
            service->withdrawing = true;
            valid = true;
        }
    }
    security::capability::release(lease);
    if (!valid) {
        reject();
        return false;
    }
    if (!security::capability::unregister_object(object)) {
        reject();
        return false;
    }
    {
        sync::LockGuard guard(registry_lock);
        service->active = false;
        service->withdrawing = false;
        service->generation = next_generation(service->generation);
        service->provider = {};
        service->source = {};
        service->type = security::capability::ObjectType::none;
        service->offered_rights = 0;
        service->object = {};
        for (char& character : service->name) {
            character = '\0';
        }
    }
    return true;
}

bool self_test() {
    last_failure = 0;
    security::capability::DomainHandle provider{};
    security::capability::DomainHandle requester{};
    security::capability::ObjectHandle object{};
    security::capability::Token source{};
    security::capability::Token resolved{};
    security::capability::Lease lease{};
    Registration registration{};
    Registration duplicate{};
    u64 probe = 0xD0'58'53'45'52'56'49'43ULL;
    if (!security::capability::create_domain(provider) ||
        !security::capability::create_domain(requester) ||
        !security::capability::register_object(security::capability::ObjectType::kernel_service,
                                               &probe, object) ||
        !security::capability::grant(
            provider, object,
            security::capability::Right::inspect | security::capability::Right::read |
                security::capability::Right::transfer,
            source) ||
        !publish(provider, "doxxer.clock", security::capability::ObjectType::kernel_service,
                 source, security::capability::rights(security::capability::Right::read),
                 registration)) {
        last_failure = 1;
        return false;
    }
    if (publish(provider, "doxxer.clock", security::capability::ObjectType::kernel_service,
                source, security::capability::rights(security::capability::Right::read),
                duplicate) ||
        publish(provider, "Doxxer Clock", security::capability::ObjectType::kernel_service,
                source, security::capability::rights(security::capability::Right::read),
                duplicate)) {
        last_failure = 2;
        return false;
    }
    if (!resolve("doxxer.clock", requester,
                 security::capability::rights(security::capability::Right::read), resolved) ||
        !security::capability::acquire(requester, resolved,
                                       security::capability::ObjectType::kernel_service,
                                       security::capability::rights(
                                           security::capability::Right::read),
                                       lease) ||
        lease.object != &probe) {
        last_failure = 3;
        return false;
    }
    security::capability::release(lease);
    if (resolve("doxxer.clock", requester,
                security::capability::rights(security::capability::Right::write), resolved) ||
        !withdraw(provider, registration.control) ||
        resolve("doxxer.clock", requester,
                security::capability::rights(security::capability::Right::read), resolved)) {
        last_failure = 4;
        return false;
    }
    if (!security::capability::revoke(provider, source) ||
        !security::capability::unregister_object(object) ||
        !security::capability::destroy_domain(requester) ||
        !security::capability::destroy_domain(provider)) {
        last_failure = 5;
        return false;
    }
    return true;
}

Statistics statistics() {
    Statistics result{
        .active_services = 0,
        .registrations = __atomic_load_n(&registration_count, __ATOMIC_RELAXED),
        .resolutions = __atomic_load_n(&resolution_count, __ATOMIC_RELAXED),
        .rejected_operations = __atomic_load_n(&rejected_operations, __ATOMIC_RELAXED),
    };
    sync::LockGuard guard(registry_lock);
    for (const ServiceEntry& service : services) {
        result.active_services += service.active ? 1U : 0U;
    }
    return result;
}

u32 failure_code() { return last_failure; }
}
