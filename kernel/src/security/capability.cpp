#include <doxxer/security/capability.hpp>

#include <doxxer/sync/spinlock.hpp>

extern "C" doxxer::uptr __stack_chk_guard;

namespace doxxer::security::capability {
namespace {
constexpr u16 kMaximumDomains = 16;
constexpr u16 kMaximumObjects = 64;
constexpr u16 kCapabilitiesPerDomain = 64;
constexpr u16 kInvalidSlot = 0xFFFFU;
constexpr u32 kGenerationBits = 22;
constexpr u32 kGenerationMask = (1U << kGenerationBits) - 1U;
constexpr u32 kSlotBits = 6;
constexpr u64 kTagMask = (1ULL << 36U) - 1ULL;
constexpr u32 kMaximumDerivationDepth = 8;
constexpr Rights kKnownRights = rights(Right::inspect) | Right::read | Right::write |
                                Right::signal | Right::wait | Right::map | Right::derive |
                                Right::transfer | Right::administer;

struct CapabilityEntry {
    bool active;
    u32 generation;
    u16 object_slot;
    u32 object_generation;
    ObjectType type;
    Rights granted_rights;
    u16 parent_slot;
    u32 parent_generation;
    u16 parent_domain_slot;
    u32 parent_domain_generation;
};

struct DomainEntry {
    bool active;
    u32 generation;
    u64 nonce;
    CapabilityEntry capabilities[kCapabilitiesPerDomain];
};

struct ObjectEntry {
    bool active;
    u32 generation;
    ObjectType type;
    void* object;
    u32 leases;
};

sync::SpinLock registry_lock{};
DomainEntry domains[kMaximumDomains]{};
ObjectEntry objects[kMaximumObjects]{};
u64 secret = 0;
u64 nonce_counter = 0;
u64 rejected = 0;
u32 last_failure = 0;
bool initialized = false;

u64 mix64(u64 value) {
    value ^= value >> 30U;
    value *= 0xBF58'476D'1CE4'E5B9ULL;
    value ^= value >> 27U;
    value *= 0x94D0'49BB'1331'11EBULL;
    value ^= value >> 31U;
    return value;
}

bool rights_valid(Rights value, bool allow_none = false) {
    return (value & ~kKnownRights) == 0 && (allow_none || value != 0);
}

bool type_valid(ObjectType type) {
    return type >= ObjectType::kernel_service && type <= ObjectType::event;
}

u32 next_generation(u32 generation) {
    generation = (generation + 1U) & kGenerationMask;
    return generation == 0 ? 1 : generation;
}

DomainEntry* valid_domain(DomainHandle handle) {
    if (handle.slot >= kMaximumDomains) {
        return nullptr;
    }
    DomainEntry& domain = domains[handle.slot];
    return domain.active && domain.generation == handle.generation ? &domain : nullptr;
}

ObjectEntry* valid_object(ObjectHandle handle) {
    if (handle.slot >= kMaximumObjects) {
        return nullptr;
    }
    ObjectEntry& object = objects[handle.slot];
    return object.active && object.generation == handle.generation ? &object : nullptr;
}

u64 authentication_tag(const DomainEntry& domain, u16 slot, const CapabilityEntry& capability) {
    u64 value = secret ^ domain.nonce ^ (static_cast<u64>(slot) << 56U) ^
                (static_cast<u64>(capability.generation) << 32U) ^
                (static_cast<u64>(capability.object_slot) << 16U) ^ capability.object_generation;
    value ^= static_cast<u64>(capability.granted_rights) << 21U;
    value ^= static_cast<u64>(capability.type) << 9U;
    value ^= static_cast<u64>(capability.parent_slot) << 47U;
    value ^= capability.parent_generation;
    value ^= static_cast<u64>(capability.parent_domain_slot) << 37U;
    value ^= static_cast<u64>(capability.parent_domain_generation) << 3U;
    return mix64(value) & kTagMask;
}

Token encode_token(const DomainEntry& domain, u16 slot, const CapabilityEntry& capability) {
    const u64 tag = authentication_tag(domain, slot, capability);
    return {.value = static_cast<u64>(slot) |
                     (static_cast<u64>(capability.generation) << kSlotBits) | (tag << 28U)};
}

bool decode_token(const DomainEntry& domain, Token token, u16& slot, CapabilityEntry*& capability) {
    slot = static_cast<u16>(token.value & ((1U << kSlotBits) - 1U));
    const u32 generation = static_cast<u32>((token.value >> kSlotBits) & kGenerationMask);
    const u64 tag = token.value >> 28U;
    if (slot >= kCapabilitiesPerDomain) {
        return false;
    }
    CapabilityEntry& candidate = const_cast<CapabilityEntry&>(domain.capabilities[slot]);
    if (!candidate.active || candidate.generation != generation ||
        authentication_tag(domain, slot, candidate) != tag) {
        return false;
    }
    capability = &candidate;
    return true;
}

bool ancestry_valid(const CapabilityEntry& capability) {
    const CapabilityEntry* child = &capability;
    for (u32 depth = 0; depth <= kMaximumDerivationDepth; ++depth) {
        if (child->parent_slot == kInvalidSlot) {
            return child->parent_domain_slot == kInvalidSlot;
        }
        if (child->parent_slot >= kCapabilitiesPerDomain ||
            child->parent_domain_slot >= kMaximumDomains) {
            return false;
        }
        const DomainEntry& parent_domain = domains[child->parent_domain_slot];
        if (!parent_domain.active ||
            parent_domain.generation != child->parent_domain_generation) {
            return false;
        }
        const CapabilityEntry& parent = parent_domain.capabilities[child->parent_slot];
        if (!parent.active || parent.generation != child->parent_generation ||
            parent.object_slot != child->object_slot ||
            parent.object_generation != child->object_generation ||
            (child->granted_rights & ~parent.granted_rights) != 0) {
            return false;
        }
        child = &parent;
    }
    return false;
}

CapabilityEntry* allocate_capability(DomainEntry& domain, u16& slot) {
    for (u16 index = 0; index < kCapabilitiesPerDomain; ++index) {
        if (!domain.capabilities[index].active) {
            slot = index;
            CapabilityEntry& capability = domain.capabilities[index];
            if (capability.generation == 0) {
                capability.generation = 1;
            }
            return &capability;
        }
    }
    return nullptr;
}

void invalidate_capability(CapabilityEntry& capability) {
    capability.active = false;
    capability.generation = next_generation(capability.generation);
    capability.object_slot = kInvalidSlot;
    capability.object_generation = 0;
    capability.type = ObjectType::none;
    capability.granted_rights = 0;
    capability.parent_slot = kInvalidSlot;
    capability.parent_generation = 0;
    capability.parent_domain_slot = kInvalidSlot;
    capability.parent_domain_generation = 0;
}

void reject() { ++rejected; }
}

bool initialize() {
    sync::LockGuard guard(registry_lock);
    if (initialized) {
        return false;
    }
    secret = mix64(static_cast<u64>(__stack_chk_guard) ^ 0xD0'58'43'41'50'53'45'43ULL);
    if (secret == 0) {
        return false;
    }
    for (auto& domain : domains) {
        domain.generation = 1;
        for (auto& capability : domain.capabilities) {
            capability.generation = 1;
            capability.object_slot = kInvalidSlot;
            capability.parent_slot = kInvalidSlot;
            capability.parent_domain_slot = kInvalidSlot;
        }
    }
    for (auto& object : objects) {
        object.generation = 1;
    }
    initialized = true;
    return true;
}

bool create_domain(DomainHandle& handle) {
    sync::LockGuard guard(registry_lock);
    if (!initialized) {
        reject();
        return false;
    }
    for (u16 index = 0; index < kMaximumDomains; ++index) {
        DomainEntry& domain = domains[index];
        if (domain.active) {
            continue;
        }
        domain.active = true;
        domain.nonce =
            mix64(secret ^ ++nonce_counter ^ (static_cast<u64>(index) << 48U) ^ domain.generation);
        for (auto& capability : domain.capabilities) {
            invalidate_capability(capability);
        }
        handle = {.slot = index, .generation = domain.generation};
        return true;
    }
    reject();
    return false;
}

bool destroy_domain(DomainHandle handle) {
    sync::LockGuard guard(registry_lock);
    DomainEntry* domain = valid_domain(handle);
    if (domain == nullptr) {
        reject();
        return false;
    }
    for (auto& capability : domain->capabilities) {
        invalidate_capability(capability);
    }
    domain->active = false;
    domain->nonce = 0;
    domain->generation = next_generation(domain->generation);
    return true;
}

bool register_object(ObjectType type, void* object_pointer, ObjectHandle& handle) {
    sync::LockGuard guard(registry_lock);
    if (!initialized || !type_valid(type) || object_pointer == nullptr) {
        reject();
        return false;
    }
    for (u16 index = 0; index < kMaximumObjects; ++index) {
        ObjectEntry& object = objects[index];
        if (object.active || object.leases != 0) {
            continue;
        }
        object.active = true;
        object.type = type;
        object.object = object_pointer;
        handle = {.slot = index, .generation = object.generation};
        return true;
    }
    reject();
    return false;
}

bool unregister_object(ObjectHandle handle) {
    sync::LockGuard guard(registry_lock);
    ObjectEntry* object = valid_object(handle);
    if (object == nullptr || object->leases != 0) {
        reject();
        return false;
    }
    object->active = false;
    object->generation = next_generation(object->generation);
    object->type = ObjectType::none;
    object->object = nullptr;
    return true;
}

bool grant(DomainHandle domain_handle, ObjectHandle object_handle, Rights granted_rights,
           Token& token) {
    sync::LockGuard guard(registry_lock);
    DomainEntry* domain = valid_domain(domain_handle);
    ObjectEntry* object = valid_object(object_handle);
    if (domain == nullptr || object == nullptr || !rights_valid(granted_rights)) {
        reject();
        return false;
    }
    u16 slot = 0;
    CapabilityEntry* capability = allocate_capability(*domain, slot);
    if (capability == nullptr) {
        reject();
        return false;
    }
    capability->object_slot = object_handle.slot;
    capability->object_generation = object_handle.generation;
    capability->type = object->type;
    capability->granted_rights = granted_rights;
    capability->parent_slot = kInvalidSlot;
    capability->parent_generation = 0;
    capability->parent_domain_slot = kInvalidSlot;
    capability->parent_domain_generation = 0;
    capability->active = true;
    token = encode_token(*domain, slot, *capability);
    return true;
}

bool derive(DomainHandle domain_handle, Token parent_token, Rights reduced_rights, Token& token) {
    sync::LockGuard guard(registry_lock);
    DomainEntry* domain = valid_domain(domain_handle);
    u16 parent_slot = 0;
    CapabilityEntry* parent = nullptr;
    if (domain == nullptr || !rights_valid(reduced_rights) ||
        !decode_token(*domain, parent_token, parent_slot, parent) ||
        !ancestry_valid(*parent) ||
        (parent->granted_rights & rights(Right::derive)) == 0 ||
        (reduced_rights & ~parent->granted_rights) != 0) {
        reject();
        return false;
    }
    u16 slot = 0;
    CapabilityEntry* child = allocate_capability(*domain, slot);
    if (child == nullptr) {
        reject();
        return false;
    }
    child->object_slot = parent->object_slot;
    child->object_generation = parent->object_generation;
    child->type = parent->type;
    child->granted_rights = reduced_rights;
    child->parent_slot = parent_slot;
    child->parent_generation = parent->generation;
    child->parent_domain_slot = domain_handle.slot;
    child->parent_domain_generation = domain_handle.generation;
    child->active = true;
    token = encode_token(*domain, slot, *child);
    return true;
}

bool delegate(DomainHandle source_domain_handle, Token source_token,
              DomainHandle destination_domain_handle, Rights reduced_rights, Token& token) {
    sync::LockGuard guard(registry_lock);
    DomainEntry* source_domain = valid_domain(source_domain_handle);
    DomainEntry* destination_domain = valid_domain(destination_domain_handle);
    u16 source_slot = 0;
    CapabilityEntry* source = nullptr;
    if (source_domain == nullptr || destination_domain == nullptr ||
        !rights_valid(reduced_rights) ||
        !decode_token(*source_domain, source_token, source_slot, source) ||
        !ancestry_valid(*source) ||
        (source->granted_rights & rights(Right::transfer)) == 0 ||
        (reduced_rights & ~source->granted_rights) != 0) {
        reject();
        return false;
    }
    u16 destination_slot = 0;
    CapabilityEntry* delegated = allocate_capability(*destination_domain, destination_slot);
    if (delegated == nullptr) {
        reject();
        return false;
    }
    delegated->object_slot = source->object_slot;
    delegated->object_generation = source->object_generation;
    delegated->type = source->type;
    delegated->granted_rights = reduced_rights;
    delegated->parent_slot = source_slot;
    delegated->parent_generation = source->generation;
    delegated->parent_domain_slot = source_domain_handle.slot;
    delegated->parent_domain_generation = source_domain_handle.generation;
    delegated->active = true;
    token = encode_token(*destination_domain, destination_slot, *delegated);
    return true;
}

bool revoke(DomainHandle domain_handle, Token token) {
    sync::LockGuard guard(registry_lock);
    DomainEntry* domain = valid_domain(domain_handle);
    u16 slot = 0;
    CapabilityEntry* capability = nullptr;
    if (domain == nullptr || !decode_token(*domain, token, slot, capability) ||
        !ancestry_valid(*capability)) {
        reject();
        return false;
    }
    invalidate_capability(*capability);
    return true;
}

bool acquire(DomainHandle domain_handle, Token token, ObjectType expected_type,
             Rights required_rights, Lease& lease) {
    lease = {};
    sync::LockGuard guard(registry_lock);
    DomainEntry* domain = valid_domain(domain_handle);
    u16 slot = 0;
    CapabilityEntry* capability = nullptr;
    if (domain == nullptr || !type_valid(expected_type) || !rights_valid(required_rights) ||
        !decode_token(*domain, token, slot, capability) || !ancestry_valid(*capability) ||
        capability->type != expected_type || (required_rights & ~capability->granted_rights) != 0 ||
        capability->object_slot >= kMaximumObjects) {
        reject();
        return false;
    }
    ObjectEntry& object = objects[capability->object_slot];
    if (!object.active || object.generation != capability->object_generation ||
        object.type != capability->type || object.object == nullptr ||
        object.leases == 0xFFFF'FFFFU) {
        reject();
        return false;
    }
    ++object.leases;
    lease = {
        .object = object.object,
        .type = object.type,
        .granted_rights = capability->granted_rights,
        .object_slot = capability->object_slot,
        .object_generation = capability->object_generation,
        .active = true,
    };
    return true;
}

void release(Lease& lease) {
    sync::LockGuard guard(registry_lock);
    if (!lease.active || lease.object_slot >= kMaximumObjects) {
        reject();
        lease = {};
        return;
    }
    ObjectEntry& object = objects[lease.object_slot];
    if (!object.active || object.generation != lease.object_generation || object.leases == 0) {
        reject();
        lease = {};
        return;
    }
    --object.leases;
    lease = {};
}

bool self_test() {
    last_failure = 0;
    DomainHandle domain{};
    DomainHandle receiver_domain{};
    ObjectHandle object{};
    ObjectHandle replacement_object{};
    Token root{};
    Token child{};
    Token replacement{};
    Token delegated{};
    Lease lease{};
    u64 probe = 0xD0'58'CA'9A'B1'1E'00'01ULL;
    const Rights root_rights = Right::inspect | Right::read | Right::write | Right::derive |
                               Right::transfer;
    if (!create_domain(domain) || !create_domain(receiver_domain) ||
        !register_object(ObjectType::kernel_service, &probe, object) ||
        !grant(domain, object, root_rights, root)) {
        last_failure = 1;
        return false;
    }
    if (!acquire(domain, root, ObjectType::kernel_service, rights(Right::read), lease) ||
        lease.object != &probe || lease.granted_rights != root_rights) {
        last_failure = 2;
        return false;
    }
    if (unregister_object(object)) {
        last_failure = 3;
        return false;
    }
    release(lease);
    if (acquire(domain, root, ObjectType::kernel_service, rights(Right::administer), lease) ||
        !derive(domain, root, rights(Right::read), child) ||
        derive(domain, child, rights(Right::write), replacement) ||
        !acquire(domain, child, ObjectType::kernel_service, rights(Right::read), lease)) {
        last_failure = 4;
        return false;
    }
    release(lease);
    if (!delegate(domain, root, receiver_domain, rights(Right::read), delegated) ||
        !acquire(receiver_domain, delegated, ObjectType::kernel_service, rights(Right::read),
                 lease)) {
        last_failure = 5;
        return false;
    }
    release(lease);
    if (delegate(receiver_domain, delegated, domain, rights(Right::read), replacement) ||
        !revoke(domain, root) ||
        acquire(domain, child, ObjectType::kernel_service, rights(Right::read), lease) ||
        acquire(receiver_domain, delegated, ObjectType::kernel_service, rights(Right::read),
                lease) ||
        acquire(domain, root, ObjectType::kernel_service, rights(Right::read), lease) ||
        !grant(domain, object, rights(Right::read), replacement) ||
        replacement.value == root.value ||
        !acquire(domain, replacement, ObjectType::kernel_service, rights(Right::read), lease)) {
        last_failure = 6;
        return false;
    }
    release(lease);
    if (!unregister_object(object) ||
        acquire(domain, replacement, ObjectType::kernel_service, rights(Right::read), lease) ||
        !register_object(ObjectType::kernel_service, &probe, replacement_object) ||
        !destroy_domain(receiver_domain) || !destroy_domain(domain) ||
        grant(domain, replacement_object, rights(Right::read), replacement) ||
        !unregister_object(replacement_object)) {
        last_failure = 7;
        return false;
    }
    return true;
}

Statistics statistics() {
    sync::LockGuard guard(registry_lock);
    Statistics result{
        .active_domains = 0,
        .active_objects = 0,
        .active_capabilities = 0,
        .active_leases = 0,
        .rejected_operations = rejected,
    };
    for (const auto& domain : domains) {
        if (!domain.active) {
            continue;
        }
        ++result.active_domains;
        for (const auto& capability : domain.capabilities) {
            result.active_capabilities += capability.active ? 1U : 0U;
        }
    }
    for (const auto& object : objects) {
        if (object.active) {
            ++result.active_objects;
        }
        result.active_leases += object.leases;
    }
    return result;
}

u32 failure_code() { return last_failure; }
}
