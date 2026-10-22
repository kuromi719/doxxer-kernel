#include <doxxer/ipc/channel.hpp>

#include <doxxer/sync/spinlock.hpp>

namespace doxxer::ipc {
namespace {
constexpr u16 kMaximumChannels = 16;

struct Channel {
    sync::SpinLock lock{};
    bool active = false;
    u32 generation = 1;
    security::capability::ObjectHandle object{};
    Message messages[kChannelDepth]{};
    usize head = 0;
    usize tail = 0;
    usize count = 0;
};

sync::SpinLock registry_lock{};
Channel channels[kMaximumChannels]{};
bool initialized = false;
u64 sent_messages = 0;
u64 received_messages = 0;
u64 rejected_operations = 0;
u32 last_failure = 0;

u32 next_generation(u32 generation) {
    ++generation;
    return generation == 0 ? 1 : generation;
}

void reject() { __atomic_add_fetch(&rejected_operations, 1ULL, __ATOMIC_RELAXED); }

Channel* acquire_channel(security::capability::DomainHandle domain,
                         security::capability::Token token,
                         security::capability::Rights rights,
                         security::capability::Lease& lease) {
    if (!security::capability::acquire(domain, token,
                                       security::capability::ObjectType::ipc_channel, rights,
                                       lease)) {
        reject();
        return nullptr;
    }
    auto* channel = static_cast<Channel*>(lease.object);
    if (channel == nullptr || !channel->active) {
        security::capability::release(lease);
        reject();
        return nullptr;
    }
    return channel;
}

bool equal_bytes(const u8* left, const u8* right, usize length) {
    for (usize index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}

bool enqueue(Channel& channel, u16 kind, const void* payload, usize length, u64 sequence,
             bool has_capability, security::capability::DomainHandle capability_domain,
             security::capability::Token capability) {
    sync::LockGuard guard(channel.lock);
    if (!channel.active || channel.count >= kChannelDepth) {
        return false;
    }
    Message& message = channel.messages[channel.tail];
    message.sequence = sequence;
    message.kind = kind;
    message.length = static_cast<u16>(length);
    message.has_capability = has_capability;
    message.capability_domain = capability_domain;
    message.capability = capability;
    const auto* bytes = static_cast<const u8*>(payload);
    for (usize index = 0; index < length; ++index) {
        message.payload[index] = bytes[index];
    }
    for (usize index = length; index < kMaximumPayloadSize; ++index) {
        message.payload[index] = 0;
    }
    channel.tail = (channel.tail + 1) % kChannelDepth;
    ++channel.count;
    return true;
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

bool create(security::capability::DomainHandle owner, ChannelHandle& handle,
            Endpoints& endpoints) {
    handle = {};
    endpoints = {};
    sync::LockGuard guard(registry_lock);
    if (!initialized) {
        reject();
        return false;
    }
    for (u16 index = 0; index < kMaximumChannels; ++index) {
        Channel& channel = channels[index];
        if (channel.active) {
            continue;
        }
        channel.head = 0;
        channel.tail = 0;
        channel.count = 0;
        if (!security::capability::register_object(
                security::capability::ObjectType::ipc_channel, &channel, channel.object)) {
            reject();
            return false;
        }
        const auto sender_rights = security::capability::Right::inspect |
                                   security::capability::Right::write |
                                   security::capability::Right::derive |
                                   security::capability::Right::transfer;
        const auto receiver_rights = security::capability::Right::inspect |
                                     security::capability::Right::read |
                                     security::capability::Right::wait |
                                     security::capability::Right::derive |
                                     security::capability::Right::transfer;
        const auto administrator_rights = security::capability::Right::inspect |
                                          security::capability::Right::administer;
        if (!security::capability::grant(owner, channel.object, sender_rights, endpoints.sender) ||
            !security::capability::grant(owner, channel.object, receiver_rights,
                                         endpoints.receiver) ||
            !security::capability::grant(owner, channel.object, administrator_rights,
                                         endpoints.administrator)) {
            (void)security::capability::revoke(owner, endpoints.sender);
            (void)security::capability::revoke(owner, endpoints.receiver);
            (void)security::capability::unregister_object(channel.object);
            endpoints = {};
            reject();
            return false;
        }
        channel.active = true;
        handle = {.slot = index, .generation = channel.generation};
        return true;
    }
    reject();
    return false;
}

bool destroy(security::capability::DomainHandle owner,
             security::capability::Token administrator) {
    security::capability::Lease lease{};
    Channel* channel = acquire_channel(owner, administrator,
                                       security::capability::rights(
                                           security::capability::Right::administer),
                                       lease);
    if (channel == nullptr) {
        return false;
    }
    const security::capability::ObjectHandle object = channel->object;
    {
        sync::LockGuard guard(channel->lock);
        for (usize index = 0; index < channel->count; ++index) {
            const usize slot = (channel->head + index) % kChannelDepth;
            if (channel->messages[slot].has_capability) {
                (void)security::capability::revoke(
                    channel->messages[slot].capability_domain,
                    channel->messages[slot].capability);
            }
            channel->messages[slot] = {};
        }
        channel->active = false;
        channel->head = 0;
        channel->tail = 0;
        channel->count = 0;
        channel->generation = next_generation(channel->generation);
    }
    security::capability::release(lease);
    if (!security::capability::unregister_object(object)) {
        reject();
        return false;
    }
    return true;
}

bool send(security::capability::DomainHandle domain, security::capability::Token endpoint,
          u16 kind, const void* payload, usize length, u64 sequence) {
    if (length > kMaximumPayloadSize || (length != 0 && payload == nullptr)) {
        reject();
        return false;
    }
    security::capability::Lease lease{};
    Channel* channel = acquire_channel(
        domain, endpoint, security::capability::rights(security::capability::Right::write), lease);
    if (channel == nullptr) {
        return false;
    }
    const bool success = enqueue(*channel, kind, payload, length, sequence, false, {}, {});
    security::capability::release(lease);
    if (!success) {
        reject();
        return false;
    }
    __atomic_add_fetch(&sent_messages, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool send_with_capability(security::capability::DomainHandle domain,
                          security::capability::Token endpoint,
                          security::capability::DomainHandle destination_domain,
                          security::capability::Token source_capability,
                          security::capability::Rights delegated_rights, u16 kind,
                          const void* payload, usize length, u64 sequence) {
    if (length > kMaximumPayloadSize || (length != 0 && payload == nullptr)) {
        reject();
        return false;
    }
    security::capability::Lease lease{};
    Channel* channel = acquire_channel(
        domain, endpoint, security::capability::rights(security::capability::Right::write), lease);
    if (channel == nullptr) {
        return false;
    }
    security::capability::Token delegated{};
    if (!security::capability::delegate(domain, source_capability, destination_domain,
                                        delegated_rights, delegated)) {
        security::capability::release(lease);
        reject();
        return false;
    }
    const bool success =
        enqueue(*channel, kind, payload, length, sequence, true, destination_domain, delegated);
    security::capability::release(lease);
    if (!success) {
        (void)security::capability::revoke(destination_domain, delegated);
        reject();
        return false;
    }
    __atomic_add_fetch(&sent_messages, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool receive(security::capability::DomainHandle domain, security::capability::Token endpoint,
             Message& message) {
    security::capability::Lease lease{};
    Channel* channel = acquire_channel(
        domain, endpoint, security::capability::rights(security::capability::Right::read), lease);
    if (channel == nullptr) {
        return false;
    }
    bool success = false;
    {
        sync::LockGuard guard(channel->lock);
        if (channel->active && channel->count != 0) {
            message = channel->messages[channel->head];
            channel->messages[channel->head] = {};
            channel->head = (channel->head + 1) % kChannelDepth;
            --channel->count;
            success = true;
        }
    }
    security::capability::release(lease);
    if (!success) {
        reject();
        return false;
    }
    __atomic_add_fetch(&received_messages, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool self_test() {
    last_failure = 0;
    security::capability::DomainHandle domain{};
    security::capability::DomainHandle receiver_domain{};
    security::capability::ObjectHandle transferred_object{};
    security::capability::Token transferred_root{};
    security::capability::Token received_capability{};
    security::capability::Lease transferred_lease{};
    ChannelHandle channel{};
    Endpoints endpoints{};
    Message message{};
    const u8 probe[] = {0x44, 0x58, 0x49, 0x50, 0x43};
    u64 transferred_probe = 0xD0'58'49'50'43'43'41'50ULL;
    if (!security::capability::create_domain(domain) ||
        !security::capability::create_domain(receiver_domain) ||
        !security::capability::register_object(security::capability::ObjectType::kernel_service,
                                               &transferred_probe, transferred_object) ||
        !security::capability::grant(
            domain, transferred_object,
            security::capability::Right::read | security::capability::Right::transfer,
            transferred_root) ||
        !create(domain, channel, endpoints)) {
        last_failure = 1;
        return false;
    }
    if (!send_with_capability(domain, endpoints.sender, receiver_domain, transferred_root,
                              security::capability::rights(security::capability::Right::read), 8,
                              nullptr, 0, 43) ||
        !receive(domain, endpoints.receiver, message) || !message.has_capability ||
        !security::capability::acquire(receiver_domain, message.capability,
                                       security::capability::ObjectType::kernel_service,
                                       security::capability::rights(
                                           security::capability::Right::read),
                                       transferred_lease) ||
        transferred_lease.object != &transferred_probe) {
        last_failure = 3;
        return false;
    }
    security::capability::release(transferred_lease);
    received_capability = message.capability;
    if (!send(domain, endpoints.sender, 7, probe, sizeof(probe), 42) ||
        !receive(domain, endpoints.receiver, message) || message.sequence != 42 ||
        message.kind != 7 || message.length != sizeof(probe) ||
        !equal_bytes(message.payload, probe, sizeof(probe))) {
        last_failure = 2;
        return false;
    }
    if (receive(domain, endpoints.receiver, message) ||
        send(domain, endpoints.receiver, 0, nullptr, 0, 0) ||
        send(domain, endpoints.sender, 0, probe, kMaximumPayloadSize + 1, 0)) {
        last_failure = 4;
        return false;
    }
    for (usize index = 0; index < kChannelDepth; ++index) {
        if (!send(domain, endpoints.sender, 9, nullptr, 0, index)) {
            last_failure = 5;
            return false;
        }
    }
    if (send(domain, endpoints.sender, 9, nullptr, 0, 99)) {
        last_failure = 6;
        return false;
    }
    for (usize index = 0; index < kChannelDepth; ++index) {
        if (!receive(domain, endpoints.receiver, message) || message.sequence != index) {
            last_failure = 7;
            return false;
        }
    }
    if (!security::capability::revoke(domain, transferred_root) ||
        security::capability::acquire(receiver_domain, received_capability,
                                      security::capability::ObjectType::kernel_service,
                                      security::capability::rights(
                                          security::capability::Right::read),
                                      transferred_lease) ||
        !destroy(domain, endpoints.administrator) ||
        send(domain, endpoints.sender, 0, nullptr, 0, 0) ||
        !security::capability::unregister_object(transferred_object) ||
        !security::capability::destroy_domain(receiver_domain) ||
        !security::capability::destroy_domain(domain)) {
        last_failure = 8;
        return false;
    }
    return true;
}

Statistics statistics() {
    Statistics result{
        .active_channels = 0,
        .queued_messages = 0,
        .sent_messages = __atomic_load_n(&sent_messages, __ATOMIC_RELAXED),
        .received_messages = __atomic_load_n(&received_messages, __ATOMIC_RELAXED),
        .rejected_operations = __atomic_load_n(&rejected_operations, __ATOMIC_RELAXED),
    };
    for (auto& channel : channels) {
        sync::LockGuard guard(channel.lock);
        if (channel.active) {
            ++result.active_channels;
            result.queued_messages += static_cast<u32>(channel.count);
        }
    }
    return result;
}

u32 failure_code() { return last_failure; }
}
