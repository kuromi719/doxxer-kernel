#pragma once

#include <doxxer/security/capability.hpp>
#include <doxxer/types.hpp>

namespace doxxer::ipc {
constexpr usize kMaximumPayloadSize = 64;
constexpr usize kChannelDepth = 8;

struct Message {
    u64 sequence;
    u16 kind;
    u16 length;
    u8 payload[kMaximumPayloadSize];
};

struct ChannelHandle {
    u16 slot;
    u32 generation;
};

struct Endpoints {
    security::capability::Token sender;
    security::capability::Token receiver;
    security::capability::Token administrator;
};

struct Statistics {
    u32 active_channels;
    u32 queued_messages;
    u64 sent_messages;
    u64 received_messages;
    u64 rejected_operations;
};

bool initialize();
bool create(security::capability::DomainHandle owner, ChannelHandle& handle, Endpoints& endpoints);
bool destroy(security::capability::DomainHandle owner,
             security::capability::Token administrator);
bool send(security::capability::DomainHandle domain, security::capability::Token endpoint, u16 kind,
          const void* payload, usize length, u64 sequence);
bool receive(security::capability::DomainHandle domain, security::capability::Token endpoint,
             Message& message);
bool self_test();
Statistics statistics();
u32 failure_code();
}
