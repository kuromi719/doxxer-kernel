#pragma once

#include <doxxer/ipc/channel.hpp>
#include <doxxer/process/process.hpp>
#include <doxxer/security/capability.hpp>
#include <doxxer/types.hpp>

namespace doxxer::syscall {
constexpr u32 kAbiVersion = 1;

enum class Number : u32 {
    abi_info = 0,
    ipc_send = 1,
    ipc_receive = 2,
    event_signal = 3,
    event_try_wait = 4,
    process_inspect = 5,
    process_terminate = 6,
};

enum class Status : u32 {
    ok = 0,
    invalid_request = 1,
    denied_or_unavailable = 2,
    unsupported = 3,
};

struct Request {
    u32 abi_version;
    Number number;
    u32 flags;
    u16 payload_kind;
    u16 payload_length;
    u64 arguments[4];
    u8 payload[ipc::kMaximumPayloadSize];
};

struct Response {
    Status status;
    u16 payload_kind;
    u16 payload_length;
    u64 values[4];
    u8 payload[ipc::kMaximumPayloadSize];
};

struct Statistics {
    u64 dispatched;
    u64 successful;
    u64 rejected;
    u64 user_entries;
    u64 user_copy_rejections;
};

bool initialize();
Status dispatch(security::capability::DomainHandle caller, const Request& request,
                Response& response);
Status dispatch_user(process::AddressSpaceLease& caller, u64 user_request,
                     u64 user_response);
bool self_test();
Statistics statistics();
u32 failure_code();
}
