#include <doxxer/syscall/dispatcher.hpp>

#include <doxxer/process/process.hpp>
#include <doxxer/memory/user_copy.hpp>
#include <doxxer/sync/event.hpp>

namespace doxxer::syscall {
namespace {
constexpr u64 kFeatureIpc = 1ULL << 0U;
constexpr u64 kFeatureEvents = 1ULL << 1U;
constexpr u64 kFeatureProcesses = 1ULL << 2U;
bool initialized = false;
u64 dispatched_calls = 0;
u64 successful_calls = 0;
u64 rejected_calls = 0;
u64 user_entries = 0;
u64 user_copy_rejections = 0;
u32 last_failure = 0;

void clear_response(Response& response) {
    response = {};
    response.status = Status::invalid_request;
}

security::capability::Token token_from(u64 value) { return {.value = value}; }

Status finish(Response& response, Status status) {
    response.status = status;
    if (status == Status::ok) {
        __atomic_add_fetch(&successful_calls, 1ULL, __ATOMIC_RELAXED);
    } else {
        __atomic_add_fetch(&rejected_calls, 1ULL, __ATOMIC_RELAXED);
    }
    return status;
}

bool bytes_equal(const u8* left, const u8* right, usize length) {
    for (usize index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}
}

bool initialize() {
    if (initialized) {
        return false;
    }
    initialized = true;
    return true;
}

Status dispatch(security::capability::DomainHandle caller, const Request& request,
                Response& response) {
    clear_response(response);
    __atomic_add_fetch(&dispatched_calls, 1ULL, __ATOMIC_RELAXED);
    if (!initialized || request.abi_version != kAbiVersion || request.flags != 0 ||
        request.payload_length > ipc::kMaximumPayloadSize) {
        return finish(response, Status::invalid_request);
    }

    switch (request.number) {
    case Number::abi_info:
        if (request.payload_length != 0) {
            return finish(response, Status::invalid_request);
        }
        response.values[0] = kAbiVersion;
        response.values[1] = ipc::kMaximumPayloadSize;
        response.values[2] = kFeatureIpc | kFeatureEvents | kFeatureProcesses;
        return finish(response, Status::ok);
    case Number::ipc_send:
        if (!ipc::send(caller, token_from(request.arguments[0]), request.payload_kind,
                       request.payload, request.payload_length, request.arguments[1])) {
            return finish(response, Status::denied_or_unavailable);
        }
        return finish(response, Status::ok);
    case Number::ipc_receive: {
        if (request.payload_length != 0) {
            return finish(response, Status::invalid_request);
        }
        ipc::Message message{};
        if (!ipc::receive(caller, token_from(request.arguments[0]), message)) {
            return finish(response, Status::denied_or_unavailable);
        }
        response.payload_kind = message.kind;
        response.payload_length = message.length;
        response.values[0] = message.sequence;
        for (usize index = 0; index < message.length; ++index) {
            response.payload[index] = message.payload[index];
        }
        return finish(response, Status::ok);
    }
    case Number::event_signal:
        if (request.payload_length != 0 ||
            !sync::event::signal(caller, token_from(request.arguments[0]))) {
            return finish(response, request.payload_length == 0
                                        ? Status::denied_or_unavailable
                                        : Status::invalid_request);
        }
        return finish(response, Status::ok);
    case Number::event_try_wait:
        if (request.payload_length != 0 ||
            !sync::event::try_wait(caller, token_from(request.arguments[0]))) {
            return finish(response, request.payload_length == 0
                                        ? Status::denied_or_unavailable
                                        : Status::invalid_request);
        }
        return finish(response, Status::ok);
    case Number::process_inspect: {
        if (request.payload_length != 0) {
            return finish(response, Status::invalid_request);
        }
        process::Info info{};
        if (!process::inspect(caller, token_from(request.arguments[0]), info)) {
            return finish(response, Status::denied_or_unavailable);
        }
        response.values[0] = info.identifier;
        response.values[1] = static_cast<u64>(info.state);
        response.values[2] = info.exit_code;
        response.values[3] = info.address_space_root;
        usize length = 0;
        while (length < sizeof(info.name) && info.name[length] != '\0') {
            response.payload[length] = static_cast<u8>(info.name[length]);
            ++length;
        }
        response.payload_length = static_cast<u16>(length);
        response.payload_kind = info.pcid;
        return finish(response, Status::ok);
    }
    case Number::process_terminate:
        if (request.payload_length != 0 || request.arguments[1] > 0xFFFF'FFFFULL) {
            return finish(response, Status::invalid_request);
        }
        if (!process::terminate(caller, token_from(request.arguments[0]),
                                static_cast<u32>(request.arguments[1]))) {
            return finish(response, Status::denied_or_unavailable);
        }
        return finish(response, Status::ok);
    default:
        return finish(response, Status::unsupported);
    }
}

Status dispatch_user(process::AddressSpaceLease& caller, u64 user_request,
                     u64 user_response) {
    __atomic_add_fetch(&user_entries, 1ULL, __ATOMIC_RELAXED);
    if (!process::validate_address_space_lease(caller)) {
        __atomic_add_fetch(&user_copy_rejections, 1ULL, __ATOMIC_RELAXED);
        return Status::denied_or_unavailable;
    }
    Request request{};
    if (!memory::user_copy::copy_from_user(*caller.space, &request, user_request,
                                           sizeof(request))) {
        __atomic_add_fetch(&user_copy_rejections, 1ULL, __ATOMIC_RELAXED);
        return Status::invalid_request;
    }
    Response response{};
    const Status result = dispatch(caller.domain, request, response);
    if (!memory::user_copy::copy_to_user(*caller.space, user_response, &response,
                                         sizeof(response))) {
        __atomic_add_fetch(&user_copy_rejections, 1ULL, __ATOMIC_RELAXED);
        return Status::invalid_request;
    }
    return result;
}

bool self_test() {
    last_failure = 0;
    security::capability::DomainHandle caller{};
    ipc::ChannelHandle channel{};
    ipc::Endpoints ipc_endpoints{};
    sync::event::Handle event{};
    sync::event::Endpoints event_endpoints{};
    process::CreateResult child{};
    process::AddressSpaceLease child_space{};
    Request request{};
    Response response{};
    u64 request_page = 0;
    u64 response_page = 0;
    constexpr u64 kUserRequest = 0x90'0000ULL;
    constexpr u64 kUserResponse = 0x91'0000ULL;
    if (!security::capability::create_domain(caller) ||
        !ipc::create(caller, channel, ipc_endpoints) ||
        !sync::event::create(caller, false, false, event, event_endpoints) ||
        !process::create(caller, "syscall-child", child)) {
        last_failure = 1;
        return false;
    }

    request.abi_version = kAbiVersion;
    request.number = Number::abi_info;
    if (dispatch(caller, request, response) != Status::ok ||
        response.values[0] != kAbiVersion || response.values[1] != ipc::kMaximumPayloadSize ||
        response.values[2] != (kFeatureIpc | kFeatureEvents | kFeatureProcesses)) {
        last_failure = 2;
        return false;
    }

    const u8 probe[] = {0x44, 0x4F, 0x58, 0x58, 0x45, 0x52};
    request = {};
    request.abi_version = kAbiVersion;
    request.number = Number::ipc_send;
    request.payload_kind = 0x51;
    request.payload_length = sizeof(probe);
    request.arguments[0] = ipc_endpoints.sender.value;
    request.arguments[1] = 0x1234;
    for (usize index = 0; index < sizeof(probe); ++index) {
        request.payload[index] = probe[index];
    }
    if (dispatch(caller, request, response) != Status::ok) {
        last_failure = 3;
        return false;
    }
    request = {};
    request.abi_version = kAbiVersion;
    request.number = Number::ipc_receive;
    request.arguments[0] = ipc_endpoints.receiver.value;
    if (dispatch(caller, request, response) != Status::ok ||
        response.payload_kind != 0x51 || response.payload_length != sizeof(probe) ||
        response.values[0] != 0x1234 ||
        !bytes_equal(response.payload, probe, sizeof(probe))) {
        last_failure = 4;
        return false;
    }

    request = {};
    request.abi_version = kAbiVersion;
    request.number = Number::event_try_wait;
    request.arguments[0] = event_endpoints.waiter.value;
    if (dispatch(caller, request, response) != Status::denied_or_unavailable) {
        last_failure = 5;
        return false;
    }
    request.number = Number::event_signal;
    request.arguments[0] = event_endpoints.signaler.value;
    if (dispatch(caller, request, response) != Status::ok) {
        last_failure = 6;
        return false;
    }
    request.number = Number::event_try_wait;
    request.arguments[0] = event_endpoints.waiter.value;
    if (dispatch(caller, request, response) != Status::ok) {
        last_failure = 7;
        return false;
    }

    request = {};
    request.abi_version = kAbiVersion;
    request.number = Number::process_inspect;
    request.arguments[0] = child.control.value;
    if (dispatch(caller, request, response) != Status::ok || response.values[0] == 0 ||
        response.values[1] != static_cast<u64>(process::State::ready)) {
        last_failure = 8;
        return false;
    }

    if (!process::acquire_address_space(caller, child.control, child_space) ||
        child_space.domain.slot != child.domain.slot ||
        child_space.domain.generation != child.domain.generation ||
        !memory::physical::allocate_page(request_page, memory::physical::PageOwner::user_data,
                                         memory::physical::Zone::any,
                                         child_space.space->isolation_domain()) ||
        !memory::physical::allocate_page(response_page, memory::physical::PageOwner::user_data,
                                         memory::physical::Zone::any,
                                         child_space.space->isolation_domain()) ||
        !memory::virtual_memory::map(*child_space.space, kUserRequest, request_page,
                                     memory::virtual_memory::MapFlags::user |
                                         memory::virtual_memory::MapFlags::write) ||
        !memory::virtual_memory::map(*child_space.space, kUserResponse, response_page,
                                     memory::virtual_memory::MapFlags::user |
                                         memory::virtual_memory::MapFlags::write)) {
        last_failure = 9;
        return false;
    }
    Request user_request{};
    user_request.abi_version = kAbiVersion;
    user_request.number = Number::abi_info;
    Response user_response{};
    process::AddressSpaceLease forged_lease = child_space;
    ++forged_lease.domain.generation;
    if (!memory::user_copy::copy_to_user(*child_space.space, kUserRequest, &user_request,
                                         sizeof(user_request)) ||
        dispatch_user(child_space, kUserRequest, kUserResponse) != Status::ok ||
        !memory::user_copy::copy_from_user(*child_space.space, &user_response, kUserResponse,
                                           sizeof(user_response)) ||
        user_response.status != Status::ok || user_response.values[0] != kAbiVersion ||
        user_response.values[1] != ipc::kMaximumPayloadSize ||
        !memory::virtual_memory::protect(*child_space.space, kUserResponse,
                                         memory::virtual_memory::MapFlags::user) ||
        dispatch_user(child_space, kUserRequest, kUserResponse) != Status::invalid_request ||
        dispatch_user(child_space, 0, kUserResponse) != Status::invalid_request ||
        dispatch_user(forged_lease, kUserRequest, kUserResponse) !=
            Status::denied_or_unavailable ||
        !memory::virtual_memory::protect(*child_space.space, kUserResponse,
                                         memory::virtual_memory::MapFlags::user |
                                             memory::virtual_memory::MapFlags::write)) {
        last_failure = 10;
        return false;
    }
    if (!memory::virtual_memory::unmap(*child_space.space, kUserRequest) ||
        !memory::virtual_memory::unmap(*child_space.space, kUserResponse) ||
        !memory::physical::free_page(request_page, memory::physical::PageOwner::user_data,
                                     child_space.space->isolation_domain()) ||
        !memory::physical::free_page(response_page, memory::physical::PageOwner::user_data,
                                     child_space.space->isolation_domain())) {
        last_failure = 11;
        return false;
    }
    process::release_address_space(child_space);

    request.number = Number::process_terminate;
    request.arguments[1] = 77;
    if (dispatch(caller, request, response) != Status::ok ||
        !process::destroy(caller, child.control)) {
        last_failure = 12;
        return false;
    }

    request = {};
    request.abi_version = kAbiVersion + 1;
    request.number = Number::abi_info;
    if (dispatch(caller, request, response) != Status::invalid_request) {
        last_failure = 13;
        return false;
    }
    request.abi_version = kAbiVersion;
    request.flags = 1;
    if (dispatch(caller, request, response) != Status::invalid_request) {
        last_failure = 14;
        return false;
    }
    request.flags = 0;
    request.number = static_cast<Number>(0xFFFF'FFFFU);
    if (dispatch(caller, request, response) != Status::unsupported) {
        last_failure = 15;
        return false;
    }

    if (!ipc::destroy(caller, ipc_endpoints.administrator) ||
        !sync::event::destroy(caller, event_endpoints.administrator) ||
        !security::capability::destroy_domain(caller)) {
        last_failure = 16;
        return false;
    }
    return true;
}

Statistics statistics() {
    return {
        .dispatched = __atomic_load_n(&dispatched_calls, __ATOMIC_RELAXED),
        .successful = __atomic_load_n(&successful_calls, __ATOMIC_RELAXED),
        .rejected = __atomic_load_n(&rejected_calls, __ATOMIC_RELAXED),
        .user_entries = __atomic_load_n(&user_entries, __ATOMIC_RELAXED),
        .user_copy_rejections =
            __atomic_load_n(&user_copy_rejections, __ATOMIC_RELAXED),
    };
}

u32 failure_code() { return last_failure; }
}
