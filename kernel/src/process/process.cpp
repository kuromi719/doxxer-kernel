#include <doxxer/process/process.hpp>

#include <doxxer/memory/virtual.hpp>
#include <doxxer/sync/spinlock.hpp>

namespace doxxer::process {
namespace {
constexpr u16 kMaximumProcesses = 16;

struct Process {
    sync::SpinLock lock{};
    bool active = false;
    bool destroying = false;
    u32 generation = 1;
    u64 identifier = 0;
    State state = State::ready;
    u32 exit_code = 0;
    u32 address_space_users = 0;
    char name[24]{};
    memory::virtual_memory::AddressSpace address_space{};
    security::capability::DomainHandle domain{};
    security::capability::ObjectHandle object{};
};

sync::SpinLock registry_lock{};
Process processes[kMaximumProcesses]{};
bool initialized = false;
u64 next_identifier = 1;
u64 created_processes = 0;
u64 exited_processes = 0;
u64 destroyed_processes = 0;
u64 rejected_operations = 0;
u32 last_failure = 0;

void reject() { __atomic_add_fetch(&rejected_operations, 1ULL, __ATOMIC_RELAXED); }

u32 next_generation(u32 generation) {
    ++generation;
    return generation == 0 ? 1 : generation;
}

bool copy_name(char (&destination)[24], const char* source) {
    if (source == nullptr || source[0] == '\0') {
        return false;
    }
    usize index = 0;
    while (index + 1 < sizeof(destination) && source[index] != '\0') {
        const char value = source[index];
        if (value < 0x20 || value > 0x7E) {
            return false;
        }
        destination[index++] = value;
    }
    if (source[index] != '\0') {
        return false;
    }
    destination[index] = '\0';
    for (++index; index < sizeof(destination); ++index) {
        destination[index] = '\0';
    }
    return true;
}

bool names_equal(const char* left, const char* right) {
    for (usize index = 0; index < 24; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
        if (left[index] == '\0') {
            return true;
        }
    }
    return false;
}

Process* acquire_process(security::capability::DomainHandle manager,
                         security::capability::Token control,
                         security::capability::Rights required,
                         security::capability::Lease& lease) {
    if (!security::capability::acquire(manager, control,
                                       security::capability::ObjectType::process, required,
                                       lease)) {
        reject();
        return nullptr;
    }
    auto* process = static_cast<Process*>(lease.object);
    if (process == nullptr) {
        security::capability::release(lease);
        reject();
        return nullptr;
    }
    bool valid = false;
    {
        sync::LockGuard guard(process->lock);
        valid = process->active && !process->destroying;
    }
    if (!valid) {
        security::capability::release(lease);
        reject();
        return nullptr;
    }
    return process;
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

bool create(security::capability::DomainHandle manager, const char* name, CreateResult& result) {
    result = {};
    sync::LockGuard registry_guard(registry_lock);
    if (!initialized) {
        reject();
        return false;
    }
    for (u16 index = 0; index < kMaximumProcesses; ++index) {
        Process& process = processes[index];
        if (process.active) {
            continue;
        }
        if (!copy_name(process.name, name)) {
            reject();
            return false;
        }
        if (!memory::virtual_memory::create(process.address_space, static_cast<u16>(index + 1))) {
            reject();
            return false;
        }
        if (!security::capability::create_domain(process.domain)) {
            (void)memory::virtual_memory::destroy(process.address_space);
            reject();
            return false;
        }
        if (!security::capability::register_object(security::capability::ObjectType::process,
                                                   &process, process.object)) {
            (void)security::capability::destroy_domain(process.domain);
            (void)memory::virtual_memory::destroy(process.address_space);
            reject();
            return false;
        }
        const auto control_rights = security::capability::Right::inspect |
                                    security::capability::Right::administer |
                                    security::capability::Right::map |
                                    security::capability::Right::derive |
                                    security::capability::Right::transfer;
        if (!security::capability::grant(manager, process.object, control_rights,
                                         result.control)) {
            (void)security::capability::unregister_object(process.object);
            (void)security::capability::destroy_domain(process.domain);
            (void)memory::virtual_memory::destroy(process.address_space);
            reject();
            return false;
        }
        process.identifier = next_identifier++;
        process.state = State::ready;
        process.exit_code = 0;
        process.address_space_users = 0;
        process.destroying = false;
        process.active = true;
        result.handle = {.slot = index, .generation = process.generation};
        result.domain = process.domain;
        __atomic_add_fetch(&created_processes, 1ULL, __ATOMIC_RELAXED);
        return true;
    }
    reject();
    return false;
}

bool inspect(security::capability::DomainHandle manager, security::capability::Token control,
             Info& info) {
    info = {};
    security::capability::Lease lease{};
    Process* process = acquire_process(
        manager, control, security::capability::rights(security::capability::Right::inspect), lease);
    if (process == nullptr) {
        return false;
    }
    {
        sync::LockGuard guard(process->lock);
        info.identifier = process->identifier;
        info.state = process->state;
        info.exit_code = process->exit_code;
        info.address_space_root = process->address_space.root_physical();
        info.pcid = process->address_space.pcid();
        for (usize index = 0; index < sizeof(info.name); ++index) {
            info.name[index] = process->name[index];
        }
    }
    security::capability::release(lease);
    return true;
}

bool terminate(security::capability::DomainHandle manager, security::capability::Token control,
               u32 exit_code) {
    security::capability::Lease lease{};
    Process* process = acquire_process(manager, control,
                                       security::capability::rights(
                                           security::capability::Right::administer),
                                       lease);
    if (process == nullptr) {
        return false;
    }
    bool transitioned = false;
    {
        sync::LockGuard guard(process->lock);
        if (process->state == State::ready) {
            process->state = State::exited;
            process->exit_code = exit_code;
            transitioned = true;
        }
    }
    security::capability::release(lease);
    if (!transitioned) {
        reject();
        return false;
    }
    __atomic_add_fetch(&exited_processes, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool destroy(security::capability::DomainHandle manager, security::capability::Token control) {
    security::capability::Lease lease{};
    Process* process = acquire_process(manager, control,
                                       security::capability::rights(
                                           security::capability::Right::administer),
                                       lease);
    if (process == nullptr) {
        return false;
    }
    security::capability::ObjectHandle object{};
    security::capability::DomainHandle domain{};
    bool destroyable = false;
    {
        sync::LockGuard guard(process->lock);
        if (process->state == State::exited && process->address_space_users == 0) {
            process->destroying = true;
            object = process->object;
            domain = process->domain;
            destroyable = true;
        }
    }
    security::capability::release(lease);
    if (!destroyable) {
        reject();
        return false;
    }
    if (!memory::virtual_memory::destroy(process->address_space) ||
        !security::capability::destroy_domain(domain) ||
        !security::capability::unregister_object(object)) {
        reject();
        return false;
    }
    {
        sync::LockGuard guard(process->lock);
        process->active = false;
        process->destroying = false;
        process->identifier = 0;
        process->state = State::ready;
        process->exit_code = 0;
        process->address_space_users = 0;
        process->domain = {};
        process->object = {};
        process->generation = next_generation(process->generation);
        for (char& character : process->name) {
            character = '\0';
        }
    }
    __atomic_add_fetch(&destroyed_processes, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool acquire_address_space(security::capability::DomainHandle manager,
                           security::capability::Token control, AddressSpaceLease& lease) {
    lease = {};
    security::capability::Lease capability_lease{};
    Process* process = acquire_process(
        manager, control, security::capability::rights(security::capability::Right::map),
        capability_lease);
    if (process == nullptr) {
        return false;
    }
    bool success = false;
    {
        sync::LockGuard guard(process->lock);
        if (process->active && !process->destroying &&
            process->address_space_users != 0xFFFF'FFFFU) {
            ++process->address_space_users;
            lease = {
                .space = &process->address_space,
                .process_cookie = process,
                .state = process->state,
                .active = true,
            };
            success = true;
        }
    }
    security::capability::release(capability_lease);
    if (!success) {
        reject();
    }
    return success;
}

void release_address_space(AddressSpaceLease& lease) {
    if (!lease.active || lease.process_cookie == nullptr || lease.space == nullptr) {
        reject();
        lease = {};
        return;
    }
    auto* process = static_cast<Process*>(lease.process_cookie);
    {
        sync::LockGuard guard(process->lock);
        if (!process->active || process->address_space_users == 0 ||
            &process->address_space != lease.space) {
            reject();
            lease = {};
            return;
        }
        --process->address_space_users;
    }
    lease = {};
}

bool self_test() {
    last_failure = 0;
    security::capability::DomainHandle manager{};
    CreateResult process{};
    security::capability::Token inspector{};
    Info info{};
    if (!security::capability::create_domain(manager) || !create(manager, "doxxer-selftest", process)) {
        last_failure = 1;
        return false;
    }
    if (!inspect(manager, process.control, info) || info.identifier == 0 ||
        info.state != State::ready || info.address_space_root == 0 || info.pcid == 0 ||
        !names_equal(info.name, "doxxer-selftest")) {
        last_failure = 2;
        return false;
    }
    if (!security::capability::derive(manager, process.control,
                                      security::capability::rights(
                                          security::capability::Right::inspect),
                                      inspector) ||
        terminate(manager, inspector, 9) || !terminate(manager, process.control, 0xD058U) ||
        terminate(manager, process.control, 0)) {
        last_failure = 3;
        return false;
    }
    if (!inspect(manager, inspector, info) || info.state != State::exited ||
        info.exit_code != 0xD058U || destroy(manager, inspector)) {
        last_failure = 4;
        return false;
    }
    if (!destroy(manager, process.control) || inspect(manager, inspector, info) ||
        !security::capability::destroy_domain(manager)) {
        last_failure = 5;
        return false;
    }
    return true;
}

Statistics statistics() {
    Statistics result{
        .active_processes = 0,
        .created_processes = __atomic_load_n(&created_processes, __ATOMIC_RELAXED),
        .exited_processes = __atomic_load_n(&exited_processes, __ATOMIC_RELAXED),
        .destroyed_processes = __atomic_load_n(&destroyed_processes, __ATOMIC_RELAXED),
        .rejected_operations = __atomic_load_n(&rejected_operations, __ATOMIC_RELAXED),
    };
    for (auto& process : processes) {
        sync::LockGuard guard(process.lock);
        result.active_processes += process.active ? 1U : 0U;
    }
    return result;
}

u32 failure_code() { return last_failure; }
}
