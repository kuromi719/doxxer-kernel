#include <doxxer/thread/user_thread.hpp>

#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/user_copy.hpp>
#include <doxxer/sync/spinlock.hpp>

namespace doxxer::thread::user {
namespace {
constexpr u16 kMaximumThreads = 32;
constexpr usize kStackPages = 8;
constexpr u64 kStackRegionTop = 0x0000'6000'0000'0000ULL;
constexpr u64 kStackStride = 0x20'0000ULL;
constexpr u16 kUserCodeSelector = 0x23;
constexpr u16 kUserDataSelector = 0x1B;
constexpr u64 kInitialRflags = 0x202;

struct Thread {
    sync::SpinLock lock{};
    bool active = false;
    bool destroying = false;
    u32 generation = 1;
    u32 execution_users = 0;
    u64 identifier = 0;
    State state = State::ready;
    u32 exit_code = 0;
    Context context{};
    u64 stack_guard = 0;
    u64 stack_base = 0;
    u64 stack_top = 0;
    u64 stack_pages[kStackPages]{};
    process::AddressSpaceLease process_space{};
    security::capability::ObjectHandle object{};
};

sync::SpinLock registry_lock{};
Thread threads[kMaximumThreads]{};
bool initialized = false;
u64 next_identifier = 1;
u64 created_threads = 0;
u64 destroyed_threads = 0;
u64 executions_started = 0;
u64 executions_completed = 0;
u64 rejected_operations = 0;
u32 last_failure = 0;

void reject() { __atomic_add_fetch(&rejected_operations, 1ULL, __ATOMIC_RELAXED); }

u32 next_generation(u32 generation) {
    ++generation;
    return generation == 0 ? 1 : generation;
}

bool same_context(const Context& left, const Context& right) {
    return left.r15 == right.r15 && left.r14 == right.r14 && left.r13 == right.r13 &&
           left.r12 == right.r12 && left.rbp == right.rbp && left.rbx == right.rbx &&
           left.rip == right.rip && left.rsp == right.rsp && left.rflags == right.rflags &&
           left.fs_base == right.fs_base && left.code_selector == right.code_selector &&
           left.stack_selector == right.stack_selector;
}

Thread* acquire_thread(security::capability::DomainHandle manager,
                       security::capability::Token control,
                       security::capability::Rights required,
                       security::capability::Lease& lease) {
    if (!security::capability::acquire(manager, control,
                                       security::capability::ObjectType::user_thread, required,
                                       lease)) {
        reject();
        return nullptr;
    }
    auto* thread = static_cast<Thread*>(lease.object);
    if (thread == nullptr) {
        security::capability::release(lease);
        reject();
        return nullptr;
    }
    bool valid = false;
    {
        sync::LockGuard guard(thread->lock);
        valid = thread->active && !thread->destroying;
    }
    if (!valid) {
        security::capability::release(lease);
        reject();
        return nullptr;
    }
    return thread;
}

bool release_stack(Thread& thread) {
    bool success = true;
    if (thread.process_space.space != nullptr) {
        for (usize index = 0; index < kStackPages; ++index) {
            if (thread.stack_pages[index] == 0) {
                continue;
            }
            if (!memory::virtual_memory::unmap(
                    *thread.process_space.space,
                    thread.stack_base + index * memory::physical::kPageSize) ||
                !memory::physical::free_page(thread.stack_pages[index],
                                             memory::physical::PageOwner::user_stack,
                                             thread.process_space.space->isolation_domain())) {
                success = false;
            }
            thread.stack_pages[index] = 0;
        }
    }
    if (thread.process_space.active) {
        process::release_address_space(thread.process_space);
    }
    return success;
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

bool create(security::capability::DomainHandle manager,
            security::capability::Token process_control, u64 entry_point,
            CreateResult& result) {
    result = {};
    sync::LockGuard registry_guard(registry_lock);
    if (!initialized) {
        reject();
        return false;
    }
    for (u16 slot = 0; slot < kMaximumThreads; ++slot) {
        Thread& thread = threads[slot];
        if (thread.active) {
            continue;
        }
        if (!process::acquire_address_space(manager, process_control, thread.process_space) ||
            thread.process_space.state != process::State::ready ||
            !memory::user_copy::validate_range(*thread.process_space.space, entry_point, 1,
                                               memory::user_copy::Access::execute)) {
            if (thread.process_space.active) {
                process::release_address_space(thread.process_space);
            }
            reject();
            return false;
        }
        thread.stack_top = kStackRegionTop - static_cast<u64>(slot) * kStackStride;
        thread.stack_base = thread.stack_top - kStackPages * memory::physical::kPageSize;
        thread.stack_guard = thread.stack_base - memory::physical::kPageSize;
        bool mapped = true;
        for (usize index = 0; index < kStackPages; ++index) {
            u64 physical_address = 0;
            if (!memory::physical::allocate_page(physical_address,
                                                 memory::physical::PageOwner::user_stack,
                                                 memory::physical::Zone::any,
                                                 thread.process_space.space->isolation_domain())) {
                mapped = false;
                break;
            }
            thread.stack_pages[index] = physical_address;
            if (!memory::virtual_memory::map(
                    *thread.process_space.space,
                    thread.stack_base + index * memory::physical::kPageSize, physical_address,
                    memory::virtual_memory::MapFlags::user |
                        memory::virtual_memory::MapFlags::write)) {
                (void)memory::physical::free_page(
                    physical_address, memory::physical::PageOwner::user_stack,
                    thread.process_space.space->isolation_domain());
                thread.stack_pages[index] = 0;
                mapped = false;
                break;
            }
        }
        if (!mapped) {
            (void)release_stack(thread);
            reject();
            return false;
        }
        if (!security::capability::register_object(
                security::capability::ObjectType::user_thread, &thread, thread.object)) {
            (void)release_stack(thread);
            reject();
            return false;
        }
        const auto control_rights = security::capability::Right::inspect |
                                    security::capability::Right::administer |
                                    security::capability::Right::derive |
                                    security::capability::Right::execute;
        if (!security::capability::grant(manager, thread.object, control_rights,
                                         result.control)) {
            (void)security::capability::unregister_object(thread.object);
            (void)release_stack(thread);
            reject();
            return false;
        }
        thread.identifier = next_identifier++;
        thread.state = State::ready;
        thread.exit_code = 0;
        thread.context = {
            .r15 = 0,
            .r14 = 0,
            .r13 = 0,
            .r12 = 0,
            .rbp = 0,
            .rbx = 0,
            .rip = entry_point,
            .rsp = thread.stack_top,
            .rflags = kInitialRflags,
            .fs_base = 0,
            .code_selector = kUserCodeSelector,
            .stack_selector = kUserDataSelector,
        };
        thread.destroying = false;
        thread.execution_users = 0;
        thread.active = true;
        result.handle = {.slot = slot, .generation = thread.generation};
        __atomic_add_fetch(&created_threads, 1ULL, __ATOMIC_RELAXED);
        return true;
    }
    reject();
    return false;
}

bool inspect(security::capability::DomainHandle manager,
             security::capability::Token thread_control, Info& info) {
    info = {};
    security::capability::Lease lease{};
    Thread* thread = acquire_thread(
        manager, thread_control,
        security::capability::rights(security::capability::Right::inspect), lease);
    if (thread == nullptr) {
        return false;
    }
    {
        sync::LockGuard guard(thread->lock);
        info = {
            .identifier = thread->identifier,
            .state = thread->state,
            .exit_code = thread->exit_code,
            .context = thread->context,
            .stack_guard = thread->stack_guard,
            .stack_base = thread->stack_base,
            .stack_top = thread->stack_top,
        };
    }
    security::capability::release(lease);
    return true;
}

bool acquire_execution(security::capability::DomainHandle manager,
                       security::capability::Token thread_control, ExecutionLease& lease) {
    lease = {};
    security::capability::Lease capability_lease{};
    Thread* thread = acquire_thread(
        manager, thread_control,
        security::capability::rights(security::capability::Right::execute), capability_lease);
    if (thread == nullptr) {
        return false;
    }
    bool success = false;
    {
        sync::LockGuard guard(thread->lock);
        if (thread->state == State::ready && thread->execution_users == 0 &&
            process::validate_address_space_lease(thread->process_space)) {
            thread->state = State::running;
            thread->execution_users = 1;
            lease = {
                .address_space = &thread->process_space,
                .thread_cookie = thread,
                .context = thread->context,
                .identifier = thread->identifier,
                .generation = thread->generation,
                .active = true,
            };
            success = true;
        }
    }
    security::capability::release(capability_lease);
    if (!success) {
        reject();
        return false;
    }
    __atomic_add_fetch(&executions_started, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool validate_execution_lease(const ExecutionLease& lease) {
    if (!lease.active || lease.thread_cookie == nullptr || lease.address_space == nullptr ||
        lease.identifier == 0 || lease.generation == 0) {
        return false;
    }
    auto* thread = static_cast<Thread*>(lease.thread_cookie);
    sync::LockGuard guard(thread->lock);
    return thread->active && !thread->destroying && thread->state == State::running &&
           thread->execution_users == 1 && thread->identifier == lease.identifier &&
           thread->generation == lease.generation &&
           &thread->process_space == lease.address_space &&
           thread->process_space.active && thread->process_space.space != nullptr &&
           same_context(thread->context, lease.context);
}

bool release_execution(ExecutionLease& lease) {
    if (!lease.active || lease.thread_cookie == nullptr || lease.address_space == nullptr) {
        reject();
        return false;
    }
    auto* thread = static_cast<Thread*>(lease.thread_cookie);
    bool success = false;
    {
        sync::LockGuard guard(thread->lock);
        if (thread->active && !thread->destroying && thread->state == State::running &&
            thread->execution_users == 1 && thread->identifier == lease.identifier &&
            thread->generation == lease.generation &&
            &thread->process_space == lease.address_space &&
            thread->process_space.active && thread->process_space.space != nullptr &&
            same_context(thread->context, lease.context)) {
            thread->execution_users = 0;
            thread->state = State::ready;
            success = true;
        }
    }
    if (!success) {
        reject();
        return false;
    }
    lease = {};
    __atomic_add_fetch(&executions_completed, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool terminate(security::capability::DomainHandle manager,
               security::capability::Token thread_control, u32 exit_code) {
    security::capability::Lease lease{};
    Thread* thread = acquire_thread(
        manager, thread_control,
        security::capability::rights(security::capability::Right::administer), lease);
    if (thread == nullptr) {
        return false;
    }
    bool success = false;
    {
        sync::LockGuard guard(thread->lock);
        if (thread->state == State::ready) {
            thread->state = State::exited;
            thread->exit_code = exit_code;
            success = true;
        }
    }
    security::capability::release(lease);
    if (!success) {
        reject();
    }
    return success;
}

bool destroy(security::capability::DomainHandle manager,
             security::capability::Token thread_control) {
    security::capability::Lease lease{};
    Thread* thread = acquire_thread(
        manager, thread_control,
        security::capability::rights(security::capability::Right::administer), lease);
    if (thread == nullptr) {
        return false;
    }
    security::capability::ObjectHandle object{};
    bool destroyable = false;
    {
        sync::LockGuard guard(thread->lock);
        if (thread->state == State::exited && thread->execution_users == 0) {
            thread->destroying = true;
            object = thread->object;
            destroyable = true;
        }
    }
    security::capability::release(lease);
    if (!destroyable) {
        reject();
        return false;
    }
    const bool stack_released = release_stack(*thread);
    if (!security::capability::unregister_object(object)) {
        reject();
        return false;
    }
    {
        sync::LockGuard guard(thread->lock);
        thread->active = false;
        thread->destroying = false;
        thread->generation = next_generation(thread->generation);
        thread->identifier = 0;
        thread->state = State::ready;
        thread->execution_users = 0;
        thread->exit_code = 0;
        thread->context = {};
        thread->stack_guard = 0;
        thread->stack_base = 0;
        thread->stack_top = 0;
        thread->object = {};
    }
    __atomic_add_fetch(&destroyed_threads, 1ULL, __ATOMIC_RELAXED);
    if (!stack_released) {
        reject();
        return false;
    }
    return true;
}

bool self_test() {
    last_failure = 0;
    security::capability::DomainHandle manager{};
    process::CreateResult child{};
    process::AddressSpaceLease process_space{};
    CreateResult thread{};
    security::capability::Token observer{};
    Info info{};
    u64 code_page = 0;
    constexpr u64 kEntry = 0x50'0000ULL;
    if (!security::capability::create_domain(manager) ||
        !process::create(manager, "thread-selftest", child) ||
        !process::acquire_address_space(manager, child.control, process_space) ||
        !memory::physical::allocate_page(
            code_page, memory::physical::PageOwner::user_image, memory::physical::Zone::any,
            process_space.space->isolation_domain()) ||
        !memory::virtual_memory::map(*process_space.space, kEntry, code_page,
                                     memory::virtual_memory::MapFlags::user |
                                         memory::virtual_memory::MapFlags::execute)) {
        last_failure = 1;
        return false;
    }
    process::release_address_space(process_space);
    if (!create(manager, child.control, kEntry, thread) ||
        !inspect(manager, thread.control, info) || info.identifier == 0 ||
        info.state != State::ready || info.context.rip != kEntry ||
        info.context.rsp != info.stack_top || info.context.rflags != kInitialRflags ||
        info.context.code_selector != kUserCodeSelector ||
        info.context.stack_selector != kUserDataSelector ||
        info.stack_base - info.stack_guard != memory::physical::kPageSize) {
        last_failure = 2;
        return false;
    }
    memory::virtual_memory::Mapping guard_mapping{};
    if (!process::acquire_address_space(manager, child.control, process_space) ||
        memory::virtual_memory::query(*process_space.space, info.stack_guard, guard_mapping)) {
        last_failure = 3;
        return false;
    }
    process::release_address_space(process_space);
    ExecutionLease execution{};
    ExecutionLease duplicate{};
    if (!security::capability::derive(
            manager, thread.control,
            security::capability::rights(security::capability::Right::inspect), observer) ||
        acquire_execution(manager, observer, duplicate) ||
        !acquire_execution(manager, thread.control, execution) ||
        !validate_execution_lease(execution) ||
        acquire_execution(manager, thread.control, duplicate) ||
        !inspect(manager, thread.control, info) || info.state != State::running) {
        last_failure = 4;
        return false;
    }
    ExecutionLease forged = execution;
    ++forged.generation;
    ExecutionLease forged_context = execution;
    forged_context.context.rip ^= 1;
    if (release_execution(forged) || validate_execution_lease(forged_context) ||
        release_execution(forged_context) || !validate_execution_lease(execution) ||
        !release_execution(execution) || execution.active ||
        !inspect(manager, thread.control, info) || info.state != State::ready) {
        last_failure = 4;
        return false;
    }
    if (!acquire_execution(manager, thread.control, execution) ||
        !process::terminate(manager, child.control, 91) ||
        process::destroy(manager, child.control) ||
        !validate_execution_lease(execution) || !release_execution(execution)) {
        last_failure = 4;
        return false;
    }
    if (!terminate(manager, thread.control, 37) || !destroy(manager, thread.control) ||
        !process::acquire_address_space(manager, child.control, process_space) ||
        !memory::virtual_memory::unmap(*process_space.space, kEntry) ||
        !memory::physical::free_page(code_page, memory::physical::PageOwner::user_image,
                                     process_space.space->isolation_domain())) {
        last_failure = 4;
        return false;
    }
    process::release_address_space(process_space);
    if (!process::destroy(manager, child.control) ||
        !security::capability::destroy_domain(manager)) {
        last_failure = 5;
        return false;
    }
    return true;
}

Statistics statistics() {
    Statistics result{
        .active_threads = 0,
        .active_executions = 0,
        .created_threads = __atomic_load_n(&created_threads, __ATOMIC_RELAXED),
        .destroyed_threads = __atomic_load_n(&destroyed_threads, __ATOMIC_RELAXED),
        .executions_started = __atomic_load_n(&executions_started, __ATOMIC_RELAXED),
        .executions_completed = __atomic_load_n(&executions_completed, __ATOMIC_RELAXED),
        .rejected_operations = __atomic_load_n(&rejected_operations, __ATOMIC_RELAXED),
    };
    for (auto& thread : threads) {
        sync::LockGuard guard(thread.lock);
        result.active_threads += thread.active ? 1U : 0U;
        result.active_executions += thread.execution_users;
    }
    return result;
}

u32 failure_code() { return last_failure; }
}
