#include <doxxer/scheduler/scheduler.hpp>

#include <doxxer/arch/x86_64/apic.hpp>
#include <doxxer/arch/x86_64/interrupts.hpp>
#include <doxxer/arch/x86_64/smp.hpp>
#include <doxxer/memory/physical.hpp>
#include <doxxer/memory/virtual.hpp>
#include <doxxer/sync/spinlock.hpp>

extern "C" void doxxer_execute_task_stack(doxxer::u64 stack_top, doxxer::scheduler::TaskEntry entry,
                                          void* argument);
extern "C" doxxer::uptr __stack_chk_guard;

namespace doxxer::scheduler {
namespace {
using memory::physical::kPageSize;
using memory::virtual_memory::MapFlags;

constexpr u32 kMaximumTasks = 64;
constexpr u32 kQueueCapacity = kMaximumTasks;
constexpr u64 kStackPages = 8;
constexpr u64 kTaskArenaBase = 0x0000'7400'0000'0000ULL;
constexpr u64 kTaskStride = 0x0000'0000'0002'0000ULL;
constexpr u64 kSelfTestTimeoutMicroseconds = 1'000'000;
constexpr u8 kRescheduleVector = 0xE2;
constexpr u32 kInvalidIndex = 0xFFFF'FFFFU;

enum class TaskState : u32 {
    free = 0,
    queued = 1,
    running = 2,
    complete = 3,
    failed = 4,
};

struct TaskSlot {
    u32 state;
    u32 generation;
    u32 target_cpu;
    u32 reserved;
    TaskEntry entry;
    void* argument;
    u64 virtual_base;
    u64 physical_base;
    u64 canary;
};

struct RunQueue {
    sync::SpinLock lock;
    u32 entries[kQueueCapacity];
    u32 head;
    u32 count;
};

struct ProbeContext {
    u32 expected_cpu;
    u32 ordinal;
    u64 token;
};

struct CpuUserBinding {
    sync::SpinLock lock;
    thread::user::ExecutionLease* execution;
    u32 generation = 1;
};

TaskSlot tasks[kMaximumTasks]{};
RunQueue queues[64]{};
sync::SpinLock task_lock{};
u32 round_robin = 0;
u32 last_failure = 0;
bool initialized = false;
u64 submitted_tasks = 0;
u64 completed_tasks = 0;
u64 failed_tasks = 0;
u64 user_context_binds = 0;
u64 user_context_rejections = 0;
ProbeContext probe_contexts[kMaximumTasks]{};
CpuUserBinding user_bindings[64]{};
u32 probe_counts[64]{};
u32 probe_mismatch = 0;
u64 probe_checksum = 0;

u64 task_canary(u32 index, const TaskSlot& task) {
    return 0xD0'58'53'43'48'45'44'00ULL ^ (static_cast<u64>(index) << 32U) ^ task.physical_base ^
           task.virtual_base ^ static_cast<u64>(__stack_chk_guard);
}

void wipe_stack(TaskSlot& task) {
    auto* words = reinterpret_cast<volatile u64*>(task.virtual_base + kPageSize);
    constexpr u64 word_count = (kStackPages * kPageSize) / sizeof(u64);
    for (u64 index = 0; index < word_count; ++index) {
        words[index] = 0;
    }
    words[0] = task.canary;
}

bool map_task_stack(u32 index, TaskSlot& task) {
    task.virtual_base = kTaskArenaBase + static_cast<u64>(index) * kTaskStride;
    if (!memory::physical::allocate_contiguous(kStackPages, 1, task.physical_base,
                                               memory::physical::PageOwner::kernel_stack)) {
        return false;
    }
    auto* space = memory::virtual_memory::active_address_space();
    if (space == nullptr) {
        return false;
    }
    for (u64 page = 0; page < kStackPages; ++page) {
        if (!memory::virtual_memory::map(*space, task.virtual_base + (page + 1) * kPageSize,
                                         task.physical_base + page * kPageSize, MapFlags::write)) {
            return false;
        }
    }
    task.canary = task_canary(index, task);
    wipe_stack(task);
    return true;
}

bool enqueue(u32 cpu, u32 slot) {
    if (cpu >= arch::x86_64::smp::processor_count()) {
        return false;
    }
    RunQueue& queue = queues[cpu];
    sync::LockGuard guard(queue.lock);
    if (queue.count >= kQueueCapacity) {
        return false;
    }
    const u32 tail = (queue.head + queue.count) % kQueueCapacity;
    queue.entries[tail] = slot;
    ++queue.count;
    return true;
}

bool dequeue(u32 cpu, u32& slot) {
    if (cpu >= arch::x86_64::smp::processor_count()) {
        return false;
    }
    RunQueue& queue = queues[cpu];
    sync::LockGuard guard(queue.lock);
    if (queue.count == 0) {
        return false;
    }
    slot = queue.entries[queue.head];
    queue.head = (queue.head + 1) % kQueueCapacity;
    --queue.count;
    return true;
}

void reschedule_handler(arch::x86_64::interrupts::ExceptionFrame&) { arch::x86_64::apic::eoi(); }

void execute_slot(u32 index) {
    if (index >= kMaximumTasks) {
        return;
    }
    TaskSlot& task = tasks[index];
    u32 expected = static_cast<u32>(TaskState::queued);
    if (!__atomic_compare_exchange_n(&task.state, &expected, static_cast<u32>(TaskState::running),
                                     false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return;
    }
    const u64 stack_top = task.virtual_base + (kStackPages + 1) * kPageSize - 16;
    doxxer_execute_task_stack(stack_top, task.entry, task.argument);
    const auto* bottom = reinterpret_cast<const volatile u64*>(task.virtual_base + kPageSize);
    const bool intact = *bottom == task.canary;
    wipe_stack(task);
    if (intact) {
        __atomic_add_fetch(&completed_tasks, 1ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&task.state, static_cast<u32>(TaskState::complete), __ATOMIC_RELEASE);
    } else {
        __atomic_add_fetch(&failed_tasks, 1ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&task.state, static_cast<u32>(TaskState::failed), __ATOMIC_RELEASE);
    }
}

bool run_one(u32 cpu) {
    u32 slot = kInvalidIndex;
    if (!dequeue(cpu, slot)) {
        return false;
    }
    execute_slot(slot);
    return true;
}

[[noreturn]] void worker_loop() {
    const u32 cpu = arch::x86_64::smp::current_index();
    if (cpu >= arch::x86_64::smp::processor_count()) {
        for (;;) {
            asm volatile("cli; hlt");
        }
    }
    for (;;) {
        arch::x86_64::interrupts::disable();
        if (run_one(cpu)) {
            arch::x86_64::interrupts::enable();
            continue;
        }
        asm volatile("sti; hlt" : : : "memory");
    }
}

u32 choose_target_cpu() {
    const u32 count = arch::x86_64::smp::processor_count();
    const u32 bsp = arch::x86_64::smp::current_index();
    if (count <= 1) {
        return bsp;
    }
    for (u32 attempt = 0; attempt < count; ++attempt) {
        const u32 candidate = __atomic_fetch_add(&round_robin, 1U, __ATOMIC_RELAXED) % count;
        if (candidate != bsp) {
            return candidate;
        }
    }
    return bsp;
}

bool submit_to(u32 cpu, TaskEntry entry, void* argument, TaskHandle& handle) {
    if (!initialized || entry == nullptr || cpu >= arch::x86_64::smp::processor_count()) {
        return false;
    }
    u32 slot = kInvalidIndex;
    {
        sync::LockGuard guard(task_lock);
        for (u32 index = 0; index < kMaximumTasks; ++index) {
            if (__atomic_load_n(&tasks[index].state, __ATOMIC_ACQUIRE) ==
                static_cast<u32>(TaskState::free)) {
                slot = index;
                break;
            }
        }
        if (slot == kInvalidIndex) {
            return false;
        }
        TaskSlot& task = tasks[slot];
        task.target_cpu = cpu;
        task.entry = entry;
        task.argument = argument;
        handle = {.slot = slot, .generation = task.generation};
        wipe_stack(task);
        __atomic_store_n(&task.state, static_cast<u32>(TaskState::queued), __ATOMIC_RELEASE);
    }
    if (!enqueue(cpu, slot)) {
        __atomic_store_n(&tasks[slot].state, static_cast<u32>(TaskState::free), __ATOMIC_RELEASE);
        return false;
    }
    __atomic_add_fetch(&submitted_tasks, 1ULL, __ATOMIC_RELAXED);
    if (cpu != arch::x86_64::smp::current_index() &&
        !arch::x86_64::apic::send_ipi(arch::x86_64::smp::apic_id(cpu), kRescheduleVector)) {
        return false;
    }
    return true;
}

void probe_task(void* argument) {
    const auto* context = static_cast<const ProbeContext*>(argument);
    const u32 cpu = arch::x86_64::smp::current_index();
    if (cpu != context->expected_cpu || context->ordinal >= kMaximumTasks) {
        __atomic_store_n(&probe_mismatch, 1U, __ATOMIC_RELEASE);
        return;
    }
    __atomic_add_fetch(&probe_counts[cpu], 1U, __ATOMIC_RELAXED);
    __atomic_xor_fetch(&probe_checksum, context->token, __ATOMIC_RELAXED);
}
}

bool initialize() {
    if (initialized || arch::x86_64::interrupts::enabled() ||
        arch::x86_64::smp::processor_count() == 0) {
        return false;
    }
    last_failure = 0;
    for (u32 index = 0; index < kMaximumTasks; ++index) {
        tasks[index].generation = 1;
        tasks[index].state = static_cast<u32>(TaskState::free);
        if (!map_task_stack(index, tasks[index])) {
            last_failure = 1;
            return false;
        }
    }
    if (!arch::x86_64::interrupts::register_handler(kRescheduleVector, reschedule_handler)) {
        last_failure = 2;
        return false;
    }
    initialized = true;
    if (!arch::x86_64::smp::install_worker_entry(worker_loop)) {
        initialized = false;
        last_failure = 3;
        return false;
    }
    return true;
}

bool submit(TaskEntry entry, void* argument, TaskHandle& handle) {
    return submit_to(choose_target_cpu(), entry, argument, handle);
}

bool completed(TaskHandle handle) {
    if (handle.slot >= kMaximumTasks || tasks[handle.slot].generation != handle.generation) {
        return false;
    }
    const u32 state = __atomic_load_n(&tasks[handle.slot].state, __ATOMIC_ACQUIRE);
    return state == static_cast<u32>(TaskState::complete);
}

bool release(TaskHandle handle) {
    if (handle.slot >= kMaximumTasks) {
        return false;
    }
    sync::LockGuard guard(task_lock);
    TaskSlot& task = tasks[handle.slot];
    const u32 state = __atomic_load_n(&task.state, __ATOMIC_ACQUIRE);
    if (task.generation != handle.generation || (state != static_cast<u32>(TaskState::complete) &&
                                                 state != static_cast<u32>(TaskState::failed))) {
        return false;
    }
    ++task.generation;
    if (task.generation == 0) {
        ++task.generation;
    }
    task.entry = nullptr;
    task.argument = nullptr;
    __atomic_store_n(&task.state, static_cast<u32>(TaskState::free), __ATOMIC_RELEASE);
    return true;
}

bool pump_one() { return run_one(arch::x86_64::smp::current_index()); }

bool bind_user_context(thread::user::ExecutionLease& execution, UserContextBinding& binding) {
    binding = {};
    const u32 cpu = arch::x86_64::smp::current_index();
    if (!initialized || !thread::user::validate_execution_lease(execution) ||
        execution.address_space == nullptr ||
        !process::validate_address_space_lease(*execution.address_space) ||
        arch::x86_64::interrupts::enabled() ||
        cpu >= arch::x86_64::smp::processor_count()) {
        __atomic_add_fetch(&user_context_rejections, 1ULL, __ATOMIC_RELAXED);
        return false;
    }
    CpuUserBinding& state = user_bindings[cpu];
    sync::LockGuard guard(state.lock);
    if (state.execution != nullptr || arch::x86_64::smp::current_syscall_context() != nullptr ||
        !arch::x86_64::smp::bind_syscall_context(&execution)) {
        __atomic_add_fetch(&user_context_rejections, 1ULL, __ATOMIC_RELAXED);
        return false;
    }
    state.execution = &execution;
    binding = {
        .execution = &execution,
        .cpu = cpu,
        .generation = state.generation,
        .active = true,
    };
    __atomic_add_fetch(&user_context_binds, 1ULL, __ATOMIC_RELAXED);
    return true;
}

bool unbind_user_context(UserContextBinding& binding) {
    const u32 cpu = arch::x86_64::smp::current_index();
    if (!initialized || !binding.active || binding.execution == nullptr ||
        arch::x86_64::interrupts::enabled() || cpu != binding.cpu ||
        cpu >= arch::x86_64::smp::processor_count()) {
        __atomic_add_fetch(&user_context_rejections, 1ULL, __ATOMIC_RELAXED);
        return false;
    }
    CpuUserBinding& state = user_bindings[cpu];
    sync::LockGuard guard(state.lock);
    if (state.execution != binding.execution || state.generation != binding.generation ||
        arch::x86_64::smp::current_syscall_context() != binding.execution ||
        !thread::user::validate_execution_lease(*binding.execution) ||
        !arch::x86_64::smp::unbind_syscall_context(binding.execution)) {
        __atomic_add_fetch(&user_context_rejections, 1ULL, __ATOMIC_RELAXED);
        return false;
    }
    state.execution = nullptr;
    ++state.generation;
    if (state.generation == 0) {
        ++state.generation;
    }
    binding = {};
    return true;
}

bool self_test() {
    if (!initialized) {
        last_failure = 4;
        return false;
    }
    const u32 cpu_count = arch::x86_64::smp::processor_count();
    const u32 tasks_per_cpu = cpu_count <= 16 ? 4 : 1;
    const u32 task_count = cpu_count * tasks_per_cpu;
    if (task_count > kMaximumTasks) {
        last_failure = 5;
        return false;
    }
    probe_mismatch = 0;
    probe_checksum = 0;
    u64 expected_checksum = 0;
    TaskHandle handles[kMaximumTasks]{};
    u32 task_index = 0;
    for (u32 cpu = 0; cpu < cpu_count; ++cpu) {
        probe_counts[cpu] = 0;
        for (u32 ordinal = 0; ordinal < tasks_per_cpu; ++ordinal) {
            const u64 token =
                0x9E37'79B9'7F4A'7C15ULL ^ (static_cast<u64>(cpu) << 32U) ^ task_index;
            probe_contexts[task_index] = {
                .expected_cpu = cpu,
                .ordinal = task_index,
                .token = token,
            };
            expected_checksum ^= token;
            if (!submit_to(cpu, probe_task, &probe_contexts[task_index], handles[task_index])) {
                last_failure = 6;
                return false;
            }
            ++task_index;
        }
    }

    const u64 start = arch::x86_64::apic::reference_counter();
    const u64 timeout =
        arch::x86_64::apic::reference_ticks_for_microseconds(kSelfTestTimeoutMicroseconds);
    for (;;) {
        while (pump_one()) {
        }
        bool all_complete = true;
        for (u32 index = 0; index < task_count; ++index) {
            if (!completed(handles[index])) {
                all_complete = false;
            }
        }
        if (all_complete) {
            break;
        }
        if (timeout == 0 || arch::x86_64::apic::reference_counter() - start >= timeout) {
            last_failure = 7;
            return false;
        }
        asm volatile("pause");
    }
    if (__atomic_load_n(&probe_mismatch, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&probe_checksum, __ATOMIC_ACQUIRE) != expected_checksum) {
        last_failure = 8;
        return false;
    }
    for (u32 cpu = 0; cpu < cpu_count; ++cpu) {
        if (__atomic_load_n(&probe_counts[cpu], __ATOMIC_ACQUIRE) != tasks_per_cpu) {
            last_failure = 9;
            return false;
        }
    }
    for (u32 index = 0; index < task_count; ++index) {
        if (!release(handles[index])) {
            last_failure = 10;
            return false;
        }
    }
    last_failure = 11;
    security::capability::DomainHandle binding_manager{};
    process::CreateResult binding_process{};
    process::AddressSpaceLease context_probe{};
    thread::user::CreateResult binding_thread{};
    thread::user::ExecutionLease execution{};
    UserContextBinding binding{};
    UserContextBinding duplicate{};
    u64 code_page = 0;
    constexpr u64 kBindingEntry = 0x4A'0000ULL;
    if (!security::capability::create_domain(binding_manager) ||
        !process::create(binding_manager, "scheduler-binding", binding_process) ||
        !process::acquire_address_space(binding_manager, binding_process.control, context_probe) ||
        !memory::physical::allocate_page(
            code_page, memory::physical::PageOwner::user_image, memory::physical::Zone::any,
            context_probe.space->isolation_domain()) ||
        !memory::virtual_memory::map(*context_probe.space, kBindingEntry, code_page,
                                     memory::virtual_memory::MapFlags::user |
                                         memory::virtual_memory::MapFlags::execute) ||
        !thread::user::create(binding_manager, binding_process.control, kBindingEntry,
                              binding_thread) ||
        !thread::user::acquire_execution(binding_manager, binding_thread.control, execution) ||
        !bind_user_context(execution, binding) ||
        arch::x86_64::smp::current_syscall_context() != &execution ||
        bind_user_context(execution, duplicate)) {
        return false;
    }
    UserContextBinding forged = binding;
    ++forged.generation;
    if (unbind_user_context(forged) || !unbind_user_context(binding) || binding.active ||
        arch::x86_64::smp::current_syscall_context() != nullptr ||
        !thread::user::release_execution(execution) ||
        !thread::user::terminate(binding_manager, binding_thread.control, 0) ||
        !thread::user::destroy(binding_manager, binding_thread.control) ||
        !memory::virtual_memory::unmap(*context_probe.space, kBindingEntry) ||
        !memory::physical::free_page(code_page, memory::physical::PageOwner::user_image,
                                     context_probe.space->isolation_domain())) {
        return false;
    }
    process::release_address_space(context_probe);
    if (!process::terminate(binding_manager, binding_process.control, 0) ||
        !process::destroy(binding_manager, binding_process.control) ||
        !security::capability::destroy_domain(binding_manager)) {
        return false;
    }
    last_failure = 0;
    return true;
}

Statistics statistics() {
    return {
        .submitted = __atomic_load_n(&submitted_tasks, __ATOMIC_RELAXED),
        .completed = __atomic_load_n(&completed_tasks, __ATOMIC_RELAXED),
        .failed = __atomic_load_n(&failed_tasks, __ATOMIC_RELAXED),
        .user_context_binds = __atomic_load_n(&user_context_binds, __ATOMIC_RELAXED),
        .user_context_rejections =
            __atomic_load_n(&user_context_rejections, __ATOMIC_RELAXED),
        .capacity = kMaximumTasks,
    };
}

u32 failure_code() { return last_failure; }
}
