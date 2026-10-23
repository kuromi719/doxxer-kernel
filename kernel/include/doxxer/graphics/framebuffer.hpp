#pragma once

#include <doxxer/types.hpp>

struct limine_framebuffer;

namespace doxxer::graphics {
enum class BootStage : u8 {
    Entropy, SealedMemory, PhysicalMemory, VirtualMemory, CpuProtection,
    ShadowRegions, KernelHeap, CapabilityModel, IpcEvents, ProcessContainers,
    SyscallAbi, ServiceRegistry, UserMemory, ImagePolicy, UserThreads,
    Ring3Boundary, Acpi, DmaProtection, SmpHardening, Scheduler, ApicTimer,
    Framebuffer, Count,
};

bool initialize(limine_framebuffer* framebuffer);
bool ready();
void clear();
void draw_boot_trace();
void stage_progress(BootStage stage, u8 percent);
void stage_pass(BootStage stage);
void stage_fail(BootStage stage);
void fail_active_stage();
void draw_failure_countdown(u32 seconds_remaining);
void draw_boot_logo();
void draw_boot_banner();
void write_char(char value);
void write(const char* text);
}
