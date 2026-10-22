#pragma once

#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::hardening {
struct Statistics {
    u32 hardened_processors;
    bool write_protect;
    bool no_execute;
    bool smep;
    bool smap;
    bool umip;
    bool user_timestamps_disabled;
    bool user_fsgsbase_disabled;
    bool speculation_controls;
};

bool initialize_boot_processor();
bool initialize_secondary_processor();
bool verify_current_processor();
Statistics statistics();
u32 failure_code();
}
