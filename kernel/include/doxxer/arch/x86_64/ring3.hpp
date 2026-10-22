#pragma once

#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::ring3 {
bool self_test();
u32 failure_code();
}
