#pragma once

#include <doxxer/types.hpp>

namespace doxxer::security::image_policy {
constexpr usize kDigestBytes = 32;
constexpr usize kMaximumTrustedImages = 32;

struct Digest {
    u8 bytes[kDigestBytes];
};

struct Statistics {
    u32 trusted_images;
    u64 accepted_images;
    u64 rejected_images;
};

bool initialize();
bool measure(const void* data, usize size, Digest& digest);
bool enroll(const void* data, usize size, Digest* digest = nullptr);
bool seal();
bool authorize(const void* data, usize size, Digest* digest = nullptr);
bool is_sealed();
bool self_test();
Statistics statistics();
u32 failure_code();
}
