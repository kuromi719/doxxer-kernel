#include <doxxer/security/image_policy.hpp>

#include <doxxer/sync/spinlock.hpp>

namespace doxxer::security::image_policy {
namespace {
constexpr u32 kInitialState[8] = {
    0x6A09'E667U, 0xBB67'AE85U, 0x3C6E'F372U, 0xA54F'F53AU,
    0x510E'527FU, 0x9B05'688CU, 0x1F83'D9ABU, 0x5BE0'CD19U,
};
constexpr u32 kRoundConstants[64] = {
    0x428A'2F98U, 0x7137'4491U, 0xB5C0'FBCFU, 0xE9B5'DBA5U, 0x3956'C25BU,
    0x59F1'11F1U, 0x923F'82A4U, 0xAB1C'5ED5U, 0xD807'AA98U, 0x1283'5B01U,
    0x2431'85BEU, 0x550C'7DC3U, 0x72BE'5D74U, 0x80DE'B1FEU, 0x9BDC'06A7U,
    0xC19B'F174U, 0xE49B'69C1U, 0xEFBE'4786U, 0x0FC1'9DC6U, 0x240C'A1CCU,
    0x2DE9'2C6FU, 0x4A74'84AAU, 0x5CB0'A9DCU, 0x76F9'88DAU, 0x983E'5152U,
    0xA831'C66DU, 0xB003'27C8U, 0xBF59'7FC7U, 0xC6E0'0BF3U, 0xD5A7'9147U,
    0x06CA'6351U, 0x1429'2967U, 0x27B7'0A85U, 0x2E1B'2138U, 0x4D2C'6DFCU,
    0x5338'0D13U, 0x650A'7354U, 0x766A'0ABBU, 0x81C2'C92EU, 0x9272'2C85U,
    0xA2BF'E8A1U, 0xA81A'664BU, 0xC24B'8B70U, 0xC76C'51A3U, 0xD192'E819U,
    0xD699'0624U, 0xF40E'3585U, 0x106A'A070U, 0x19A4'C116U, 0x1E37'6C08U,
    0x2748'774CU, 0x34B0'BCB5U, 0x391C'0CB3U, 0x4ED8'AA4AU, 0x5B9C'CA4FU,
    0x682E'6FF3U, 0x748F'82EEU, 0x78A5'636FU, 0x84C8'7814U, 0x8CC7'0208U,
    0x90BE'FFFAU, 0xA450'6CEBU, 0xBEF9'A3F7U, 0xC671'78F2U,
};

struct Sha256 {
    u32 state[8];
    u8 block[64];
    usize block_size;
    u64 total_size;
};

sync::SpinLock policy_lock{};
Digest trusted[kMaximumTrustedImages]{};
u32 trusted_count = 0;
u64 accepted = 0;
u64 rejected = 0;
u32 last_failure = 0;
bool initialized = false;
bool sealed = false;

constexpr u32 rotate_right(u32 value, u32 count) {
    return (value >> count) | (value << (32U - count));
}

void transform(Sha256& context, const u8* block) {
    u32 words[64]{};
    for (usize index = 0; index < 16; ++index) {
        const usize offset = index * 4;
        words[index] = (static_cast<u32>(block[offset]) << 24U) |
                       (static_cast<u32>(block[offset + 1]) << 16U) |
                       (static_cast<u32>(block[offset + 2]) << 8U) |
                       static_cast<u32>(block[offset + 3]);
    }
    for (usize index = 16; index < 64; ++index) {
        const u32 sigma0 = rotate_right(words[index - 15], 7) ^
                           rotate_right(words[index - 15], 18) ^ (words[index - 15] >> 3U);
        const u32 sigma1 = rotate_right(words[index - 2], 17) ^
                           rotate_right(words[index - 2], 19) ^ (words[index - 2] >> 10U);
        words[index] = words[index - 16] + sigma0 + words[index - 7] + sigma1;
    }

    u32 a = context.state[0];
    u32 b = context.state[1];
    u32 c = context.state[2];
    u32 d = context.state[3];
    u32 e = context.state[4];
    u32 f = context.state[5];
    u32 g = context.state[6];
    u32 h = context.state[7];
    for (usize index = 0; index < 64; ++index) {
        const u32 choice = (e & f) ^ (~e & g);
        const u32 majority = (a & b) ^ (a & c) ^ (b & c);
        const u32 sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        const u32 sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        const u32 temporary1 = h + sum1 + choice + kRoundConstants[index] + words[index];
        const u32 temporary2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    context.state[0] += a;
    context.state[1] += b;
    context.state[2] += c;
    context.state[3] += d;
    context.state[4] += e;
    context.state[5] += f;
    context.state[6] += g;
    context.state[7] += h;
}

void update(Sha256& context, const u8* data, usize size) {
    context.total_size += size;
    while (size != 0) {
        const usize available = sizeof(context.block) - context.block_size;
        const usize chunk = size < available ? size : available;
        for (usize index = 0; index < chunk; ++index) {
            context.block[context.block_size + index] = data[index];
        }
        context.block_size += chunk;
        data += chunk;
        size -= chunk;
        if (context.block_size == sizeof(context.block)) {
            transform(context, context.block);
            context.block_size = 0;
        }
    }
}

void finish(Sha256& context, Digest& digest) {
    const u64 bit_length = context.total_size * 8ULL;
    context.block[context.block_size++] = 0x80;
    if (context.block_size > 56) {
        while (context.block_size < sizeof(context.block)) {
            context.block[context.block_size++] = 0;
        }
        transform(context, context.block);
        context.block_size = 0;
    }
    while (context.block_size < 56) {
        context.block[context.block_size++] = 0;
    }
    for (usize index = 0; index < 8; ++index) {
        context.block[56 + index] = static_cast<u8>(bit_length >> (56U - index * 8U));
    }
    transform(context, context.block);
    for (usize index = 0; index < 8; ++index) {
        digest.bytes[index * 4] = static_cast<u8>(context.state[index] >> 24U);
        digest.bytes[index * 4 + 1] = static_cast<u8>(context.state[index] >> 16U);
        digest.bytes[index * 4 + 2] = static_cast<u8>(context.state[index] >> 8U);
        digest.bytes[index * 4 + 3] = static_cast<u8>(context.state[index]);
    }
}

bool equal(const Digest& left, const Digest& right) {
    u8 difference = 0;
    for (usize index = 0; index < kDigestBytes; ++index) {
        difference |= left.bytes[index] ^ right.bytes[index];
    }
    return difference == 0;
}

void reject() { ++rejected; }
}

bool initialize() {
    sync::LockGuard guard(policy_lock);
    if (initialized) {
        reject();
        return false;
    }
    trusted_count = 0;
    accepted = 0;
    rejected = 0;
    last_failure = 0;
    sealed = false;
    initialized = true;
    return true;
}

bool measure(const void* data, usize size, Digest& digest) {
    if (data == nullptr || size == 0 || size > static_cast<u64>(-1) / 8ULL) {
        return false;
    }
    Sha256 context{
        .state = {kInitialState[0], kInitialState[1], kInitialState[2], kInitialState[3],
                  kInitialState[4], kInitialState[5], kInitialState[6], kInitialState[7]},
        .block = {},
        .block_size = 0,
        .total_size = 0,
    };
    update(context, static_cast<const u8*>(data), size);
    finish(context, digest);
    return true;
}

bool enroll(const void* data, usize size, Digest* digest) {
    Digest measured{};
    if (!measure(data, size, measured)) {
        sync::LockGuard guard(policy_lock);
        reject();
        return false;
    }
    sync::LockGuard guard(policy_lock);
    if (!initialized || sealed || trusted_count >= kMaximumTrustedImages) {
        reject();
        return false;
    }
    for (u32 index = 0; index < trusted_count; ++index) {
        if (equal(trusted[index], measured)) {
            reject();
            return false;
        }
    }
    trusted[trusted_count++] = measured;
    if (digest != nullptr) {
        *digest = measured;
    }
    return true;
}

bool seal() {
    sync::LockGuard guard(policy_lock);
    if (!initialized || sealed || trusted_count == 0) {
        reject();
        return false;
    }
    sealed = true;
    return true;
}

bool authorize(const void* data, usize size, Digest* digest) {
    Digest measured{};
    if (!measure(data, size, measured)) {
        sync::LockGuard guard(policy_lock);
        reject();
        return false;
    }
    sync::LockGuard guard(policy_lock);
    bool matched = false;
    if (initialized && sealed) {
        for (u32 index = 0; index < trusted_count; ++index) {
            matched = equal(trusted[index], measured) || matched;
        }
    }
    if (!matched) {
        reject();
        return false;
    }
    ++accepted;
    if (digest != nullptr) {
        *digest = measured;
    }
    return true;
}

bool is_sealed() {
    sync::LockGuard guard(policy_lock);
    return initialized && sealed;
}

bool self_test() {
    last_failure = 0;
    constexpr u8 input[3] = {'a', 'b', 'c'};
    constexpr u8 expected[kDigestBytes] = {
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40,
        0xDE, 0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17,
        0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
    };
    Digest digest{};
    if (!initialized || sealed || !measure(input, sizeof(input), digest)) {
        last_failure = 1;
        return false;
    }
    for (usize index = 0; index < kDigestBytes; ++index) {
        if (digest.bytes[index] != expected[index]) {
            last_failure = 2;
            return false;
        }
    }
    if (authorize(input, sizeof(input))) {
        last_failure = 3;
        return false;
    }
    return true;
}

Statistics statistics() {
    sync::LockGuard guard(policy_lock);
    return {
        .trusted_images = trusted_count,
        .accepted_images = accepted,
        .rejected_images = rejected,
    };
}

u32 failure_code() { return last_failure; }
}
