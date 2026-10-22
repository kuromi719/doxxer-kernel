#include <doxxer/security/sealed_memory.hpp>

#include <doxxer/sync/spinlock.hpp>

namespace doxxer::security::sealed_memory {
namespace {
constexpr u16 kMaximumSlots = 32;
constexpr usize kSha256Bytes = 32;
constexpr usize kSha256BlockBytes = 64;
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
    u8 block[kSha256BlockBytes];
    usize block_size;
    u64 total_size;
};

struct Slot {
    bool active;
    u32 generation;
    u16 size;
    u8 nonce[12];
    u8 ciphertext[kMaximumSecretBytes];
    u8 tag[kSha256Bytes];
};

sync::SpinLock vault_lock{};
Slot slots[kMaximumSlots]{};
u8 encryption_key[kSha256Bytes]{};
u8 authentication_key[kSha256Bytes]{};
u32 nonce_prefix = 0;
u64 nonce_counter = 0;
u64 sealed_objects = 0;
u64 opened_objects = 0;
u64 destroyed_objects = 0;
u64 authentication_failures = 0;
u64 rejected_operations = 0;
u32 last_failure = 0;
bool initialized = false;

constexpr u32 rotate_right(u32 value, u32 count) {
    return (value >> count) | (value << (32U - count));
}

constexpr u32 rotate_left(u32 value, u32 count) {
    return (value << count) | (value >> (32U - count));
}

u32 load32_le(const u8* data) {
    return static_cast<u32>(data[0]) | (static_cast<u32>(data[1]) << 8U) |
           (static_cast<u32>(data[2]) << 16U) | (static_cast<u32>(data[3]) << 24U);
}

void store32_le(u8* data, u32 value) {
    data[0] = static_cast<u8>(value);
    data[1] = static_cast<u8>(value >> 8U);
    data[2] = static_cast<u8>(value >> 16U);
    data[3] = static_cast<u8>(value >> 24U);
}

void secure_zero(void* data, usize size) {
    auto* bytes = static_cast<volatile u8*>(data);
    for (usize index = 0; index < size; ++index) {
        bytes[index] = 0;
    }
    asm volatile("" : : "r"(data) : "memory");
}

void sha256_transform(Sha256& context, const u8* block) {
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
    secure_zero(words, sizeof(words));
}

void sha256_initialize(Sha256& context) {
    for (usize index = 0; index < 8; ++index) {
        context.state[index] = kInitialState[index];
    }
    context.block_size = 0;
    context.total_size = 0;
    secure_zero(context.block, sizeof(context.block));
}

void sha256_update(Sha256& context, const u8* data, usize size) {
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
            sha256_transform(context, context.block);
            context.block_size = 0;
        }
    }
}

void sha256_finish(Sha256& context, u8 digest[kSha256Bytes]) {
    const u64 bit_length = context.total_size * 8ULL;
    context.block[context.block_size++] = 0x80;
    if (context.block_size > 56) {
        while (context.block_size < sizeof(context.block)) {
            context.block[context.block_size++] = 0;
        }
        sha256_transform(context, context.block);
        context.block_size = 0;
    }
    while (context.block_size < 56) {
        context.block[context.block_size++] = 0;
    }
    for (usize index = 0; index < 8; ++index) {
        context.block[56 + index] = static_cast<u8>(bit_length >> (56U - index * 8U));
    }
    sha256_transform(context, context.block);
    for (usize index = 0; index < 8; ++index) {
        digest[index * 4] = static_cast<u8>(context.state[index] >> 24U);
        digest[index * 4 + 1] = static_cast<u8>(context.state[index] >> 16U);
        digest[index * 4 + 2] = static_cast<u8>(context.state[index] >> 8U);
        digest[index * 4 + 3] = static_cast<u8>(context.state[index]);
    }
    secure_zero(&context, sizeof(context));
}

void hmac_sha256(const u8* key, usize key_size, const u8* first, usize first_size,
                 const u8* second, usize second_size, u8 tag[kSha256Bytes]) {
    u8 normalized[kSha256BlockBytes]{};
    if (key_size > sizeof(normalized)) {
        Sha256 key_hash{};
        sha256_initialize(key_hash);
        sha256_update(key_hash, key, key_size);
        sha256_finish(key_hash, normalized);
    } else {
        for (usize index = 0; index < key_size; ++index) {
            normalized[index] = key[index];
        }
    }
    u8 inner_pad[kSha256BlockBytes]{};
    u8 outer_pad[kSha256BlockBytes]{};
    for (usize index = 0; index < kSha256BlockBytes; ++index) {
        inner_pad[index] = normalized[index] ^ 0x36U;
        outer_pad[index] = normalized[index] ^ 0x5CU;
    }
    u8 inner[kSha256Bytes]{};
    Sha256 hash{};
    sha256_initialize(hash);
    sha256_update(hash, inner_pad, sizeof(inner_pad));
    sha256_update(hash, first, first_size);
    if (second_size != 0) {
        sha256_update(hash, second, second_size);
    }
    sha256_finish(hash, inner);
    sha256_initialize(hash);
    sha256_update(hash, outer_pad, sizeof(outer_pad));
    sha256_update(hash, inner, sizeof(inner));
    sha256_finish(hash, tag);
    secure_zero(normalized, sizeof(normalized));
    secure_zero(inner_pad, sizeof(inner_pad));
    secure_zero(outer_pad, sizeof(outer_pad));
    secure_zero(inner, sizeof(inner));
}

void quarter_round(u32& a, u32& b, u32& c, u32& d) {
    a += b;
    d = rotate_left(d ^ a, 16);
    c += d;
    b = rotate_left(b ^ c, 12);
    a += b;
    d = rotate_left(d ^ a, 8);
    c += d;
    b = rotate_left(b ^ c, 7);
}

void chacha20_block(const u8 key[32], u32 counter, const u8 nonce[12], u8 output[64]) {
    u32 state[16] = {
        0x6170'7865U, 0x3320'646EU, 0x7962'2D32U, 0x6B20'6574U,
        load32_le(key), load32_le(key + 4), load32_le(key + 8), load32_le(key + 12),
        load32_le(key + 16), load32_le(key + 20), load32_le(key + 24), load32_le(key + 28),
        counter, load32_le(nonce), load32_le(nonce + 4), load32_le(nonce + 8),
    };
    u32 working[16]{};
    for (usize index = 0; index < 16; ++index) {
        working[index] = state[index];
    }
    for (usize round = 0; round < 10; ++round) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[1], working[5], working[9], working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);
        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8], working[13]);
        quarter_round(working[3], working[4], working[9], working[14]);
    }
    for (usize index = 0; index < 16; ++index) {
        store32_le(output + index * 4, working[index] + state[index]);
    }
    secure_zero(state, sizeof(state));
    secure_zero(working, sizeof(working));
}

void chacha20_xor(const u8 key[32], const u8 nonce[12], const u8* input, u8* output,
                  usize size) {
    u32 counter = 1;
    while (size != 0) {
        u8 stream[64]{};
        chacha20_block(key, counter++, nonce, stream);
        const usize chunk = size < sizeof(stream) ? size : sizeof(stream);
        for (usize index = 0; index < chunk; ++index) {
            output[index] = input[index] ^ stream[index];
        }
        input += chunk;
        output += chunk;
        size -= chunk;
        secure_zero(stream, sizeof(stream));
    }
}

void store16_le(u8* data, u16 value) {
    data[0] = static_cast<u8>(value);
    data[1] = static_cast<u8>(value >> 8U);
}

void build_header(u16 slot, const Slot& record, u8 header[20]) {
    store16_le(header, slot);
    store32_le(header + 2, record.generation);
    store16_le(header + 6, record.size);
    for (usize index = 0; index < sizeof(record.nonce); ++index) {
        header[8 + index] = record.nonce[index];
    }
}

void authenticate(u16 slot, const Slot& record, u8 tag[kSha256Bytes]) {
    u8 header[20]{};
    build_header(slot, record, header);
    hmac_sha256(authentication_key, sizeof(authentication_key), header, sizeof(header),
                record.ciphertext, record.size, tag);
    secure_zero(header, sizeof(header));
}

bool constant_time_equal(const u8* left, const u8* right, usize size) {
    u8 difference = 0;
    for (usize index = 0; index < size; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

void reject() { ++rejected_operations; }

u32 next_generation(u32 generation) {
    ++generation;
    return generation == 0 ? 1 : generation;
}

bool primitive_self_test() {
    u8 key[32]{};
    for (usize index = 0; index < sizeof(key); ++index) {
        key[index] = static_cast<u8>(index);
    }
    const u8 nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
                          0x00, 0x4A, 0x00, 0x00, 0x00, 0x00};
    const u8 expected[64] = {
        0x10, 0xF1, 0xE7, 0xE4, 0xD1, 0x3B, 0x59, 0x15, 0x50, 0x0F, 0xDD,
        0x1F, 0xA3, 0x20, 0x71, 0xC4, 0xC7, 0xD1, 0xF4, 0xC7, 0x33, 0xC0,
        0x68, 0x03, 0x04, 0x22, 0xAA, 0x9A, 0xC3, 0xD4, 0x6C, 0x4E, 0xD2,
        0x82, 0x64, 0x46, 0x07, 0x9F, 0xAA, 0x09, 0x14, 0xC2, 0xD7, 0x05,
        0xD9, 0x8B, 0x02, 0xA2, 0xB5, 0x12, 0x9C, 0xD1, 0xDE, 0x16, 0x4E,
        0xB9, 0xCB, 0xD0, 0x83, 0xE8, 0xA2, 0x50, 0x3C, 0x4E,
    };
    u8 output[64]{};
    chacha20_block(key, 1, nonce, output);
    if (!constant_time_equal(output, expected, sizeof(output))) {
        secure_zero(key, sizeof(key));
        secure_zero(output, sizeof(output));
        return false;
    }
    u8 hmac_key[20]{};
    for (u8& value : hmac_key) {
        value = 0x0B;
    }
    const u8 message[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
    const u8 expected_hmac[32] = {
        0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53, 0x5C, 0xA8, 0xAF,
        0xCE, 0xAF, 0x0B, 0xF1, 0x2B, 0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83,
        0x3D, 0xA7, 0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32, 0xCF, 0xF7,
    };
    u8 hmac[32]{};
    hmac_sha256(hmac_key, sizeof(hmac_key), message, sizeof(message), nullptr, 0, hmac);
    const bool valid = constant_time_equal(hmac, expected_hmac, sizeof(hmac));
    secure_zero(key, sizeof(key));
    secure_zero(output, sizeof(output));
    secure_zero(hmac_key, sizeof(hmac_key));
    secure_zero(hmac, sizeof(hmac));
    return valid;
}

void derive_key(const volatile u64* entropy, usize entropy_words, const u8* label,
                usize label_size, u8 output[32]) {
    Sha256 hash{};
    sha256_initialize(hash);
    sha256_update(hash, label, label_size);
    for (usize word = 0; word < entropy_words; ++word) {
        const u64 value = entropy[word];
        u8 bytes[8]{};
        for (usize index = 0; index < sizeof(bytes); ++index) {
            bytes[index] = static_cast<u8>(value >> (index * 8U));
        }
        sha256_update(hash, bytes, sizeof(bytes));
        secure_zero(bytes, sizeof(bytes));
    }
    sha256_finish(hash, output);
}
}

bool initialize(const volatile u64* entropy, usize entropy_words) {
    sync::LockGuard guard(vault_lock);
    if (initialized || entropy == nullptr || entropy_words == 0 || entropy_words > 64 ||
        !primitive_self_test()) {
        reject();
        return false;
    }
    constexpr u8 encryption_label[] = {'D', 'O', 'X', 'X', 'E', 'R', '-', 'E', 'N', 'C'};
    constexpr u8 authentication_label[] = {'D', 'O', 'X', 'X', 'E', 'R', '-', 'M', 'A', 'C'};
    constexpr u8 nonce_label[] = {'D', 'O', 'X', 'X', 'E', 'R', '-', 'N', 'O', 'N', 'C', 'E'};
    derive_key(entropy, entropy_words, encryption_label, sizeof(encryption_label),
               encryption_key);
    derive_key(entropy, entropy_words, authentication_label, sizeof(authentication_label),
               authentication_key);
    u8 nonce_seed[32]{};
    derive_key(entropy, entropy_words, nonce_label, sizeof(nonce_label), nonce_seed);
    nonce_prefix = load32_le(nonce_seed);
    nonce_counter = static_cast<u64>(load32_le(nonce_seed + 4)) |
                    (static_cast<u64>(load32_le(nonce_seed + 8)) << 32U);
    if (nonce_counter == static_cast<u64>(-1)) {
        nonce_counter = 0;
    }
    secure_zero(nonce_seed, sizeof(nonce_seed));
    for (Slot& slot : slots) {
        slot.generation = 1;
    }
    initialized = true;
    return true;
}

bool seal(const void* plaintext, usize size, Handle& handle) {
    handle = {};
    if (plaintext == nullptr || size == 0 || size > kMaximumSecretBytes) {
        sync::LockGuard guard(vault_lock);
        reject();
        return false;
    }
    sync::LockGuard guard(vault_lock);
    if (!initialized || nonce_counter == static_cast<u64>(-1)) {
        reject();
        return false;
    }
    u16 selected = kMaximumSlots;
    for (u16 index = 0; index < kMaximumSlots; ++index) {
        if (!slots[index].active) {
            selected = index;
            break;
        }
    }
    if (selected == kMaximumSlots) {
        reject();
        return false;
    }
    Slot& slot = slots[selected];
    slot.size = static_cast<u16>(size);
    store32_le(slot.nonce, nonce_prefix);
    const u64 counter = nonce_counter++;
    store32_le(slot.nonce + 4, static_cast<u32>(counter));
    store32_le(slot.nonce + 8, static_cast<u32>(counter >> 32U));
    chacha20_xor(encryption_key, slot.nonce, static_cast<const u8*>(plaintext),
                 slot.ciphertext, size);
    for (usize index = size; index < sizeof(slot.ciphertext); ++index) {
        slot.ciphertext[index] = 0;
    }
    authenticate(selected, slot, slot.tag);
    slot.active = true;
    handle = {.slot = selected, .generation = slot.generation};
    ++sealed_objects;
    return true;
}

bool open(Handle handle, void* plaintext, usize capacity, usize& size) {
    size = 0;
    if (plaintext == nullptr || handle.slot >= kMaximumSlots) {
        sync::LockGuard guard(vault_lock);
        if (plaintext != nullptr) {
            secure_zero(plaintext,
                        capacity < kMaximumSecretBytes ? capacity : kMaximumSecretBytes);
        }
        reject();
        return false;
    }
    sync::LockGuard guard(vault_lock);
    Slot& slot = slots[handle.slot];
    if (!initialized || !slot.active || slot.generation != handle.generation ||
        slot.size == 0 || slot.size > kMaximumSecretBytes || capacity < slot.size) {
        secure_zero(plaintext,
                    capacity < kMaximumSecretBytes ? capacity : kMaximumSecretBytes);
        reject();
        return false;
    }
    u8 expected[kSha256Bytes]{};
    authenticate(handle.slot, slot, expected);
    if (!constant_time_equal(expected, slot.tag, sizeof(expected))) {
        secure_zero(expected, sizeof(expected));
        secure_zero(plaintext, capacity < kMaximumSecretBytes ? capacity : kMaximumSecretBytes);
        ++authentication_failures;
        reject();
        return false;
    }
    secure_zero(expected, sizeof(expected));
    chacha20_xor(encryption_key, slot.nonce, slot.ciphertext, static_cast<u8*>(plaintext),
                 slot.size);
    size = slot.size;
    ++opened_objects;
    return true;
}

bool destroy(Handle handle) {
    sync::LockGuard guard(vault_lock);
    if (!initialized || handle.slot >= kMaximumSlots) {
        reject();
        return false;
    }
    Slot& slot = slots[handle.slot];
    if (!slot.active || slot.generation != handle.generation) {
        reject();
        return false;
    }
    secure_zero(slot.ciphertext, sizeof(slot.ciphertext));
    secure_zero(slot.tag, sizeof(slot.tag));
    secure_zero(slot.nonce, sizeof(slot.nonce));
    slot.size = 0;
    slot.active = false;
    slot.generation = next_generation(slot.generation);
    ++destroyed_objects;
    return true;
}

bool self_test() {
    last_failure = 0;
    constexpr u8 secret[] = {0xD0, 0x58, 0x53, 0x45, 0x41, 0x4C, 0x45, 0x44,
                             0x2D, 0x52, 0x41, 0x4D, 0x2D, 0x54, 0x45, 0x53, 0x54};
    Handle handle{};
    u8 opened[sizeof(secret)]{};
    usize opened_size = 0;
    if (!initialized || !seal(secret, sizeof(secret), handle) ||
        !open(handle, opened, sizeof(opened), opened_size) || opened_size != sizeof(secret) ||
        !constant_time_equal(secret, opened, sizeof(secret))) {
        last_failure = 1;
        secure_zero(opened, sizeof(opened));
        return false;
    }
    secure_zero(opened, sizeof(opened));
    {
        sync::LockGuard guard(vault_lock);
        slots[handle.slot].ciphertext[0] ^= 0x80U;
    }
    for (u8& value : opened) {
        value = 0xA5;
    }
    if (open(handle, opened, sizeof(opened), opened_size) || opened_size != 0) {
        last_failure = 2;
        return false;
    }
    for (u8 value : opened) {
        if (value != 0) {
            last_failure = 3;
            return false;
        }
    }
    {
        sync::LockGuard guard(vault_lock);
        slots[handle.slot].ciphertext[0] ^= 0x80U;
    }
    if (!open(handle, opened, sizeof(opened), opened_size) ||
        !constant_time_equal(secret, opened, sizeof(secret)) || !destroy(handle) ||
        open(handle, opened, sizeof(opened), opened_size) || destroy(handle)) {
        last_failure = 4;
        secure_zero(opened, sizeof(opened));
        return false;
    }
    secure_zero(opened, sizeof(opened));
    return true;
}

Statistics statistics() {
    sync::LockGuard guard(vault_lock);
    return {
        .sealed_objects = sealed_objects,
        .opened_objects = opened_objects,
        .destroyed_objects = destroyed_objects,
        .authentication_failures = authentication_failures,
        .rejected_operations = rejected_operations,
        .capacity = kMaximumSlots,
    };
}

u32 failure_code() { return last_failure; }
}
