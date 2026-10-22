#include <doxxer/types.hpp>

extern "C" {
void* memset(void* destination, int value, doxxer::usize count) {
    auto* output = static_cast<doxxer::u8*>(destination);
    for (doxxer::usize index = 0; index < count; ++index) {
        output[index] = static_cast<doxxer::u8>(value);
    }
    return destination;
}

void* memcpy(void* destination, const void* source, doxxer::usize count) {
    auto* output = static_cast<doxxer::u8*>(destination);
    const auto* input = static_cast<const doxxer::u8*>(source);
    for (doxxer::usize index = 0; index < count; ++index) {
        output[index] = input[index];
    }
    return destination;
}

void* memmove(void* destination, const void* source, doxxer::usize count) {
    auto* output = static_cast<doxxer::u8*>(destination);
    const auto* input = static_cast<const doxxer::u8*>(source);
    if (output < input) {
        for (doxxer::usize index = 0; index < count; ++index) {
            output[index] = input[index];
        }
    } else if (output > input) {
        for (doxxer::usize index = count; index > 0; --index) {
            output[index - 1] = input[index - 1];
        }
    }
    return destination;
}

int memcmp(const void* left, const void* right, doxxer::usize count) {
    const auto* lhs = static_cast<const doxxer::u8*>(left);
    const auto* rhs = static_cast<const doxxer::u8*>(right);
    for (doxxer::usize index = 0; index < count; ++index) {
        if (lhs[index] != rhs[index]) {
            return static_cast<int>(lhs[index]) - static_cast<int>(rhs[index]);
        }
    }
    return 0;
}
}
