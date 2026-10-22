#include <doxxer/arch/x86_64/io.hpp>
#include <doxxer/arch/x86_64/serial.hpp>

namespace doxxer::serial {
namespace {
constexpr u16 kCom1 = 0x3F8;
bool initialized = false;

bool transmit_empty() {
    return (arch::x86_64::in8(kCom1 + 5) & 0x20U) != 0;
}
}

bool initialize() {
    using arch::x86_64::in8;
    using arch::x86_64::out8;

    out8(kCom1 + 1, 0x00);
    out8(kCom1 + 3, 0x80);
    out8(kCom1 + 0, 0x03);
    out8(kCom1 + 1, 0x00);
    out8(kCom1 + 3, 0x03);
    out8(kCom1 + 2, 0xC7);
    out8(kCom1 + 4, 0x1E);
    out8(kCom1 + 0, 0xAE);

    if (in8(kCom1 + 0) != 0xAE) {
        return false;
    }

    out8(kCom1 + 4, 0x0F);
    initialized = true;
    return true;
}

bool ready() {
    return initialized;
}

void write_char(char value) {
    if (!initialized) {
        return;
    }
    if (value == '\n') {
        write_char('\r');
    }
    while (!transmit_empty()) {
        asm volatile("pause");
    }
    arch::x86_64::out8(kCom1, static_cast<u8>(value));
}

void write(const char* text) {
    if (text == nullptr) {
        return;
    }
    while (*text != '\0') {
        write_char(*text++);
    }
}
}
