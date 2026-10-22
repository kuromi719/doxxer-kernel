#include <doxxer/arch/x86_64/serial.hpp>
#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/log.hpp>
#include <doxxer/types.hpp>

namespace doxxer::log {
namespace {
bool framebuffer_attached = false;
}

void initialize() { framebuffer_attached = false; }

void attach_framebuffer() { framebuffer_attached = graphics::ready(); }

void write(const char* text) {
    serial::write(text);
    if (framebuffer_attached) {
        graphics::write(text);
    }
}

void write_decimal(unsigned long long value) {
    char buffer[21]{};
    unsigned long long divisor = 1;
    while (value / divisor >= 10 && divisor <= 1000000000000000000ULL) {
        divisor *= 10;
    }
    usize index = 0;
    do {
        buffer[index++] = static_cast<char>('0' + ((value / divisor) % 10));
        divisor /= 10;
    } while (divisor != 0);
    buffer[index] = '\0';
    write(buffer);
}

void write_hex(unsigned long long value) {
    constexpr char digits[] = "0123456789ABCDEF";
    char buffer[19] = {'0', 'x'};
    for (usize index = 0; index < 16; ++index) {
        const usize shift = (15 - index) * 4;
        buffer[index + 2] = digits[(value >> shift) & 0xFU];
    }
    buffer[18] = '\0';
    write(buffer);
}

void line(const char* text) {
    write(text);
    write("\n");
}

void info(const char* text) {
    write("[INFO] ");
    line(text);
}

void success(const char* text) {
    write("[OK] ");
    line(text);
}

void error(const char* text) {
    write("[ERROR] ");
    line(text);
}
}
