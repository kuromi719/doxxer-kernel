#include <doxxer/arch/x86_64/serial.hpp>
#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/log.hpp>

namespace doxxer::log {
namespace {
bool framebuffer_attached = false;
}

void initialize() {
    framebuffer_attached = false;
}

void attach_framebuffer() {
    framebuffer_attached = graphics::ready();
}

void write(const char* text) {
    serial::write(text);
    if (framebuffer_attached) {
        graphics::write(text);
    }
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
