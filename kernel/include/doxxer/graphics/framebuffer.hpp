#pragma once

struct limine_framebuffer;

namespace doxxer::graphics {
bool initialize(limine_framebuffer* framebuffer);
bool ready();
void clear();
void draw_boot_banner();
void write_char(char value);
void write(const char* text);
}
