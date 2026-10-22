#pragma once

namespace doxxer::log {
void initialize();
void attach_framebuffer();
void write(const char* text);
void line(const char* text);
void info(const char* text);
void success(const char* text);
void error(const char* text);
}
