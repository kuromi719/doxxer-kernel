#pragma once

namespace doxxer::serial {
bool initialize();
bool ready();
void write_char(char value);
void write(const char* text);
}
