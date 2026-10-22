#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/types.hpp>

#include <limine.h>

namespace doxxer::graphics {
namespace {
limine_framebuffer* active = nullptr;
u64 cursor_x = 0;
u64 cursor_y = 0;
constexpr u64 kGlyphWidth = 5;
constexpr u64 kGlyphHeight = 7;
constexpr u64 kTextScale = 2;
constexpr u64 kTextAdvance = (kGlyphWidth + 1) * kTextScale;
constexpr u64 kLineAdvance = (kGlyphHeight + 2) * kTextScale;

struct Glyph {
    char character;
    u8 rows[kGlyphHeight];
};

constexpr Glyph kGlyphs[] = {
    {' ', {0,0,0,0,0,0,0}}, {'?', {14,17,1,2,4,0,4}},
    {'A', {14,17,17,31,17,17,17}}, {'B', {30,17,17,30,17,17,30}},
    {'C', {14,17,16,16,16,17,14}}, {'D', {30,17,17,17,17,17,30}},
    {'E', {31,16,16,30,16,16,31}}, {'F', {31,16,16,30,16,16,16}},
    {'G', {14,17,16,23,17,17,15}}, {'H', {17,17,17,31,17,17,17}},
    {'I', {14,4,4,4,4,4,14}}, {'J', {1,1,1,1,17,17,14}},
    {'K', {17,18,20,24,20,18,17}}, {'L', {16,16,16,16,16,16,31}},
    {'M', {17,27,21,21,17,17,17}}, {'N', {17,25,21,19,17,17,17}},
    {'O', {14,17,17,17,17,17,14}}, {'P', {30,17,17,30,16,16,16}},
    {'Q', {14,17,17,17,21,18,13}}, {'R', {30,17,17,30,20,18,17}},
    {'S', {15,16,16,14,1,1,30}}, {'T', {31,4,4,4,4,4,4}},
    {'U', {17,17,17,17,17,17,14}}, {'V', {17,17,17,17,17,10,4}},
    {'W', {17,17,17,21,21,21,10}}, {'X', {17,17,10,4,10,17,17}},
    {'Y', {17,17,10,4,4,4,4}}, {'Z', {31,1,2,4,8,16,31}},
    {'0', {14,17,19,21,25,17,14}}, {'1', {4,12,4,4,4,4,14}},
    {'2', {14,17,1,2,4,8,31}}, {'3', {30,1,1,14,1,1,30}},
    {'4', {2,6,10,18,31,2,2}}, {'5', {31,16,16,30,1,1,30}},
    {'6', {14,16,16,30,17,17,14}}, {'7', {31,1,2,4,8,8,8}},
    {'8', {14,17,17,14,17,17,14}}, {'9', {14,17,17,15,1,1,14}},
    {'[', {14,8,8,8,8,8,14}}, {']', {14,2,2,2,2,2,14}},
    {':', {0,4,4,0,4,4,0}}, {'.', {0,0,0,0,0,0,4}},
    {'-', {0,0,0,31,0,0,0}}, {'_', {0,0,0,0,0,0,31}},
    {'/', {1,2,2,4,8,8,16}}, {'+', {0,4,4,31,4,4,0}},
};

const u8* glyph_for(char value) {
    if (value >= 'a' && value <= 'z') {
        value = static_cast<char>(value - ('a' - 'A'));
    }
    for (const auto& glyph : kGlyphs) {
        if (glyph.character == value) {
            return glyph.rows;
        }
    }
    return kGlyphs[1].rows;
}

u32 channel(u8 value, u8 size, u8 shift) {
    if (size == 0 || size > 16) {
        return 0;
    }
    const u64 maximum = (u64{1} << size) - 1U;
    return static_cast<u32>((static_cast<u64>(value) * maximum / 255U) << shift);
}

u32 pixel(u8 red, u8 green, u8 blue) {
    return channel(red, active->red_mask_size, active->red_mask_shift)
         | channel(green, active->green_mask_size, active->green_mask_shift)
         | channel(blue, active->blue_mask_size, active->blue_mask_shift);
}

void put_pixel(u64 x, u64 y, u32 color) {
    if (active == nullptr || x >= active->width || y >= active->height) {
        return;
    }
    auto* row = reinterpret_cast<volatile u32*>(
        static_cast<volatile u8*>(active->address) + y * active->pitch);
    row[x] = color;
}

void draw_glyph(char value, u64 x, u64 y, u64 scale, u32 color) {
    const u8* rows = glyph_for(value);
    for (u64 row = 0; row < kGlyphHeight; ++row) {
        for (u64 column = 0; column < kGlyphWidth; ++column) {
            if ((rows[row] & (1U << (kGlyphWidth - 1U - column))) == 0) {
                continue;
            }
            for (u64 dy = 0; dy < scale; ++dy) {
                for (u64 dx = 0; dx < scale; ++dx) {
                    put_pixel(x + column * scale + dx, y + row * scale + dy, color);
                }
            }
        }
    }
}

void draw_text_at(const char* text, u64 x, u64 y, u64 scale, u32 color) {
    while (text != nullptr && *text != '\0') {
        draw_glyph(*text++, x, y, scale, color);
        x += (kGlyphWidth + 1U) * scale;
    }
}

u64 text_width(const char* text, u64 scale) {
    u64 length = 0;
    while (text != nullptr && text[length] != '\0') {
        ++length;
    }
    return length * (kGlyphWidth + 1U) * scale;
}
}

bool initialize(limine_framebuffer* framebuffer) {
    if (framebuffer == nullptr || framebuffer->address == nullptr
        || framebuffer->memory_model != LIMINE_FRAMEBUFFER_RGB
        || framebuffer->bpp != 32 || framebuffer->width < 320
        || framebuffer->height < 200 || framebuffer->pitch < framebuffer->width * 4U) {
        return false;
    }
    active = framebuffer;
    cursor_x = 24;
    cursor_y = 150;
    clear();
    return true;
}

bool ready() {
    return active != nullptr;
}

void clear() {
    if (active == nullptr) {
        return;
    }
    const u32 black = pixel(3, 5, 8);
    for (u64 y = 0; y < active->height; ++y) {
        for (u64 x = 0; x < active->width; ++x) {
            put_pixel(x, y, black);
        }
    }
}

void draw_boot_banner() {
    if (active == nullptr) {
        return;
    }
    constexpr const char* logo = "DOXXER";
    const u64 scale = active->width >= 800 ? 8 : 5;
    const u64 width = text_width(logo, scale);
    const u64 x = active->width > width ? (active->width - width) / 2U : 8U;
    draw_text_at(logo, x, 36, scale, pixel(235, 238, 242));
    constexpr const char* subtitle = "PRIVACY FIRST KERNEL PROTOTYPE";
    const u64 subtitle_width = text_width(subtitle, 2);
    const u64 subtitle_x = active->width > subtitle_width
        ? (active->width - subtitle_width) / 2U : 8U;
    draw_text_at(subtitle, subtitle_x, 112, 2, pixel(150, 158, 168));
    cursor_x = 24;
    cursor_y = 158;
}

void write_char(char value) {
    if (active == nullptr) {
        return;
    }
    if (value == '\r') {
        return;
    }
    if (value == '\n') {
        cursor_x = 24;
        cursor_y += kLineAdvance;
        return;
    }
    if (cursor_x + kTextAdvance >= active->width) {
        cursor_x = 24;
        cursor_y += kLineAdvance;
    }
    if (cursor_y + kGlyphHeight * kTextScale >= active->height) {
        return;
    }
    draw_glyph(value, cursor_x, cursor_y, kTextScale, pixel(215, 219, 225));
    cursor_x += kTextAdvance;
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
