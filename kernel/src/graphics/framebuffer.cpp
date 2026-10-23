#include <doxxer/graphics/framebuffer.hpp>
#include <doxxer/platform.hpp>

#include <limine.h>

namespace doxxer::graphics {
namespace {
limine_framebuffer* active = nullptr;
u64 cursor_x = 0;
u64 cursor_y = 0;
BootStage current_stage = BootStage::Framebuffer;

enum class StageState : u8 { Waiting, Progress, Passed, Failed };
struct StageView { StageState state; u8 percent; };
StageView stages[static_cast<u8>(BootStage::Count)]{};

constexpr const char* kStageNames[] = {
    "ENTROPY + STACK GUARD", "SEALED MEMORY", "PHYSICAL MEMORY", "VIRTUAL MEMORY",
    "CPU PROTECTION", "SHADOW REGIONS", "KERNEL HEAP", "CAPABILITY MODEL",
    "IPC + EVENTS", "PROCESS CONTAINERS", "SYSCALL ABI", "SERVICE REGISTRY",
    "USER MEMORY", "ELF + IMAGE POLICY", "USER THREADS", "RING3 BOUNDARY",
    "ACPI TABLES", "DMA PROTECTION", "SMP + CPU HARDENING", "SCHEDULER",
    "APIC TIMER", "FRAMEBUFFER"
};

#include "font_atlas.inc"

struct FontView { const u8* alpha; u64 width; u64 height; };
FontView font_view(u64 mode) {
    if (mode >= 3U) return {kFont3Alpha, kFont3Width, kFont3Height};
    if (mode == 2U) return {kFont2Alpha, kFont2Width, kFont2Height};
    return {kFont1Alpha, kFont1Width, kFont1Height};
}
u32 channel(u8 value, u8 size, u8 shift) {
    if (size == 0 || size > 16) return 0;
    const u64 maximum = (u64{1} << size) - 1U;
    return static_cast<u32>((static_cast<u64>(value) * maximum / 255U) << shift);
}
u32 color(u8 r, u8 g, u8 b) {
    return channel(r, active->red_mask_size, active->red_mask_shift)
         | channel(g, active->green_mask_size, active->green_mask_shift)
         | channel(b, active->blue_mask_size, active->blue_mask_shift);
}
void put_pixel(u64 x, u64 y, u32 value) {
    if (active == nullptr || x >= active->width || y >= active->height) return;
    auto* row = reinterpret_cast<volatile u32*>(static_cast<volatile u8*>(active->address)
                                                + y * active->pitch);
    row[x] = value;
}
u8 unpack_channel(u32 value, u8 size, u8 shift) {
    if (size == 0 || size > 16) return 0;
    const u32 maximum = (u32{1} << size) - 1U;
    return static_cast<u8>(((value >> shift) & maximum) * 255U / maximum);
}
void blend_pixel(u64 x, u64 y, u32 foreground, u8 alpha) {
    if (active == nullptr || x >= active->width || y >= active->height || alpha == 0) return;
    if (alpha == 255) { put_pixel(x, y, foreground); return; }
    auto* row = reinterpret_cast<volatile u32*>(static_cast<volatile u8*>(active->address)
                                                + y * active->pitch);
    const u32 background = row[x];
    const auto mix = [&](u8 fg, u8 bg) -> u8 {
        return static_cast<u8>((static_cast<u32>(fg) * alpha
            + static_cast<u32>(bg) * (255U - alpha)) / 255U);
    };
    row[x] = color(mix(unpack_channel(foreground, active->red_mask_size,
                                      active->red_mask_shift),
                       unpack_channel(background, active->red_mask_size,
                                      active->red_mask_shift)),
                   mix(unpack_channel(foreground, active->green_mask_size,
                                      active->green_mask_shift),
                       unpack_channel(background, active->green_mask_size,
                                      active->green_mask_shift)),
                   mix(unpack_channel(foreground, active->blue_mask_size,
                                      active->blue_mask_shift),
                       unpack_channel(background, active->blue_mask_size,
                                      active->blue_mask_shift)));
}
void fill_rect(u64 x, u64 y, u64 width, u64 height, u32 value) {
    for (u64 py = y; py < y + height && py < active->height; ++py)
        for (u64 px = x; px < x + width && px < active->width; ++px) put_pixel(px, py, value);
}
void hline(u64 x, u64 y, u64 width, u32 value) { fill_rect(x, y, width, 1, value); }
void vline(u64 x, u64 y, u64 height, u32 value) { fill_rect(x, y, 1, height, value); }
[[maybe_unused]] void thick_line(int64_t x0, int64_t y0, int64_t x1, int64_t y1,
                                 u64 thickness, u32 value) {
    int64_t dx = x1 > x0 ? x1 - x0 : x0 - x1;
    const int64_t sx = x0 < x1 ? 1 : -1;
    int64_t dy = y1 > y0 ? y0 - y1 : y1 - y0;
    const int64_t sy = y0 < y1 ? 1 : -1;
    int64_t error = dx + dy;
    for (;;) {
        const int64_t half = static_cast<int64_t>(thickness / 2U);
        if (x0 >= half && y0 >= half)
            fill_rect(static_cast<u64>(x0 - half), static_cast<u64>(y0 - half),
                      thickness, thickness, value);
        if (x0 == x1 && y0 == y1) break;
        const int64_t twice = error * 2;
        if (twice >= dy) { error += dy; x0 += sx; }
        if (twice <= dx) { error += dx; y0 += sy; }
    }
}
void draw_mask(const u8* alpha, u64 width, u64 height, u64 x, u64 y, u32 value_color) {
    for (u64 row = 0; row < height; ++row)
        for (u64 column = 0; column < width; ++column)
            blend_pixel(x + column, y + row, value_color, alpha[row * width + column]);
}
void draw_glyph(char value, u64 x, u64 y, u64 mode, u32 value_color) {
    if (value >= 'a' && value <= 'z') value = static_cast<char>(value - ('a' - 'A'));
    if (value < ' ' || value > '_') value = '?';
    const FontView font = font_view(mode);
    const u64 index = static_cast<u8>(value) - static_cast<u8>(' ');
    draw_mask(font.alpha + index * font.width * font.height,
              font.width, font.height, x, y, value_color);
}
void draw_text_at(const char* text, u64 x, u64 y, u64 mode, u32 value_color) {
    const FontView font = font_view(mode);
    while (text != nullptr && *text != '\0') {
        draw_glyph(*text++, x, y, mode, value_color);
        x += font.width;
    }
}
u64 text_width(const char* text, u64 mode) {
    u64 length = 0; while (text != nullptr && text[length] != '\0') ++length;
    return length * font_view(mode).width;
}
void draw_number(u32 value, u64 x, u64 y, u64 scale, u32 value_color) {
    char digits[4]{};
    digits[0] = static_cast<char>('0' + ((value / 100U) % 10U));
    digits[1] = static_cast<char>('0' + ((value / 10U) % 10U));
    digits[2] = static_cast<char>('0' + (value % 10U));
    draw_text_at(digits, x, y, scale, value_color);
}
void draw_frame() {
    const u32 purple = color(190, 58, 255);
    const u64 inset = active->width >= 800 ? 8 : 4;
    const u64 inset2 = inset + 4;
    hline(inset, inset, active->width - 2 * inset, purple);
    hline(inset2, inset2, active->width - 2 * inset2, purple);
    hline(inset, active->height - inset - 1, active->width - 2 * inset, purple);
    hline(inset2, active->height - inset2 - 1, active->width - 2 * inset2, purple);
    vline(inset, inset, active->height - 2 * inset, purple);
    vline(inset2, inset2, active->height - 2 * inset2, purple);
    vline(active->width - inset - 1, inset, active->height - 2 * inset, purple);
    vline(active->width - inset2 - 1, inset2, active->height - 2 * inset2, purple);
    const u64 mark = active->width >= 800 ? 5 : 3;
    fill_rect(inset2 + 7, inset2 + 7, mark, mark, purple);
    fill_rect(inset2 + 10 + mark, inset2 + 7, mark, mark, purple);
    fill_rect(inset2 + 7, inset2 + 10 + mark, mark, mark, purple);
    fill_rect(active->width - inset2 - 7 - mark, inset2 + 7, mark, mark, purple);
    fill_rect(active->width - inset2 - 10 - 2 * mark, inset2 + 7, mark, mark, purple);
    fill_rect(active->width - inset2 - 7 - mark, inset2 + 10 + mark, mark, mark, purple);
    fill_rect(inset2 + 7, active->height - inset2 - 7 - mark, mark, mark, purple);
    fill_rect(inset2 + 10 + mark, active->height - inset2 - 7 - mark, mark, mark, purple);
    fill_rect(active->width - inset2 - 7 - mark, active->height - inset2 - 7 - mark, mark, mark, purple);
}
void paint_background() {
    const u32 base = color(8, 1, 18);
    const u32 scan = color(15, 4, 28);
    fill_rect(0, 0, active->width, active->height, base);
    for (u64 y = 2; y < active->height; y += 4) hline(0, y, active->width, scan);
}
u64 row_top(u8 index) {
    const u64 content_top = active->height / 9U;
    const u64 footer = active->height / 10U;
    const u64 available = active->height - content_top - footer - 12U;
    return content_top + static_cast<u64>(index) * available / static_cast<u8>(BootStage::Count);
}
u64 row_height() {
    const u64 content_top = active->height / 9U;
    const u64 footer = active->height / 10U;
    return (active->height - content_top - footer - 12U) / static_cast<u8>(BootStage::Count);
}
void render_stage(BootStage stage) {
    if (active == nullptr) return;
    const u8 index = static_cast<u8>(stage);
    const u64 scale = active->width >= 900 ? 2 : 1;
    const FontView font = font_view(scale);
    const u64 y = row_top(index);
    const u64 rh = row_height();
    const u64 text_y = y + (rh > font.height ? (rh - font.height) / 2U : 0);
    const u64 left = active->width / 24U;
    const u64 box = 8U * scale;
    const u64 status_x = left + box + 15U * scale;
    const u64 label_x = status_x + 11U * font.width;
    const u64 percent_x = active->width - active->width / 18U - 4U * font.width;
    const u64 bar_x = active->width * 49U / 100U;
    const u64 bar_right = percent_x - 4U * scale;
    const u64 bar_width = bar_right > bar_x ? bar_right - bar_x : 0;
    const StageView view = stages[index];
    fill_rect(left - 2, y, active->width - left * 2 + 4, rh, color(12, 2, 24));
    const u32 purple = color(188, 60, 255), green = color(0, 255, 153);
    const u32 yellow = color(255, 208, 74), red = color(255, 56, 110);
    const u32 white = color(229, 213, 239);
    const u32 state_color = view.state == StageState::Passed ? green
        : view.state == StageState::Failed ? red : view.state == StageState::Progress ? yellow
        : color(92, 67, 112);
    hline(left, text_y, box, purple); hline(left, text_y + box - 1, box, purple);
    vline(left, text_y, box, purple); vline(left + box - 1, text_y, box, purple);
    if (view.state != StageState::Waiting) fill_rect(left + 2, text_y + 2, box - 4, box - 4, state_color);
    const char* status = view.state == StageState::Passed ? "[PASSED]"
        : view.state == StageState::Failed ? "[FAIL]" : view.state == StageState::Progress
        ? "[PROGRESS]" : "[WAITING]";
    draw_text_at(status, status_x, text_y, scale, state_color);
    draw_text_at(kStageNames[index], label_x, text_y, scale, white);
    if (bar_width > 0) {
        constexpr u64 segments = 40;
        const u64 gap = scale, segment_width = bar_width / segments;
        const u64 filled = static_cast<u64>(view.percent) * segments / 100U;
        for (u64 i = 0; i < segments; ++i) {
            const u32 bar_color = i < filled ? purple : color(36, 14, 50);
            if (segment_width > gap) fill_rect(bar_x + i * segment_width, text_y,
                                               segment_width - gap, 7U * scale, bar_color);
        }
    }
    vline(percent_x - 3U * scale, text_y, 7U * scale, white);
    draw_number(view.percent, percent_x, text_y, scale, white);
    draw_text_at("%", percent_x + 3U * font.width, text_y, scale, white);
}
void render_footer() {
    const u64 scale = active->width >= 900 ? 2 : 1;
    const u64 y = active->height - active->height / 14U;
    const u64 left = active->width / 24U;
    fill_rect(left - 2U, y - 14U * scale, active->width - left * 2U + 4U,
              14U * scale + 7U * scale, color(12, 2, 24));
    hline(left, y - 14U * scale, active->width - left * 2U, color(188, 60, 255));
    u32 passed = 0;
    for (u8 i = 0; i < static_cast<u8>(BootStage::Count); ++i)
        if (stages[i].state == StageState::Passed) ++passed;
    draw_text_at("> VERIFIED CHECKS", left, y, scale, color(0, 255, 153));
    const u64 counter_x = left + text_width("> VERIFIED CHECKS  ", scale);
    draw_number(passed, counter_x, y, scale, color(229, 213, 239));
    draw_text_at("/", counter_x + 4U * font_view(scale).width, y, scale,
                 color(229, 213, 239));
    draw_number(static_cast<u8>(BootStage::Count), counter_x + 6U * font_view(scale).width,
                 y, scale,
                 color(229, 213, 239));
    const char* failure = "FAILURE: F5 TO REBOOT";
    draw_text_at(failure, active->width - left - text_width(failure, scale), y, scale,
                 color(255, 56, 110));
}
}

bool initialize(limine_framebuffer* framebuffer) {
    if (framebuffer == nullptr || framebuffer->address == nullptr
        || framebuffer->memory_model != LIMINE_FRAMEBUFFER_RGB || framebuffer->bpp != 32
        || framebuffer->width < 640 || framebuffer->height < 400
        || framebuffer->pitch < framebuffer->width * 4U) return false;
    active = framebuffer; cursor_x = 24; cursor_y = 150; return true;
}
bool ready() { return active != nullptr; }
void clear() { if (active != nullptr) paint_background(); }
void draw_boot_trace() {
    if (active == nullptr) return;
    for (auto& stage : stages) stage = {StageState::Waiting, 0};
    paint_background(); draw_frame();
    const u64 scale = active->width >= 900 ? 3 : 2, left = active->width / 24U;
    draw_text_at("DOXXER KERNEL / BOOT TRACE", left, active->height / 24U, scale,
                 color(211, 116, 255));
    hline(left, active->height / 11U, active->width - left * 2U, color(188, 60, 255));
    for (u8 i = 0; i < static_cast<u8>(BootStage::Count); ++i)
        render_stage(static_cast<BootStage>(i));
    render_footer();
}
void stage_progress(BootStage stage, u8 percent) {
    if (active == nullptr || stage == BootStage::Count) return;
    current_stage = stage;
    stages[static_cast<u8>(stage)] = {
        StageState::Progress, static_cast<u8>(percent > 99 ? 99 : percent)};
    render_stage(stage); render_footer();
#ifndef DOXXER_TEST_MODE
    // The stage is genuinely executing during this short presentation window;
    // it keeps fast hardware from making the real trace visually unreadable.
    platform::delay_milliseconds(220);
#endif
}
void stage_pass(BootStage stage) {
    if (active == nullptr || stage == BootStage::Count) return;
    current_stage = stage; stages[static_cast<u8>(stage)] = {StageState::Passed, 100};
    render_stage(stage); render_footer();
#ifndef DOXXER_TEST_MODE
    platform::delay_milliseconds(180);
#endif
}
void stage_fail(BootStage stage) {
    if (active == nullptr || stage == BootStage::Count) return;
    stages[static_cast<u8>(stage)].state = StageState::Failed;
    render_stage(stage); render_footer();
}
void fail_active_stage() { stage_fail(current_stage); }
void draw_failure_countdown(u32 seconds_remaining) {
    if (active == nullptr) return;
    const u64 scale = active->width >= 900 ? 2 : 1, left = active->width / 24U;
    const u64 y = active->height - active->height / 14U;
    const u64 x = active->width - left - text_width("AUTO RESTART IN 000", scale);
    fill_rect(x, y, text_width("AUTO RESTART IN 000", scale), 7U * scale, color(12, 2, 24));
    draw_text_at("AUTO RESTART IN", x, y, scale, color(255, 56, 110));
    draw_number(seconds_remaining, x + 16U * font_view(scale).width, y, scale,
                color(255, 56, 110));
}

void draw_boot_logo() {
    if (active == nullptr) return;
    paint_background();
    draw_frame();
    const u32 purple = color(190, 60, 255);
    const u32 deep_purple = color(116, 36, 224);
    const u32 pale = color(238, 221, 247);
    const u64 emblem_x = (active->width - kEmblemWidth) / 2U;
    const u64 emblem_y = active->height / 8U;
    draw_mask(kEmblemAlpha, kEmblemWidth, kEmblemHeight,
              emblem_x, emblem_y, purple);

    auto logo_text_width = [](const char* text) -> u64 {
        u64 length = 0; while (text[length] != '\0') ++length;
        return length * kLogoFontWidth;
    };
    auto draw_logo_text = [&](const char* text, u64 x, u64 y, u32 ink) {
        while (*text != '\0') {
            char value = *text++;
            if (value < ' ' || value > '_') value = '?';
            const u64 index = static_cast<u8>(value) - static_cast<u8>(' ');
            draw_mask(kLogoFontAlpha + index * kLogoFontWidth * kLogoFontHeight,
                      kLogoFontWidth, kLogoFontHeight, x, y, ink);
            x += kLogoFontWidth;
        }
    };
    constexpr u64 gap = 18U;
    const u64 right_width = logo_text_width("ER - OS");
    const u64 total = logo_text_width("DO") + gap + kXxWidth + gap + right_width;
    u64 x = (active->width - total) / 2U;
    const u64 y = emblem_y + kEmblemHeight + 42U;
    draw_logo_text("DO", x, y, pale);
    x += logo_text_width("DO") + gap;
    draw_mask(kXxAlpha0, kXxWidth, kXxHeight, x, y + 2U, deep_purple);
    draw_mask(kXxAlpha1, kXxWidth, kXxHeight, x, y + 2U, purple);
    x += kXxWidth + gap;
    draw_logo_text("ER - OS", x, y, pale);
}

void draw_boot_banner() { draw_boot_logo(); }
void write_char(char value) {
    if (active == nullptr) return;
    constexpr u64 scale = 2;
    if (value == '\r') return;
    const FontView font = font_view(scale);
    if (value == '\n') { cursor_x = 24; cursor_y += font.height + 2U; return; }
    if (cursor_x + font.width >= active->width) {
        cursor_x = 24; cursor_y += font.height + 2U;
    }
    if (cursor_y + font.height >= active->height) return;
    draw_glyph(value, cursor_x, cursor_y, scale, color(215, 219, 225));
    cursor_x += font.width;
}
void write(const char* text) { while (text != nullptr && *text != '\0') write_char(*text++); }
}
