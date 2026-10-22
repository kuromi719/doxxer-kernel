#include <doxxer/boot/requests.hpp>

namespace doxxer::boot {
__attribute__((used, section(".limine_requests_start"))) volatile uint64_t requests_start_marker[] =
    LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests"))) volatile uint64_t base_revision[] =
    LIMINE_BASE_REVISION(6);

__attribute__((
    used, section(".limine_requests"))) volatile limine_framebuffer_request framebuffer_request = {
    .id = LIMINE_FRAMEBUFFER_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};

__attribute__((used,
               section(".limine_requests"))) volatile limine_entropy_request entropy_request = {
    .id = LIMINE_ENTROPY_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
    .value_count = 2,
};

__attribute__((used, section(".limine_requests"))) volatile limine_bootloader_info_request
    bootloader_info_request = {
        .id = LIMINE_BOOTLOADER_INFO_REQUEST_ID,
        .revision = 0,
        .response = nullptr,
};

__attribute__((used, section(".limine_requests"))) volatile limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};

__attribute__((used, section(".limine_requests"))) volatile limine_hhdm_request hhdm_request = {
    .id = LIMINE_HHDM_REQUEST_ID,
    .revision = 0,
    .response = nullptr,
};

__attribute__((used, section(".limine_requests_end"))) volatile uint64_t requests_end_marker[] =
    LIMINE_REQUESTS_END_MARKER;
}
