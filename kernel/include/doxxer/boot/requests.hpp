#pragma once

#include <limine.h>

namespace doxxer::boot {
extern volatile uint64_t base_revision[];
extern volatile limine_framebuffer_request framebuffer_request;
extern volatile limine_entropy_request entropy_request;
extern volatile limine_bootloader_info_request bootloader_info_request;
extern volatile limine_memmap_request memmap_request;
extern volatile limine_hhdm_request hhdm_request;
}
