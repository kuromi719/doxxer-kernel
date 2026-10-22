#pragma once

#include <doxxer/firmware/acpi.hpp>
#include <doxxer/types.hpp>

namespace doxxer::arch::x86_64::iommu {
struct Statistics {
    u32 enabled_units;
    u32 quiesced_pci_functions;
    u8 dma_address_width;
    bool default_deny;
};

bool initialize(const firmware::acpi::Topology& topology);
bool self_test();
Statistics statistics();
u32 failure_code();
}
