# DMA Isolation

Doxxer treats bus-mastering devices as hostile until a future capability-aware driver explicitly owns
them. The kernel validates the ACPI DMAR table, requires segment-zero remapping units whose explicit
endpoint/hierarchy scopes or include-all coverage account for every discovered PCI requester,
allocates private zeroed VT-d root tables, and enables DMA translation before driver startup.
All discovered non-host PCI functions have bus mastering disabled and read back before the remapping
unit is activated. DMAR endpoint and bridge-hierarchy scopes are resolved through PCI configuration
space, and boot stops unless they cover every discovered DMA-capable PCI function.

Every root entry remains non-present in this milestone. Consequently, PCI requesters have no valid
translation context and cannot address system RAM. Kernel boot fails closed when DMAR is missing,
malformed, unsupported, or when translation cannot be observed in the hardware status register.

The remapping register page is mapped supervisor-only, writable, non-executable, global, and
cache-disabled. Root-table pages remain kernel-owned and are checked for unexpected entries by the
boot self-test.

This mechanism protects against ordinary PCI/PCIe DMA on the supported Intel VT-d path. It does not
make an absolute claim against malicious firmware, CPU debug facilities, RAM probing, cold-boot
attacks, compromised silicon, or platforms whose devices bypass the declared remapping hardware.
Later milestones must add AMD-Vi, interrupt remapping, per-device capability domains, invalidation,
fault handling, and encrypted memory support where hardware provides it.
