SHELL := /usr/bin/bash
.SUFFIXES:
.DELETE_ON_ERROR:

BUILD_DIR := build
DIST_DIR := dist
OBJ_DIR := $(BUILD_DIR)/obj
KERNEL := $(BUILD_DIR)/doxxer-kernel.elf
KERNEL_MAP := $(BUILD_DIR)/doxxer-kernel.map
LIMINE_BUILD := $(BUILD_DIR)/limine-build
LIMINE_PREFIX := $(BUILD_DIR)/limine-install
LIMINE_SHARE := $(LIMINE_PREFIX)/share/limine
LIMINE_STAMP := $(LIMINE_PREFIX)/.ready
ISO_ROOT := $(BUILD_DIR)/iso-root
DISK_ROOT := $(BUILD_DIR)/disk-root
ISO := $(DIST_DIR)/doxxer.iso
DISK := $(DIST_DIR)/doxxer-uefi.img

CXX := clang++
SOURCES := $(shell find kernel/src -name '*.cpp' -print | sort)
OBJECTS := $(patsubst kernel/src/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))
DEPS := $(OBJECTS:.o=.d)

COMMON_FLAGS := \
    -target x86_64-unknown-none-elf \
    -std=gnu++20 -O2 -g -ffreestanding \
    -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-use-cxa-atexit \
    -fno-common -fno-pic -fno-pie -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -ffunction-sections -fdata-sections \
    -m64 -march=x86-64 -mno-mmx -mno-sse -mno-sse2 -mno-80387 \
    -mno-red-zone -mcmodel=kernel -fcf-protection=none \
    -Wall -Wextra -Wpedantic -Werror \
    -Ikernel/include -Ithird_party/limine-protocol/include \
    -MMD -MP

PROTECTED_FLAGS := -fstack-protector-strong -mstack-protector-guard=global
ENTRY_FLAGS := -fno-stack-protector
LDFLAGS := \
    -target x86_64-unknown-none-elf -fuse-ld=lld \
    -nostdlib -static -Wl,-m,elf_x86_64 \
    -Wl,--build-id=sha1 -Wl,-z,max-page-size=0x1000 -Wl,-z,noexecstack \
    -Wl,-z,separate-code -Wl,--gc-sections \
    -Wl,-T,kernel/linker.ld -Wl,-Map,$(KERNEL_MAP)

ifeq ($(TEST_MODE),1)
COMMON_FLAGS += -DDOXXER_TEST_MODE=1
endif

.PHONY: all kernel limine disk iso run run-iso test verify clean distclean
all: verify disk iso
kernel: $(KERNEL) verify
limine: $(LIMINE_STAMP)
disk: verify $(DISK)
iso: verify $(ISO)

$(OBJ_DIR)/boot/entry.o: kernel/src/boot/entry.cpp
	@mkdir -p $(@D)
	$(CXX) $(COMMON_FLAGS) $(ENTRY_FLAGS) -c $< -o $@

$(OBJ_DIR)/memory.o: kernel/src/memory.cpp
	@mkdir -p $(@D)
	$(CXX) $(COMMON_FLAGS) $(PROTECTED_FLAGS) -fno-builtin -c $< -o $@

$(OBJ_DIR)/%.o: kernel/src/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(COMMON_FLAGS) $(PROTECTED_FLAGS) -c $< -o $@

$(KERNEL): $(OBJECTS) kernel/linker.ld
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

$(LIMINE_STAMP):
	@test -d third_party/limine || { echo 'Limine submodule is missing. Run git submodule update --init --recursive.'; exit 1; }
	@test -x third_party/limine/configure || (cd third_party/limine && ./bootstrap)
	@mkdir -p $(LIMINE_BUILD) $(LIMINE_PREFIX)
	@cd $(LIMINE_BUILD) && ../../third_party/limine/configure \
		--prefix="$(abspath $(LIMINE_PREFIX))" --enable-uefi-x86-64 --enable-uefi-cd
	$(MAKE) -C $(LIMINE_BUILD) -j4
	$(MAKE) -C $(LIMINE_BUILD) install
	@touch $@

$(DISK): $(KERNEL) $(LIMINE_STAMP) limine.conf
	@rm -rf $(DISK_ROOT)
	@mkdir -p $(DISK_ROOT)/EFI/BOOT $(DISK_ROOT)/boot $(DIST_DIR)
	@cp $(LIMINE_SHARE)/BOOTX64.EFI $(DISK_ROOT)/EFI/BOOT/BOOTX64.EFI
	@cp $(KERNEL) $(DISK_ROOT)/boot/doxxer-kernel.elf
	@cp limine.conf $(DISK_ROOT)/limine.conf
	@rm -f $@
	@truncate -s 64M $@
	@sgdisk -n 1:2048:0 -t 1:ef00 -c 1:DOXXER_EFI $@ >/dev/null
	@mformat -i "$@@@1048576" -F -v DOXXER ::
	@mmd -i "$@@@1048576" ::/EFI ::/EFI/BOOT ::/boot
	@mcopy -o -i "$@@@1048576" $(DISK_ROOT)/EFI/BOOT/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
	@mcopy -o -i "$@@@1048576" $(DISK_ROOT)/boot/doxxer-kernel.elf ::/boot/doxxer-kernel.elf
	@mcopy -o -i "$@@@1048576" $(DISK_ROOT)/limine.conf ::/limine.conf

$(ISO): $(KERNEL) $(LIMINE_STAMP) limine.conf
	@rm -rf $(ISO_ROOT)
	@mkdir -p $(ISO_ROOT)/EFI/BOOT $(ISO_ROOT)/boot $(DIST_DIR)
	@cp $(LIMINE_SHARE)/BOOTX64.EFI $(ISO_ROOT)/EFI/BOOT/BOOTX64.EFI
	@cp $(LIMINE_SHARE)/limine-uefi-cd.bin $(ISO_ROOT)/boot/limine-uefi-cd.bin
	@cp $(KERNEL) $(ISO_ROOT)/boot/doxxer-kernel.elf
	@cp limine.conf $(ISO_ROOT)/limine.conf
	xorriso -as mkisofs -R -r -J \
		--efi-boot boot/limine-uefi-cd.bin \
		-efi-boot-part --efi-boot-image --protective-msdos-label \
		$(ISO_ROOT) -o $@

verify: $(KERNEL)
	@tools/verify-elf.sh $(KERNEL)

run: $(DISK)
	@powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/run.ps1 -Media disk

run-iso: $(ISO)
	@powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/run.ps1 -Media iso

test:
	@powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/test.ps1

clean:
	@rm -rf $(OBJ_DIR) $(KERNEL) $(KERNEL_MAP) $(ISO_ROOT) $(DISK_ROOT) $(ISO) $(DISK)

distclean: clean
	@rm -rf $(LIMINE_BUILD) $(LIMINE_PREFIX)

-include $(DEPS)
