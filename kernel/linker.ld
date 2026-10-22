OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    requests PT_LOAD FLAGS(0x06);
    text     PT_LOAD FLAGS(0x05);
    rodata   PT_LOAD FLAGS(0x04);
    data     PT_LOAD FLAGS(0x06);
    stack    PT_GNU_STACK FLAGS(0x06);
}

SECTIONS
{
    . = 0xffffffff80000000;

    .limine_requests : ALIGN(8) {
        __requests_start = .;
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
        __requests_end = .;
    } :requests

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .text : {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .rodata : {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.note.gnu.build-id)
        __rodata_end = .;
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .data : {
        __data_start = .;
        *(.data .data.*)
        *(.data.rel.ro .data.rel.ro.*)
        __data_end = .;
    } :data

    .init_array : {
        __init_array = .;
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
        KEEP(*(.init_array))
        __init_array_end = .;
    } :data

    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    ASSERT(SIZEOF(.init_array) == 0, "Global constructors are not supported")

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.got .got.*)
    }
}
