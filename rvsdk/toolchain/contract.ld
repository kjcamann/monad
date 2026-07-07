/*
 * See the documentation in category/rv/docs/dynlink.md for an explanation
 * of the address space and section layout described by this file
 */

ENTRY(mrv_start)

MEMORY
{
    CODE_RO (rx) : ORIGIN = 0x200000, LENGTH = 256K
    DATA    (rw) : ORIGIN = 0x400000, LENGTH = 256K
}

PHDRS
{
    text   PT_LOAD FLAGS(0x5);       /* R X */
    relro  PT_LOAD FLAGS(0x100004);  /* R only - written by dynlink time, ro after */
    initro PT_LOAD FLAGS(0x200004);  /* R only - written at `init_contract` time, ro after */
    data   PT_LOAD FLAGS(0x6);       /* R W - copy-on-write */
    dyn    PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    .text : {
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > CODE_RO :text

    .dynamic : {
        . = ALIGN(8);
        *(.dynamic)
    } > CODE_RO :relro :dyn

    .got : {
        . = ALIGN(8);
        *(.got)
    } > CODE_RO :relro

    .got.plt : {
        *(.got.plt)
    } > CODE_RO :relro

    .data.contract_init : {
        . = ALIGN(8);
        *(.data.contract_init)
    } > CODE_RO :initro

    /* extern from mrv_stdlib; this must be placed here */
    g_mrv_default_param_abi = 0x400000;

    .data : {
        . = ALIGN(8);
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > DATA :data

    .bss (NOLOAD) : {
        . = ALIGN(8);
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    } > DATA :data
}
