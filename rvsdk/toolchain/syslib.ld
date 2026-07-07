/*
 * See the documentation in category/rv/docs/dynlink.md for an explanation
 * of the address space and section layout described by this file
 */

MEMORY
{
    SHARED_RX (rx) : ORIGIN = 0x0, LENGTH = 2M
    PRIV_RW   (rw) : ORIGIN = 0x800000, LENGTH = 2M
}

PHDRS
{
    text  PT_LOAD FLAGS(5);    /* R X */
    relro PT_LOAD FLAGS(4);    /* R only - written at dynlink them, ro after */
    data  PT_LOAD FLAGS(6);    /* R W - copy-on-write */
    dyn   PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    .text : {
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > SHARED_RX :text

    .dynamic : {
        . = ALIGN(8);
        *(.dynamic)
    } > SHARED_RX :relro :dyn

    .got : {
        . = ALIGN(8);
        *(.got)
    } > SHARED_RX :relro

    .got.plt : {
        *(.got.plt)
    } > SHARED_RX :relro

    .data : {
        . = ALIGN(8);
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > PRIV_RW :data

    .bss (NOLOAD) : {
        . = ALIGN(8);
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    } > PRIV_RW :data
}
