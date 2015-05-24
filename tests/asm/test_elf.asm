%include "defines/elf.asm"
bits 32
header:
    istruc Elf32_Ehdr
        at e_ident,     db `\x7FELF`, ELFCLASS32, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, 0, 0, 0, 0
        at e_type,      dw ET_EXEC
        at e_machine,   dw EM_386
        at e_version,   dd EV_CURRENT
    iend
