%include "defines/elf.asm"
bits 32
ORG 0x08048000
header:
    istruc Elf32_Ehdr
        at Elf32_Ehdr.e_ident,      db `\x7FELF`, ELFCLASS32, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, 0, 0, 0, 0
        at Elf32_Ehdr.e_type,       dw ET_EXEC
        at Elf32_Ehdr.e_machine,    dw EM_386
        at Elf32_Ehdr.e_version,    dd EV_CURRENT
        at Elf32_Ehdr.e_entry,      dd _start
        at Elf32_Ehdr.e_phoff,      dd (program_section_headers - header)
        at Elf32_Ehdr.e_shoff,      dd 0
        at Elf32_Ehdr.e_flags,      dd 0
        at Elf32_Ehdr.e_ehsize,     dw Elf32_Ehdr.size
        at Elf32_Ehdr.e_phentsize,  dw Elf32_Phdr.size
        at Elf32_Ehdr.e_phnum,      dw 1
        at Elf32_Ehdr.e_shentsize,  dw 0
        at Elf32_Ehdr.e_shnum,      dw 0
        at Elf32_Ehdr.e_shstrndx,   dw 0
    iend

program_section_headers:
    istruc Elf32_Phdr
        at Elf32_Phdr.p_type,   db PT_LOAD
        at Elf32_Phdr.p_offset, dd 0
        at Elf32_Phdr.p_vaddr,  dd header
        at Elf32_Phdr.p_paddr,  dd header
        at Elf32_Phdr.p_filesz, dd (end - header)
        at Elf32_Phdr.p_memsz,  dd (end - header)
        at Elf32_Phdr.p_flags,  dd PF_X | PF_R
        at Elf32_Phdr.p_align,  dd 0x1000
    iend


data:
    HelloWorld  db "Hello world! TOTO", 10
_start:
    mov eax, 4 ; sys_write
    mov ebx, 1 ; stdout
    mov ecx, HelloWorld
    mov edx, 18
    int 0x80

    mov eax, 1
    xor ebx, ebx
    int 0x80

end:
