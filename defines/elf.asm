; These constants are for the segment types stored in the image headers
%define PT_NULL    0
%define PT_LOAD    1
%define PT_DYNAMIC 2
%define PT_INTERP  3
%define PT_NOTE    4
%define PT_SHLIB   5
%define PT_PHDR    6
%define PT_TLS     7        /* Thread local storage segment */
%define PT_LOOS    0x60000000   /* OS-specific */
%define PT_HIOS    0x6fffffff   /* OS-specific */
%define PT_LOPROC  0x70000000
%define PT_HIPROC  0x7fffffff
%define PT_GNU_EH_FRAME     0x6474e550

%define PT_GNU_STACK    (PT_LOOS + 0x474e551)

; These constants define the different elf file types
%define ET_NONE   0
%define ET_REL    1
%define ET_EXEC   2
%define ET_DYN    3
%define ET_CORE   4
%define ET_LOPROC 0xff00
%define ET_HIPROC 0xffff

; These constants define the various ELF target machines
%define EM_NONE         0
%define EM_M32          1
%define EM_SPARC        2
%define EM_386          3
%define EM_68K          4
%define EM_88K          5
%define EM_860          6
%define EM_MIPS         7
%define EM_PARISC       8
%define EM_SPARC32PLUS  9
%define EM_PPC          10
%define EM_PPC64        11
%define EM_S390         12
%define EM_ARM          13
%define EM_SH           14
%define EM_SPARCV9      15
%define EM_IA_64        16
%define EM_X86_64       17
%define EM_VAX          18

%define EI_NIDENT   16

struc Elf32_Ehdr
    .e_ident:        resb    16
    .e_type:         resw    1
    .e_machine:      resw    1
    .e_version:      resd    1
    .e_entry:        resd    1
    .e_phoff:        resd    1
    .e_shoff:        resd    1
    .e_flags:        resd    1
    .e_ehsize:       resw    1
    .e_phentsize:    resw    1
    .e_phnum:        resw    1
    .e_shentsize:    resw    1
    .e_shnum:        resw    1
    .e_shstrndx:     resw    1

    .size:
endstruc

; These constants define the permissions on sections in the program
; header, p_flags.
%define PF_R        0x4
%define PF_W        0x2
%define PF_X        0x1

struc Elf32_Phdr
    .p_type:         resd    1
    .p_offset:       resd    1
    .p_vaddr:        resd    1
    .p_paddr:        resd    1
    .p_filesz:       resd    1
    .p_memsz:        resd    1
    .p_flags:        resd    1
    .p_align:        resd    1

    .size:
endstruc

%define EI_MAG0     0   ; e_ident[] indexes
%define EI_MAG1     1
%define EI_MAG2     2
%define EI_MAG3     3
%define EI_CLASS    4
%define EI_DATA     5
%define EI_VERSION  6
%define EI_OSABI    7
%define EI_PAD      8

%define ELFMAG0     0x7f    ; EI_MAG
%define ELFMAG1     'E'
%define ELFMAG2     'L'
%define ELFMAG3     'F'
%define ELFMAG      `\177ELF`
%define SELFMAG     4

%define ELFCLASSNONE    0   ; EI_CLASS
%define ELFCLASS32  1
%define ELFCLASS64  2
%define ELFCLASSNUM 3

%define ELFDATANONE 0   ; e_ident[EI_DATA]
%define ELFDATA2LSB 1
%define ELFDATA2MSB 2

%define EV_NONE     0   ; e_version, EI_VERSION
%define EV_CURRENT  1
%define EV_NUM      2

%define ELFOSABI_NONE   0
%define ELFOSABI_LINUX  3


