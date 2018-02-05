%include "defines/pe.asm"

IMAGE_BASE    equ 0x00400000
BASE_OF_CODE  equ 0x00001000
BASE_OF_DATA  equ 0x00002000
SECTION_ALIGN equ 1000h
FILE_ALIGN    equ 200h

ORG IMAGE_BASE
mz_dos_header:
    istruc IMAGE_DOS_HEADER
        at IMAGE_DOS_HEADER.e_magic,    dw `MZ`
        at IMAGE_DOS_HEADER.e_cblp,     dw 0x0090
        at IMAGE_DOS_HEADER.e_cp,       dw 0x0003
        at IMAGE_DOS_HEADER.e_crlc,     dw 0x0000
        at IMAGE_DOS_HEADER.e_cparhdr,  dw (dos_stub - mz_dos_header) >> 4
        at IMAGE_DOS_HEADER.e_minalloc, dw 0x0000
        at IMAGE_DOS_HEADER.e_maxalloc, dw 0xFFFF
        at IMAGE_DOS_HEADER.e_ss,       dw 0x0000
        at IMAGE_DOS_HEADER.e_sp,       dw 0x00B8
        at IMAGE_DOS_HEADER.e_csum,     dw 0x0000
        at IMAGE_DOS_HEADER.e_ip,       dw 0x0000
        at IMAGE_DOS_HEADER.e_cs,       dw 0x0000
        at IMAGE_DOS_HEADER.e_lfarlc,   dw 0x0040
        at IMAGE_DOS_HEADER.e_ovno,     dw 0x0000
        at IMAGE_DOS_HEADER.e_res,      dw 0x0000, 0x0000, 0x0000, 0x0000
        at IMAGE_DOS_HEADER.e_oemid,    dw 0x0000
        at IMAGE_DOS_HEADER.e_oeminfo,  dw 0x0000
        at IMAGE_DOS_HEADER.e_res2,     dw 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
        at IMAGE_DOS_HEADER.e_lfanew,   dw (image_nt_headers - mz_dos_header)
    iend
    
align 010h, db 0

dos_stub:
bits 16
    push    cs
    pop     ds
    mov     dx, dos_msg - dos_stub
    mov     ah, 9
    int     21h
    mov     ax, 4c01h
    int     21h
dos_msg:
    db 'This program cannot be run in DOS mode.', 0x0d, 0x0d, 0x0a, '$'

align 16, db 0
;RichHeader:
;    dd "DanS" ^ RichKey     , 0 ^ RichKey, 0 ^ RichKey       , 0 ^ RichKey
;    dd 0131f8eh ^ RichKey   , 7 ^ RichKey, 01220fch ^ RichKey, 1 ^ RichKey
;    dd "Rich", 0 ^ RichKey  , 0, 0
;align 16, db 0

bits 32
image_nt_headers:
    istruc IMAGE_NT_HEADERS
        at IMAGE_NT_HEADERS.Signature, dd `PE\x00\x00`
    iend
image_file_headers:
    istruc IMAGE_FILE_HEADER
        at IMAGE_FILE_HEADER.Machine,              dw IMAGE_FILE_MACHINE_I386
        at IMAGE_FILE_HEADER.NumberOfSections,     dw NUMBER_OF_SECTIONS
        at IMAGE_FILE_HEADER.TimeDateStamp,        dd 0x00000000
        at IMAGE_FILE_HEADER.PointerToSymbolTable, dd 0x00000000
        at IMAGE_FILE_HEADER.NumberOfSymbols,      dd 0
        at IMAGE_FILE_HEADER.SizeOfOptionalHeader, dw SIZE_OF_OPTIONAL_HEADER
        at IMAGE_FILE_HEADER.Characteristics,      dw IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
    iend
    
image_optional_header32:
    istruc IMAGE_OPTIONAL_HEADER32
        at IMAGE_OPTIONAL_HEADER32.Magic,                       dw IMAGE_NT_OPTIONAL_HDR32_MAGIC
        at IMAGE_OPTIONAL_HEADER32.MajorLinkerVersion,          db 0x09
        at IMAGE_OPTIONAL_HEADER32.MinorLinkerVersion,          db 0x00
        at IMAGE_OPTIONAL_HEADER32.SizeOfCode,                  dd 0x00000000
        at IMAGE_OPTIONAL_HEADER32.SizeOfInitializedData,       dd 0x00000000
        at IMAGE_OPTIONAL_HEADER32.SizeOfUninitializedData,     dd 0x00000000
        at IMAGE_OPTIONAL_HEADER32.AddressOfEntryPoint,         dd entry_point - IMAGE_BASE
        at IMAGE_OPTIONAL_HEADER32.BaseOfCode,                  dd BASE_OF_CODE
        at IMAGE_OPTIONAL_HEADER32.BaseOfData,                  dd BASE_OF_CODE
        at IMAGE_OPTIONAL_HEADER32.ImageBase,                   dd IMAGE_BASE
        at IMAGE_OPTIONAL_HEADER32.SectionAlignment,            dd 0x00001000
        at IMAGE_OPTIONAL_HEADER32.FileAlignment,               dd 0x00000200
        at IMAGE_OPTIONAL_HEADER32.MajorOperatingSystemVersion, dw 0x0006
        at IMAGE_OPTIONAL_HEADER32.MinorOperatingSystemVersion, dw 0x0001
        at IMAGE_OPTIONAL_HEADER32.MajorImageVersion,           dw 0x0006
        at IMAGE_OPTIONAL_HEADER32.MinorImageVersion,           dw 0x0001
        at IMAGE_OPTIONAL_HEADER32.MajorSubsystemVersion,       dw 0x0006
        at IMAGE_OPTIONAL_HEADER32.MinorSubsystemVersion,       dw 0x0001
        at IMAGE_OPTIONAL_HEADER32.Win32VersionValue,           dd 0x00000000
        at IMAGE_OPTIONAL_HEADER32.SizeOfImage,                 dd 0x00002000
        at IMAGE_OPTIONAL_HEADER32.SizeOfHeaders,               dd SIZE_OF_HEADERS
        at IMAGE_OPTIONAL_HEADER32.CheckSum,                    dd 0x00000000
        at IMAGE_OPTIONAL_HEADER32.Subsystem,                   dw IMAGE_SUBSYSTEM_WINDOWS_CUI
        at IMAGE_OPTIONAL_HEADER32.DllCharacteristics,          dw 0x8140
        at IMAGE_OPTIONAL_HEADER32.SizeOfStackReserve,          dd 0x00040000
        at IMAGE_OPTIONAL_HEADER32.SizeOfStackCommit,           dd 0x00002000
        at IMAGE_OPTIONAL_HEADER32.SizeOfHeapReserve,           dd 0x00100000
        at IMAGE_OPTIONAL_HEADER32.SizeOfHeapCommit,            dd 0x00001000
        at IMAGE_OPTIONAL_HEADER32.LoaderFlags,                 dd 0x00000000
        at IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes,         dd 0x00000000
    iend
        
SIZE_OF_OPTIONAL_HEADER equ $ - image_optional_header32
section_headers:
    istruc IMAGE_SECTION_HEADER
        at IMAGE_SECTION_HEADER.Name,             db '.text', 0, 0, 0
        at IMAGE_SECTION_HEADER.VirtualSize,      dd section_text_size - section_text
        at IMAGE_SECTION_HEADER.VirtualAddress,   dd SECTION_ALIGN
        at IMAGE_SECTION_HEADER.SizeOfRawData,    dd FILE_ALIGN
        at IMAGE_SECTION_HEADER.PointerToRawData, dd FILE_ALIGN
        at IMAGE_SECTION_HEADER.Characteristics,  dd IMAGE_SCN_MEM_EXECUTE
    iend

NUMBER_OF_SECTIONS      equ ($ - section_headers) / IMAGE_SECTION_HEADER_size
SIZE_OF_HEADERS         equ ($ - IMAGE_BASE)
headers_end:


section progbits vstart=IMAGE_BASE+SECTION_ALIGN align=FILE_ALIGN
section_text:

entry_point:
    push ebp
    mov ebp, esp
    ; ADD SOME CODE.
    leave
    ret


section_text_size:
align FILE_ALIGN, db 0
image_end: