import capstone
import struct

class BinaryDisassembler(object):
    def set_org(self, org):
        pass
    def disassemble_unknown_region(self, region, data):
        pass
    def disassemble_code_region(self, region, data):
        pass
    def disassemble_data_region(self, region, data):
        pass
    def disassemble_elf32_ehdr_region(self, region, data):
        pass

class NaiveBinaryDisassembler(BinaryDisassembler):
    def __init__(self, output_file):
        self._handle = open("%s_naive_disass.asm" % (output_file), "w")
        self._handle.write("%include \"defines/elf.asm\"\n")
        self._handle.write("bits 32\n") # For the beauty of the PoC

    def _output_region_comments(self, region, comment="REGION"):
        self._handle.write("; ---------------- %s ----------------\n"
        "; Name: %s\n"
        "; Base Address: 0x%08X\n"
        "; Size: %d bytes\n" % (comment, region.label, region.base_address, region.size))

    def set_org(self, org):
        self._handle.write("ORG 0x%08X\n" % (org))

    def disassemble_elf32_phdr_region(self, region, data):
        self._output_region_comments(region, "ELF PROGRAM HEADER")
        self._handle.write("%s:\n" % (region.label))
        self._handle.write("   istruc Elf32_Phdr\n")
        self._handle.write("        at Elf32_Phdr.p_type,    dd %d\n" % (struct.unpack('<L', data[0:4])[0]))
        self._handle.write("        at Elf32_Phdr.p_offset,  dd %d\n" % (struct.unpack('<L', data[4:8])[0]))
        self._handle.write("        at Elf32_Phdr.p_vaddr,   dd 0x%08X\n" % (struct.unpack('<L', data[8:12])[0]))
        self._handle.write("        at Elf32_Phdr.p_paddr,   dd 0x%08X\n" % (struct.unpack('<L', data[12:16])[0]))
        self._handle.write("        at Elf32_Phdr.p_filesz,  dd %d\n" % (struct.unpack('<L', data[16:20])[0]))
        self._handle.write("        at Elf32_Phdr.p_memsz,   dd %d\n" % (struct.unpack('<L', data[20:24])[0]))
        self._handle.write("        at Elf32_Phdr.p_flags,   dd %d\n" % (struct.unpack('<L', data[24:28])[0]))
        self._handle.write("        at Elf32_Phdr.p_align,   dd %d\n" % (struct.unpack('<L', data[28:32])[0]))
        self._handle.write("   iend\n\n")

    def disassemble_elf32_ehdr_region(self, region, data):
        self._output_region_comments(region, "ELF HEADER")
        self._handle.write("%s:\n" % (region.label))
        self._handle.write("    istruc Elf32_Ehdr\n")
        self._handle.write("        at Elf32_Ehdr.e_ident,      db %d, `%s`, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d\n" %
            (data[0], data[1:4].decode(), data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]))
        self._handle.write("        at Elf32_Ehdr.e_type,       dw %d\n" % (struct.unpack('<H', data[16:18])[0]))
        self._handle.write("        at Elf32_Ehdr.e_machine,    dw %d\n" % (struct.unpack('<H', data[18:20])[0]))
        self._handle.write("        at Elf32_Ehdr.e_version,    dd %d\n" % (struct.unpack('<L', data[20:24])[0]))
        self._handle.write("        at Elf32_Ehdr.e_entry,      dd 0x%08X\n" % (struct.unpack('<L', data[24:28])[0]))
        self._handle.write("        at Elf32_Ehdr.e_phoff,      dd %d\n" % (struct.unpack('<L', data[28:32])[0]))
        self._handle.write("        at Elf32_Ehdr.e_shoff,      dd %d\n" % (struct.unpack('<L', data[32:36])[0]))
        self._handle.write("        at Elf32_Ehdr.e_flags,      dd %d\n" % (struct.unpack('<L', data[36:40])[0]))
        self._handle.write("        at Elf32_Ehdr.e_ehsize,     dw %d\n" % (struct.unpack('<H', data[40:42])[0]))
        self._handle.write("        at Elf32_Ehdr.e_phentsize,  dw %d\n" % (struct.unpack('<H', data[42:44])[0]))
        self._handle.write("        at Elf32_Ehdr.e_phnum,      dw %d\n" % (struct.unpack('<H', data[44:46])[0]))
        self._handle.write("        at Elf32_Ehdr.e_shentsize,  dw %d\n" % (struct.unpack('<H', data[46:48])[0]))
        self._handle.write("        at Elf32_Ehdr.e_shnum,      dw %d\n" % (struct.unpack('<H', data[48:50])[0]))
        self._handle.write("        at Elf32_Ehdr.e_shstrndx,   dw %d\n" % (struct.unpack('<H', data[50:52])[0]))
        self._handle.write("    iend\n\n")

    def disassemble_elf_interp_region(self, region, data):
        self._output_region_comments(region, "INTERP SEGMENT")
        self._handle.write("%s:\n" % (region.label))
        self._handle.write("    db `%s`, 0\n\n" % (data[:-1].decode()))

    def disassemble_unknown_region(self, region, data):
        self._output_region_comments(region, "UNKNOWN REGION")
        self._handle.write("%s:\n" % (region.label))
        self._handle.write("    db 0x%02X" % (data[0]))
        i = 1
        while i < len(data):
            if(i % 16 == 0):
                self._handle.write("\n    db 0x%02X" % (data[i]))
            else:
                self._handle.write(", 0x%02X" % (data[i]))
            i += 1
        self._handle.write("\n")

        self._handle.write("; ------------------------------------------------\n\n")

    def disassemble_code_region(self, region, data):
        self._output_region_comments(region, "EXECUTABLE CODE")
        self._handle.write("%s:\n" % (region.label))
        # TODO: check the target architecture.
        md  = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        for instruction in md.disasm(data, region.base_address):
            self._handle.write("\t%s %s\n" % (instruction.mnemonic, instruction.op_str))
        #self.disassemble_unknown_region(region, data)

    def disassemble_data_region(region, data):
        # TODO
        self.disassemble_unknown_region(region, data)
