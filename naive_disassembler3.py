#!/usr/bin/env python3
import sys
import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_p_type
import capstone
import okita.code_coverage as code_coverage
import okita.binary_disassembler as binary_disassembler

def linear_sweep_disassemble(base_addr, code, arch, mode):
    # Dumb strategy, disass until:
    #   - end of code reached OR
    #   - ret or hlt instruction is met
    disassembler = capstone.Cs(arch, mode)
    for current_instruction in disassembler.disasm(code, base_addr):
        print("%s\t%s" % (current_instruction.mnemonic, current_instruction.op_str))

def create_start_proc_region(content, base_address):
    region = code_coverage.CodeRegion("_start", 0, base_address)
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for instruction in disassembler.disasm(content, 0x00000000):
        region._size += instruction.size
        if instruction.mnemonic == "ret" or instruction.mnemonic == "hlt":
            break
    return region

if len(sys.argv) < 2:
    print("Usage: %s <binary>" % (sys.argv[0]))
    sys.exit(-1)

def get_elf_information(elf_file):
    base_address = 0
    start_offset = 0
    for segment in elf_file.iter_segments():
        if(segment['p_type'] == 'PT_LOAD' and segment['p_offset'] == 0):
            base_address = segment['p_vaddr']
        if(elf_file['e_entry'] >= segment['p_vaddr'] and elf_file['e_entry'] < (segment['p_vaddr'] + segment['p_filesz'])):
            start_offset = segment['p_offset'] + (elf_file['e_entry'] - base_address)
    return (base_address, start_offset)

def elf_gen_code_coverage(elf_file):
    elf_base_address, start_offset = get_elf_information(elf_file)

    disasm = binary_disassembler.NaiveBinaryDisassembler(sys.argv[1])
    regions = [
        code_coverage.Elf32EhdrRegion("header", size=elf_file['e_ehsize'], base_address=elf_base_address),
        code_coverage.UnknownRegion("before_start", size=start_offset-elf_file['e_ehsize'], base_address=elf_base_address+elf_file['e_ehsize'])
    ]

    # start code until ret/hlt
    regions.append(create_start_proc_region(binary_content[start_offset:], elf_file['e_entry']))

    # rest of the code
    regions.append(code_coverage.UnknownRegion("after_start", len(binary_content) - (start_offset + regions[-1].size), elf_file['e_entry'] + (start_offset +regions[-1].size)))
 
    cover = code_coverage.CodeCoverage(disasm, regions, base_address=elf_base_address)
    return cover
    

with open(sys.argv[1], "rb") as file_handle:
    binary_content = file_handle.read()
    elf_file       = ELFFile(file_handle)

    print("Creating code coverage...")
    cover = elf_gen_code_coverage(elf_file)
    print("Disassembling the file...")
    cover.disassemble(binary_content)
    print("Done.")
    file_handle.close()
