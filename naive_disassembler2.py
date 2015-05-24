#!/usr/bin/env python3
import sys
import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_p_type

if len(sys.argv) < 2:
    print("Usage: %s <binary>" % (sys.argv[0]))
    sys.exit(-1)

with open(sys.argv[1], "rb") as file_handle:
    binary_content = file_handle.read()
    elf_file       = ELFFile(file_handle)
    entry_point    = elf_file['e_entry']
    #print(entry_point)
    print("Entry point: %08X\n" % (entry_point))
    print("Retrieving appropriated offset...")
    start_offset = -1
    for segment in elf_file.iter_segments():

        start = segment['p_vaddr']
        size  = segment['p_filesz']

        print("Segment '%s' starting at %08X with size of %d bytes" %
            (describe_p_type(segment['p_type']), segment['p_vaddr'], segment['p_filesz']))

        if(entry_point >= start and entry_point < (start+size)):
            print("\t*** Entry point is located here! ***")
            start_offset = segment['p_offset'] + (entry_point - start)

    if start_offset >= 0:
        print("Start offset computed at %08X" % (start_offset))

    with open("%s.asm" % (sys.argv[1]), "w") as output_asm_file:
        output_asm_file.write("bits 32\n\n")
        i = 0
        for c in binary_content:
            if i == start_offset:
                output_asm_file.write("_start:\n")
            output_asm_file.write("\tdb 0x%02X\n" % (c & 0xff))
            i += 1
        output_asm_file.close()
        print("Written %d bytes into output file!" % len(binary_content))

    file_handle.close()
