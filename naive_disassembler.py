#!/usr/bin/env python3
import sys

if len(sys.argv) < 2:
    print("Usage: %s <binary>" % (sys.argv[0]))
    sys.exit(-1)

with open(sys.argv[1], "rb") as file_handle:
    binary_content = file_handle.read()
    file_handle.close()

    with open("%s.asm" % (sys.argv[1]), "w") as output_asm_file:
        output_asm_file.write("bits 32\n\n")
        for c in binary_content:
            output_asm_file.write("db 0x%02X\n" % (c & 0xff))
        output_asm_file.close()
        print("Written %d bytes into output file!" % len(binary_content))

