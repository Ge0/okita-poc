class CodeCoverage(object):
    def __init__(self, disassembler, regions, base_address=0x0):
        """ Init a CodeCoverage class, which aims at "covering" a whole binary by
        locating/differentiating code from (relevant) data, and so on."""
        self._base_address = base_address
        self._disassembler = disassembler
        if regions is None:
            self._regions = []
        else:
            self._regions = regions

    @property
    def base_address():
        """ Retrieve the base memory address used by the code coverage """
        return self._base_address

    @property
    def regions():
        """ Retrieve the regions handled by the code coverage """
        return self._regions

    @property
    def disassembler(self):
        """ Get the current disassembler instance """
        return self._disassembler

    def disassemble(self, data):
        self._disassembler.set_org(self._base_address)
        offset = 0
        for region in self._regions:
            region.get_disassembled(self._disassembler, data[offset:offset+region.size])
            offset += region.size

class BinaryRegion(object):
    def __init__(self, label, size, base_address, internal_symbols={}):
        self._size = size
        self._label = label
        self._base_address = base_address
        self._internal_symbols = internal_symbols
    
    @property
    def size(self):
        """ Retrieve the size of the region """
        return self._size

    @property
    def label(self):
        """ Retrieve the label of the region """
        return self._label

    @property
    def base_address(self):
        """ Retrieve the base address of the region """
        return self._base_address

    @property
    def internal_symbols(self):
        """ Retrieve some internal symbols of the region """
        return self._internal_symbols

    def get_disassembled(self, disassembler, data):
        pass

class UnknownRegion(BinaryRegion):
    def get_disassembled(self, disassembler, data):
        disassembler.disassemble_unknown_region(self, data)

class CodeRegion(BinaryRegion):
    def get_disassembled(self, disassembler, data):
        disassembler.disassemble_code_region(self, data)

class DataRegion(BinaryRegion):
    def get_disassembled(self, disassembler, data):
        disassembler.disassemble_data_region(self, data)

class Elf32EhdrRegion(BinaryRegion):
    def get_disassembled(self, disassembler, data):
        disassembler.disassemble_elf32_ehdr_region(self, data)

class Elf32PhdrRegion(BinaryRegion):
    def get_disassembled(self, disassembler, data):
        disassembler.disassemble_elf32_phdr_region(self, data)

class ElfInterpRegion(BinaryRegion):
    def get_disassembled(self, disassembler, data):
        disassembler.disassemble_elf_interp_region(self, data)
