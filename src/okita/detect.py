"""Okita detection module."""
import struct

from .base import Type


MAGIC_ELF = 0x464c457f  # 'ELF\x7F'
MAGIC_MZ = 0x5a3D  # 'MZ\0\0'


def detect(filename: str) -> Type:
    """Detect the binary type of `filename`.
    
    Args:
        filename: The filename of the binary to detect the type from.
        
    Returns:
        The type of the binary.

    """
    with open(filename, "rb") as stream:
        magic_word = struct.unpack('<L', stream.read(4))[0]
        if magic_word == MAGIC_ELF:
            return Type.ELF
        elif magic_word == MAGIC_MZ:
            return Type.PE
        else:
            return Type.UNKNOWN
