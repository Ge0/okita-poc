"""Okita detection submodule.

This module provides helpers in order to detect the provided binary type.

It should return a factory class dedicated to proper handling of the binary.

"""

def detect(filename):
    with open(filename, "rb") as stream:
        