import os
import struct
from ctypes import *
host="127.0.0.1"

class IP(Structure):
    _fields_=[
        ("ihl",     c_ubyte,4),
        ("version", c_ubyte,4),
        ("tos",     c_ubyte),
        ("len",     c_ushort),
        ("",        c_ushort),