# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import hashlib
import zlib
from ctypes import c_ushort
import kernel
import k2io


# -------------------------------------------------------------------------
# md5(data)
# Compute MD5 hash for given data
# input  : data
# return : hash value
# -------------------------------------------------------------------------
def md5(data):
    return hashlib.md5(k2io.k2byte(data)).hexdigest()


# -------------------------------------------------------------------------
# crc32(data)
# Compute CRC32 hash for given data
# input  : data
# return : hash value
# -------------------------------------------------------------------------
def crc32(data):
    return '%08x' % (zlib.crc32(k2io.k2byte(data)) & 0xffffffff)


# -------------------------------------------------------------------------
# sha256(data)
# Compute SHA256 hash for given data
# input  : data
# return : hash value
# -------------------------------------------------------------------------
def sha256(data):
    return hashlib.sha256(k2io.k2byte(data)).hexdigest()


# -------------------------------------------------------------------------
# class CRC16
# -------------------------------------------------------------------------
class CRC16(object):
    crc16_tab = []

    # The CRC's are computed using polynomials. Here is the most used
    # coefficient for CRC16
    crc16_constant = 0xA001  # 40961

    def __init__(self, modbus_flag=False):
        # initialize the precalculated tables
        if not len(self.crc16_tab):
            self.init_crc16()
        self.mdflag = bool(modbus_flag)

    def calculate(self, input_data=None):
        try:
            is_string = isinstance(input_data, str)
            is_bytes = isinstance(input_data, (bytes, bytearray))

            if not is_string and not is_bytes:
                raise Exception("Please provide a string or a byte sequence "
                                "as argument for calculation.")

            crc_value = 0x0000 if not self.mdflag else 0xffff

            for c in input_data:
                d = ord(c) if is_string else c
                tmp = crc_value ^ d
                rotated = crc_value >> 8
                crc_value = rotated ^ self.crc16_tab[(tmp & 0x00ff)]

            return crc_value
        except Exception as e:
            print("EXCEPTION(calculate): {}".format(e))

    def init_crc16(self):
        """The algorithm uses tables with precalculated values"""
        for i in range(0, 256):
            crc = c_ushort(i).value
            for j in range(0, 8):
                if crc & 0x0001:
                    crc = c_ushort(crc >> 1).value ^ self.crc16_constant
                else:
                    crc = c_ushort(crc >> 1).value
            self.crc16_tab.append(crc)


# -------------------------------------------------------------------------
# crc16(data)
# Compute CRC16 hash for given data
# input  : data
# return : hash value
# -------------------------------------------------------------------------
def crc16(data):
    return '%04x' % CRC16().calculate(k2io.k2byte(data))


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(kernel.PluginsMain):
    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    def getinfo(self):
        info = k2io.k2dict()

        k2io.k2dict_append(info, 'author', 'Kei Choi')
        k2io.k2dict_append(info, 'version', '1.0')
        k2io.k2dict_append(info, 'title', 'Crypto Library')
        k2io.k2dict_append(info, 'kmd_name', 'cryptolib')

        return info
