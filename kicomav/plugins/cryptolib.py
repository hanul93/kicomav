# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import hashlib
import zlib
from ctypes import c_ushort
from kicomav.plugins import kernel


# -------------------------------------------------------------------------
# md5(data)
# Compute MD5 hash for given data
# input  : data
# return : hash value
# -------------------------------------------------------------------------
def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# -------------------------------------------------------------------------
# crc32(data)
# Compute CRC32 hash for given data
# input  : data
# return : hash value
# -------------------------------------------------------------------------
def crc32(data: bytes) -> str:
    return "%08x" % int(zlib.crc32(data) & 0xFFFFFFFF)


# -------------------------------------------------------------------------
# sha256(data)
# Compute SHA256 hash for given data
# input  : data
# return : hash value
# -------------------------------------------------------------------------
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
                raise Exception("Please provide a string or a byte sequence " "as argument for calculation.")

            crc_value = 0xFFFF if self.mdflag else 0x0000

            for c in input_data:
                d = ord(c) if is_string else c
                tmp = crc_value ^ d
                rotated = crc_value >> 8
                crc_value = rotated ^ self.crc16_tab[(tmp & 0x00FF)]

            return crc_value
        except Exception as e:
            print(f"EXCEPTION(calculate): {e}")

    def init_crc16(self):
        """The algorithm uses tables with precalculated values"""
        for i in range(256):
            crc = c_ushort(i).value
            for _ in range(8):
                crc = c_ushort(crc >> 1).value ^ self.crc16_constant if crc & 0x0001 else c_ushort(crc >> 1).value
            self.crc16_tab.append(crc)


# -------------------------------------------------------------------------
# crc16(data)
# Compute CRC16 hash for given data
# input  : data
# return : hash value
# -------------------------------------------------------------------------
def crc16(data: bytes) -> str:
    return "%04x" % CRC16().calculate(data)


# -------------------------------------------------------------------------
# rol1(byte, count)
# Rotate left by count bits
# input  : byte, count
# return : rotated byte
# -------------------------------------------------------------------------
def rol1(byte, count):
    """Rotate left by count bits"""
    return ((byte << count) | (byte >> (8 - count))) & 0xFF


# -------------------------------------------------------------------------
# ishield_decrypt(encrypted_data, key_data)
# Decrypt InstallShield encrypted data
# input  : encrypted_data, key_data
# return : decrypted data
# -------------------------------------------------------------------------
def ishield_decrypt(encrypted_data, key_data):
    key_len = len(key_data)
    decrypted = bytearray(len(encrypted_data))
    n = 0

    for i in range(len(encrypted_data)):
        val = encrypted_data[i]
        val = rol1(val, 3)
        decrypted[i] = val ^ key_data[n % key_len]

        n += 1
        if n >= key_len:
            n = 0

    return bytes(decrypted)


def reset_padding(data: bytes, offset: int, actual_size: int, max_size: int) -> bytes:
    """Reset padding area after a specific offset to 0x00

    Args:
        data: Original data
        offset: Offset with size field (include size field itself, +4 to get data start)
        actual_size: Actual used size
        max_size: Maximum allowed size

    Returns:
        Data with reset padding
    """
    reset_size = max_size - actual_size
    start_pos = offset + 4 + actual_size
    return data[:start_pos] + bytes(reset_size) + data[start_pos + reset_size :]


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
        return {
            "author": "Kei Choi",
            "version": "1.0",
            "title": "Crypto Library",
            "kmd_name": "cryptolib",
        }
