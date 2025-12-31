# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
Macro Engine Plugin

This plugin handles Office macro malware detection and disinfection.
"""

import contextlib
import logging
import os
import re
import shutil
import struct
import tempfile
import zlib
from ctypes import POINTER, Structure, addressof, c_char, c_ubyte, c_uint, c_ushort, c_void_p, memmove, sizeof

from kicomav.plugins import cryptolib
from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.plugins import ole
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Malware ID
# -------------------------------------------------------------------------
MALWARE_ID_WORD95 = 0
MALWARE_ID_WORD97 = 1
MALWARE_ID_EXCEL95 = 2
MALWARE_ID_EXCEL97 = 3
MALWARE_ID_EXCEL_FORMULA95 = 4
MALWARE_ID_EXCEL_FORMULA97 = 5
MALWARE_ID_OLE = 99


# -------------------------------------------------------------------------
# Define the structure of Word95 macro
# -------------------------------------------------------------------------
BYTE = c_ubyte
WORD = c_ushort
DWORD = c_uint
FLOAT = c_uint
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_uint
SIZE_T = c_uint


class MCD(Structure):
    _pack_ = 1
    _fields_ = [
        ("cmg", BYTE),
        ("bEncrypt", BYTE),
        ("ibst", WORD),
        ("ibsName", WORD),
        ("ibstMenuHelp", WORD),
        ("fcFirst", DWORD),
        ("dfc", DWORD),
        ("fn", DWORD),
        ("fcFirstSave", DWORD),
    ]


class Error(Exception):
    pass


# ---------------------------------------------------------------------
# Read data
# ---------------------------------------------------------------------
def get_uint16(t_data, off):
    return struct.unpack("<H", t_data[off : off + 2])[0]


def get_uint32(t_data, off):
    return struct.unpack("<L", t_data[off : off + 4])[0]


def get_biff_record_size16(t_data, off):
    l = get_uint16(t_data, off + 2)
    return t_data[off : off + 4 + l]


def get_record_size32(t_data, off):
    l = get_uint32(t_data, off + 2)
    return t_data[off : off + 6 + l]


# ---------------------------------------------------------------------
# Create data
# ---------------------------------------------------------------------
def set_uint16(val):
    return struct.pack("<H", val)


def set_uint32(val):
    return struct.pack("<L", val)


# ---------------------------------------------------------------------
# Disinfect Word97.Macro
# ---------------------------------------------------------------------
def disinfect_word97_macro(data, verbose=False):
    if data[0x0B] & 0x01 == 0x01:
        if verbose:
            print("PASSWORD")
        return False, None  # The document is password protected

    data = data[:0x15E] + b"\x00\x00\x00\x00" + data[0x162:]
    return True, data


# ---------------------------------------------------------------------
# Disinfect Excel95.Macro
# ---------------------------------------------------------------------
def disinfect_excel95_macro(data: bytes):
    d1 = get_biff_record_size16(data, 0)
    d2 = get_biff_record_size16(data, len(d1))
    d3 = get_biff_record_size16(data, len(d1) + len(d2))

    if get_uint16(d2, 0) == 0x002F or get_uint16(d3, 0) == 0x002F:
        return False, None  # The sheet is password protected

    # Disinfect the macro in the book
    off = 0

    while off < len(data):
        t_data = get_biff_record_size16(data, off)
        val = get_uint16(t_data, 0)
        size = get_uint16(t_data, 2)

        # Manipulate the BIFF record
        if val == 0x0085:  # Sheet
            worksheet_pos = get_uint32(t_data, 4)
            if get_uint16(data, worksheet_pos + 6) == 0x06:  # Sheet containing macro : dt
                t_ret, data = disinfect_excel_worksheet(data, worksheet_pos)
                if t_ret is False:
                    return False, None

                data = data[: off + 8] + set_uint16(0x0001) + data[off + 10 :]

                len_sheet_name = data[off + 10]
                data = data[: off + 11] + (b" " * len_sheet_name) + data[off + 11 + len_sheet_name :]
        elif val in [0x00D3, 0x01BA]:  # ObProj or CodeName
            data = data[:off] + set_uint16(0x22) + data[off + 2 :]
        elif val in [0x000A, 0x0000]:  # EOF
            break

        off += len(t_data)

    return True, data


# ---------------------------------------------------------------------
# Disinfect Word95.Macro
# ---------------------------------------------------------------------
def disinfect_word95_macro(data: bytes):
    # Check if it is Word95
    start_macro = get_uint32(data, 0x118)
    if start_macro > len(data) or data[start_macro] != 0xFF:
        return False, None

    # Delete the existence of macro
    macro_magic = data[0xA] & 0xFE
    data = data[:0xA] + bytes([macro_magic]) + data[0xA + 1 :]
    data = data[:0x11C] + b"\x02\x00\x00\x00" + data[0x11C + 4 :]

    off = start_macro + 1

    while True:
        cmd = data[off]
        off += 1

        if cmd == 0x01:  # chHplmcd
            num_macro = get_uint16(data, off)
            off += 2
            break
        elif cmd == 0x02:  # chHplacd
            off += (get_uint16(data, off) * 0x04) + 2
        elif cmd in {0x03, 0x04}:  # chHplkme or chHplkmeBad
            off += (get_uint16(data, off) * 0x0E) + 2
        elif cmd == 0x05:  # chHplmud
            off += (get_uint16(data, off) * 0x0C) + 2
        elif cmd == 0x10:  # chHsttb
            off += get_uint16(data, off)
        elif cmd == 0x11:  # chMacroNames
            k = get_uint16(data, off)
            off += 2

            for _ in range(k):
                off += 2
                off += data[off] + 2
        elif cmd == 0x40:  # chTcgEnd
            return False, None

    mcd = []
    for _ in range(num_macro):
        t = MCD()
        memmove(addressof(t), data[off:], sizeof(t))
        t.fn = 0
        data = data[:off] + bytes(t) + data[off + sizeof(t) :]
        mcd.append(t)
        off += sizeof(t)

    for macro in mcd:
        t_size = macro.dfc
        t_off = macro.fcFirstSave
        data = data[:t_off] + (b"\x00" * t_size) + data[t_off + t_size :]

    data = data[: start_macro + 1] + b"\x40" + data[start_macro + 2 :]

    return True, data


# ---------------------------------------------------------------------
# Disinfect Excel97.Macro
# ---------------------------------------------------------------------
def disinfect_excel97_macro(data: bytes, verbose=False):
    d1 = get_biff_record_size16(data, 0)
    d2 = get_biff_record_size16(data, len(d1))
    d3 = get_biff_record_size16(data, len(d1) + len(d2))

    if get_uint16(d2, 0) == 0x002F or get_uint16(d3, 0) == 0x002F:
        if verbose:
            print("PASSWORD")
        return False, None  # The sheet is password protected

    # Disinfect the macro in the workbook
    off = 0

    while off < len(data):
        t_data = get_biff_record_size16(data, off)
        val = get_uint16(t_data, 0)
        size = get_uint16(t_data, 2)

        # Manipulate the BIFF record
        if val == 0x0085:  # Sheet
            worksheet_pos = get_uint32(t_data, 4)
            if get_uint16(data, worksheet_pos + 6) == 0x06:  # Sheet containing macro : dt
                t_ret, data = disinfect_excel_worksheet(data, worksheet_pos)
                if t_ret is False:
                    if verbose:
                        print("SHEET")
                    return False, None

                data = data[: off + 8] + set_uint16(0x0001) + data[off + 10 :]
                data = data[: off + 12] + (b" " * (size - 8)) + data[off + 12 + (size - 8) :]
        elif val in [0x00D3, 0x01BA]:  # ObProj or CodeName
            data = data[:off] + set_uint16(0x22) + data[off + 2 :]
        elif val in [0x000A, 0x0000]:  # EOF
            break

        off += len(t_data)

    return True, data


# ---------------------------------------------------------------------
# Disinfect Excel97.Formula
# ---------------------------------------------------------------------
def disinfect_excel97_formula(data: bytes):
    d1 = get_biff_record_size16(data, 0)
    d2 = get_biff_record_size16(data, len(d1))
    d3 = get_biff_record_size16(data, len(d1) + len(d2))

    if get_uint16(d2, 0) == 0x002F or get_uint16(d3, 0) == 0x002F:
        return False, None  # The sheet is password protected

    # Disinfect the formula in the workbook
    off = 0

    while off < len(data):
        t_data = get_biff_record_size16(data, off)
        val = get_uint16(t_data, 0)
        size = get_uint16(t_data, 2)

        # Manipulate the BIFF record
        if val == 0x0085:  # Sheet
            worksheet_pos = get_uint32(t_data, 4)
            us = get_uint16(data, off + 8)
            if us & 0x0F00 == 0x0100 or us == 0x40:
                data = data[: off + 8] + b"\x02\x00" + data[off + 10 :]
                data = data[: off + 12] + (b" " * (size - 8)) + data[off + 12 + (size - 8) :]

                t_ret, data = disinfect_excel_worksheet(data, worksheet_pos, del_formula=True)
                if t_ret is False:
                    return False, None
        elif val == 0x0018:
            data = data[: off + 4] + (b"\x00" * size) + data[off + 4 + size :]
        elif val in [0x000A, 0x0000]:  # EOF
            break

        off += len(t_data)

    return True, data


# ---------------------------------------------------------------------
# Disinfect Excel Sheet
# ---------------------------------------------------------------------
def disinfect_excel_worksheet(data: bytes, off, excel_version=MALWARE_ID_EXCEL95, del_formula=False):
    while off < len(data):
        t_data = get_biff_record_size16(data, off)
        val = get_uint16(t_data, 0)
        size = get_uint16(t_data, 2)

        if val == 0x0809:  # BOF
            data = data[: off + 6] + set_uint16(0x10) + data[off + 8 :]
        elif val == 0x023E:  # Window2
            t = set_uint16(0x08BE) + (b"\x00" * (size - 2))
            data = data[: off + 4] + t + data[off + size + 4 :]
        elif val == 0x0006:
            if del_formula:  # Disinfect the formula
                t_size = len(t_data[0x1B:]) - 2
                data = (
                    data[: off + 0x1A] + b"\x17" + set_uint16(t_size) + (b"\x00" * t_size) + data[off + 0x1D + t_size :]
                )
        elif val in [0x000A, 0x0000]:  # EOF
            break

        off += len(t_data)

    return True, data


# ---------------------------------------------------------------------
# Disinfect the macro
# ---------------------------------------------------------------------
def disinfect_office_macro(filename, malware_id):
    disinfect_macro_ref = {
        MALWARE_ID_WORD95: (None, "WordDocument", disinfect_word95_macro),
        MALWARE_ID_WORD97: ("Macros", "WordDocument", disinfect_word97_macro),
        MALWARE_ID_EXCEL95: ("_VBA_PROJECT", "Book", disinfect_excel95_macro),
        MALWARE_ID_EXCEL97: ("_VBA_PROJECT_CUR", "Workbook", disinfect_excel97_macro),
        MALWARE_ID_EXCEL_FORMULA97: (None, "Workbook", disinfect_excel97_formula),
    }

    ret = False
    while True:
        o = ole.OleFile(filename, write_mode=True)
        ole_lists = o.listdir(streams=True, storages=True)

        for name in ole_lists:
            pps = name.split("/")
            if disinfect_macro_ref[malware_id][0] and pps[-1] == disinfect_macro_ref[malware_id][0]:
                o.delete(name, delete_storage=True, reset_stream=True)
                o.close()
                break  # for
            elif pps[-1] == disinfect_macro_ref[malware_id][1]:
                pics = o.openstream(name)
                t_data = pics.read()
                t_ret, t_data = disinfect_macro_ref[malware_id][2](t_data)

                if t_ret:
                    o.write_stream(name, t_data)
                    ret = True
                else:
                    ret = False
        else:
            o.close()
            break  # while

    return ret


# ---------------------------------------------------------------------
# Analyze the dir stream
# ---------------------------------------------------------------------
def analysis_dir_stream(data, verbose=False):
    off = dir_informationrecord(data, 0, verbose)
    off = dir_referencesrecord(data, off, verbose)
    return dir_modulesrecord(data, off, verbose)


def dir_informationrecord(data, off, verbose=False):
    val = get_uint16(data, off)
    if val != 0x0001:
        raise Error("dir:InformationRecord:SysKindRecord")
    off += 10

    val = get_uint16(data, off)
    if val != 0x0002:
        raise Error("dir:InformationRecord:LcidRecord")
    off += 10

    val = get_uint16(data, off)
    if val != 0x0014:
        raise Error("dir:InformationRecord:LcidInvokeRecord")
    off += 10

    val = get_uint16(data, off)
    if val != 0x0003:
        raise Error("dir:InformationRecord:CodePageRecord")
    off += 8

    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x0004:
        raise Error("dir:InformationRecord:NameRecord")
    off += len(t_data)

    if verbose:
        print(f"Name : {t_data[6:]}")

    # DocStringRecord contains 2 records
    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x0005:
        raise Error("dir:InformationRecord:DocStringRecord #1")
    off += len(t_data)

    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x0040:
        raise Error("dir:InformationRecord:DocStringRecord #2")
    off += len(t_data)

    # HelpFilePathRecord contains 2 records
    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x0006:
        raise Error("dir:InformationRecord:HelpFilePathRecord #1")
    off += len(t_data)

    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x003D:
        raise Error("dir:InformationRecord:HelpFilePathRecord #2")
    off += len(t_data)

    val = get_uint16(data, off)
    if val != 0x0007:
        raise Error("dir:InformationRecord:HelpContextRecord")
    off += 10

    val = get_uint16(data, off)
    if val != 0x0008:
        raise Error("dir:InformationRecord:LibFlagsRecord")
    off += 10

    val = get_uint16(data, off)
    if val != 0x0009:
        raise Error("dir:InformationRecord:VersionRecord")
    off += 12

    # ConstantsRecord contains 2 records
    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x000C:
        raise Error("dir:InformationRecord:ConstantsRecord #1")
    off += len(t_data)

    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x003C:
        raise Error("dir:InformationRecord:ConstantsRecord #2")
    off += len(t_data)

    return off


def dir_referencesrecord(data, off, verbose=False):
    while True:
        _follow = False
        # NameRecord contains 2 records
        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)

        if val != 0x0016:
            break

        off += len(t_data)

        if verbose:
            print(f"ReferencesRecord Name : {t_data[6:]}")

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x003E:
            raise Error("dir:ReferencesRecord:NameRecord #2")
        off += len(t_data)

        # ReferenceRecord
        val = get_uint16(data, off)
        if val == 0x0033:  # REFERENCEREGISTERED
            t_data = get_record_size32(data, off)
            off += len(t_data)
            t_data = get_record_size32(data, off)
            val = get_uint16(data, off)
            _follow = True

        if val == 0x002F:  # REFERENCECONTROL
            if not _follow:
                t_data = get_record_size32(data, off)

            off += len(t_data)
            t_data = get_record_size32(data, off)
            if get_uint16(t_data, 0) != 0x0016:
                raise Error("dir:ReferencesRecord:ReferenceRecord:REFERENCECONTROL:NameRecordExtended")

            off += len(t_data)
            t_data = get_record_size32(data, off)
            if get_uint16(t_data, 0) != 0x003E:
                raise Error("dir:ReferencesRecord:ReferenceRecord:REFERENCECONTROL:NameRecordExtended:Reserved")

            off += len(t_data)
            t_data = get_record_size32(data, off)
            if get_uint16(t_data, 0) == 0x0030:  # Reserved3
                off += len(t_data)
            else:
                raise Error("dir:ReferencesRecord:ReferenceRecord:REFERENCECONTROL:Reserved3")
        elif val in [0x000D, 0x000E]:  # REFERENCEPROJECT
            t_data = get_record_size32(data, off)
            off += len(t_data)
        else:
            raise Error("dir:ReferencesRecord:ReferenceRecord")

    return off


def dir_modulesrecord(data, off, verbose=False):
    import math

    vba_modules = []

    val = get_uint16(data, off)
    if val != 0x000F:
        raise Error("dir:ModulesRecord")
    off += 16

    while True:
        # Process the module
        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0019:
            break
        off += len(t_data)

        m_name = t_data[6:]

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0047:
            continue
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x001A:
            raise Error("dir:ModulesRecord:StreamNameRecord #1")
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0032:
            raise Error("dir:ModulesRecord:StreamNameRecord #2")
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x001C:
            raise Error("dir:ModulesRecord:DocStringRecord #1")
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0048:
            raise Error("dir:ModulesRecord:DocStringRecord #2")
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0031:
            raise Error("dir:ModulesRecord:OffsetRecord")

        m_off = get_uint32(t_data, 6)
        off += 40

        if verbose:
            print("ModulesRecord Name : %s : %08X" % (m_name, m_off))

        vba_modules.append((m_name, m_off))

    return vba_modules


# ---------------------------------------------------------------------
# Decompress the macro source code in Office97
# ---------------------------------------------------------------------
def decompress(data: bytes):
    import math

    if data[0] != 1:
        return False, None

    remainder = data[1:]

    decompressed = b""
    while len(remainder) != 0:
        decompressed_chunk, remainder = decompress_chunk(remainder)

        if decompressed_chunk is None:
            return False, decompressed

        decompressed += decompressed_chunk

    return True, decompressed


def parse_token_sequence(data: bytes):
    flags = data[0]
    data = data[1:]
    result = []
    for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        if len(data) > 0:
            if flags & mask:
                result.append(data[:2])
                data = data[2:]
            else:
                result.append(data[:1])
                data = data[1:]
    return result, data


def offset_bits(data):
    import math

    number_of_bits = int(math.ceil(math.log(len(data), 2)))
    if number_of_bits < 4:
        number_of_bits = 4
    elif number_of_bits > 12:
        number_of_bits = 12
    return number_of_bits


def decompress_chunk(compressed_chunk: bytes):
    if len(compressed_chunk) < 2:
        return None, None

    header = compressed_chunk[0] + compressed_chunk[1] * 0x100
    size = (header & 0x0FFF) + 3
    flag_compressed = header & 0x8000
    data = compressed_chunk[2 : 2 + size - 2]

    if flag_compressed == 0:
        return data, compressed_chunk[size:]

    decompressed_chunk = b""
    while len(data) != 0:
        tokens, data = parse_token_sequence(data)
        for token in tokens:
            if len(token) == 1:
                decompressed_chunk += token
            else:
                if decompressed_chunk == b"":
                    return None, None

                number_of_offset_bits = offset_bits(decompressed_chunk)
                copy_token = token[0] + token[1] * 0x100
                offset = 1 + (copy_token >> (16 - number_of_offset_bits))
                length = 3 + (((copy_token << number_of_offset_bits) & 0xFFFF) >> number_of_offset_bits)
                copy = decompressed_chunk[-offset:]
                copy = copy[:length]
                length_copy = len(copy)

                while length > length_copy:
                    if length - length_copy >= length_copy:
                        copy += copy[:length_copy]
                        length -= length_copy
                    else:
                        copy += copy[: length - length_copy]
                        length -= length - length_copy

                decompressed_chunk += copy

    return decompressed_chunk, compressed_chunk[size:]


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """Macro malware detector plugin.

    This plugin provides functionality for:
    - Detecting macro malware in Office documents
    - Disinfecting macro viruses
    """

    def __init__(self):
        """Initialize the Macro Engine plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Macro Engine",
            kmd_name="macro",
        )
        self.p_vba_cmt = None
        self.p_vba_word = None
        self.word97_macro_crcs = []

    def _load_virus_database(self) -> int:
        """Load virus patterns.

        Returns:
            0 for success
        """
        self.p_vba_cmt = re.compile(rb"(\'|\bREM\b).*", re.IGNORECASE)
        self.p_vba_word = re.compile(rb"\w{2,}")

        # Suspicious Word97 macro virus CRC patterns
        self.word97_macro_crcs = [
            {0x839CE07A, 0xFC454C30, 0x084E324F},
            {0x700C7258, 0x2B408807, 0x9CECF67D},
        ]

        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        s_num = 1
        if kavutil.handle_pattern_md5:
            s_num = kavutil.handle_pattern_md5.get_sig_num("macro") + 1
        info["sig_num"] = s_num
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        vlist = kavutil.handle_pattern_md5.get_sig_vlist("macro")
        if vlist is None:
            vlist = []
        vlist.append("Virus.MSExcel.Laroux.Gen")
        vlist.sort()
        return vlist

    def scan(self, filehandle, filename, fileformat, filename_ex):
        """Scan for malware.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            fileformat: Format info from format() method
            filename_ex: Extended filename info

        Returns:
            Tuple of (found, malware_name, malware_id, result)
        """
        mm = filehandle
        o = None

        try:
            # Is there an OLE format in the pre-analyzed file format?
            if "ff_ole" in fileformat:
                o = ole.OleFile(filename)

                # Is it a vulnerable attack?
                if len(o.exploit):
                    if o:
                        o.close()
                    return True, o.exploit[0], MALWARE_ID_OLE, kernel.INFECTED

                ole_lists = o.listdir()

                for pps_name in ole_lists:
                    if pps_name.lower().find("/vba/dir") != -1:
                        pics = o.openstream(pps_name)
                        data = pics.read()
                        ret, decom_data = decompress(data)
                        if ret:
                            vba_modules = analysis_dir_stream(decom_data)

                            t = pps_name.split("/")

                            for vba in vba_modules:
                                t[-1] = vba[0].decode("utf-8", errors="ignore")
                                t_pps_name = "/".join(t)

                                t_pics = o.openstream(t_pps_name)
                                t_data = t_pics.read()

                                if len(t_data) == 0:
                                    continue

                                t_ret, buf = decompress(t_data[vba[1] :])
                                buf = buf.replace(b"\r\n", b"\n")

                                if t_ret:
                                    if self.verbose:
                                        kavutil.vprint("Macro Source")
                                        kavutil.vprint(None, "PPS", f"{t_pps_name}")
                                        print(buf)

                                    buf = self.p_vba_cmt.sub(b"", buf)
                                    buf = buf.lower()

                                    key_words = self.p_vba_word.findall(buf)

                                    vba_keyword_crc32 = set()
                                    for i in range(len(key_words) - 1):
                                        word = key_words[i] + key_words[i + 1]
                                        c = zlib.crc32(word) & 0xFFFFFFFF
                                        vba_keyword_crc32.add(c)

                                    if self.verbose:
                                        self._print_debug_keywords(key_words)

                                    # Heuristic scan
                                    for macro_crc in self.word97_macro_crcs:
                                        if macro_crc.issubset(vba_keyword_crc32):
                                            if o:
                                                o.close()
                                            return (
                                                True,
                                                "Virus.MSWord.Generic",
                                                MALWARE_ID_WORD97,
                                                kernel.SUSPECT,
                                            )

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
        except ole.Error as e:
            logger.debug("OLE error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)

        if o:
            o.close()

        return False, "", -1, kernel.NOT_FOUND

    def _print_debug_keywords(self, key_words):
        """Print debug keyword information in verbose mode."""
        max_len = len(key_words[0])

        t_word = []
        for i in range(len(key_words) - 1):
            word = key_words[i] + key_words[i + 1]
            c = zlib.crc32(word) & 0xFFFFFFFF
            t_word.append([c, key_words[i], key_words[i + 1]])

            if len(key_words[i + 1]) > max_len:
                max_len = len(key_words[i + 1])

        t_l = "+-" + ("-" * 8) + "-+-" + ("-" * max_len) + "-+-" + ("-" * max_len) + "-+"
        print(t_l)
        msg = "| %%-8s | %%-%ds | %%-%ds |" % (max_len, max_len)
        print(msg % ("CRC32", "Keyword #1", "Keyword #2"))
        print(t_l)

        msg = "| %%08X | %%-%ds | %%-%ds |" % (max_len, max_len)
        for n in t_word:
            print(msg % (n[0], n[1], n[2]))

        print(t_l)

    def disinfect(self, filename, malware_id):
        """Disinfect malware.

        Args:
            filename: Path to infected file
            malware_id: Malware ID to disinfect

        Returns:
            True if successful, False otherwise
        """
        # If it is an OLE vulnerability, delete it immediately
        if malware_id == MALWARE_ID_OLE:
            try:
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True
            except (IOError, OSError, k2security.SecurityError) as e:
                logger.debug("Disinfect error for %s: %s", filename, e)
                return False

        # Create a temporary file for disinfection failure recovery
        fd, t_name = tempfile.mkstemp(suffix="k2ole")
        os.close(fd)
        shutil.copy(filename, t_name)

        try:
            if malware_id == MALWARE_ID_EXCEL95:
                ret = disinfect_office_macro(filename, MALWARE_ID_EXCEL95)
            elif malware_id == MALWARE_ID_WORD95:
                ret = disinfect_office_macro(filename, MALWARE_ID_WORD95)
            elif malware_id == MALWARE_ID_EXCEL97:
                ret = disinfect_office_macro(filename, MALWARE_ID_EXCEL97)
            elif malware_id == MALWARE_ID_WORD97:
                ret = disinfect_office_macro(filename, MALWARE_ID_WORD97)
            elif malware_id == MALWARE_ID_EXCEL_FORMULA97:
                ret = disinfect_office_macro(filename, MALWARE_ID_EXCEL_FORMULA97)
            else:
                ret = False

            if ret:
                # Disinfect success, delete the temporary file
                with contextlib.suppress(k2security.SecurityError):
                    t_name_dir = os.path.dirname(t_name) or os.getcwd()
                    k2security.safe_remove_file(t_name, t_name_dir)
            else:
                # If it fails, restore the temporary file
                shutil.move(t_name, filename)

            return ret

        except (IOError, OSError, k2security.SecurityError) as e:
            logger.debug("Disinfect error for %s: %s", filename, e)
            # Restore the temporary file on error
            with contextlib.suppress(Exception):
                shutil.move(t_name, filename)
            return False
        except Exception as e:
            logger.warning("Unexpected error disinfecting %s: %s", filename, e)
            return False
