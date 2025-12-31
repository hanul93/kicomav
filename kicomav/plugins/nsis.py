# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
NSIS Archive Engine Plugin

This plugin handles NSIS (Nullsoft Scriptable Install System) format for scanning and manipulation.
"""

import contextlib
import datetime
import logging
import mmap
import os
import struct
import tempfile
import zlib
from ctypes import *
from io import BytesIO

try:
    import pylzma

    HAS_PYLZMA = True
except ImportError:
    HAS_PYLZMA = False

from kicomav.plugins import cryptolib
from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Structure for NSIS
# ----------------------------------------------------------------------------
BYTE = c_ubyte
WORD = c_ushort
LONG = c_long
DWORD = c_uint
FLOAT = c_float
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_uint
SIZE_T = c_uint


class StructNsisHeader(Structure):
    _pack_ = 1
    _fields_ = [
        ("flag", DWORD),
        ("pages", DWORD),
        ("pages_num", DWORD),
        ("sections", DWORD),
        ("sections_num", DWORD),
        ("entries", DWORD),
        ("entries_num", DWORD),
        ("strings", DWORD),
        ("strings_num", DWORD),
        ("langtables", DWORD),
        ("langtables_num", DWORD),
        ("ctlcolors", DWORD),
        ("ctlcolors_num", DWORD),
        ("bgfont", DWORD),
        ("bgfont_num", DWORD),
        ("data", DWORD),
        ("data_num", DWORD),
    ]


class StructNsisRecord(Structure):
    _pack_ = 1
    _fields_ = [
        ("which", DWORD),
        ("parm0", LONG),
        ("parm1", LONG),
        ("parm2", LONG),
        ("parm3", LONG),
        ("parm4", LONG),
        ("parm5", LONG),
    ]


NsisVarNames = {
    # init with 1
    0: "0",
    1: "1",
    2: "2",
    3: "3",
    4: "4",
    5: "5",
    6: "6",
    7: "7",
    8: "8",
    9: "9",
    10: "R0",
    11: "R1",
    12: "R2",
    13: "R3",
    14: "R4",
    15: "R5",
    16: "R6",
    17: "R7",
    18: "R8",
    19: "R9",
    20: "CMDLINE",
    21: "INSTDIR",
    22: "OUTDIR",
    23: "EXEDIR",
    24: "LANGUAGE",
    # init with -1
    25: "TEMP",
    26: "PLUGINSDIR",
    27: "EXEPATH",
    28: "EXEFILE",
    29: "HWNDPARENT",
    30: "_CLICK",
    # init with 1
    31: "_OUTDIR",
}


class NSIS:
    TYPE_UNKNOWN = -1
    TYPE_LZMA = 0
    TYPE_BZIP2 = 1
    TYPE_ZLIB = 2
    TYPE_COPY = 3

    def __init__(self, filename, offset=0, verbose=False):
        self.verbose = verbose
        self.filename = filename
        self.fp = None
        self.mm = None

        self.nsis_header = None
        self.body_data = None
        self.case_type = 0

        self.temp_name = None
        self.start_offset = offset

    def parse(self):
        # Use mkstemp instead of mktemp to prevent race condition (CWE-377)
        fd, self.temp_name = tempfile.mkstemp(prefix="knsf")

        with open(self.filename, "rb") as fp:
            fp.seek(self.start_offset)
            data = fp.read()

        try:
            os.write(fd, data)
        finally:
            os.close(fd)

        self.fp = open(self.temp_name, "rb")
        fsize = os.path.getsize(self.temp_name)
        if fsize == 0:
            return False

        self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

        flag = kavutil.get_uint32(self.mm, 0)
        head_size = kavutil.get_uint32(self.mm, 0x14)
        comp_size = kavutil.get_uint32(self.mm, 0x18)

        data, case_type = self.get_data()  # Get all NSIS data
        self.body_data = data
        self.case_type = case_type

        if self.verbose:
            self.print_nsis_debug_info(flag, case_type, data)
        return True

    def print_nsis_debug_info(self, flag, case_type, data):
        """
        Prints detailed debug information about NSIS file format

        Args:
            flag: NSIS header flag
            case_type: Compression case type
            data: Uncompressed NSIS data

        Prints:
            - Engine information
            - NSIS header details
            - Uncompressed data preview
            - File extraction information
        """
        print("-" * 79)
        kavutil.vprint("Engine")
        kavutil.vprint(None, "Engine", "nsis")
        kavutil.vprint(None, "File name", os.path.split(self.filename)[-1])

        print()
        kavutil.vprint("NSIS")
        kavutil.vprint(None, "Flag", f"{flag}")
        kavutil.vprint(None, "Uncompress Case", f"{case_type}")

        self.print_section_header("Uncompress Data")
        kavutil.HexDump().Buffer(data, 0, 0x80)

        s = self.nsis_header.namelist_ex()
        if len(s):
            self.print_section_header("File Extract")
            for t in s:
                (foff, fname, ftime, extract_type) = t
                print("%08X | %-45s | %s" % (foff, fname, ftime if ftime != "" else "N/A"))

    def print_section_header(self, section_name):
        """
        Prints a formatted section header with empty lines

        Args:
            section_name: Name of the section to display
        """
        print()
        kavutil.vprint(section_name)
        print()

    def namelist(self):
        return self.nsis_header.namelist()

    def read(self, filename):
        if filename not in self.nsis_header.files:
            return None
        data = None
        (foff, ftime, extract_type) = self.nsis_header.files[filename]

        if self.case_type == 1:  # case 1: Compressing the entire installation file
            fsize = kavutil.get_uint32(self.body_data, foff) & 0x7FFFFFFF
            return self.body_data[foff + 4 : foff + 4 + fsize]

        elif self.case_type == 2:  # case 2: Compressing individually
            fsize = kavutil.get_uint32(self.body_data, foff) & 0x7FFFFFFF
            fdata = self.body_data[foff + 4 : foff + 4 + fsize]
            comp_type = self.check_compression_type(kavutil.get_uint32(fdata, 0))

            if comp_type == self.TYPE_LZMA:
                if HAS_PYLZMA:
                    with contextlib.suppress(TypeError):
                        stream = BytesIO(fdata)
                        obj = pylzma.decompressobj()
                        data = b""

                        while chunk := stream.read(1024):
                            data += obj.decompress(chunk)

                        data += obj.flush()  # Process remaining data
            elif comp_type == self.TYPE_ZLIB:
                if kavutil.get_uint32(self.body_data, foff) & 0x80000000 == 0x80000000:
                    with contextlib.suppress(zlib.error):
                        data = zlib.decompress(fdata, -15)
                else:
                    data = fdata  # TYPE_COPY
        return data

    def close(self):
        if self.mm:
            self.mm.close()
            self.mm = None

        if self.fp:
            self.fp.close()
            self.fp = None

    def get_data(self):
        # NSIS appears to have two types

        # 1. Compressing the entire installation file
        with contextlib.suppress(struct.error):
            head_size = kavutil.get_uint32(self.mm, 0x14)
            comp_size = kavutil.get_uint32(self.mm, 0x18)
            comp_type = self.check_compression_type(kavutil.get_uint32(self.mm, 0x1C))
            if uncmp_data := self.do_decompress(comp_type, 0x1C, comp_size):
                if head_size == kavutil.get_uint32(uncmp_data, 0):
                    self.nsis_header = NSISHeader(uncmp_data[4 : head_size + 4])
                    if self.nsis_header.parse():
                        return uncmp_data[head_size + 4 :], 1

        # case 2: Compressing individually
        with contextlib.suppress(struct.error):
            head_size = kavutil.get_uint32(self.mm, 0x14)
            comp_size = kavutil.get_uint32(self.mm, 0x1C) & 0x7FFFFFFF
            comp_type = self.check_compression_type(kavutil.get_uint32(self.mm, 0x20))
            if uncmp_data := self.do_decompress(comp_type, 0x20, comp_size):
                if head_size == len(uncmp_data):
                    self.nsis_header = NSISHeader(uncmp_data)
                    if self.nsis_header.parse():
                        return self.mm[0x20 + comp_size :], 2

        return None, 0

    def do_decompress(self, comp_type, off, size):
        comp_success = True
        if comp_type == self.TYPE_LZMA:
            if not HAS_PYLZMA:
                comp_success = False
            else:
                try:  # Check if it is compressed
                    stream = BytesIO(self.mm[off : off + size])
                    obj = pylzma.decompressobj()
                    uncmp_data = b""

                    while chunk := stream.read(1024):  # Read 1024 bytes at a time
                        uncmp_data += obj.decompress(chunk)

                    uncmp_data += obj.flush()  # Process remaining data
                except TypeError:
                    comp_success = False
        elif comp_type == self.TYPE_ZLIB:
            try:  # Check if it is compressed
                uncmp_data = zlib.decompress(self.mm[off : off + size], -15)
            except zlib.error:
                comp_success = False
        else:
            uncmp_data = None
            comp_success = False

        if comp_success:
            return uncmp_data

    def check_compression_type(self, data_size):
        """
        Determines the compression type based on data size value

        Args:
            data_size: Size value from NSIS header

        Returns:
            Compression type (LZMA, BZIP2, or ZLIB)
        """
        if data_size & 0x7FFFFFFF == 0x5D:
            return self.TYPE_LZMA
        if data_size & 0xFF == 0x31:
            return self.TYPE_BZIP2
        return self.TYPE_ZLIB

    def __del(self):
        self.close()

        if self.temp_name:
            os.unlink(self.temp_name)


class NSISHeader:
    def __init__(self, data):
        self.mm = data
        self.header_data = None

        self.nh = None
        self.strings_max = 0
        self.ver3 = None
        self.is_unicode = 0  # 1: str, 2:unicode

        # # nsis-2.09-src
        self.ns_skip_code = 252  # 0xfc : to consider next character as a normal character
        self.ns_var_code = 253  # 0xfd : for a variable
        self.ns_shell_code = 254  # 0xfe : for a shell folder path
        self.ns_lang_code = 255  # 0xff : for a langstring

        self.ns_codes_start = 0

        self.files = {}
        self.success = False

    def __set_value(self):
        # Is it a Unicode data set?
        if self.header_data[self.nh.strings : self.nh.strings + 2] == b"\x00\x00":
            self.is_unicode = 2  # Unicode is correct
        else:
            self.is_unicode = 1

        self.strings_max = self.nh.langtables - self.nh.strings  # Maximum string length

        # Check the specific location of the data area in the NSIS header to see if it is Ver3
        off = self.nh.strings + (0x11 * self.is_unicode)
        d = self.header_data[off : off + (14 * self.is_unicode)]

        self.ver3 = self.__binary_unicode_to_str(d) == b"CommonFilesDir"

        if self.ver3:
            self.ns_skip_code = -self.ns_skip_code & 0xFF
            self.ns_var_code = -self.ns_var_code & 0xFF
            self.ns_shell_code = -self.ns_shell_code & 0xFF
            self.ns_lang_code = -self.ns_lang_code & 0xFF
        # end if

        self.ns_codes_start = self.ns_skip_code

        self.__processentries()

    def __binary_str_to_unicode(self, s):
        if self.is_unicode == 2:
            s = s.decode("cp949", errors="replace").encode("utf-16", errors="replace")

        return s

    def __binary_unicode_to_str(self, us):
        if self.is_unicode == 2:
            us = us.decode("utf-16", errors="replace").encode("cp949", errors="replace")

        return us

    def __get_user_var_name(self, n_data):
        if n_data < 0:
            return self.__get_string(n_data)

        static_user_vars = len(NsisVarNames)
        if n_data in range(static_user_vars):
            return f"${NsisVarNames[n_data]}".encode("utf-8")
        else:
            return "$%d".encode("utf-8") % (n_data - static_user_vars)

    def __decode_short(self, off):
        a = int(self.header_data[off])
        b = int(self.header_data[off + 1])

        return ((b & ~0x80) << 7) | (a & ~0x80)

    def __get_string(self, str_off):
        if str_off < 0:
            off = self.nh.langtables + 2 + 4 + -str_off * 4
            str_off = kavutil.get_uint32(self.header_data, off)

        if (str_off * self.is_unicode) in range(self.strings_max):
            return self.__decode_nsis_string(str_off)
        else:
            return ""

    def __decode_nsis_string(self, str_off):
        """
        Decodes a NSIS string from the given offset

        Args:
            str_off: Offset to the string in the header data

        Returns:
            Decoded string with variables expanded

        Handles:
            - Unicode/ASCII string decoding
            - Variable code expansion
            - Special character handling
        """
        str_data = b""
        off = self.nh.strings + (str_off * self.is_unicode)

        char = self.header_data[off : off + (1 * self.is_unicode)]
        off += 1 * self.is_unicode

        while char != b"\x00" * self.is_unicode and len(char) != 0:
            ch = struct.unpack("<H", char)[0] if self.is_unicode == 2 else int.from_bytes(char, byteorder="little")
            # print(off, ch, self.ns_var_code, char)

            if (ch >= self.ns_codes_start) if self.ver3 else (ch < self.ns_codes_start):
                str_data += char

            elif ch == self.ns_var_code:
                n_data = self.__decode_short(off)
                off += 2
                str_data += self.__binary_str_to_unicode(self.__get_user_var_name(n_data))

            char = self.header_data[off : off + (1 * self.is_unicode)]
            off += 1 * self.is_unicode

        str_data = self.__binary_unicode_to_str(str_data)
        return str_data

    def __processentries(self):
        off = self.nh.entries

        for _ in range(self.nh.entries_num):
            # nr = StructNsisRecord()
            # memmove(addressof(nr), self.header_data[off:], sizeof(nr))
            # off += sizeof(nr)  # 28Byte

            val = self.header_data[off : off + 4]

            # if nr.which == 20:  # EW_EXTRACTFILE
            if val == b"\x14\x00\x00\x00":
                nr = StructNsisRecord()
                memmove(addressof(nr), self.header_data[off:], sizeof(nr))

                dt = ""
                with contextlib.suppress(Exception):
                    ft_dec = struct.unpack(">Q", struct.pack(">ll", nr.parm4, nr.parm3))[0]

                    # UnixTimeToFileTime http://support.microsoft.com/kb/167296
                    dt = datetime.datetime.fromtimestamp((ft_dec - 116444736000000000) // 10000000)

                file_name = self.__get_string(nr.parm1).replace(b"\\", b"/")
                self.files[file_name.decode("utf-8")] = nr.parm2, dt, nr.which

            elif val == b"\x3e\x00\x00\x00":
                nr = StructNsisRecord()
                memmove(addressof(nr), self.header_data[off:], sizeof(nr))

                file_name = self.__get_string(nr.parm0).replace(b"\\", b"/")
                # print hex(nr.parm2)
                # print hex(nr.parm3)
                # print hex(nr.parm4)
                # print hex(nr.parm5)

                self.files[file_name.decode("utf-8")] = nr.parm1, "", nr.which

            off += 28

    def parse(self):
        if self.header_data:  # If already analyzed, do not analyze
            return self.success

        self.header_data = self.mm

        self.nh = StructNsisHeader()  # Read the header
        memmove(addressof(self.nh), self.header_data[:], sizeof(self.nh))

        self.__set_value()  # Set important values

        self.success = True
        return self.success

    def namelist(self):
        return self.files.keys()

    def namelist_ex(self):
        fl = []

        for filename in self.files.keys():
            (file_offset, file_time, extract_type) = self.files[filename]
            fl.append((file_offset, filename, file_time, extract_type))

        fl.sort()
        return fl


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """NSIS archive handler plugin.

    This plugin provides functionality for:
    - Detecting NSIS (Nullsoft Scriptable Install System) format
    - Listing files within NSIS installers
    - Extracting files from NSIS installers
    """

    def __init__(self):
        """Initialize the NSIS plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="NSIS Engine",
            kmd_name="nsis",
        )

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["make_arc_type"] = kernel.MASTER_DELETE
        return info

    def __get_handle(self, filename, offset=0):
        """Get or create handle for NSIS file.

        Args:
            filename: Path to NSIS file
            offset: Offset within file

        Returns:
            NSIS object or None
        """
        if filename in self.handle:
            return self.handle.get(filename, None)

        try:
            zfile = NSIS(filename, offset, self.verbose)
            if zfile.parse():
                self.handle[filename] = zfile
                return zfile

        except (IOError, OSError) as e:
            logger.debug("Failed to open NSIS file %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error opening NSIS file %s: %s", filename, e)

        return None

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive.

        Args:
            filename: Path to archive file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_nsis" not in fileformat:
            return file_scan_list

        try:
            off = fileformat["ff_nsis"]["Offset"]
            zfile = self.__get_handle(filename, off)
            if zfile is None:
                return file_scan_list

            for name in zfile.namelist():
                # CWE-22: Path traversal prevention
                if k2security.is_safe_archive_member(name):
                    file_scan_list.append(["arc_nsis", name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_nsis')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_nsis":
            return None

        try:
            zfile = self.__get_handle(arc_name)
            if zfile is None:
                return None

            return zfile.read(fname_in_arc)

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create an NSIS archive.

        Note: NSIS cannot be re-compressed, so this only marks for deletion.

        Args:
            arc_engine_id: Engine ID ('arc_nsis')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_nsis":
            return False

        try:
            # NSIS cannot be re-compressed, so it must be deleted
            return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                zfile = self.handle.get(fname)
                if zfile:
                    zfile.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
