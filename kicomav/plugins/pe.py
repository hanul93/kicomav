# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

# ref: https://github.com/lifenjoiner/ISx

"""
PE File Format Engine Plugin

This plugin handles PE (Portable Executable) format for scanning and analysis.
It also provides resource extraction capabilities.
"""

import binascii
import contextlib
import ctypes
import logging
import os
import re
import struct
import zlib

from kicomav.plugins import cryptolib
from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

BYTE = ctypes.c_ubyte
WORD = ctypes.c_ushort
DWORD = ctypes.c_uint
FLOAT = ctypes.c_float
LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
LPTSTR = ctypes.POINTER(ctypes.c_char)
HANDLE = ctypes.c_void_p
PVOID = ctypes.c_void_p
LPVOID = ctypes.c_void_p
UINT_PTR = ctypes.c_uint
SIZE_T = ctypes.c_uint


class DOS_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("e_magic", WORD),
        ("e_cblp", WORD),
        ("e_cp", WORD),
        ("e_crlc", WORD),
        ("e_cparhdr", WORD),
        ("e_minalloc", WORD),
        ("e_maxalloc", WORD),
        ("e_ss", WORD),
        ("e_sp", WORD),
        ("e_csum", WORD),
        ("e_ip", WORD),
        ("e_cs", WORD),
        ("e_lfarlc", WORD),
        ("e_ovno", WORD),
        ("e_res", BYTE * 8),  # 8Byte
        ("e_oemid", WORD),
        ("e_oeminfo", WORD),
        ("e_res2", BYTE * 20),  # 20Byte
        ("e_lfanew", DWORD),
    ]


class FILE_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Machine", WORD),
        ("NumberOfSections", WORD),
        ("CreationYear", DWORD),
        ("PointerToSymbolTable", DWORD),
        ("NumberOfSymbols", DWORD),
        ("SizeOfOptionalHeader", WORD),
        ("Characteristics", WORD),
    ]


class OPTIONAL_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Magic", WORD),
        ("MajorLinkerVersion", BYTE),
        ("MinorLinkerVersion", BYTE),
        ("SizeOfCode", DWORD),
        ("SizeOfInitializedData", DWORD),
        ("SizeOfUninitializedData", DWORD),
        ("AddressOfEntryPoint", DWORD),
        ("BaseOfCode", DWORD),
        ("BaseOfData", DWORD),
        ("ImageBase", DWORD),
        ("SectionAlignment", DWORD),
        ("FileAlignment", DWORD),
        ("MajorOperatingSystemVersion", WORD),
        ("MinorOperatingSystemVersion", WORD),
        ("MajorImageVersion", WORD),
        ("MinorImageVersion", WORD),
        ("MajorSubsystemVersion", WORD),
        ("MinorSubsystemVersion", WORD),
        ("Reserved1", DWORD),
        ("SizeOfImage", DWORD),
        ("SizeOfHeaders", DWORD),
        ("CheckSum", DWORD),
        ("Subsystem", WORD),
        ("DllCharacteristics", WORD),
        ("SizeOfStackReserve", DWORD),
        ("SizeOfStackCommit", DWORD),
        ("SizeOfHeapReserve", DWORD),
        ("SizeOfHeapCommit", DWORD),
        ("LoaderFlags", DWORD),
        ("NumberOfRvaAndSizes", DWORD),
    ]


class DATA_DIRECTORY(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("VirtualAddress", DWORD),
        ("Size", DWORD),
    ]


class SECTION_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Name", BYTE * 8),
        ("Misc_VirtualSize", DWORD),
        ("VirtualAddress", DWORD),
        ("SizeOfRawData", DWORD),
        ("PointerToRawData", DWORD),
        ("PointerToRelocations", DWORD),
        ("PointerToLinenumbers", DWORD),
        ("NumberOfRelocations", WORD),
        ("NumberOfLinenumbers", WORD),
        ("Characteristics", DWORD),
    ]


def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = {value: key for key, value in enums.items()}
    enums["reverse_mapping"] = reverse
    return type("Enum", (), enums)


image_directory_entry = enum(
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "COPYRIGHT",  # Architecture on non-x86 platforms
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "COM_DESCRIPTOR",
    "RESERVED",
)


p_str = re.compile(rb"[^\x00]*")  # Copy up to the NULL character


class PE:
    def __init__(self, mm, verbose, filename):
        self.filename = filename
        self.filesize = os.path.getsize(filename)
        self.verbose = verbose
        self.mm = mm
        self.sections = []  # List to hold all section information
        self.data_directories = []  # List to hold all data directory information
        self.pe_file_align = 0

    # -------------------------------------------------------------------------
    # parse(mm)
    # Parse the PE file and return the main information.
    # Input : mm - File handle
    # Return : {PE file analysis information} or None
    # -------------------------------------------------------------------------
    def parse(self):
        pe_format = {
            "PE_Position": 0,
            "EntryPoint": 0,
            "SectionNumber": 0,
            "Sections": None,
            "EntryPointRaw": 0,
            "FileAlignment": 0,
        }

        mm = self.mm
        with contextlib.suppress(ValueError, struct.error):
            self.parse_pe_parse(mm, pe_format)
            return pe_format

        return None

    def parse_pe_parse(self, mm, pe_format):
        if mm[:2] != b"MZ":  # Does it start with MZ?
            raise ValueError

        dos_header = DOS_HEADER()
        ctypes.memmove(ctypes.addressof(dos_header), mm[:], ctypes.sizeof(dos_header))

        # Get the position of the PE signature
        pe_pos = dos_header.e_lfanew

        # Is it a PE file?
        if mm[pe_pos : pe_pos + 4] != b"PE\x00\x00":
            raise ValueError

        pe_format["PE_Position"] = pe_pos

        # Read the File Header
        file_header = FILE_HEADER()
        file_header_size = ctypes.sizeof(file_header)  # file_header_size : 0x14
        ctypes.memmove(ctypes.addressof(file_header), mm[pe_pos + 4 :], file_header_size)

        # Read the Optional Header
        optional_header = OPTIONAL_HEADER()
        optional_header_size = ctypes.sizeof(optional_header)
        ctypes.memmove(
            ctypes.addressof(optional_header),
            mm[pe_pos + 4 + file_header_size :],
            optional_header_size,
        )

        # Is the Magic ID of the Optional Header correct?
        if optional_header.Magic != 0x10B:
            raise ValueError

        # Get the Entry Point
        pe_ep = optional_header.AddressOfEntryPoint
        pe_format["EntryPoint"] = pe_ep

        # Get the Image Base
        pe_img = optional_header.ImageBase
        pe_format["ImageBase"] = pe_img

        # Get the File Alignment
        self.pe_file_align = optional_header.FileAlignment
        pe_format["FileAlignment"] = self.pe_file_align

        # Get the number of sections
        section_num = file_header.NumberOfSections
        pe_format["SectionNumber"] = section_num

        # Get the size of the Optional Header
        opthdr_size = file_header.SizeOfOptionalHeader
        pe_format["OptionalHederSize"] = opthdr_size

        # Read the Data Directory
        data_directory_size = ctypes.sizeof(DATA_DIRECTORY())  # data_directory_size : 8
        num_data_directory = (opthdr_size - optional_header_size) // data_directory_size
        off_data_directory = pe_pos + 4 + file_header_size + optional_header_size

        for i in range(num_data_directory):
            dx = DATA_DIRECTORY()
            ctypes.memmove(
                ctypes.addressof(dx),
                mm[off_data_directory + (i * data_directory_size) :],
                data_directory_size,
            )

            self.data_directories.append(dx)

        # Start position of the section
        section_pos = pe_pos + 4 + file_header_size + opthdr_size

        # Extract all section information
        for i in range(section_num):
            section_header = SECTION_HEADER()
            section_header_size = ctypes.sizeof(section_header)  # section_header_size : 0x28

            s = section_pos + (section_header_size * i)
            ctypes.memmove(ctypes.addressof(section_header), mm[s:], section_header_size)

            sec_name = ctypes.cast(section_header.Name, ctypes.c_char_p)
            section = {
                "Name": sec_name.value,
                "VirtualSize": section_header.Misc_VirtualSize,
                "RVA": section_header.VirtualAddress,
                "SizeRawData": section_header.SizeOfRawData,
                "PointerRawData": section_header.PointerToRawData,
                "Characteristics": section_header.Characteristics,
            }
            self.sections.append(section)

        pe_format["Sections"] = self.sections

        # Get the position of the EntryPoint in the file
        ep_raw, sec_idx = self.rva_to_off(pe_ep)
        pe_format["EntryPointRaw"] = ep_raw  # Raw position of the EP
        pe_format["EntryPoint_in_Section"] = sec_idx  # Section containing the EP

        # Analyze resources
        try:
            rsrc_rva = self.data_directories[image_directory_entry.RESOURCE].VirtualAddress
            rsrc_size = self.data_directories[image_directory_entry.RESOURCE].Size
        except IndexError:
            rsrc_rva = 0
            rsrc_size = 0

        if rsrc_rva:  # Does the resource exist?
            # with contextlib.suppress(struct.error, ValueError):
            self.parse_pe_resources(rsrc_rva, mm, rsrc_size, pe_format)

        # Analyze import API
        try:
            imp_rva = self.data_directories[image_directory_entry.IMPORT].VirtualAddress  # Import API location (RVA)
            imp_size = self.data_directories[image_directory_entry.IMPORT].Size  # Import API size
        except IndexError:
            imp_rva = 0
            imp_size = 0

        if imp_rva:  # Import API exists
            imp_api = {}

            imp_off = self.rva_to_off(imp_rva)[0]
            imp_data = mm[imp_off : imp_off + imp_size]

            if len(imp_data) == imp_size:
                for i in range(imp_size // 0x14):  # DLL information size is 0x14
                    with contextlib.suppress(struct.error):
                        dll_rva = kavutil.get_uint32(imp_data, (i * 0x14) + 0xC)
                        api_rva = kavutil.get_uint32(imp_data, (i * 0x14))
                        bo = 2
                        if api_rva == 0:
                            api_rva = kavutil.get_uint32(imp_data, (i * 0x14) + 0x10)
                            bo = 0

                        # print (hex(api_rva))
                        if dll_rva == 0:  # DLL information is missing
                            break

                        t_off = self.rva_to_off(dll_rva)[0]
                        dll_name = p_str.search(mm[t_off : t_off + 0x20]).group()
                        # print ('[+]', dll_name)
                        imp_api[dll_name] = []

                        t_off = self.rva_to_off(api_rva)[0]
                        while True:
                            try:
                                api_name_rva = kavutil.get_uint32(mm, t_off)
                            except struct.error:
                                break

                            if api_name_rva & 0x80000000 == 0x80000000:  # Odinal API
                                t_off += 4
                                continue

                            if api_name_rva == 0:
                                break

                            t = self.rva_to_off(api_name_rva)[0]
                            # print (hex(t_off), hex(t))
                            api_name = p_str.search(mm[t + bo : t + bo + 0x20]).group()
                            # print ('   ', api_name)
                            imp_api[dll_name].append(api_name)
                            t_off += 4
            # end if

            pe_format["Import_API"] = imp_api

        # Analyze digital certificate
        try:
            cert_off = self.data_directories[
                image_directory_entry.SECURITY
            ].VirtualAddress  # The only offset that is not RVA
            cert_size = self.data_directories[image_directory_entry.SECURITY].Size  # Digital certificate size
        except IndexError:
            cert_off = 0
            cert_size = 0

        # Digital certificate exists and UPack's case, an unusual value is set
        if cert_off and cert_off + cert_size <= len(mm[:]):
            pe_format["CERTIFICATE_Offset"] = cert_off
            pe_format["CERTIFICATE_Size"] = cert_size

        # Analyze debug information
        try:
            debug_rva = self.data_directories[image_directory_entry.DEBUG].VirtualAddress  # RVA
            debug_size = self.data_directories[image_directory_entry.DEBUG].Size  # Size
            if debug_size < 0x1C:
                raise ValueError
        except (IndexError, ValueError) as e:
            debug_rva = 0
            debug_size = 0

        if debug_rva:  # Debug information exists
            t = self.rva_to_off(debug_rva)[0]
            debug_off = kavutil.get_uint32(mm, t + 0x18)
            debug_size = kavutil.get_uint32(mm, t + 0x10)

            debug_data = mm[debug_off : debug_off + debug_size]

            if debug_data[:4] == b"RSDS":
                pe_format["PDB_Name"] = debug_data[0x18:]
            else:
                pe_format["PDB_Name"] = b"Not support Type : " + debug_data[:4]

        if self.verbose:
            self.print_pe_debug_info(mm, pe_format, section_num)

    # Print PE debug information
    def print_pe_debug_info(self, mm, pe_format, section_num):
        print("-" * 79)
        kavutil.vprint("Engine")
        kavutil.vprint(None, "Engine", "pe")
        kavutil.vprint(None, "File name", os.path.split(self.filename)[-1])
        kavutil.vprint(None, "MD5", cryptolib.md5(mm[:]))

        print()
        kavutil.vprint("PE")
        kavutil.vprint(None, "EntryPoint", "%08X" % pe_format["EntryPoint"])
        kavutil.vprint(
            None,
            "EntryPoint (Section)",
            "%d" % pe_format["EntryPoint_in_Section"],
        )

        # View sections
        if section_num:
            print()
            kavutil.vprint("Section Header")
            print("    %-8s %-8s %-8s %-8s %-8s %-8s" % ("Name", "VOFF", "VSIZE", "FOFF", "FSIZE", "EXEC"))
            print("    " + ("-" * (9 * 6 - 1)))

            for s in self.sections:
                print(
                    "    %-8s %08X %08X %08X %08X %-05s"
                    % (
                        s["Name"],
                        s["RVA"],
                        s["VirtualSize"],
                        s["PointerRawData"],
                        s["SizeRawData"],
                        s["Characteristics"] & 0x20000000 == 0x20000000,
                    )
                )

        if section_num:
            print()
            kavutil.vprint("Section MD5")
            print("    %-8s %-8s %-32s" % ("Name", "FSIZE", "MD5"))
            print("    " + ("-" * ((9 * 2 - 1) + 32)))

            for s in self.sections:
                off = s["PointerRawData"]
                size = s["SizeRawData"]
                fmd5 = cryptolib.md5(mm[off : off + size]) if size else "-"
                print("    %-8s %8d %s" % (s["Name"], size, fmd5))

        print()
        kavutil.vprint("Entry Point (Raw)")
        print()
        kavutil.HexDump().Buffer(mm[:], pe_format["EntryPointRaw"], 0x80)
        print()
        if "PDB_Name" in pe_format:
            kavutil.vprint("PDB Information")
            kavutil.vprint(None, "Name", f'{repr(pe_format["PDB_Name"])}')
            print(repr(pe_format["PDB_Name"]))
            print()

    def parse_pe_resources(self, rsrc_rva, mm, rsrc_size, pe_format):
        rsrc_off, rsrc_idx = self.rva_to_off(rsrc_rva)  # Convert resource position

        if rsrc_off > self.filesize:
            raise ValueError

        t_size = self.sections[rsrc_idx]["SizeRawData"]
        if len(mm[rsrc_off : rsrc_off + rsrc_size]) != rsrc_size and len(mm[rsrc_off : rsrc_off + t_size]) != t_size:
            raise ValueError

        # Check the type
        num_type_name = kavutil.get_uint16(mm, rsrc_off + 0xC)
        num_type_id = kavutil.get_uint16(mm, rsrc_off + 0xE)

        for i in range(num_type_name + num_type_id):
            type_id = kavutil.get_uint32(mm, rsrc_off + 0x10 + (i * 8))
            name_id_off = kavutil.get_uint32(mm, rsrc_off + 0x14 + (i * 8))

            # Type is user-defined name or RCDATA?
            if type_id & 0x80000000 == 0x80000000 or type_id == 0xA or type_id == 0:
                if type_id & 0x80000000 == 0x80000000:
                    # Extract the user-defined name
                    string_off = (type_id & 0x7FFFFFFF) + rsrc_off
                    len_name = kavutil.get_uint16(mm, string_off)
                    rsrc_type_name = mm[string_off + 2 : string_off + 2 + (len_name * 2) : 2].decode("utf-8")
                elif type_id == 0xA:
                    rsrc_type_name = "RCDATA"
                else:
                    rsrc_type_name = f"{type_id}"

                # Name ID
                name_id_off = (name_id_off & 0x7FFFFFFF) + rsrc_off
                if name_id_off > self.filesize:
                    raise ValueError

                num_name_id_name = kavutil.get_uint16(mm, name_id_off + 0xC)
                num_name_id_id = kavutil.get_uint16(mm, name_id_off + 0xE)

                for j in range(num_name_id_name + num_name_id_id):
                    name_id_id = kavutil.get_uint32(mm, name_id_off + 0x10 + (j * 8))
                    language_off = kavutil.get_uint32(mm, name_id_off + 0x14 + (j * 8))

                    if name_id_id & 0x80000000 == 0x80000000:
                        string_off = (name_id_id & 0x7FFFFFFF) + rsrc_off
                        if string_off > self.filesize:
                            raise ValueError

                        len_name = kavutil.get_uint16(mm, string_off)
                        rsrc_name_id_name = mm[string_off + 2 : string_off + 2 + (len_name * 2) : 2]
                        string_name = f"{rsrc_type_name}/{rsrc_name_id_name.decode('utf-8')}"
                    else:
                        string_name = f"{rsrc_type_name}/{hex(name_id_id).upper()[2:]}"

                    # Language
                    language_off = (language_off & 0x7FFFFFFF) + rsrc_off
                    if language_off > self.filesize:
                        raise ValueError

                    num_language_name = kavutil.get_uint16(mm, language_off + 0xC)
                    num_language_id = kavutil.get_uint16(mm, language_off + 0xE)

                    for k in range(num_language_name + num_language_id):
                        data_entry_off = kavutil.get_uint32(mm, language_off + 0x14 + (k * 8))
                        data_entry_off = (data_entry_off & 0x7FFFFFFF) + rsrc_off

                        data_rva = kavutil.get_uint32(mm, data_entry_off)
                        data_off, _ = self.rva_to_off(data_rva)
                        if data_off > self.filesize:
                            continue

                        data_size = kavutil.get_uint32(mm, data_entry_off + 4)
                        if data_size > self.filesize:
                            continue

                        if data_size > 8192:  # Extract only resources of at least 8K
                            if "Resource_UserData" in pe_format:
                                pe_format["Resource_UserData"][string_name] = (data_off, data_size)
                            else:
                                pe_format["Resource_UserData"] = {string_name: (data_off, data_size)}

    def rva_to_off(self, t_rva):
        for section in self.sections:
            size = section["SizeRawData"]
            rva = section["RVA"]

            if rva <= t_rva < rva + size:
                if self.pe_file_align:
                    foff = (section["PointerRawData"] // self.pe_file_align) * self.pe_file_align
                else:
                    foff = section["PointerRawData"]
                t_off = t_rva - rva + foff

                return t_off, self.sections.index(section)

        return t_rva, -1  # If not associated with any section, return RVA


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """PE file format handler plugin.

    This plugin provides functionality for:
    - Detecting PE (Portable Executable) format
    - Parsing PE headers, sections, and resources
    - Detecting NSIS, InstallShield installers
    - Extracting resources from PE files
    """

    def __init__(self):
        """Initialize the PE plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.2",
            title="PE Engine",
            kmd_name="pe",
        )
        self.p_nsis = None

    def _custom_init(self) -> int:
        """Custom initialization for PE plugin.

        Returns:
            0 for success
        """
        # NSIS code pattern
        # 81 7D DC EF BE AD DE    cmp     [ebp+var_24], 0DEADBEEFh
        # 75 69                   jnz     short loc_402D79
        # 81 7D E8 49 6E 73 74    cmp     [ebp+var_18], 'tsnI'
        # ...
        self.p_nsis = re.compile(
            r"81 7D .. EF BE AD DE 75 .. 81 7D .. 49 6E 73 74 75 .. 81 7D .. 73 6F 66 74 75 .. 81 7D .. 4E 75 6C 6C 75".replace(
                " ", ""
            ),
            re.IGNORECASE,
        )
        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["make_arc_type"] = kernel.MASTER_DELETE
        return info

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect PE format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        ret = {}

        try:
            pe = PE(filehandle, self.verbose, filename)
            try:
                pe_format = pe.parse()
            except MemoryError:
                pe_format = None

            if pe_format is None:
                return None

            fileformat = {"pe": pe_format}
            ret = {"ff_pe": fileformat}

            # Check if there is additional information at the end of the PE file
            pe_size = 0
            last_section_off = 0

            pe_file_align = pe_format["FileAlignment"]

            for sec in pe_format.get("Sections", []):
                if pe_file_align:
                    off = (sec["PointerRawData"] // pe_file_align) * pe_file_align
                else:
                    off = sec["PointerRawData"]
                size = sec["SizeRawData"]
                pe_size = max(pe_size, off + size)
                last_section_off = pe_size

            file_size = len(filehandle)

            if "CERTIFICATE_Offset" in pe_format:
                if pe_format["CERTIFICATE_Offset"] == pe_size:
                    t_pe_size = pe_format["CERTIFICATE_Offset"] + pe_format["CERTIFICATE_Size"]
                    pe_size = max(pe_size, t_pe_size)
                    attach_size = file_size - pe_size
                else:
                    attach_size = file_size - pe_size - pe_format["CERTIFICATE_Size"]
            else:
                attach_size = file_size - pe_size

            if pe_size < file_size and pe_size != 0:
                mm = filehandle
                self._detect_installers(mm, pe_format, pe_file_align, pe_size, last_section_off, attach_size, ret)

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return ret if ret else None

    def _detect_installers(self, mm, pe_format, pe_file_align, pe_size, last_section_off, attach_size, ret):
        """Detect various installer formats in PE file.

        Args:
            mm: File data
            pe_format: Parsed PE format info
            pe_file_align: PE file alignment
            pe_size: PE file size
            last_section_off: Last section offset
            attach_size: Attached data size
            ret: Result dictionary to update
        """
        # Check if NSIS code exists in the .text section
        text_sec = pe_format["Sections"][0]
        if pe_file_align:
            off = (text_sec["PointerRawData"] // pe_file_align) * pe_file_align
        else:
            off = text_sec["PointerRawData"]
        size = text_sec["SizeRawData"]

        # Process NSIS
        hex_data = binascii.hexlify(mm[off : off + size]).decode()
        if self.p_nsis and self.p_nsis.search(hex_data):
            i = 1
            while True:
                t = mm[i * 0x200 + 4 : i * 0x200 + 20]
                if len(t) != 16:
                    break

                if t == b"\xEF\xBE\xAD\xDENullsoftInst":
                    ret["ff_nsis"] = {"Offset": i * 0x200}
                    break

                i += 1

        # Process InstallShield
        ishield_header = mm[-0x30:]
        if ishield_header[0x18:0x1C] == b"\x01\x91\x48\x48":
            if mm[last_section_off : last_section_off + 14] == b"InstallShield\x00":
                version = "2.0"  # INI file based InstallShield
            else:
                version = "x.x"  # CAB based InstallShield

            ret["ff_installshield"] = {
                "Header": ishield_header,
                "Attached_Pos": last_section_off,
                "Version": version,
            }

        # Process InstallShield for InstallStream
        if mm[last_section_off : last_section_off + 14] == b"ISSetupStream\x00":
            ret["ff_installshield_setup_stream"] = {
                "Attached_Pos": last_section_off,
            }

        # Process InstallShield embedded setup.exe
        ishield_embedded_file_header = mm[-712:]
        decrypted = cryptolib.ishield_decrypt(ishield_embedded_file_header, b"%eR@toPm|<#YKs$^")
        v1 = kavutil.get_uint32(decrypted, 668)
        v2 = kavutil.get_uint32(decrypted, 12)
        file_name_size = kavutil.get_uint32(decrypted, 144)
        crc32_value = kavutil.get_uint32(decrypted, 704)

        if v1 <= 0x20 and v2 <= 0x40 and file_name_size <= 0x104:
            decrypted = cryptolib.reset_padding(decrypted, 668, v1, 0x20)
            decrypted = cryptolib.reset_padding(decrypted, 12, v2, 0x40)
            decrypted = cryptolib.reset_padding(decrypted, 144, file_name_size, 0x104)
            crc32_value_calculated = int(zlib.crc32(decrypted[:704]) & 0xFFFFFFFF)

            if crc32_value == crc32_value_calculated:
                ret["ff_installshield_embedded_file"] = {
                    "Embedded_File_Pos": pe_size,
                    "Embedded_File_Size": file_name_size,
                }

        # Process attachments (do not process if NSIS or InstallShield exists)
        if (
            "ff_nsis" not in ret
            and "ff_installshield" not in ret
            and "ff_installshield_embedded_file" not in ret
            and "ff_installshield_setup_stream" not in ret
        ):
            fileformat = {
                "Attached_Pos": pe_size,
                "Attached_Size": attach_size,
            }
            ret["ff_attach"] = fileformat

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive (PE resources).

        Args:
            filename: Path to PE file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        try:
            if "ff_pe" in fileformat and "Resource_UserData" in fileformat["ff_pe"]["pe"]:
                for key in fileformat["ff_pe"]["pe"]["Resource_UserData"].keys():
                    off, size = fileformat["ff_pe"]["pe"]["Resource_UserData"][key]
                    file_scan_list.append(["arc_pe_rcdata:%d:%d" % (off, size), key])

        except (KeyError, TypeError) as e:
            logger.debug("Archive list error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing resources in %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive (PE resource).

        Args:
            arc_engine_id: Engine ID (format: 'arc_pe_rcdata:offset:size')
            arc_name: Path to PE file
            fname_in_arc: Name of resource to extract

        Returns:
            Extracted file data, or None on error
        """
        if arc_engine_id.find("arc_pe_rcdata:") == -1:
            return None

        try:
            t = arc_engine_id.split(":")
            off = int(t[1])
            size = int(t[2])

            with open(arc_name, "rb") as fp:
                fp.seek(off)
                data = fp.read(size)

            return data

        except (IOError, OSError) as e:
            logger.debug("Resource extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except (ValueError, IndexError) as e:
            logger.debug("Resource extract parse error: %s", e)
        except Exception as e:
            logger.warning("Unexpected error extracting resource %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        pass  # No persistent handles to close
