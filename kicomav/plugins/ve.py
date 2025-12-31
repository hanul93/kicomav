# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
Virus Engine Plugin

This plugin handles virus type malware detection using signature patterns.
"""

import contextlib
import logging
import os

from kicomav.plugins import cryptolib
from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Structure of the signature file
# -------------------------------------------------------------------------
# Flag + Word(Offset for the corresponding Flag is always at the 0th position of the 2Byte)
# Flag
# 0 : Start of the file
# 1 : Execution position (DOS-EP)
# 2 : Execution position (PE-EP)
# 3 : Start of each section (PE, ELF, etc.)
# 4 : Start of Attach
# Checksum1 : Flag, Offset, Length, CRC32
# Checksum2 : Flag, Offset, Length, CRC32
# MalwareName
# -------------------------------------------------------------------------
# Example:  0000 F8A8:02, 0000, 0000, XXXXXXXX:02, 0000, 0000, XXXXXXXX:MalwareName
# -------------------------------------------------------------------------


# -------------------------------------------------------------------------
# Pre-create patterns for specific sizes in the given buffer.
# -------------------------------------------------------------------------
def gen_checksums(buf):
    patterns = []

    # First 10 are 6, 7, 8, 9 ... 0xF
    patterns.extend(int(gen_checksum(buf, 0, i), 16) for i in range(1, 0x10))

    # The remaining 15 are 0x10, 0x18, 0x20 ... 0x80
    patterns.extend(int(gen_checksum(buf, 0, i), 16) for i in range(0x10, 0x88, 8))
    return patterns


def gen_checksum(buf, off, size):
    return cryptolib.crc32(buf[off : off + size])


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """Virus malware detector plugin.

    This plugin provides functionality for:
    - Detecting virus type malware using signature patterns
    - CRC32 checksum based detection
    """

    def __init__(self):
        """Initialize the Virus Engine plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Virus Engine",
            kmd_name="ve",
        )
        self.flags_off = {}

    def _load_virus_database(self) -> int:
        """Load virus patterns.

        Returns:
            0 for success
        """
        self.flags_off = {}
        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = kavutil.handle_pattern_vdb.get_sig_num("ve") + 2
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        vlist = kavutil.handle_pattern_vdb.get_sig_vlist("ve")

        vlists = ["Virus.Win32.Small.a", "Virus.Win32.SuperThreat.b"]
        if vlist:
            vlists.extend(kavutil.normal_vname(vname) for vname in vlist)
        vlists.sort()
        return vlists

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
        try:
            self.flags_off = {}
            mm = filehandle

            # Scan for Virus.Win32.Small.a
            ret, vname = self.__scan_virus_win32_small_a(filehandle, fileformat)
            if ret:
                return True, vname, 0, kernel.INFECTED

            flags = [[int(f"0000{mm[:2].hex()}", 16), gen_checksums(mm[:0x80])]]
            self.flags_off[0] = [0]

            # Is there a PE format in the pre-analyzed file format?
            if "ff_pe" in fileformat:
                self.process_pe_flags_and_checksums(fileformat, flags, mm)

            # Is there an attach area?
            if "ff_attach" in fileformat:
                size = fileformat["ff_attach"]["Attached_Size"]
                if size > 0x80:
                    # Flag - 4 : Attach area
                    pos = fileformat["ff_attach"]["Attached_Pos"]
                    flags.append(
                        [
                            int(f"0004{mm[pos : pos + 2].hex()}", 16),
                            gen_checksums(mm[pos : pos + 0x80]),
                        ]
                    )
                    self.flags_off[4] = [pos]

            cs_size = [
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                0xA,
                0xB,
                0xC,
                0xD,
                0xE,
                0xF,
                0x10,
                0x18,
                0x20,
                0x28,
                0x30,
                0x38,
                0x40,
                0x48,
                0x50,
                0x58,
                0x60,
                0x68,
                0x70,
                0x78,
                0x80,
            ]

            if self.verbose:
                self.write_debug_vdb_file(filename, mm, flags, cs_size)

            for flag in flags:
                if p1 := kavutil.handle_pattern_vdb.match_size("ve", flag[0]):
                    for ve_id in p1.keys():
                        for idx in p1[ve_id]:
                            cs1 = kavutil.handle_pattern_vdb.get_cs1(ve_id, idx)

                            cs1_flag = cs1[0]
                            cs1_off = cs1[1]
                            cs1_size = cs1[2]
                            cs1_crc = cs1[3]

                            if flag[0] >> 16 == cs1_flag and cs1_off == 0 and cs1_size in cs_size:
                                i = cs_size.index(cs1_size)

                                if cs1_crc == flag[1][i]:  # Is the first pattern the same?
                                    if vname := self.__scan_cs2(mm, ve_id, idx):
                                        return True, vname, 0, kernel.INFECTED
                            else:
                                buf = self.__get_data_crc32(mm, cs1_flag, cs1_off, cs1_size)
                                if cs1_crc == int(gen_checksum(mm, cs1_off, cs1_size), 16):
                                    if vname := self.__scan_cs2(mm, ve_id, idx):
                                        return True, vname, 0, kernel.INFECTED

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)

        return False, "", -1, kernel.NOT_FOUND

    def process_pe_flags_and_checksums(self, fileformat, flags, mm):
        """Process PE format flags and checksums."""
        # Flag - 2 : PE EP
        ff = fileformat["ff_pe"]
        ep_off = ff["pe"]["EntryPointRaw"]
        flags.append(
            [
                int(f"0002{mm[ep_off : ep_off + 2].hex()}", 16),
                gen_checksums(mm[ep_off : ep_off + 0x80]),
            ]
        )
        self.flags_off[2] = [ep_off]

        # Flag - 3 : Start of each section
        flag3_off = []
        for section in ff["pe"]["Sections"]:
            fsize = section["SizeRawData"]
            foff = section["PointerRawData"]
            flags.append(
                [
                    int(f"0003{mm[foff : foff + 2].hex()}", 16),
                    gen_checksums(mm[foff : foff + 0x80]),
                ]
            )
            flag3_off.append(foff)
        self.flags_off[3] = flag3_off

    def write_debug_vdb_file(self, filename, mm, flags, cs_size):
        """Write debug VDB file in verbose mode."""
        print("-" * 79)
        kavutil.vprint("Engine")
        kavutil.vprint(None, "Engine", "ve")
        kavutil.vprint(None, "File name", os.path.split(filename)[-1])
        kavutil.vprint(None, "MD5", cryptolib.md5(mm[:]))

        print()
        kavutil.vprint("VE")
        vdb_name = f"{os.path.split(filename)[-1]}.vdb"
        kavutil.vprint(None, "VDB File name", vdb_name)

        with open(vdb_name, "w") as fp:
            for flag in flags:
                msg = "Flag : %08x\n" % flag[0]
                fp.write(msg)

                for i, cs in enumerate(flag[1]):
                    msg = "CS = %02x : %08x\n" % (cs_size[i], int(cs))
                    fp.write(msg)
                fp.write("\n")

    def disinfect(self, filename, malware_id):
        """Disinfect malware.

        Args:
            filename: Path to infected file
            malware_id: Malware ID to disinfect

        Returns:
            True if successful, False otherwise
        """
        try:
            if malware_id == 0:
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False

    def __get_data_crc32(self, buf, flag, off, size):
        """Get the crc32 of a specific position."""
        base_offs = self.flags_off.get(flag, [])
        return [int(gen_checksum(buf, base_off + off, size), 16) for base_off in base_offs]

    def __scan_cs2(self, mm, ve_id, idx):
        """Scan for the second pattern."""
        cs2 = kavutil.handle_pattern_vdb.get_cs2(ve_id, idx)
        cs2_flag = cs2[0]
        cs2_off = cs2[1]
        cs2_size = cs2[2]
        cs2_crc = cs2[3]
        vname_id = cs2[4]

        crc32s = self.__get_data_crc32(mm, cs2_flag, cs2_off, cs2_size)
        if cs2_crc in crc32s:  # Pattern match
            if vname := kavutil.handle_pattern_vdb.get_vname(ve_id, vname_id):
                return kavutil.normal_vname(vname)

        return None

    def __scan_virus_win32_small_a(self, mm, fileformat):
        """Scan for Virus.Win32.Small.a."""
        if "ff_pe" in fileformat:
            ff = fileformat["ff_pe"]["pe"]
            ep_off = ff["EntryPointRaw"]

            if cryptolib.crc32(mm[ep_off : ep_off + 12]) == "4d49a25f":
                v_rva = kavutil.get_uint32(mm, ep_off + 12) + 1  # Malware RVA
                v_rva -= ff["ImageBase"]

                # Check if v_rva is a value in the last section.
                sec = ff["Sections"][-1]
                if sec["RVA"] <= v_rva <= sec["RVA"] + sec["VirtualSize"]:
                    pe_file_align = ff["FileAlignment"]
                    if pe_file_align:
                        foff = (sec["PointerRawData"] // pe_file_align) * pe_file_align
                    else:
                        foff = sec["PointerRawData"]

                    v_off = v_rva - sec["RVA"] + foff

                    x = cryptolib.crc32(mm[v_off : v_off + 0x30])
                    if x == "8d964738":
                        return True, "Virus.Win32.Small.a"
                    elif x in ["00000000", "f288b395"]:
                        return True, "Virus.Win32.SuperThreat.b"

        return False, None
