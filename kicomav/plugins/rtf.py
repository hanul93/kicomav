# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
RTF File Format Engine Plugin

This plugin handles RTF format for scanning, malware detection, and extraction.
"""

import contextlib
import logging
import os
import re
from pathlib import Path

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Functions related to extracting objdata
# -------------------------------------------------------------------------
HEX_RE = re.compile(rb"[0-9A-Fa-f]{2}")


# -------------------------------------------------------------------------
# RtfFile class
# -------------------------------------------------------------------------
class RtfFile:
    def __init__(self, filename, verbose=False):
        self.verbose = verbose  # Debugging mode
        self.filename = filename

        self.p = re.compile(rb"[A-Fa-f0-9]+")

        self.num_objdata = 0  # Number of objdata inserted into RTF
        self.objdata = {}  # objdata
        self.payloads = []  # Extracted payloads
        self.parse()

    def parse(self):
        self.payloads = self.extract_objdata_payloads()
        for idx, payload in enumerate(self.payloads):
            fname = f"Objdata #{idx + 1}"
            self.objdata[fname] = payload

        self.num_objdata = len(self.payloads)

    def extract_objdata_payloads(self) -> list[bytes]:
        payloads: list[bytes] = []
        rtf_bytes = Path(self.filename).read_bytes()

        for m in re.finditer(rb"\\objdata\b", rtf_bytes):
            pos = m.start()
            group_start = rtf_bytes.rfind(b"{", 0, pos)
            if group_start == -1:
                continue

            try:
                group_end = self._find_matching_brace(rtf_bytes, group_start)
            except ValueError:
                continue

            group = rtf_bytes[group_start : group_end + 1]

            # Parse only after \objdata in the group
            objdata_idx = group.find(b"\\objdata")
            if objdata_idx == -1:
                continue
            i = objdata_idx + len(b"\\objdata")
            out = bytearray()

            while i < len(group):
                # Process \binN
                if group[i : i + 4] == b"\\bin":
                    j = i + 4
                    # Read the number (decimal)
                    num_start = j
                    while j < len(group) and group[j : j + 1].isdigit():
                        j += 1
                    if j == num_start:
                        i += 4
                        continue

                    nbytes = int(group[num_start:j].decode("ascii", errors="ignore") or "0")
                    j = self._skip_whitespace(group, j)
                    # Copy the next nbytes as is
                    out += group[j : j + nbytes]
                    i = j + nbytes
                    continue

                # End of group
                if group[i : i + 1] == b"}":
                    break

                # Collect only 2-hex tokens (ignore whitespace/line breaks/other control characters)
                # If the current position is a hex 2-digit, select it
                if i + 2 <= len(group) and HEX_RE.fullmatch(group[i : i + 2]):
                    out.append(int(group[i : i + 2], 16))
                    i += 2
                    continue

                i += 1

            if out:
                payloads.append(bytes(out))

        return payloads

    def _find_matching_brace(self, data: bytes, start: int) -> int:
        """
        start is the position of '{'. Return the position of the matching '}'.
        In RTF, \{ \} are ignored (simple processing).
        """
        depth = 0
        i = start
        n = len(data)

        while i < n:
            ch = data[i : i + 1]

            if ch == b"{":
                depth += 1
            elif ch == b"}":
                depth -= 1
                if depth == 0:
                    return i

            i += 1

        raise ValueError("No matching '}' found for objdata group.")

    def _skip_whitespace(self, data: bytes, i: int) -> int:
        n = len(data)
        while i < n and data[i] in b" \t\r\n":
            i += 1
        return i

    def close(self):
        pass

    def namelist(self):
        names = []

        if len(self.objdata):
            names = list(self.objdata.keys())
            names.sort()

        return names

    def read(self, fname):
        return self.objdata.get(fname, None)


# -------------------------------------------------------------------------
# RtfPackage class
# -------------------------------------------------------------------------
class RtfPackage:
    def __init__(self, filename, verbose=False):
        self.verbose = verbose  # Debugging mode
        self.filename = filename

        self.objdata = {}  # objdata
        self.payloads = []  # Extracted payloads
        self.parse()

    def parse(self):
        rtf_package_bytes = Path(self.filename).read_bytes()
        package_data = self.extract_package_from_rtf(rtf_package_bytes)

        for idx, (fname, data) in enumerate(package_data.items()):
            self.objdata[fname] = data

        self.num_objdata = len(self.objdata)

    def extract_package_from_rtf(self, rtf_bytes: bytes) -> dict[str, bytes]:
        # extract file name and data from RTF Package
        fname_start = 0x22
        pos = rtf_bytes[fname_start:].find(b"\x00")
        if pos == -1:
            return {}

        fname_end = fname_start + pos
        fname = rtf_bytes[fname_start:fname_end].decode("utf-8", errors="ignore")

        path_name_start = fname_end + 1
        pos = rtf_bytes[path_name_start:].find(b"\x00")
        if pos == -1:
            return {}

        path_name_end = path_name_start + pos
        path_name = rtf_bytes[path_name_start:path_name_end].decode("utf-8", errors="ignore")

        path_name2_len = kavutil.get_uint32(rtf_bytes, path_name_end + 5)
        data_len_off = path_name_end + 5 + path_name2_len + 4
        data_len = kavutil.get_uint32(rtf_bytes, data_len_off)

        if self.verbose:
            print(f"[+] Extracted filename: {fname}")
            print(f"[+] Extracted path name: {path_name}")

        return {
            fname: rtf_bytes[data_len_off + 4 : data_len_off + 4 + data_len],
        }

    def close(self):
        pass

    def namelist(self):
        names = []

        if len(self.objdata):
            names = list(self.objdata.keys())
            names.sort()

        return names

    def read(self, fname):
        return self.objdata.get(fname, None)


# -------------------------------------------------------------------------
# RtfOle2link class
# -------------------------------------------------------------------------
class RtfOle2link:
    def __init__(self, filename, verbose=False):
        self.verbose = verbose  # Debugging mode
        self.filename = filename

        self.objdata = {}  # objdata
        self.payloads = []  # Extracted payloads
        self.parse()

    def parse(self):
        rtf_ole2link_bytes = Path(self.filename).read_bytes()
        ole2link_data = self.extract_ole2link_from_rtf(rtf_ole2link_bytes)

        for idx, (fname, data) in enumerate(ole2link_data.items()):
            self.objdata[fname] = data

        self.num_objdata = len(self.objdata)

    def extract_ole2link_from_rtf(self, rtf_bytes: bytes) -> dict[str, bytes]:
        # extract OLE2Link data from RTF OLE2Link
        if rtf_bytes.find(b"OLE2Link") != 0xC:
            return {}

        ole2link_data_len = kavutil.get_uint32(rtf_bytes, 0x1D)
        ole2link_data = rtf_bytes[0x21 : 0x21 + ole2link_data_len]

        return {
            "OLE2Link": ole2link_data,
        }

    def close(self):
        pass

    def namelist(self):
        names = []

        if len(self.objdata):
            names = list(self.objdata.keys())
            names.sort()

        return names

    def read(self, fname):
        return self.objdata.get(fname, None)


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """RTF malware detector and archive handler plugin.

    This plugin provides functionality for:
    - Detecting RTF format
    - Scanning for RTF-based exploits (CVE-2010-3333, CVE-2014-1761)
    - Extracting objects from RTF files
    """

    def __init__(self):
        """Initialize the RTF plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="RTF Engine",
            kmd_name="rtf",
        )
        self.cve_2010_3333_magic = None
        self.prog_cve_2010_3333_1 = None
        self.prog_cve_2010_3333_2 = None
        self.prog_cve_2014_1761 = None
        self.prog_eps_dropper = None

    def _custom_init(self) -> int:
        """Custom initialization for RTF plugin.

        Returns:
            0 for success
        """
        self.cve_2010_3333_magic = re.compile(rb"\bpfragments\b", re.IGNORECASE)
        self.prog_cve_2010_3333_1 = re.compile(
            rb"pfragments\b.*?\\sv\b.*?(\d+)|\\sv\b.*?(\d+).*?pfragments\b",
            re.IGNORECASE | re.DOTALL,
        )
        self.prog_cve_2010_3333_2 = re.compile(rb"\\sn[\W]{1,20}?pfragments\b", re.IGNORECASE)
        self.prog_cve_2014_1761 = re.compile(rb"\\listoverridecount(\d+)", re.IGNORECASE)
        self.prog_eps_dropper = re.compile(rb"exec\s+(4d5a)?([0-9a-f]{2})+50450000", re.IGNORECASE)
        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["make_arc_type"] = kernel.MASTER_DELETE
        info["sig_num"] = len(self.listvirus())
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        return [
            "Exploit.RTF.CVE-2010-3333.a",
            "Exploit.RTF.CVE-2010-3333.b",
            "Exploit.RTF.CVE-2014-1761",
            "Trojan.PS.Agent",
        ]

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect RTF format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or empty dict if not recognized
        """
        ret = {}

        try:
            mm = filehandle

            if mm[:4] == b"{\\rt":
                ret["ff_rtf"] = "RTF"
            elif mm[:8] == b"\x01\x05\x00\x00\x02\x00\x00\x00":
                ret["ff_rtf_package"] = "RTF Package"
            elif mm[:8] == b"\x00\x00\x00\x00\x02\x00\x00\x00":
                ret["ff_rtf_ole2link"] = "RTF OLE2Link"

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return ret

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
            mm = filehandle

            if "ff_rtf" in fileformat:
                # Check CVE-2010-3333
                if self.cve_2010_3333_magic and self.cve_2010_3333_magic.search(mm):
                    if t := self.prog_cve_2010_3333_1.search(mm):
                        val1 = int(t.groups()[0]) if t.groups()[0] else 0
                        val2 = int(t.groups()[1]) if t.groups()[1] else 0
                        val = max(val1, val2)

                        if val not in [2, 4, 8]:
                            if self.verbose:
                                print("[*] RTF :", val)
                            return True, "Exploit.RTF.CVE-2010-3333.a", 0, kernel.INFECTED

                    if self.prog_cve_2010_3333_2 and self.prog_cve_2010_3333_2.search(mm):
                        return True, "Exploit.RTF.CVE-2010-3333.b", 0, kernel.INFECTED

                # Check CVE-2014-1761
                if self.prog_cve_2014_1761:
                    if t := self.prog_cve_2014_1761.search(mm):
                        val = int(t.groups()[0])

                        if self.verbose:
                            print("[*] RTF :", val)

                        if val >= 25:
                            if t1 := re.findall(r"{\\lfolevel}", mm):
                                if self.verbose:
                                    print("[*] N :", len(t1))
                                if len(t1) > val:
                                    return True, "Exploit.RTF.CVE-2014-1761", 0, kernel.INFECTED

            elif kavutil.is_textfile(mm[:4096]):
                if self.prog_eps_dropper and self.prog_eps_dropper.search(mm):
                    return True, "Trojan.PS.Agent", 0, kernel.INFECTED

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)

        return False, "", -1, kernel.NOT_FOUND

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

    def __get_handle(self, filename, handler_class):
        """Get or create handle for RTF file.

        Args:
            filename: Path to RTF file
            handler_class: Class to use for parsing

        Returns:
            Handler object or None
        """
        if filename in self.handle:
            return self.handle.get(filename, None)

        try:
            zfile = handler_class(filename, self.verbose)
            self.handle[filename] = zfile
            return zfile

        except (IOError, OSError) as e:
            logger.debug("Failed to open RTF file %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error opening RTF file %s: %s", filename, e)

        return None

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive.

        Args:
            filename: Path to RTF file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        try:
            if "ff_rtf" in fileformat:
                zfile = self.__get_handle(filename, RtfFile)
                if zfile:
                    file_scan_list.extend(["arc_rtf", name] for name in zfile.namelist())
            elif "ff_rtf_package" in fileformat:
                zfile = self.__get_handle(filename, RtfPackage)
                if zfile:
                    file_scan_list.extend(["arc_rtf_package", name] for name in zfile.namelist())
            elif "ff_rtf_ole2link" in fileformat:
                zfile = self.__get_handle(filename, RtfOle2link)
                if zfile:
                    file_scan_list.extend(["arc_rtf_ole2link", name] for name in zfile.namelist())

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_rtf', 'arc_rtf_package', 'arc_rtf_ole2link')
            arc_name: Path to RTF file
            fname_in_arc: Name of object to extract

        Returns:
            Extracted object data, or None on error
        """
        try:
            if arc_engine_id == "arc_rtf":
                zfile = self.__get_handle(arc_name, RtfFile)
            elif arc_engine_id == "arc_rtf_package":
                zfile = self.__get_handle(arc_name, RtfPackage)
            elif arc_engine_id == "arc_rtf_ole2link":
                zfile = self.__get_handle(arc_name, RtfOle2link)
            else:
                return None

            if zfile:
                return zfile.read(fname_in_arc)

        except (IOError, OSError) as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

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

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create an archive.

        Args:
            arc_engine_id: Engine ID
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        return arc_engine_id in ("arc_rtf", "arc_rtf_package", "arc_rtf_ole2link")
