# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
LNK File Format Engine Plugin

This plugin handles LNK (Windows Shortcut) format for malware detection.
"""

import contextlib
import logging
import os
import re

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """LNK malware detector plugin.

    This plugin provides functionality for:
    - Detecting malicious LNK files
    - Scanning for downloader patterns in shortcuts
    """

    def __init__(self):
        """Initialize the LNK plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="LNK Scan Engine",
            kmd_name="lnk",
        )
        self.p_http = None

    def _load_virus_database(self) -> int:
        """Load virus patterns.

        Returns:
            0 for success
        """
        self.p_http = re.compile(rb"https?://")
        self.virus_names = ["Trojan.LNK.Agent.gen"]
        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = 1
        return info

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

            if mm[:8] != b"\x4c\x00\x00\x00\x01\x14\x02\x00":  # Check LNK header
                return False, "", kernel.DISINFECT_NONE, kernel.NOT_FOUND

            flag = kavutil.get_uint32(mm, 0x14)

            off = 0x4C
            if flag & 0x0001 == 0x0001:  # HasLinkTargetIDList
                clid_mycom = b"\x14\x00\x1F\x50\xE0\x4F\xD0\x20\xEA\x3A\x69\x10\xA2\xD8\x08\x00\x2B\x30\x30\x9D"
                if mm[off + 2 : off + 2 + 0x14] != clid_mycom:  # MyComputer
                    return False, "", kernel.DISINFECT_NONE, kernel.NOT_FOUND

                off += 2
                while True:
                    size = kavutil.get_uint16(mm, off)
                    if size == 0:
                        off += 2
                        break
                    if int(mm[off + 2]) == 0x32 and mm[off + 0xE : off + 0xE + 7].lower() != b"cmd.exe":
                        return False, "", kernel.DISINFECT_NONE, kernel.NOT_FOUND

                    off += size

            if flag & 0x0002 == 0x0002:  # HasLinkInfo
                off += kavutil.get_uint16(mm, off)

            if flag & 0x0004 == 0x0004:  # HasName
                size = kavutil.get_uint16(mm, off)
                off += 2 + (size * 2)

            if flag & 0x0008 == 0x0008:  # HasRelativePath
                size = kavutil.get_uint16(mm, off)
                cmd_path = mm[off + 2 : off + 2 + (size * 2) : 2].lower()

                if cmd_path.find(b"cmd.exe") == -1:
                    return False, "", kernel.DISINFECT_NONE, kernel.NOT_FOUND
                off += 2 + (size * 2)

            if flag & 0x0010 == 0x0010:  # HasWorkingDir
                size = kavutil.get_uint16(mm, off)
                off += 2 + (size * 2)

            if flag & 0x0020 == 0x0020:  # HasArguments
                size = kavutil.get_uint16(mm, off)
                cmd_arg = mm[off + 2 : off + 2 + (size * 2) : 2].lower()
                cmd_arg = cmd_arg.replace(b"^", b"")

                # Compare malware pattern
                if self.p_http and self.p_http.search(cmd_arg):
                    return True, "Trojan.LNK.Agent.gen", kernel.DISINFECT_DELETE, kernel.INFECTED

        except (IOError, OSError, ValueError) as e:
            logger.debug("Scan error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)

        return False, "", kernel.DISINFECT_NONE, kernel.NOT_FOUND

    def disinfect(self, filename, malware_id):
        """Disinfect malware.

        Args:
            filename: Path to infected file
            malware_id: Malware ID to disinfect

        Returns:
            True if successful, False otherwise
        """
        try:
            if malware_id == kernel.DISINFECT_DELETE:
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False
