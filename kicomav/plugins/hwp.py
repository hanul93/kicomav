# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
HWP File Format Engine Plugin

This plugin handles HWP (Hangul Word Processor) format for malware detection.
"""

import contextlib
import logging
import os
import re
import zlib

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# get_hwp_recoard(val)
# Convert the input 4Byte value to the HWP record structure and extract it.
# input  : val - DWORD
# return : tag_id, level, size
# -------------------------------------------------------------------------
def get_hwp_recoard(val):
    b = 0b1111111111
    c = 0b111111111111

    tag_id = val & b
    level = (val >> 10) & b
    size = (val >> 20) & c

    return tag_id, level, size


# -------------------------------------------------------------------------
# scan_hwp_recoard(buf, lenbuf)
# Interpret the given buffer as an HWP record structure.
# input  : buf - buffer
#         lenbuf - buffer size
# return : True or False (HWP record tracking success or failure) and the problematic tagid
# -------------------------------------------------------------------------
def scan_hwp_recoard(buf, lenbuf):
    pos = 0
    tagid = 0

    while pos < lenbuf:
        extra_size = 4
        val = kavutil.get_uint32(buf, pos)
        tagid, level, size = get_hwp_recoard(val)

        if size == 0xFFF:
            extra_size = 8
            size = kavutil.get_uint32(buf, pos + 4)

        if tagid == 0x43 and size > 4000:  # PARA_TEXT
            t_buf = buf[pos : pos + size + extra_size]
            d_buf = zlib.compress(t_buf)
            if len(d_buf) / float(len(t_buf)) < 0.02:
                return False, 0x43

        pos += size + extra_size

    return (True, -1) if pos == lenbuf else (False, tagid)


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """HWP malware detector plugin.

    This plugin provides functionality for:
    - Detecting HWP exploits
    - Detecting JavaScript-based exploits in HWP files
    - Disinfecting infected HWP sections
    """

    def __init__(self):
        """Initialize the HWP plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="HWP Engine",
            kmd_name="hwp",
        )
        self.hwp_ole = None
        self.hwp_js = None

    def _load_virus_database(self) -> int:
        """Load virus patterns.

        Returns:
            0 for success
        """
        # Compile patterns
        self.hwp_ole = re.compile(b"bindata/bin\d+\.ole$", re.IGNORECASE)

        s = rb"n\x00e\x00w\x00(\x20\x00)+A\x00c\x00t\x00i\x00v\x00e\x00X\x00O\x00b\x00j\x00e\x00c\x00t\x00"
        self.hwp_js = re.compile(s, re.IGNORECASE)

        # Set virus names
        self.virus_names = ["Exploit.HWP.Generic", "Exploit.JS.Agent.gen"]

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

            if filename_ex.lower().find("bodytext/section") >= 0 or filename_ex.lower().find("docinfo") >= 0:
                val = kavutil.get_uint32(mm, 0)
                tagid, level, size = get_hwp_recoard(val)

                # Track only if the first tag is the document header (0x42) or document properties (0x10)
                if tagid in [0x42, 0x10]:
                    ret, tagid = scan_hwp_recoard(mm, len(mm))
                    if ret is False:  # Track failed
                        return True, "Exploit.HWP.Generic.%02X" % tagid, kernel.DISINFECT_DELETE, kernel.INFECTED

            elif filename_ex.lower().find("scripts/defaultjscript") >= 0:
                if self.hwp_js and self.hwp_js.search(mm):
                    return True, "Exploit.JS.Agent.gen", kernel.DISINFECT_DELETE, kernel.INFECTED

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)

        # Return that no malware was found
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
                # CWE-73: Safe file deletion
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False
