# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
EPS File Format Engine Plugin

This plugin handles EPS (Encapsulated PostScript) format for malware detection.
"""

import contextlib
import logging
import os
import re

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import FileFormatPluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(FileFormatPluginBase):
    """EPS malware detector and format handler plugin.

    This plugin provides functionality for:
    - Detecting EPS format
    - Scanning for EPS-based malware
    """

    def __init__(self):
        """Initialize the EPS plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Eps Engine",
            kmd_name="eps",
        )
        self.p_eps = None
        self.p_hex1 = None

    def _custom_init(self) -> int:
        """Custom initialization for EPS plugin.

        Returns:
            0 for success
        """
        self.p_eps = re.compile(
            rb"(\bexec\b)|(\bdef\b)|(\bexch\b)|(\bstring\b)|"
            + rb"(\breadhexstring\b)|(\bcurrentfile\b)|(\bwritestring\b)|"
            + rb"(\bhexstring\b)"
        )
        self.p_hex1 = re.compile(rb"<?\s*([0-9A-Fa-f\s]+)\s*>?")
        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = len(self.listvirus())
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        return ["Trojan.EPS.Generic"]

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect EPS format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            mm = filehandle
            buf = mm[:4096]

            if kavutil.is_textfile(buf) and self.p_eps:
                t = []
                t.extend(i.group() for i in self.p_eps.finditer(mm))
                if len(t):
                    return {"ff_eps": list(set(t))}

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

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
            if "ff_eps" not in fileformat:
                return False, "", -1, kernel.NOT_FOUND

            mm = filehandle

            if self.verbose:
                print("-" * 79)
                kavutil.vprint("Engine")
                kavutil.vprint(None, "Engine", "eps")
                kavutil.vprint(None, "File name", os.path.split(filename)[-1])
                print()

            eps_keywords = fileformat["ff_eps"]

            if self.verbose:
                kavutil.vprint("EPS Keyword")
                for i, name in enumerate(eps_keywords):
                    kavutil.vprint(None, "Keyword #%d" % (i + 1), name)
                print()

            if self.p_hex1:
                t_hex = self.p_hex1.findall(mm)
                for i, x in enumerate(t_hex):
                    if self.verbose:
                        kavutil.vprint(None, "Hex String #%d" % (i + 1), x)
                    if len(x) > 10 * 1024:  # Is it 10K or more?
                        return True, "Trojan.EPS.Generic", 0, kernel.INFECTED

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
