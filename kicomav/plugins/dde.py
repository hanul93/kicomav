# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
DDE File Format Engine Plugin

This plugin handles DDE (Dynamic Data Exchange) based malware detection.
"""

import contextlib
import logging
import os
import re
import zipfile

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Returns the data from the decompressed file in the zip file.
# -------------------------------------------------------------------------
def get_zip_data(zip_name, filename):
    data = None

    with contextlib.suppress(zipfile.BadZipfile):
        with zipfile.ZipFile(zip_name) as zfile:
            names = zfile.namelist()

            for name in names:
                if name.lower() == filename:
                    data = zfile.read(name)
                    break

    return data


def InstrSub(obj):
    text = obj.groups()[0]

    off = text.find(b"QUOTE")
    if off != -1:
        t = text[off + 5 :].strip().split(b" ")
        text = b"".join([chr(int(x)) for x in t])

    return text


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """DDE malware detector plugin.

    This plugin provides functionality for:
    - Detecting DDE-based exploits in Word documents
    - Detecting CVE-2017-0199 exploits
    """

    def __init__(self):
        """Initialize the DDE plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="DDE Scan Engine",
            kmd_name="dde",
        )
        self.p_dde_text = None
        self.p_instr = None
        self.p_dde = None
        self.p_cmd = None
        self.p_tag = None
        self.p_dde2 = None

    def _load_virus_database(self) -> int:
        """Load virus patterns.

        Returns:
            0 for success
        """
        self.p_dde_text = re.compile(rb'"begin"(.+?)"end"', re.IGNORECASE)
        self.p_instr = re.compile(rb'<w:fldSimple\s+?w:instr=\s*?"(.+?)"\s*>', re.IGNORECASE)
        self.p_dde = re.compile(rb"\bdde(auto)?\b", re.IGNORECASE)
        self.p_cmd = re.compile(rb"\\system32\b(.+)\.exe", re.IGNORECASE)
        self.p_tag = re.compile(rb"\<[\d\D]+?\>")
        self.p_dde2 = re.compile(rb"\x13\s*dde(auto)?\b[^\x00]+", re.IGNORECASE)

        self.virus_names = [
            "Exploit.MSWord.DDE.a",
            "Exploit.MSWord.DDE.b",
            "Exploit.MSWord.CVE-2017-0199",
        ]

        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
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
            if "ff_ooxml" in fileformat:
                if fileformat["ff_ooxml"] == "docx":
                    if data := get_zip_data(filename, "word/document.xml"):
                        if self.__scan_dde_docx(data):
                            return True, "Exploit.MSWord.DDE.a", 0, kernel.INFECTED
                        elif self.__scan_cve_2017_0199_docx(data):
                            return (
                                True,
                                "Exploit.MSWord.CVE-2017-0199",
                                0,
                                kernel.INFECTED,
                            )
            elif filename_ex.lower() == "worddocument":
                data = filehandle
                if self.__scan_dde_doc(data):
                    return True, "Exploit.MSWord.DDE.b", 0, kernel.INFECTED

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

    def __scan_dde_docx(self, data):
        """Scans for DDE malware in DOCX files."""
        if not self.p_dde_text:
            return False

        texts = self.p_dde_text.findall(data)
        if len(texts):
            buf = b""
            for text in texts:
                # Remove the front begin Tag
                off = text.find(b">")
                text = text[off + 1 :]

                # Remove the back end Tag
                off = text.rfind(b"<")
                text = text[:off]

                # Process instr
                if self.p_instr:
                    text = self.p_instr.sub(InstrSub, text)

                # Remove all Tags
                if self.p_tag:
                    buf += self.p_tag.sub(b"", text) + b"\n"

            if len(buf) and (self.p_dde and self.p_dde.search(buf) and self.p_cmd and self.p_cmd.search(buf)):
                return True

        return False

    def __scan_dde_doc(self, data):
        """Scans for DDE malware in DOC files."""
        if not self.p_dde2:
            return False

        if s := self.p_dde2.search(data):
            buf = s.group()
            if len(buf) and (self.p_dde and self.p_dde.search(buf) and self.p_cmd and self.p_cmd.search(buf)):
                return True

        return False

    def __scan_cve_2017_0199_docx(self, data):
        """Scans for CVE-2017-0199 malware in DOCX files."""
        return data.find(b'<o:OLEObject Type="Link" ProgID="Word.Document.8"') != -1
