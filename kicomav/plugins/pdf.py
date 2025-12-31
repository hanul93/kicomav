# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
PDF File Format Engine Plugin

This plugin handles PDF format for scanning, malware detection, and extraction.
"""

import contextlib
import logging
import os
import re
from pathlib import Path

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# PdfFile class
# -------------------------------------------------------------------------
class PdfFile:
    def __init__(self, filename, verbose=False):
        self.REF_OBJ = 0  # Extract Stream from referenced OBJ
        self.IN_OBJ = 1  # Extract Stream from OBJ containing the sentence

        # Try to scan for malware if the pattern exists
        self.p_pdf_scanables = {}
        pats = {rb"/JS\s+(\d+)\s+0\s+R\b": self.REF_OBJ, rb"/Length\s+0\b": self.IN_OBJ}

        for pat in pats:
            self.p_pdf_scanables[re.compile(pat, re.IGNORECASE)] = pats[pat]

        # Use to record the location of OBJ within PDF
        s = rb"(\d+)\s+0\s+obj\s*<<.+?endobj"
        self.p_obj = re.compile(s, re.IGNORECASE | re.DOTALL)
        self.pdf_obj_off = None

        # Extract Stream
        pat = rb"stream\s*(.+?)\s*endstream"
        self.p_stream = re.compile(pat, re.IGNORECASE | re.DOTALL)

        # /Filter
        pat = rb"/Filter\s*/(\w+)"
        self.p_pdf_filter = re.compile(pat, re.IGNORECASE)

        self.buf = None
        self.verbose = verbose  # Debugging mode
        self.filename = filename

        self.p = re.compile(rb"[A-Fa-f0-9]+")

        self.num_obj = 0  # Number of obj inserted into PDF
        self.objdata = {}  # objects data
        self.pdf_obj_off = {}
        self.payloads = []  # Extracted payloads
        self.parse()

    def parse(self):
        self.payloads = self.extract_objects_data()
        for _, no in enumerate(self.payloads):
            fname = f"Obj #{int(no)}"
            self.objdata[fname] = no

        self.num_obj = len(self.payloads)

    def extract_objects_data(self):
        payloads: list[(bytes, bytes)] = []

        pdf_bytes = Path(self.filename).read_bytes()
        self.buf = pdf_bytes

        for pat in self.p_pdf_scanables.keys():
            for p in pat.finditer(pdf_bytes):
                if self.p_pdf_scanables[pat] == self.REF_OBJ:
                    payloads.append(p.groups()[0])
                else:  # self.IN_OBJ
                    self.__search_object_off(pdf_bytes)

                    for obj_no in self.pdf_obj_off.keys():
                        start_off = self.pdf_obj_off[obj_no][0]
                        end_off = self.pdf_obj_off[obj_no][1]
                        if start_off < p.span()[0] < end_off:
                            payloads.append(obj_no)
                            break

        return payloads

    def close(self):
        pass

    def namelist(self):
        names = []

        if self.num_obj:  # Is there a target for extracting Stream?
            names = list(self.objdata.keys())
            names.sort(key=lambda x: int(x.split("#")[1]))

        return names

    def read(self, fname):
        obj_no = self.objdata.get(fname, None)
        if obj_no is None:
            return None

        start_off, end_off = self.pdf_obj_off[obj_no]

        p = self.p_stream.search(self.buf[start_off:end_off])
        if p is None:
            return None

        return p.groups()[0]

    def __search_object_off(self, buf):
        """Record the location of PDF OBJ."""
        if self.pdf_obj_off:
            return

        self.pdf_obj_off = {}
        for p in self.p_obj.finditer(buf):
            obj_no = p.groups()[0]
            obj_off = p.span()
            self.pdf_obj_off[obj_no] = obj_off

        if not self.pdf_obj_off:
            self.pdf_obj_off = None


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """PDF malware detector and archive handler plugin.

    This plugin provides functionality for:
    - Detecting PDF format
    - Scanning for PDF-based malware
    - Extracting objects from PDF files
    """

    def __init__(self):
        """Initialize the PDF plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.2",
            title="PDF Engine",
            kmd_name="pdf",
        )
        self.p_pdf_header = None
        self.p_pdf_trojan_js = None

    def _custom_init(self) -> int:
        """Custom initialization for PDF plugin.

        Returns:
            0 for success
        """
        # PDF header
        pat = rb"^s*%PDF-1."
        self.p_pdf_header = re.compile(pat, re.IGNORECASE)

        # PDF Trojan pattern for detection
        pat = rb"this\.exportDataObject.+?cName:.+?nLaunch"
        self.p_pdf_trojan_js = re.compile(pat)

        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = 1
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        return ["Trojan.PDF.Generic"]

    def __get_handle(self, filename):
        """Get or create handle for PDF file.

        Args:
            filename: Path to PDF file

        Returns:
            PdfFile object or None
        """
        if filename in self.handle:
            return self.handle.get(filename, None)

        try:
            zfile = PdfFile(filename, self.verbose)
            self.handle[filename] = zfile
            return zfile

        except (IOError, OSError) as e:
            logger.debug("Failed to open PDF file %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error opening PDF file %s: %s", filename, e)

        return None

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect PDF format.

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

            if self.p_pdf_header and self.p_pdf_header.match(buf):
                return {"ff_pdf": "PDF"}

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
            if "ff_pdf" in fileformat:
                mm = filehandle

                if self.p_pdf_trojan_js and self.p_pdf_trojan_js.search(mm):
                    return True, "Trojan.PDF.Generic", 0, kernel.INFECTED

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
                # CWE-73: Safe file deletion
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive (PDF objects).

        Args:
            filename: Path to PDF file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_pdf" not in fileformat:
            return file_scan_list

        try:
            zfile = self.__get_handle(filename)
            if zfile is None:
                return file_scan_list

            file_scan_list.extend(["arc_pdf", name] for name in zfile.namelist())

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive (PDF object).

        Args:
            arc_engine_id: Engine ID ('arc_pdf')
            arc_name: Path to PDF file
            fname_in_arc: Name of object to extract

        Returns:
            Extracted object data, or None on error
        """
        if arc_engine_id != "arc_pdf":
            return None

        try:
            zfile = self.__get_handle(arc_name)
            if zfile is None:
                return None

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
            arc_engine_id: Engine ID ('arc_pdf')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        # PDF cannot be recompressed, so it must be deleted
        return arc_engine_id == "arc_pdf"
