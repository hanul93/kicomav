# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
BZ2 Archive Engine Plugin

This plugin handles BZ2 archive format for scanning and manipulation.
"""

import bz2
import mmap
import os
import logging

from kicomav.plugins import kernel
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# class BZ2File
# -------------------------------------------------------------------------
class BZ2File:
    """BZ2 file handler with attached data support."""

    def __init__(self, filename, mode="r"):
        self.mode = mode

        if mode == "r":
            self.decompress_data = None
            self.unused_data = None

            self.fp = open(filename, "rb")
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

        else:  # mode == 'w'
            self.bz2 = bz2.BZ2File(filename, "w")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def is_bz2(self):
        return False if self.mode != "r" else self.mm[:3] == b"BZh"

    def is_attach(self):
        if self.mode != "r":
            return False

        if not self.decompress_data:
            self.read()

        return bool(self.unused_data)

    def read(self):
        if self.mode != "r":
            return False

        if not self.is_bz2():
            return None

        if self.decompress_data:
            return self.decompress_data

        data = b""
        src = self.mm[:]
        while len(src):
            try:
                b = bz2.BZ2Decompressor()
                data += b.decompress(src)
                src = b.unused_data
            except IOError:
                break

        if len(src):
            self.unused_data = src

        if data != b"":
            self.decompress_data = data
            return self.decompress_data

        return None

    def get_attach_info(self):
        if self.mode != "r":
            return None, None

        if not self.decompress_data:
            self.read()

        if self.unused_data:
            asize = len(self.unused_data)
            return len(self.mm) - asize, asize

        return None, None

    def write(self, data):
        if self.mode != "w":
            return False

        self.bz2.write(data)
        return True

    def close(self):
        if self.mode == "r":
            if self.mm:
                self.mm.close()
                self.mm = None
            if self.fp:
                self.fp.close()
                self.fp = None
        elif hasattr(self, "bz2") and self.bz2:
            self.bz2.close()
            self.bz2 = None

    def __del__(self):
        self.close()


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """BZ2 archive handler plugin.

    This plugin provides functionality for:
    - Detecting BZ2 archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    """

    def __init__(self):
        """Initialize the BZ2 plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Bz2 Archive Engine",
            kmd_name="bz2",
        )

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["engine_type"] = kernel.ARCHIVE_ENGINE
        info["make_arc_type"] = kernel.MASTER_PACK
        return info

    def __get_handle(self, filename):
        """Get or create handle for BZ2 file.

        Args:
            filename: Path to BZ2 file

        Returns:
            BZ2File object
        """
        if filename in self.handle:
            return self.handle[filename]

        zfile = BZ2File(filename)
        self.handle[filename] = zfile
        return zfile

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect BZ2 format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            if filehandle[:3] == b"BZh":
                fileformat = {}

                with BZ2File(filename) as bfile:
                    aoff, asize = bfile.get_attach_info()
                    fileformat["ff_bz2"] = "bz2"

                    if aoff:
                        fileformat["ff_attach"] = {
                            "Attached_Pos": aoff,
                            "Attached_Size": asize,
                        }

                    return fileformat

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

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

        if "ff_bz2" in fileformat:
            file_scan_list.append(["arc_bz2", "BZ2"])

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_bz2')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        try:
            if arc_engine_id == "arc_bz2":
                bfile = self.__get_handle(arc_name)
                return bfile.read()

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                bfile = self.handle[fname]
                bfile.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create a BZ2 archive.

        Args:
            arc_engine_id: Engine ID ('arc_bz2')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_bz2":
            return False

        try:
            bfile = BZ2File(arc_name, "w")
            file_info = file_infos[0]

            rname = file_info.get_filename()
            fsize = os.path.getsize(rname)

            with open(rname, "rb") as fp:
                data = fp.read(fsize)

            bfile.write(data)
            bfile.close()
            return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
