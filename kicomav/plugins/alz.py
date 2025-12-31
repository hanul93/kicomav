# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
ALZ Archive Engine Plugin

This plugin handles ALZ archive format for scanning and manipulation.
"""

import bz2
import contextlib
import mmap
import os
import shutil
import zipfile
import zlib
import logging

from kicomav.plugins import kernel
from kicomav.plugins import kavutil
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# ALZ compression methods
# -------------------------------------------------------------------------
COMPRESS_METHOD_STORE = 0
COMPRESS_METHOD_BZIP2 = 1
COMPRESS_METHOD_DEFLATE = 2


# -------------------------------------------------------------------------
# class AlzFile
# -------------------------------------------------------------------------
class AlzFile:
    """ALZ file handler."""

    def __init__(self, filename):
        self.fp = None
        self.mm = None
        self.alz_pos = 0

        with contextlib.suppress(IOError):
            self.fp = open(filename, "rb")
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

    def close(self):
        if self.mm is not None:
            self.mm.close()
            self.mm = None

        if self.fp is not None:
            self.fp.close()
            self.fp = None

    def read(self, filename):
        ret_data = None

        with contextlib.suppress(IOError):
            fname, data = self.__FindFirstFileName__()
            while fname is not None:
                if fname == filename:
                    data, method, _, _ = self.__Alz_LocalFileHeader__(data)
                    if method == COMPRESS_METHOD_STORE:
                        ret_data = data
                        break
                    elif method == COMPRESS_METHOD_DEFLATE:
                        ret_data = zlib.decompress(data, -15)
                        break
                    elif method == COMPRESS_METHOD_BZIP2:
                        ret_data = bz2.decompress(data)
                        break
                fname, data = self.__FindNextFileName__()

        return ret_data

    def namelist(self):
        name_list = []

        with contextlib.suppress(IOError):
            fname, data = self.__FindFirstFileName__()
            while fname is not None:
                name_list.append(fname)
                fname, data = self.__FindNextFileName__()

        return name_list

    def __FindFirstFileName__(self):
        self.alz_pos = 8
        start = 8

        fname, self.alz_pos = self.__GetFileName__(self.alz_pos)
        if fname is None:
            return None, None

        end = self.alz_pos
        return fname, self.mm[start:end]

    def __FindNextFileName__(self):
        start = self.alz_pos
        fname, self.alz_pos = self.__GetFileName__(self.alz_pos)
        end = self.alz_pos

        return fname, self.mm[start:end]

    def __GetFileName__(self, alz_pos):
        try:
            mm = self.mm
            data_size = len(mm)
        except TypeError:
            return None, -1

        with contextlib.suppress(ValueError):
            while alz_pos < data_size:
                magic = kavutil.get_uint32(mm, alz_pos)

                if magic == 0x015A4C42:  # Local File Header
                    _, _, size, fname = self.__Alz_LocalFileHeader__(mm[alz_pos:])
                    if size == -1:
                        raise ValueError
                    alz_pos += size
                    return fname, alz_pos
                else:
                    alz_pos = self.__DefaultMagicIDProc__(magic, alz_pos)
                    if alz_pos == -1:
                        raise ValueError

        return None, -1

    def __Alz_LocalFileHeader__(self, data):
        with contextlib.suppress(IndexError):
            fname_size = kavutil.get_uint16(data, 4)
            file_desc = int(data[11])
            compress_method = int(data[13])

            size = 19
            if file_desc & 0x10:
                compress_size = int(data[size])
                size += 1 * 2
            elif file_desc & 0x20:
                compress_size = kavutil.get_uint16(data, size)
                size += 2 * 2
            elif file_desc & 0x40:
                compress_size = kavutil.get_uint32(data, size)
                size += 4 * 2
            elif file_desc & 0x80:
                compress_size = kavutil.get_uint64(data, size)
                size += 8 * 2
            else:
                raise SystemError

            fname = data[size : size + fname_size].decode("utf-8")
            size += fname_size

            if file_desc & 1:
                size += 12  # Encrypt Block

            compressed_data = data[size : size + compress_size]

            return compressed_data, compress_method, size + compress_size, fname

        return None, -1, -1, None

    def __DefaultMagicIDProc__(self, magic, alz_pos):
        try:
            if magic == 0x015A4C41:  # ALZ Header
                alz_pos += 8
            elif magic == 0x015A4C43:  # Central Directory Structure
                alz_pos += 12
            elif magic == 0x025A4C43:  # EOF Central Directory Record
                alz_pos += 4
            else:
                raise ValueError
        except ValueError:
            return -1

        return alz_pos


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """ALZ archive handler plugin.

    This plugin provides functionality for:
    - Detecting ALZ archive format
    - Listing files within archives
    - Extracting files from archives
    - Converting ALZ to ZIP format
    """

    def __init__(self):
        """Initialize the ALZ plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Alz Archive Engine",
            kmd_name="alz",
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
        """Get or create handle for ALZ file.

        Args:
            filename: Path to ALZ file

        Returns:
            AlzFile object
        """
        if filename in self.handle:
            return self.handle.get(filename, None)
        else:
            zfile = AlzFile(filename)
            self.handle[filename] = zfile
            return zfile

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect ALZ format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            mm = filehandle
            if mm[:4] == b"ALZ\x01":
                fileformat = {"size": len(mm)}
                return {"ff_alz": fileformat}
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

        try:
            if "ff_alz" in fileformat:
                zfile = self.__get_handle(filename)
                for name in zfile.namelist():
                    # CWE-22: Path traversal prevention
                    if k2security.is_safe_archive_member(name):
                        file_scan_list.append(["arc_alz", name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_alz')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        try:
            if arc_engine_id == "arc_alz":
                zfile = self.__get_handle(arc_name)
                return zfile.read(fname_in_arc)

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                zfile = self.handle[fname]
                zfile.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create archive (converts ALZ to ZIP format).

        Args:
            arc_engine_id: Engine ID ('arc_alz')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_alz":
            return False

        try:
            uname = kavutil.uniq_string()
            tname = f".tmp_{uname}"
            oname = f".org_{uname}"

            # Check if already converted to ZIP
            with open(arc_name, "rb") as f:
                if f.read(2) != b"PK":
                    self._convert_alz_to_zip(arc_name, tname)

            shutil.move(arc_name, arc_name + oname)
            shutil.move(arc_name + tname, arc_name)

            # Add cleaned file to converted ZIP
            kavutil.make_zip(arc_name, file_infos)

            # Clean up original file
            fname = arc_name + oname
            if os.path.exists(fname):
                with contextlib.suppress(k2security.SecurityError):
                    fname_dir = os.path.dirname(fname) or os.getcwd()
                    k2security.safe_remove_file(fname, fname_dir)

            return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False

    def _convert_alz_to_zip(self, arc_name, tname):
        """Convert ALZ to ZIP format.

        Args:
            arc_name: Path to ALZ file
            tname: Temporary file suffix
        """
        zfile_r = None
        try:
            with zipfile.ZipFile(arc_name + tname, "w") as zfile_w:
                zfile_r = AlzFile(arc_name)
                for name in zfile_r.namelist():
                    data = zfile_r.read(name)
                    zfile_w.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
        finally:
            if zfile_r is not None:
                zfile_r.close()
