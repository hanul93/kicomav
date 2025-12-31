# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
EGG Archive Engine Plugin

This plugin handles EGG archive format for scanning and manipulation.
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
# EGG constants
# -------------------------------------------------------------------------
SIZE_EGG_HEADER = 14

COMPRESS_METHOD_STORE = 0
COMPRESS_METHOD_DEFLATE = 1
COMPRESS_METHOD_BZIP2 = 2
COMPRESS_METHOD_AZO = 3
COMPRESS_METHOD_LZMA = 4


# -------------------------------------------------------------------------
# class EggFile
# -------------------------------------------------------------------------
class EggFile:
    """EGG file handler."""

    def __init__(self, filename):
        self.fp = None
        self.mm = None
        self.data_size = 0
        self.egg_pos = None

        with contextlib.suppress(IOError):
            self.data_size = os.path.getsize(filename)
            self.fp = open(filename, "rb")
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

    def close(self):
        if self.mm:
            self.mm.close()
            self.mm = None

        if self.fp:
            self.fp.close()
            self.fp = None

    def read(self, filename):
        ret_data = None

        with contextlib.suppress(Exception):
            fname = self.__FindFirstFileName__()
            while fname:
                if fname == filename:
                    data, method, self.egg_pos = self.__ReadBlockData__()
                    if method == COMPRESS_METHOD_STORE:
                        ret_data = data
                        break
                    elif method == COMPRESS_METHOD_DEFLATE:
                        ret_data = zlib.decompress(data, -15)
                        break
                    elif method == COMPRESS_METHOD_BZIP2:
                        ret_data = bz2.decompress(data)
                        break
                fname = self.__FindNextFileName__()

        return ret_data

    def namelist(self):
        name_list = []

        with contextlib.suppress(Exception):
            fname = self.__FindFirstFileName__()
            while fname:
                name_list.append(fname)
                fname = self.__FindNextFileName__()

        return name_list

    def __FindFirstFileName__(self):
        self.egg_pos = 0
        fname, self.egg_pos = self.__GetFileName__(self.egg_pos)
        return fname

    def __FindNextFileName__(self):
        fname, self.egg_pos = self.__GetFileName__(self.egg_pos)
        return fname

    def __GetFileName__(self, egg_pos):
        mm = self.mm
        data_size = self.data_size

        with contextlib.suppress(SystemError):
            while egg_pos < data_size:
                magic = kavutil.get_uint32(mm, egg_pos)

                if magic == 0x0A8591AC:  # Filename Header
                    size, fname = self.__EGG_Filename_Header__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                    return fname, egg_pos
                else:
                    egg_pos = self.__DefaultMagicIDProc__(magic, egg_pos)
                    if egg_pos == -1:
                        raise SystemError

        return None, -1

    def __ReadBlockData__(self):
        egg_pos = self.egg_pos
        mm = self.mm
        data_size = self.data_size

        with contextlib.suppress(SystemError):
            while egg_pos < data_size:
                magic = kavutil.get_uint32(mm, egg_pos)

                if magic == 0x02B50C13:  # Block Header
                    size = self.__EGG_Block_Header_Size__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError

                    compress_method = int(mm[egg_pos + 4])
                    compress_size = kavutil.get_uint32(mm, egg_pos + 10)
                    compressed_data = mm[egg_pos + 22 : egg_pos + 22 + compress_size]
                    egg_pos += size
                    return compressed_data, compress_method, egg_pos
                else:
                    egg_pos = self.__DefaultMagicIDProc__(magic, egg_pos)
                    if egg_pos == -1:
                        raise SystemError

        return None, -1, -1

    def __DefaultMagicIDProc__(self, magic, egg_pos):
        mm = self.mm
        data_size = self.data_size

        try:
            if egg_pos < data_size:
                if magic == 0x41474745:  # EGG Header
                    if self.__EGG_Header__(mm) == -1:
                        raise SystemError
                    egg_pos += SIZE_EGG_HEADER
                elif magic == 0x0A8590E3:  # File Header
                    egg_pos += 16
                elif magic == 0x02B50C13:  # Block Header
                    size = self.__EGG_Block_Header_Size__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                elif magic == 0x08D1470F:  # Encrypt Header
                    size = self.__EGG_Encrypt_Header_Size__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                elif magic == 0x2C86950B:  # Windows File Information
                    egg_pos += 16
                elif magic == 0x1EE922E5:  # Posix File Information
                    egg_pos += 27
                elif magic == 0x07463307:  # Dummy Header
                    size = self.__EGG_Dummy_Header_Size__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                elif magic == 0x0A8591AC:  # Filename Header
                    size, fname = self.__EGG_Filename_Header__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                elif magic == 0x04C63672:  # Comment Header
                    raise SystemError  # Not supported
                elif magic == 0x24F5A262:  # Split Compression
                    egg_pos += 15
                elif magic == 0x24E5A060:  # Solid Compression
                    egg_pos += 7
                elif magic == 0x08E28222:  # End of File Header
                    egg_pos += 4
                else:
                    raise SystemError
        except SystemError:
            return -1

        return egg_pos

    def __EGG_Header__(self, data):
        with contextlib.suppress(SystemError):
            magic = kavutil.get_uint32(data, 0)
            if magic != 0x41474745:
                raise SystemError

            version = kavutil.get_uint16(data, 4)
            if version != 0x0100:
                raise SystemError

            header_id = kavutil.get_uint32(data, 6)
            if header_id == 0:
                raise SystemError

            reserved = kavutil.get_uint32(data, 10)
            if reserved != 0:
                raise SystemError

            return 0

        return -1

    def __EGG_Encrypt_Header_Size__(self, data):
        with contextlib.suppress(SystemError):
            encrypt_method = int(data[7])
            if encrypt_method == 0:
                return 24
            elif encrypt_method == 1:
                return 28
            elif encrypt_method == 2:
                return 36
            else:
                raise SystemError

        return -1

    def __EGG_Dummy_Header_Size__(self, data):
        with contextlib.suppress(Exception):
            dummy_size = kavutil.get_uint16(data, 5)
            return 7 + dummy_size

        return -1

    def __EGG_Filename_Header__(self, data):
        size = -1
        fname = None

        with contextlib.suppress(Exception):
            fname_size = kavutil.get_uint16(data, 5)
            fname = data[7 : 7 + fname_size]
            size = 7 + fname_size

        return size, fname.decode("utf-8") if fname else None

    def __EGG_Block_Header_Size__(self, data):
        size = -1

        with contextlib.suppress(Exception):
            block_size = 18 + 4
            compress_size = kavutil.get_uint32(data, 10)
            size = block_size + compress_size

        return size


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """EGG archive handler plugin.

    This plugin provides functionality for:
    - Detecting EGG archive format
    - Listing files within archives
    - Extracting files from archives
    - Converting EGG to ZIP format
    """

    def __init__(self):
        """Initialize the EGG plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Egg Archive Engine",
            kmd_name="egg",
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
        """Get or create handle for EGG file.

        Args:
            filename: Path to EGG file

        Returns:
            EggFile object
        """
        if filename in self.handle:
            return self.handle.get(filename, None)
        else:
            zfile = EggFile(filename)
            self.handle[filename] = zfile
            return zfile

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect EGG format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            if filehandle[:4] == b"EGGA":
                return {"ff_egg": "EGG"}
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
            if "ff_egg" in fileformat:
                zfile = self.__get_handle(filename)
                for name in zfile.namelist():
                    # CWE-22: Path traversal prevention
                    if k2security.is_safe_archive_member(name):
                        file_scan_list.append(["arc_egg", name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_egg')
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
            if arc_engine_id == "arc_egg":
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
        """Create archive (converts EGG to ZIP format).

        Args:
            arc_engine_id: Engine ID ('arc_egg')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_egg":
            return False

        try:
            uname = kavutil.uniq_string()
            tname = f".tmp_{uname}"
            oname = f".org_{uname}"

            # Check if already converted to ZIP
            with open(arc_name, "rb") as f:
                if f.read(2) != b"PK":
                    self._convert_egg_to_zip(arc_name, tname)

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

    def _convert_egg_to_zip(self, arc_name, tname):
        """Convert EGG to ZIP format.

        Args:
            arc_name: Path to EGG file
            tname: Temporary file suffix
        """
        zfile_r = None
        try:
            with zipfile.ZipFile(arc_name + tname, "w") as zfile_w:
                zfile_r = EggFile(arc_name)
                for name in zfile_r.namelist():
                    data = zfile_r.read(name)
                    zfile_w.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
        finally:
            if zfile_r is not None:
                zfile_r.close()
