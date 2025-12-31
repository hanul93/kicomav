# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
Zip Archive Engine Plugin

This plugin handles ZIP and 7Z archive formats for scanning and manipulation.
"""

import os
import shutil
import zipfile
import contextlib
import logging
import tempfile

import py7zr

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """ZIP and 7Z archive handler plugin.

    This plugin provides functionality for:
    - Detecting ZIP and 7Z archive formats
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    """

    def __init__(self):
        """Initialize the ZIP plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Zip Archive Engine",
            kmd_name="zip",
        )
        # self.handle = {} is initialized in ArchivePluginBase
        self.password = None  # Password for encrypted archives

    def _custom_init(self) -> int:
        """Custom initialization for ZIP plugin.

        Returns:
            0 for success
        """
        # self.handle = {} is already initialized in ArchivePluginBase
        return 0

    def _custom_uninit(self) -> int:
        """Custom cleanup for ZIP plugin.

        Returns:
            0 for success
        """
        self.arcclose()
        return 0

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
        """Get or create handle for ZIP file.

        Args:
            filename: Path to ZIP file

        Returns:
            ZipFile object
        """
        if filename in self.handle:
            return self.handle.get(filename, None)
        else:
            zfile = zipfile.ZipFile(filename)
            self.handle[filename] = zfile
            return zfile

    def __get_handle_7z(self, filename, password=None):
        """Get or create handle for 7Z file.

        Args:
            filename: Path to 7Z file
            password: Optional password for encrypted archives

        Returns:
            SevenZipFile object
        """
        if filename in self.handle:
            return self.handle.get(filename, None)
        else:
            if password:
                zfile = py7zr.SevenZipFile(filename, mode="r", password=password)
            else:
                zfile = py7zr.SevenZipFile(filename, mode="r")
            self.handle[filename] = zfile
            return zfile

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect archive format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        ret = {}

        try:
            mm = filehandle
            if mm[:4] == b"PK\x03\x04":  # ZIP signature
                with contextlib.suppress(zipfile.BadZipfile):
                    with zipfile.ZipFile(filename) as zfile:
                        names = zfile.namelist()

                        if names is not None:
                            for name in names:
                                n = name.lower()
                                if n == "classes.dex":
                                    ret["ff_apk"] = "apk"
                                elif n == "ppt/presentation.xml":
                                    ret["ff_ooxml"] = "pptx"
                                elif n == "word/document.xml":
                                    ret["ff_ooxml"] = "docx"
                                elif n == "xl/workbook.xml":
                                    ret["ff_ooxml"] = "xlsx"
                                elif n == "mimetype":
                                    data = zfile.read(name)
                                    if data == b"application/hwp+zip":
                                        ret["ff_hwpx"] = "hwpx"

                            ret["ff_zip"] = "zip"
                return ret

            elif mm[:4] == b"7z\xbc\xaf":  # 7Z signature
                ret["ff_7z"] = "7z"
                return ret

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
            password: Optional password for encrypted archives

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        # Store password for later use in unarc
        self.password = password

        try:
            if "ff_zip" in fileformat:
                zfile = self.__get_handle(filename)
                for name in zfile.namelist():
                    # CWE-22: Path traversal prevention
                    if k2security.is_safe_archive_member(name):
                        file_scan_list.append(["arc_zip", name])

            elif "ff_7z" in fileformat:
                # 7z needs password at open time for encrypted headers
                zfile = self.__get_handle_7z(filename, password)
                for name in zfile.getnames():
                    # CWE-22: Path traversal prevention
                    if k2security.is_safe_archive_member(name):
                        file_scan_list.append(["arc_7z", name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_zip' or 'arc_7z')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id == "arc_zip":
            return self.__unarc_zip(arc_name, fname_in_arc)
        elif arc_engine_id == "arc_7z":
            return self.__unarc_7z(arc_name, fname_in_arc)

        return None

    def __unarc_zip(self, arc_name, fname_in_arc):
        """Extract a file from ZIP archive with password support.

        Args:
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        zfile = self.__get_handle(arc_name)
        if zfile is None:
            return None

        # Try 1: Extract without password first
        try:
            return zfile.read(fname_in_arc)
        except RuntimeError as e:
            # RuntimeError is raised for password-protected files
            if "password" not in str(e).lower():
                logger.debug("ZIP extract error for %s: %s", fname_in_arc, e)
                return None
        except zipfile.BadZipfile as e:
            logger.debug("Bad ZIP file when extracting %s: %s", fname_in_arc, e)
            return None
        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
            return None
        except Exception as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)
            return None

        # Try 2: Extract with stored password
        if self.password:
            try:
                pwd = self.password.encode() if isinstance(self.password, str) else self.password
                return zfile.read(fname_in_arc, pwd=pwd)
            except RuntimeError as e:
                logger.debug("Wrong password for %s in ZIP archive: %s", fname_in_arc, e)
                raise RuntimeError("password required")
            except zipfile.BadZipfile as e:
                logger.debug("Bad ZIP file when extracting %s with password: %s", fname_in_arc, e)
            except (IOError, OSError) as e:
                logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
            except Exception as e:
                logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)
        else:
            logger.debug("Password required for %s in ZIP archive", fname_in_arc)
            raise RuntimeError("password required")

        return None

    def __unarc_7z(self, arc_name, fname_in_arc):
        """Extract a file from 7Z archive with password support.

        Args:
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # 7z handle is already created with password in arclist
        zfile = self.handle.get(arc_name)
        if zfile is None:
            return None

        try:
            zfile.reset()  # Reset required because EOF may be exhausted
            with tempfile.TemporaryDirectory() as tmpdir:
                zfile.extract(path=tmpdir, targets=[fname_in_arc])
                extracted_path = os.path.join(tmpdir, fname_in_arc)
                if os.path.exists(extracted_path):
                    with open(extracted_path, "rb") as f:
                        return f.read()
        except py7zr.exceptions.PasswordRequired:
            logger.debug("Password required for %s in 7Z archive", fname_in_arc)
            raise RuntimeError("password required")
        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                zfile = self.handle[fname]
                if hasattr(zfile, "close"):
                    zfile.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create or update an archive.

        Args:
            arc_engine_id: Engine ID ('arc_zip' or 'arc_7z')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        try:
            if arc_engine_id == "arc_zip":
                with zipfile.ZipFile(arc_name, "w") as zfile:
                    for file_info in file_infos:
                        rname = file_info.get_filename()
                        with contextlib.suppress(IOError):
                            with open(rname, "rb") as fp:
                                buf = fp.read()
                                a_name = file_info.get_filename_in_archive()
                                zfile.writestr(a_name, buf, compress_type=zipfile.ZIP_DEFLATED)
                return True

            elif arc_engine_id == "arc_7z":
                return self._convert_7z_to_zip(arc_name, file_infos)

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False

    def _convert_7z_to_zip(self, arc_name, file_infos):
        """Convert 7Z archive to ZIP format and update with cured files.

        Args:
            arc_name: Archive file name
            file_infos: Information about files to be included

        Returns:
            True if successful, False otherwise
        """
        uname = kavutil.uniq_string()
        tname = f".tmp_{uname}"
        oname = f".org_{uname}"

        try:
            with open(arc_name, "rb") as f:
                if f.read(2) != b"PK":
                    self._convert_7z_file_format(arc_name, tname, oname)

            shutil.move(arc_name, arc_name + oname)
            shutil.move(arc_name + tname, arc_name)

            # Put the cured file into the converted ZIP file
            kavutil.make_zip(arc_name, file_infos)

            # Clean up original file
            fname = arc_name + oname
            if os.path.exists(fname):
                with contextlib.suppress(k2security.SecurityError):
                    fname_dir = os.path.dirname(fname) or os.getcwd()
                    k2security.safe_remove_file(fname, fname_dir)

            return True

        except (IOError, OSError) as e:
            logger.error("7Z to ZIP conversion IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error converting 7Z to ZIP %s: %s", arc_name, e)

        return False

    def _convert_7z_file_format(self, arc_name, tname, oname):
        """Convert 7Z file to ZIP format while preserving contents.

        Args:
            arc_name: Original 7Z archive name
            tname: Temporary file suffix
            oname: Original file backup suffix
        """
        with zipfile.ZipFile(arc_name + tname, "w") as zfile_w:
            with py7zr.SevenZipFile(arc_name, mode="r") as zfile_r:
                with tempfile.TemporaryDirectory() as tmpdir:
                    zfile_r.extractall(path=tmpdir)
                    for name in zfile_r.getnames():
                        extracted_path = os.path.join(tmpdir, name)
                        if os.path.isfile(extracted_path):
                            with open(extracted_path, "rb") as f:
                                data = f.read()
                            zfile_w.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)
