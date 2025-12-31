# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
TAR Archive Engine Plugin

This plugin handles TAR archive format for scanning and manipulation.
"""

import contextlib
import os
import re
import tarfile
import logging

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """TAR archive handler plugin.

    This plugin provides functionality for:
    - Detecting TAR archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    """

    def __init__(self):
        """Initialize the TAR plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Tar Archive Engine",
            kmd_name="tar",
        )
        self.p_tar_magic = None

    def _custom_init(self) -> int:
        """Custom initialization for TAR plugin.

        Returns:
            0 for success
        """
        self.p_tar_magic = re.compile(rb"[\d\x20\x00]+")
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
        """Get or create handle for TAR file.

        Args:
            filename: Path to TAR file

        Returns:
            TarFile object
        """
        if filename in self.handle:
            return self.handle.get(filename, None)
        else:
            tfile = tarfile.open(filename)
            self.handle[filename] = tfile
            return tfile

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect TAR format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            mm = filehandle
            if p := self.p_tar_magic.match(mm[100:157]):
                if len(p.group()) == 57:
                    ret = {}

                    with contextlib.suppress(tarfile.ReadError):
                        # CWE-404: Use with statement for proper resource cleanup
                        with tarfile.open(filename) as tfile:
                            pass  # Just verify the file can be opened

                        ret["ff_tar"] = "tar"
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

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        try:
            if "ff_tar" in fileformat:
                with contextlib.suppress(tarfile.ReadError):
                    tfile = self.__get_handle(filename)

                    for name in tfile.getnames():
                        # CWE-22: Path traversal prevention
                        if k2security.is_safe_archive_member(name):
                            file_scan_list.append(["arc_tar", name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_tar')
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
            if arc_engine_id == "arc_tar":
                tfile = self.__get_handle(arc_name)
                with contextlib.suppress(tarfile.ReadError):
                    f = tfile.extractfile(fname_in_arc)
                    if f is not None:  # extractfile returns None for directories
                        return f.read()

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create a TAR archive.

        Args:
            arc_engine_id: Engine ID ('arc_tar')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_tar":
            return False

        try:
            with tarfile.open(arc_name, "w") as zfile:
                for file_info in file_infos:
                    rname = file_info.get_filename()
                    if not os.path.exists(rname):
                        continue

                    a_name = file_info.get_filename_in_archive()
                    zfile.add(rname, arcname=a_name)
                return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
