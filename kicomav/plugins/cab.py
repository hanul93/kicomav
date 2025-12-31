# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
CAB Archive Engine Plugin

This plugin handles CAB archive format for scanning and manipulation.
"""

import contextlib
import os
import tempfile
import shutil
import logging

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

try:
    from pycabfile import CabFile

    PYCABFILE_AVAILABLE = True
except ImportError:
    PYCABFILE_AVAILABLE = False


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """CAB archive handler plugin.

    This plugin provides functionality for:
    - Detecting CAB archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    """

    def __init__(self):
        """Initialize the CAB plugin."""
        super().__init__(
            author="Kei Choi",
            version="3.0",
            title="CAB Archive Engine",
            kmd_name="cab",
        )
        self.temp_path = {}
        self.root_temp_path = None

    def _custom_init(self) -> int:
        """Custom initialization for CAB plugin.

        Returns:
            0 for success, -1 for failure
        """
        if not PYCABFILE_AVAILABLE:
            if self.verbose:
                logger.info("pycabfile package is not available")
            return -1

        pid = os.getpid()
        self.root_temp_path = os.path.join(tempfile.gettempdir(), "ktmp_cab_%05x" % pid)
        return 0

    def _custom_uninit(self) -> int:
        """Custom cleanup for CAB plugin.

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
        return info

    def __get_handle(self, filename):
        """Get or create handle for CAB file.

        Args:
            filename: Path to CAB file

        Returns:
            CabFile object or None
        """
        if filename in self.handle:
            return self.handle[filename]

        try:
            cab_file = CabFile(filename, "r")
            self.handle[filename] = cab_file

            if self.root_temp_path and not os.path.exists(self.root_temp_path):
                os.makedirs(self.root_temp_path, exist_ok=True)

            self.temp_path[filename] = tempfile.mkdtemp(prefix="ktmp", dir=self.root_temp_path)
            return cab_file

        except (IOError, OSError) as e:
            logger.debug("Failed to open CAB file %s: %s", filename, e)
        except Exception as e:
            logger.debug("Error opening CAB file %s: %s", filename, e)

        return None

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect CAB format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        if not PYCABFILE_AVAILABLE:
            return None

        try:
            if len(filehandle) >= 4 and filehandle[:4] == b"MSCF":
                with CabFile(filename, "r") as cab_file:
                    file_list = cab_file.namelist()

                fileformat = {
                    "size": len(filehandle),
                    "file_count": len(file_list),
                }
                return {"ff_cab": fileformat}

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.debug("Format detection error for %s: %s", filename, e)

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

        if "ff_cab" not in fileformat:
            return file_scan_list

        try:
            cab_file = self.__get_handle(filename)
            if cab_file is None:
                return file_scan_list

            file_list = cab_file.namelist()

            for filename_in_cab in file_list:
                # CWE-22: Path traversal prevention
                if k2security.is_safe_archive_member(filename_in_cab):
                    file_scan_list.append(["arc_cab", filename_in_cab])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.debug("Archive list error for %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_cab')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_cab":
            return None

        try:
            cab_file = self.handle.get(arc_name)
            if cab_file is None:
                return None

            file_data = cab_file.read(fname_in_arc)
            if file_data:
                return file_data

        except KeyError:
            logger.debug("File %s not found in CAB archive", fname_in_arc)
        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                cab_file = self.handle.get(fname)
                if cab_file:
                    cab_file.close()

                # Delete temporary directory
                temp_path = self.temp_path.get(fname)
                if temp_path and os.path.exists(temp_path):
                    with contextlib.suppress(OSError):
                        if os.path.isdir(temp_path):
                            shutil.rmtree(temp_path)
                        else:
                            os.remove(temp_path)

            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
                self.temp_path.pop(fname, None)

        # Delete root temporary directory
        if self.root_temp_path and os.path.exists(self.root_temp_path):
            with contextlib.suppress(OSError):
                shutil.rmtree(self.root_temp_path)

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create a CAB archive.

        Args:
            arc_engine_id: Engine ID ('arc_cab')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_cab":
            return False

        try:
            cab_file = CabFile(arc_name, "w")

            for file_info in file_infos:
                rname = file_info.get_filename()
                a_name = file_info.get_filename_in_archive()
                with contextlib.suppress(IOError, OSError):
                    cab_file.write(rname, arcname=a_name)

            cab_file.close()
            return True

        except (IOError, OSError) as e:
            logger.debug("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.debug("Archive creation error for %s: %s", arc_name, e)

        return False
