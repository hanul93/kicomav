# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
XZ Archive Engine Plugin

This plugin handles XZ/LZMA archive format for scanning and manipulation.
"""

import lzma
import logging

from kicomav.plugins import kernel
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """XZ archive handler plugin.

    This plugin provides functionality for:
    - Detecting XZ archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    """

    def __init__(self):
        """Initialize the XZ plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="XZ Archive Engine",
            kmd_name="xz",
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

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect XZ format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            mm = filehandle
            if mm[:6] == b"\xFD7zXZ\x00":
                return {"ff_xz": "xz"}
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

        if "ff_xz" in fileformat:
            file_scan_list.append(["arc_xz", "XZ"])

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_xz')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        try:
            if arc_engine_id == "arc_xz":
                with lzma.open(arc_name, "rb") as in_file:
                    return in_file.read()

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create an XZ archive.

        Args:
            arc_engine_id: Engine ID ('arc_xz')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_xz":
            return False

        try:
            with lzma.open(arc_name, "wb") as zfile:
                file_info = file_infos[0]
                rname = file_info.get_filename()

                with open(rname, "rb") as f:
                    data = f.read()

                zfile.write(data)
                return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
