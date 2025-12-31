# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
GZ Archive Engine Plugin

This plugin handles GZIP archive format for scanning and manipulation.
"""

import contextlib
import gzip
import logging

from kicomav.plugins import kernel
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """GZ archive handler plugin.

    This plugin provides functionality for:
    - Detecting GZIP archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    """

    def __init__(self):
        """Initialize the GZ plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="GZ Archive Engine",
            kmd_name="gz",
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
        """Analyze and detect GZIP format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            mm = filehandle
            if mm[:3] == b"\x1F\x8B\x08":
                return {"ff_gz": "gz"}
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

        if "ff_gz" in fileformat:
            file_scan_list.append(["arc_gz", "GZ"])

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_gz')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        try:
            if arc_engine_id == "arc_gz":
                with contextlib.suppress(IOError):
                    with gzip.open(arc_name, "rb") as f:
                        return f.read()

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create a GZIP archive.

        Args:
            arc_engine_id: Engine ID ('arc_gz')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_gz":
            return False

        try:
            with gzip.open(arc_name, "wb") as zfile:
                file_info = file_infos[0]
                rname = file_info.get_filename()

                with open(rname, "rb") as fp:
                    data = fp.read()

                zfile.write(data)
                return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
