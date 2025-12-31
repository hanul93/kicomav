# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
Unpack Archive Engine Plugin

This plugin handles various unpacking formats (ZLIB, Embed OLE) for scanning and manipulation.
"""

import contextlib
import logging
import os
import struct
import zlib

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """Unpack archive handler plugin.

    This plugin provides functionality for:
    - Detecting ZLIB compressed data
    - Detecting embedded OLE data
    - Extracting and recompressing data
    """

    def __init__(self):
        """Initialize the Unpack plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Unpack Engine",
            kmd_name="unpack",
        )

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["make_arc_type"] = kernel.MASTER_PACK
        return info

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect unpack formats.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        ret = {}

        try:
            mm = filehandle

            with contextlib.suppress(zlib.error):
                d = zlib.decompress(mm, -15)
                if len(d) > 1:
                    ret["ff_zlib"] = "ZLIB"

            with contextlib.suppress(zlib.error):
                d = zlib.decompress(mm)
                if len(d) > 1:
                    ret["ff_zlib_header"] = "ZLIB_HEADER"

            with contextlib.suppress(struct.error):
                if kavutil.get_uint32(mm, 0) == len(mm) - 4:
                    ret["ff_embed_ole"] = "EMBED_OLE"

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return ret if len(ret) else None

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
            if "ff_zlib" in fileformat:
                file_scan_list.append(["arc_zlib", "<Zlib>"])

            if "ff_zlib_header" in fileformat:
                file_scan_list.append(["arc_zlib_header", "<Zlib>"])

            if "ff_embed_ole" in fileformat:
                file_scan_list.append(["arc_embed_ole", "<Embed>"])

        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_zlib', 'arc_zlib_header', 'arc_embed_ole')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        try:
            if arc_engine_id == "arc_zlib" or arc_engine_id == "arc_zlib_header":
                with contextlib.suppress(zlib.error):
                    with open(arc_name, "rb") as fp:
                        buf = fp.read()
                        if arc_engine_id == "arc_zlib_header":
                            return zlib.decompress(buf)
                        else:
                            return zlib.decompress(buf, -15)

            elif arc_engine_id == "arc_embed_ole":
                with open(arc_name, "rb") as fp:
                    buf = fp.read()
                    return buf[4:]

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        pass  # No persistent handles to close

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create an archive.

        Args:
            arc_engine_id: Engine ID ('arc_zlib', 'arc_embed_ole')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        try:
            file_info = file_infos[0]
            rname = file_info.get_filename()

            if arc_engine_id == "arc_embed_ole":
                with contextlib.suppress(IOError):
                    if os.path.exists(rname):
                        with open(rname, "rb") as fp, open(arc_name, "wb") as wp:
                            buf = fp.read()
                            new_data = struct.pack("<L", len(buf)) + buf
                            wp.write(new_data)
                            return True
                    else:
                        # CWE-73: Safe file deletion
                        arc_name_dir = os.path.dirname(arc_name) or os.getcwd()
                        k2security.safe_remove_file(arc_name, arc_name_dir)
                        return True

            elif arc_engine_id == "arc_zlib":
                with contextlib.suppress(IOError):
                    if os.path.exists(rname):
                        with open(rname, "rb") as fp, open(arc_name, "wb") as wp:
                            buf = fp.read()
                            new_data = zlib.compress(buf)[2:]
                            wp.write(new_data)
                            return True
                    else:
                        # CWE-73: Safe file deletion
                        arc_name_dir = os.path.dirname(arc_name) or os.getcwd()
                        k2security.safe_remove_file(arc_name, arc_name_dir)
                        return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
