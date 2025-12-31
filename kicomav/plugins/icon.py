# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

# ICON Spec-1 : http://www.daubnet.com/en/file-format-ico
# ICON Spec-2 : https://formats.kaitai.io/ico/index.html

"""
Icon File Format Engine Plugin

This plugin handles ICO (Icon) format for scanning and analysis.
"""

import logging
import re
import struct

from kicomav.plugins import kavutil
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

# Pattern for icon dimensions
p_name = re.compile(r"(\d+)x(\d+)")


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """Icon file format handler plugin.

    This plugin provides functionality for:
    - Detecting ICO (Icon) format
    - Listing icon images within ICO files
    - Extracting individual icon images
    """

    def __init__(self):
        """Initialize the Icon plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Icon Engine",
            kmd_name="icon",
        )

    def __get_handle(self, filename):
        """Get or create handle for icon file.

        Args:
            filename: Path to icon file

        Returns:
            File data buffer or None
        """
        if filename in self.handle:
            return self.handle.get(filename, None)

        try:
            with open(filename, "rb") as fp:
                buf = fp.read()
            self.handle[filename] = buf
            return buf

        except (IOError, OSError) as e:
            logger.debug("Failed to open icon file %s: %s", filename, e)

        return None

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect ICO format.

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
            if mm[:4] == b"\x00\x00\x01\x00":  # Check the header
                ret["ff_icon"] = kavutil.get_uint16(mm, 4)
                return ret

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive (icon images).

        Args:
            filename: Path to icon file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_icon" not in fileformat:
            return file_scan_list

        try:
            num = fileformat["ff_icon"]
            mm = self.__get_handle(filename)
            if mm is None:
                return file_scan_list

            for i in range(num):
                off = 6 + (16 * i)
                w = mm[off]
                h = 256 if mm[off + 1] == 0 else mm[off + 1]

                name = "%dx%d" % (w, h)
                file_scan_list.append(["arc_icon", name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except (IndexError, struct.error) as e:
            logger.debug("Archive list parse error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive (icon image).

        Args:
            arc_engine_id: Engine ID ('arc_icon')
            arc_name: Path to icon file
            fname_in_arc: Name of icon to extract (e.g., '32x32')

        Returns:
            Extracted icon data, or None on error
        """
        if arc_engine_id != "arc_icon":
            return None

        try:
            mm = self.__get_handle(arc_name)
            if mm is None:
                return None

            num = kavutil.get_uint16(mm, 4)

            if p := p_name.search(fname_in_arc):
                fw = int(p.groups()[0])
                fh = int(p.groups()[1])

                for i in range(num):
                    off = 6 + (16 * i)
                    w = mm[off]
                    h = 256 if mm[off + 1] == 0 else mm[off + 1]

                    if w == fw and h == fh:
                        img_size = kavutil.get_uint32(mm, off + 8)
                        img_off = kavutil.get_uint32(mm, off + 12)
                        return mm[img_off : img_off + img_size]

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                self.handle.pop(fname, None)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
