# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
Attach Engine Plugin

This plugin handles attached data extraction from files.
"""

import contextlib
import os
import logging

from kicomav.plugins import kernel
from kicomav.plugins import kavutil
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """Attach data handler plugin.

    This plugin provides functionality for:
    - Extracting attached data from files
    - Creating files with attached data removed
    """

    def __init__(self):
        """Initialize the Attach plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Attach Engine",
            kmd_name="attach",
        )

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["make_arc_type"] = kernel.MASTER_PACK
        return info

    def arclist(self, filename, fileformat, password=None):
        """List attached data in the file.

        Args:
            filename: Path to file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_attach" in fileformat:
            pos = fileformat["ff_attach"]["Attached_Pos"]
            size = fileformat["ff_attach"]["Attached_Size"]
            file_scan_list.append([f"arc_attach:{pos}:{size}", "Attached"])

            if self.verbose:
                self._print_attach_debug_info(filename, pos, size)

        return file_scan_list

    def _print_attach_debug_info(self, filename, pos, size):
        """Print debug information about attached data."""
        print("-" * 79)
        kavutil.vprint("Engine")
        kavutil.vprint(None, "Engine", "attach")
        kavutil.vprint(None, "File name", os.path.split(filename)[-1])
        kavutil.vprint(None, "Attach Point", "0x%08X" % pos)
        kavutil.vprint(None, "Attach Size", "0x%08X" % size)

        try:
            with open(filename, "rb") as fp:
                fp.seek(pos)
                buf = fp.read(0x80)
                print()
                kavutil.vprint("Attach Point (Raw)")
                print()
                kavutil.HexDump().Buffer(buf, 0, 0x80)
        except (IOError, OSError) as e:
            logger.debug("Error reading attach point: %s", e)

        print()

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract attached data from the file.

        Args:
            arc_engine_id: Engine ID (arc_attach:pos:size)
            arc_name: Path to file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        try:
            if arc_engine_id.startswith("arc_attach:"):
                t = arc_engine_id.split(":")
                pos = int(t[1])
                size = int(t[2])

                with open(arc_name, "rb") as fp:
                    fp.seek(pos)
                    return fp.read(size)

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create file with attached data removed or replaced.

        Args:
            arc_engine_id: Engine ID (arc_attach:pos:size)
            arc_name: Path to file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if not arc_engine_id.startswith("arc_attach:"):
            return False

        try:
            t = arc_engine_id.split(":")
            pos = int(t[1])

            file_info = file_infos[0]
            rname = file_info.get_filename()

            # Read original file
            with open(arc_name, "rb") as fp:
                t_buf = fp.read()

            # Build new content
            if os.path.exists(rname):
                with open(rname, "rb") as fp:
                    buf = fp.read()
                data = t_buf[:pos] + buf
            else:
                data = t_buf[:pos]

            # Write clean file
            with open(arc_name, "wb") as wp:
                wp.write(data)

            return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
