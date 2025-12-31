# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)
# Reference : https://github.com/unixfreak0037/officeparser/blob/master/officeparser.py (696~)

"""
Ole10Native Archive Engine Plugin

This plugin handles Ole10Native stream format for scanning and manipulation.
"""

import contextlib
import logging
import os
import struct

from kicomav.plugins import kernel
from kicomav.plugins import kavutil
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

MAX_PATH = 512


def find_null_bytes(byte_data):
    return [i for i, b in enumerate(byte_data) if b == 0]


def analysis_ole10native(mm, verbose=False):
    """Analyze Ole10Native stream format.

    Args:
        mm: File data (memory mapped)
        verbose: Debug mode flag

    Returns:
        Dictionary with format info, or None if not recognized
    """
    fileformat = {}

    try:
        if mm[:2] == b"\x02\x00":
            size = len(mm)
            fileformat["size"] = size

            index = find_null_bytes(mm[2:])
            fileformat["label"] = mm[2 : 2 + index[0]].decode("utf-8")

            off = 2 + len(fileformat["label"]) + 1
            index = find_null_bytes(mm[off:])
            fileformat["fname"] = mm[off : off + index[0]].decode("utf-8")

            off += len(fileformat["fname"]) + 1
            off += 2  # flag

            unknown_size = int(mm[off])
            off += 1 + unknown_size + 2

            index = find_null_bytes(mm[off:])
            fileformat["command"] = mm[off : off + index[0]].decode("utf-8")

            off += len(fileformat["command"]) + 1

            data_size = kavutil.get_uint32(mm, off)

            fileformat["data_off"] = off + 4
            fileformat["data_size"] = data_size

            if len(mm) < off + data_size:  # Error
                raise ValueError

            if verbose:
                print()
                kavutil.vprint("Ole10Native Stream")
                kavutil.vprint(None, "Size", f"0x{size:08X}")
                kavutil.vprint(None, "Label", fileformat["label"])
                kavutil.vprint(None, "File Name", fileformat["fname"])
                kavutil.vprint(None, "Command Line", fileformat["command"])
                kavutil.vprint(None, "Data Offset", f"0x{off + 4:08X}")
                kavutil.vprint(None, "Data Size", f"0x{data_size:08X}")

                print()
                kavutil.vprint("Data Dump")
                print()
                kavutil.HexDump().Buffer(mm[:], off + 4, 0x80)
                print()

            return fileformat
    except ValueError:
        pass
    except struct.error:
        pass

    return None


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """Ole10Native archive handler plugin.

    This plugin provides functionality for:
    - Detecting Ole10Native stream format
    - Extracting embedded files from Ole10Native streams
    """

    def __init__(self):
        """Initialize the Ole10Native plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Ole10Native Engine",
            kmd_name="olenative",
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
        """Analyze and detect Ole10Native format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or empty dict if not recognized
        """
        ret = {}

        try:
            mm = filehandle

            if mm[:2] == b"\x02\x00" and filename_ex.find("_Ole10Native") != -1:
                if fileformat := analysis_ole10native(mm, self.verbose):
                    ret = {"ff_ole10native": fileformat}

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return ret

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive.

        Args:
            filename: Path to archive file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_ole10native" not in fileformat:
            return file_scan_list

        try:
            fformat = fileformat["ff_ole10native"]
            name = fformat["label"]  # File name hidden inside OLE

            # CWE-22: Path traversal prevention
            if not k2security.is_safe_archive_member(name):
                logger.warning("Unsafe archive member rejected: %s in %s", name, filename)
                return file_scan_list

            off = fformat["data_off"]
            data_size = fformat["data_size"]

            arc_name = f"arc_ole10native:{off}:{data_size}"
            file_scan_list.append([arc_name, name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_ole10native:offset:size')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id.find("arc_ole10native:") == -1:
            return None

        try:
            val = arc_engine_id.split(":")
            off = int(val[1])
            size = int(val[2])

            with open(arc_name, "rb") as f:
                buf = f.read()
                return buf[off : off + size]

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        pass  # No persistent handles to close

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create an Ole10Native archive.

        Args:
            arc_engine_id: Engine ID ('arc_ole10native:offset:size')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id.find("arc_ole10native:") == -1:
            return False

        try:
            val = arc_engine_id.split(":")
            off = int(val[1])
            size = int(val[2])

            with open(arc_name, "rb") as fp:
                ole10native_data = fp.read()

            file_info = file_infos[0]
            rname = file_info.get_filename()

            with open(rname, "rb") as fp:
                buf = fp.read()

                new_data = ole10native_data[: off - 4]  # Delete original data
                new_data += struct.pack("<L", len(buf)) + buf  # Replace with new data
                new_data += ole10native_data[off + size :]

                with open(arc_name, "wb") as out_fp:
                    out_fp.write(new_data)

            return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
