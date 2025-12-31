# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
TNEF (Transport Neutral Encapsulation Format) Archive Engine Plugin

This plugin handles TNEF files (winmail.dat) for scanning attachments.
Supports:
- TNEF format detection (signature 0x223E9F78)
- Attachment extraction
- RTF body extraction
- MAPI property parsing
"""

import struct
import os
import re
import logging
from enum import IntEnum
from typing import Optional, Dict, Any, List

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

# TNEF signature (little-endian)
TNEF_SIGNATURE = 0x223E9F78


# Attribute levels
class AttrLevel(IntEnum):
    MESSAGE = 0x01
    ATTACHMENT = 0x02


# TNEF attribute IDs
class TnefAttrId(IntEnum):
    # Message level
    TNEF_VERSION = 0x00089006
    OEM_CODEPAGE = 0x00069007
    MESSAGE_CLASS = 0x00078008
    MESSAGE_CLASS2 = 0x00050008
    MAPI_PROPS = 0x00069003
    SUBJECT = 0x00018004
    BODY = 0x0002800C

    # Attachment level
    ATTACH_REND_DATA = 0x00069002
    ATTACH_DATA = 0x0006800F
    ATTACH_TITLE = 0x00018010
    ATTACH_META_FILE = 0x00068011
    ATTACH_CREATE_DATE = 0x00038012
    ATTACH_MODIFY_DATE = 0x00038013
    ATTACHMENT = 0x00069005  # MAPI attachment props


# MAPI property types
class MapiType(IntEnum):
    SHORT = 0x0002
    LONG = 0x0003
    BOOLEAN = 0x000B
    LONGLONG = 0x0014
    DOUBLE = 0x0005
    STRING8 = 0x001E
    UNICODE = 0x001F
    SYSTIME = 0x0040
    BINARY = 0x0102
    CLSID = 0x0048
    MV_FLAG = 0x1000


# MAPI property IDs
class MapiProp(IntEnum):
    RTF_COMPRESSED = 0x1009
    ATTACH_FILENAME = 0x3704
    ATTACH_LONG_FILENAME = 0x3707
    ATTACH_DATA_BIN = 0x3701


# RTF compression magic values
RTF_COMPRESSED_MAGIC = 0x75465A4C  # "LZFu"
RTF_UNCOMPRESSED_MAGIC = 0x414E4D  # "MELA"


class RTFDecompressor:
    """RTF LZFu decompressor."""

    INIT_DICT = (
        b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}"
        b"{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript "
        b"\\fdecor MS Sans SesijSymbolArialTimes New RomanCourier"
        b"{\\colortbl\\red0\\green0\\blue0\r\n\\par "
        b"\\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"
    )
    INIT_DICT_SIZE = 207

    @classmethod
    def decompress(cls, data: bytes) -> bytes:
        """Decompress LZFu compressed RTF data."""
        if len(data) < 16:
            return b""

        comp_size = struct.unpack("<I", data[0:4])[0]
        raw_size = struct.unpack("<I", data[4:8])[0]
        magic = struct.unpack("<I", data[8:12])[0]
        crc = struct.unpack("<I", data[12:16])[0]

        if magic == RTF_UNCOMPRESSED_MAGIC:
            return data[16 : 16 + raw_size]

        if magic != RTF_COMPRESSED_MAGIC:
            return b""

        dictionary = bytearray(4096)
        dictionary[: cls.INIT_DICT_SIZE] = cls.INIT_DICT[: cls.INIT_DICT_SIZE]
        write_pos = cls.INIT_DICT_SIZE

        comp_data = data[16:]
        output = bytearray()
        pos = 0

        while pos < len(comp_data) and len(output) < raw_size:
            if pos >= len(comp_data):
                break
            control = comp_data[pos]
            pos += 1

            for i in range(8):
                if pos >= len(comp_data) or len(output) >= raw_size:
                    break

                if control & (1 << i):
                    # Reference - read big-endian (per MS docs)
                    if pos + 1 >= len(comp_data):
                        break
                    ref_hi = comp_data[pos]
                    ref_lo = comp_data[pos + 1]
                    pos += 2

                    offset = (ref_hi << 4) | (ref_lo >> 4)
                    length = (ref_lo & 0x0F) + 2

                    for j in range(length):
                        if len(output) >= raw_size:
                            break
                        byte = dictionary[(offset + j) % 4096]
                        output.append(byte)
                        dictionary[write_pos % 4096] = byte
                        write_pos += 1
                else:
                    byte = comp_data[pos]
                    pos += 1
                    output.append(byte)
                    dictionary[write_pos % 4096] = byte
                    write_pos += 1

        return bytes(output)


class TNEFHandle:
    """TNEF file handle for archive operations."""

    def __init__(self, filename: str):
        """Initialize TNEF handle.

        Args:
            filename: Path to TNEF file
        """
        self.filename = filename
        self.attachments: List[Dict[str, Any]] = []
        self.rtf_body: bytes = b""
        self.codepage = "cp949"

    def open(self) -> bool:
        """Open and parse the TNEF file.

        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.filename, "rb") as f:
                return self._parse(f)
        except (IOError, OSError) as e:
            logger.debug("Failed to open TNEF file %s: %s", self.filename, e)
            return False
        except Exception as e:
            logger.debug("Failed to parse TNEF file %s: %s", self.filename, e)
            return False

    def close(self):
        """Close the TNEF file handle."""
        self.attachments.clear()
        self.rtf_body = b""

    def _read_bytes(self, fp, size: int) -> bytes:
        """Read exact number of bytes from file."""
        data = fp.read(size)
        if len(data) < size:
            raise ValueError(f"Unexpected EOF: expected {size}, got {len(data)}")
        return data

    def _read_u8(self, fp) -> int:
        return struct.unpack("<B", self._read_bytes(fp, 1))[0]

    def _read_u16(self, fp) -> int:
        return struct.unpack("<H", self._read_bytes(fp, 2))[0]

    def _read_u32(self, fp) -> int:
        return struct.unpack("<I", self._read_bytes(fp, 4))[0]

    def _parse_string(self, data: bytes) -> str:
        """Parse string with null terminator removal."""
        if data.endswith(b"\x00"):
            data = data[:-1]

        for encoding in ["utf-8", self.codepage, "cp1252", "euc-kr", "latin-1"]:
            try:
                return data.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return data.decode("latin-1", errors="replace")

    def _parse_mapi_props(self, data: bytes) -> Dict[int, Any]:
        """Parse MAPI properties."""
        props = {}
        pos = 0

        if len(data) < 4:
            return props

        prop_count = struct.unpack("<I", data[0:4])[0]
        pos = 4

        for _ in range(prop_count):
            if pos + 4 > len(data):
                break

            prop_tag = struct.unpack("<I", data[pos : pos + 4])[0]
            pos += 4

            prop_type = prop_tag & 0xFFFF
            prop_id = prop_tag >> 16

            # Named Property handling
            if prop_id >= 0x8000:
                if pos + 16 > len(data):
                    break
                pos += 16  # Skip GUID

                if pos + 4 > len(data):
                    break
                kind = struct.unpack("<I", data[pos : pos + 4])[0]
                pos += 4

                if kind == 0:
                    if pos + 4 > len(data):
                        break
                    pos += 4
                else:
                    if pos + 4 > len(data):
                        break
                    name_len = struct.unpack("<I", data[pos : pos + 4])[0]
                    pos += 4
                    pos += name_len
                    pos = (pos + 3) & ~3

            value = None
            base_type = prop_type & ~MapiType.MV_FLAG

            try:
                if base_type == MapiType.SHORT:
                    if pos + 2 > len(data):
                        break
                    value = struct.unpack("<H", data[pos : pos + 2])[0]
                    pos += 4

                elif base_type == MapiType.LONG:
                    if pos + 4 > len(data):
                        break
                    value = struct.unpack("<I", data[pos : pos + 4])[0]
                    pos += 4

                elif base_type == MapiType.BOOLEAN:
                    if pos + 2 > len(data):
                        break
                    value = struct.unpack("<H", data[pos : pos + 2])[0] != 0
                    pos += 4

                elif base_type == MapiType.LONGLONG:
                    if pos + 8 > len(data):
                        break
                    value = struct.unpack("<Q", data[pos : pos + 8])[0]
                    pos += 8

                elif base_type == MapiType.DOUBLE:
                    if pos + 8 > len(data):
                        break
                    value = struct.unpack("<d", data[pos : pos + 8])[0]
                    pos += 8

                elif base_type == MapiType.SYSTIME:
                    if pos + 8 > len(data):
                        break
                    pos += 8

                elif base_type in (MapiType.STRING8, MapiType.UNICODE):
                    if pos + 4 > len(data):
                        break
                    count = struct.unpack("<I", data[pos : pos + 4])[0]
                    pos += 4

                    values = []
                    for _ in range(count):
                        if pos + 4 > len(data):
                            break
                        str_len = struct.unpack("<I", data[pos : pos + 4])[0]
                        pos += 4
                        if pos + str_len > len(data):
                            break
                        str_data = data[pos : pos + str_len]
                        pos += str_len
                        pos = (pos + 3) & ~3

                        if base_type == MapiType.UNICODE:
                            try:
                                values.append(str_data.decode("utf-16-le").rstrip("\x00"))
                            except Exception:
                                values.append(str_data.decode("latin-1", errors="replace"))
                        else:
                            values.append(self._parse_string(str_data))

                    value = values[0] if len(values) == 1 else values if values else None

                elif base_type == MapiType.BINARY:
                    if pos + 4 > len(data):
                        break
                    count = struct.unpack("<I", data[pos : pos + 4])[0]
                    pos += 4

                    values = []
                    for _ in range(count):
                        if pos + 4 > len(data):
                            break
                        bin_len = struct.unpack("<I", data[pos : pos + 4])[0]
                        pos += 4
                        if pos + bin_len > len(data):
                            break
                        values.append(data[pos : pos + bin_len])
                        pos += bin_len
                        pos = (pos + 3) & ~3

                    value = values[0] if len(values) == 1 else values if values else None

                elif base_type == MapiType.CLSID:
                    if pos + 16 > len(data):
                        break
                    value = data[pos : pos + 16]
                    pos += 16

                else:
                    continue

            except (struct.error, IndexError):
                continue

            if value is not None:
                props[prop_id] = value

        return props

    def _parse_attribute(self, fp) -> Optional[Dict[str, Any]]:
        """Parse a single TNEF attribute."""
        try:
            level = self._read_u8(fp)
            if level not in (AttrLevel.MESSAGE, AttrLevel.ATTACHMENT):
                return None

            attr_id = self._read_u32(fp)
            length = self._read_u32(fp)
            data = self._read_bytes(fp, length)
            checksum = self._read_u16(fp)

            return {"level": level, "attr_id": attr_id, "data": data, "checksum": checksum}
        except (struct.error, ValueError):
            return None

    def _parse(self, fp) -> bool:
        """Parse TNEF file."""
        # Check signature
        signature = self._read_u32(fp)
        if signature != TNEF_SIGNATURE:
            return False

        # Read legacy key
        self._read_u16(fp)

        current_attachment: Optional[Dict[str, Any]] = None

        while True:
            try:
                attr = self._parse_attribute(fp)
                if attr is None:
                    break

                if attr["level"] == AttrLevel.MESSAGE:
                    self._process_message_attribute(attr)
                else:
                    # New attachment start
                    if attr["attr_id"] == TnefAttrId.ATTACH_REND_DATA:
                        if current_attachment and (
                            current_attachment.get("data") or current_attachment.get("filename")
                        ):
                            self.attachments.append(current_attachment)
                        current_attachment = {"filename": "", "long_filename": "", "data": b""}

                    if current_attachment:
                        self._process_attachment_attribute(attr, current_attachment)

            except Exception:
                break

        if current_attachment and (current_attachment.get("data") or current_attachment.get("filename")):
            self.attachments.append(current_attachment)

        return True

    def _process_message_attribute(self, attr: Dict[str, Any]):
        """Process message-level attribute."""
        attr_id = attr["attr_id"]
        data = attr["data"]

        if attr_id == TnefAttrId.OEM_CODEPAGE:
            if len(data) >= 4:
                cp = struct.unpack("<I", data[:4])[0]
                cp_map = {949: "cp949", 932: "cp932", 936: "cp936", 950: "cp950", 1252: "cp1252", 65001: "utf-8"}
                self.codepage = cp_map.get(cp, f"cp{cp}")

        elif attr_id == TnefAttrId.MAPI_PROPS:
            props = self._parse_mapi_props(data)

            if MapiProp.RTF_COMPRESSED in props:
                rtf_data = props[MapiProp.RTF_COMPRESSED]
                self.rtf_body = RTFDecompressor.decompress(rtf_data)

    def _process_attachment_attribute(self, attr: Dict[str, Any], attachment: Dict[str, Any]):
        """Process attachment-level attribute."""
        attr_id = attr["attr_id"]
        data = attr["data"]

        if attr_id == TnefAttrId.ATTACH_TITLE:
            attachment["filename"] = self._parse_string(data)

        elif attr_id == TnefAttrId.ATTACH_DATA:
            attachment["data"] = data

        elif attr_id == TnefAttrId.ATTACHMENT:
            props = self._parse_mapi_props(data)

            if MapiProp.ATTACH_LONG_FILENAME in props:
                attachment["long_filename"] = props[MapiProp.ATTACH_LONG_FILENAME]
            if MapiProp.ATTACH_FILENAME in props and not attachment.get("filename"):
                attachment["filename"] = props[MapiProp.ATTACH_FILENAME]
            if MapiProp.ATTACH_DATA_BIN in props:
                attachment["data"] = props[MapiProp.ATTACH_DATA_BIN]

    def list_files(self) -> List[str]:
        """Get list of extractable files.

        Returns:
            List of filenames (attachments + RTF body if present)
        """
        files = []

        # Add RTF body if present
        if self.rtf_body:
            files.append("message.rtf")

        # Add attachments
        for att in self.attachments:
            filename = att.get("long_filename") or att.get("filename") or "attachment"
            filename = self._sanitize_filename(filename)
            if filename:
                files.append(filename)

        return files

    def extract_file(self, filename: str) -> Optional[bytes]:
        """Extract file data by filename.

        Args:
            filename: File to extract

        Returns:
            File data or None if not found
        """
        # Check RTF body
        if filename == "message.rtf" and self.rtf_body:
            return self.rtf_body

        # Check attachments
        for att in self.attachments:
            att_filename = att.get("long_filename") or att.get("filename") or "attachment"
            att_filename = self._sanitize_filename(att_filename)
            if att_filename == filename:
                return att.get("data")

        return None

    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe extraction."""
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename)
        filename = filename.strip(". ")
        return filename


def is_valid_tnef(data: bytes) -> bool:
    """Check if data is a valid TNEF file.

    Args:
        data: File data to check

    Returns:
        True if valid TNEF, False otherwise
    """
    if len(data) < 6:
        return False

    try:
        signature = struct.unpack("<I", data[:4])[0]
        return signature == TNEF_SIGNATURE
    except struct.error:
        return False


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """TNEF archive handler plugin.

    This plugin provides functionality for:
    - Detecting TNEF format (winmail.dat)
    - Listing attachments within TNEF files
    - Extracting attachments and RTF body from TNEF files
    """

    def __init__(self):
        """Initialize the TNEF plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="TNEF Archive Engine",
            kmd_name="tnef",
        )

    def _custom_init(self) -> int:
        """Custom initialization for TNEF plugin.

        Returns:
            0 for success
        """
        return 0

    def _custom_uninit(self) -> int:
        """Custom cleanup for TNEF plugin.

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

    def __get_handle(self, filename: str) -> Optional[TNEFHandle]:
        """Get or create handle for TNEF file.

        Args:
            filename: Path to TNEF file

        Returns:
            TNEFHandle object or None
        """
        if filename in self.handle:
            return self.handle.get(filename)

        tnef_handle = TNEFHandle(filename)
        if tnef_handle.open():
            self.handle[filename] = tnef_handle
            return tnef_handle

        return None

    def format(self, filehandle, filename, filename_ex) -> Optional[Dict[str, Any]]:
        """Analyze and detect TNEF format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to TNEF file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        ret = {}

        try:
            mm = filehandle

            if is_valid_tnef(bytes(mm)):
                ret["ff_tnef"] = "tnef"
                return ret

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

    def arclist(self, filename: str, fileformat: Dict[str, Any], password: Optional[str] = None) -> List[List[str]]:
        """List files in the TNEF archive.

        Args:
            filename: Path to TNEF file
            fileformat: Format info from format() method
            password: Not used for TNEF (no encryption support)

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        try:
            if "ff_tnef" in fileformat:
                tnef_handle = self.__get_handle(filename)
                if tnef_handle:
                    for file_name in tnef_handle.list_files():
                        # CWE-22: Path traversal prevention
                        if k2security.is_safe_archive_member(file_name):
                            file_scan_list.append(["arc_tnef", file_name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id: str, arc_name: str, fname_in_arc: str) -> Optional[bytes]:
        """Extract a file from the TNEF archive.

        Args:
            arc_engine_id: Engine ID ('arc_tnef')
            arc_name: Path to TNEF file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.debug("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_tnef":
            return None

        try:
            tnef_handle = self.handle.get(arc_name)
            if tnef_handle is None:
                return None

            return tnef_handle.extract_file(fname_in_arc)

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open TNEF handles."""
        for fname in list(self.handle.keys()):
            try:
                tnef_handle = self.handle[fname]
                if hasattr(tnef_handle, "close"):
                    tnef_handle.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
