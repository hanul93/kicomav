# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
ISO 9660 Archive Engine Plugin

This plugin handles ISO 9660 image files for scanning.
Supports:
- ISO 9660 basic format
- Joliet extension (Unicode filenames)
"""

import struct
import logging
from typing import Optional, Dict, Any, List, Generator
from dataclasses import dataclass
from datetime import datetime

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

# ISO 9660 constants
SECTOR_SIZE = 2048
SYSTEM_AREA_SECTORS = 16
PRIMARY_VOLUME_DESCRIPTOR_TYPE = 1
SUPPLEMENTARY_VOLUME_DESCRIPTOR_TYPE = 2
VOLUME_DESCRIPTOR_SET_TERMINATOR = 255

# Directory record flags
FLAG_HIDDEN = 0x01
FLAG_DIRECTORY = 0x02
FLAG_ASSOCIATED = 0x04
FLAG_EXTENDED = 0x08
FLAG_PERMISSIONS = 0x10
FLAG_NOT_FINAL = 0x80

# ISO 9660 signature
ISO_SIGNATURE = b"CD001"


@dataclass
class VolumeDescriptor:
    """Volume descriptor information."""

    type: int
    identifier: str
    version: int
    system_identifier: str
    volume_identifier: str
    volume_space_size: int
    volume_set_size: int
    volume_sequence_number: int
    logical_block_size: int
    path_table_size: int
    root_directory_record: bytes
    is_joliet: bool = False


@dataclass
class DirectoryRecord:
    """Directory record information."""

    length: int
    extended_attr_length: int
    extent_location: int
    data_length: int
    recording_date: datetime
    flags: int
    file_unit_size: int
    interleave_gap_size: int
    volume_sequence_number: int
    file_identifier_length: int
    file_identifier: str
    is_directory: bool
    is_hidden: bool
    raw_identifier: bytes


class ISO9660Handle:
    """ISO 9660 file handle for archive operations."""

    def __init__(self, filename: str):
        """Initialize ISO handle.

        Args:
            filename: Path to ISO file
        """
        self.filename = filename
        self.fp = None
        self.primary_descriptor: Optional[VolumeDescriptor] = None
        self.joliet_descriptor: Optional[VolumeDescriptor] = None
        self.use_joliet = False
        self._file_cache: Dict[str, DirectoryRecord] = {}

    def open(self) -> bool:
        """Open the ISO file.

        Returns:
            True if successful, False otherwise
        """
        try:
            self.fp = open(self.filename, "rb")
            self._parse_volume_descriptors()
            return True
        except (IOError, OSError, ValueError) as e:
            logger.debug("Failed to open ISO file %s: %s", self.filename, e)
            if self.fp:
                self.fp.close()
                self.fp = None
            return False

    def close(self):
        """Close the ISO file."""
        if self.fp:
            self.fp.close()
            self.fp = None
        self._file_cache.clear()

    def _read_sector(self, sector_num: int, count: int = 1) -> bytes:
        """Read sectors from ISO file.

        Args:
            sector_num: Starting sector number
            count: Number of sectors to read

        Returns:
            Sector data
        """
        self.fp.seek(sector_num * SECTOR_SIZE)
        return self.fp.read(SECTOR_SIZE * count)

    def _parse_datetime(self, data: bytes) -> datetime:
        """Parse directory record datetime (7-byte format).

        Args:
            data: 7 bytes of datetime data

        Returns:
            Parsed datetime object
        """
        if len(data) < 7:
            return datetime(1970, 1, 1)

        year = 1900 + data[0]
        month = max(1, min(12, data[1]))
        day = max(1, min(31, data[2]))
        hour = min(23, data[3])
        minute = min(59, data[4])
        second = min(59, data[5])

        try:
            return datetime(year, month, day, hour, minute, second)
        except ValueError:
            return datetime(1970, 1, 1)

    def _parse_volume_descriptor(self, data: bytes) -> Optional[VolumeDescriptor]:
        """Parse volume descriptor.

        Args:
            data: Sector data containing volume descriptor

        Returns:
            VolumeDescriptor object or None
        """
        vd_type = data[0]
        identifier = data[1:6].decode("ascii", errors="ignore")

        if identifier != "CD001":
            return None

        version = data[6]

        # Check for Joliet extension
        is_joliet = False
        if vd_type == SUPPLEMENTARY_VOLUME_DESCRIPTOR_TYPE:
            escape_sequences = data[88:120]
            if b"%/@" in escape_sequences or b"%/C" in escape_sequences or b"%/E" in escape_sequences:
                is_joliet = True

        # String decoding
        if is_joliet:

            def decode_str(b):
                return b.decode("utf-16-be", errors="ignore").strip()

        else:

            def decode_str(b):
                return b.decode("ascii", errors="ignore").strip()

        return VolumeDescriptor(
            type=vd_type,
            identifier=identifier,
            version=version,
            system_identifier=decode_str(data[8:40]),
            volume_identifier=decode_str(data[40:72]),
            volume_space_size=struct.unpack("<I", data[80:84])[0],
            volume_set_size=struct.unpack("<H", data[120:122])[0],
            volume_sequence_number=struct.unpack("<H", data[124:126])[0],
            logical_block_size=struct.unpack("<H", data[128:130])[0],
            path_table_size=struct.unpack("<I", data[132:136])[0],
            root_directory_record=data[156:190],
            is_joliet=is_joliet,
        )

    def _parse_volume_descriptors(self):
        """Parse all volume descriptors."""
        sector = SYSTEM_AREA_SECTORS  # Volume descriptors start at sector 16

        while True:
            data = self._read_sector(sector)
            vd_type = data[0]

            if vd_type == VOLUME_DESCRIPTOR_SET_TERMINATOR:
                break

            descriptor = self._parse_volume_descriptor(data)

            if descriptor:
                if descriptor.type == PRIMARY_VOLUME_DESCRIPTOR_TYPE:
                    self.primary_descriptor = descriptor
                elif descriptor.type == SUPPLEMENTARY_VOLUME_DESCRIPTOR_TYPE and descriptor.is_joliet:
                    self.joliet_descriptor = descriptor

            sector += 1

            # Safety limit: search up to 100 sectors
            if sector > SYSTEM_AREA_SECTORS + 100:
                break

        if not self.primary_descriptor:
            raise ValueError("Primary Volume Descriptor not found")

        # Prefer Joliet if available
        self.use_joliet = self.joliet_descriptor is not None

    def _parse_directory_record(self, data: bytes, offset: int = 0) -> Optional[DirectoryRecord]:
        """Parse directory record.

        Args:
            data: Directory data
            offset: Offset within data

        Returns:
            DirectoryRecord object or None
        """
        if offset >= len(data):
            return None

        length = data[offset]
        if length == 0:
            return None

        if offset + length > len(data):
            return None

        record_data = data[offset : offset + length]

        extended_attr_length = record_data[1]
        extent_location = struct.unpack("<I", record_data[2:6])[0]
        data_length = struct.unpack("<I", record_data[10:14])[0]
        recording_date = self._parse_datetime(record_data[18:25])
        flags = record_data[25]
        file_unit_size = record_data[26]
        interleave_gap_size = record_data[27]
        volume_sequence_number = struct.unpack("<H", record_data[28:30])[0]
        file_identifier_length = record_data[32]

        raw_identifier = record_data[33 : 33 + file_identifier_length]

        # Decode file identifier
        if self.use_joliet:
            try:
                file_identifier = raw_identifier.decode("utf-16-be", errors="ignore")
            except Exception:
                file_identifier = raw_identifier.decode("ascii", errors="ignore")
        else:
            file_identifier = raw_identifier.decode("ascii", errors="ignore")

        # Handle special directories
        if file_identifier_length == 1:
            if raw_identifier == b"\x00":
                file_identifier = "."
            elif raw_identifier == b"\x01":
                file_identifier = ".."

        # Remove version number (e.g., FILE.TXT;1 -> FILE.TXT)
        if ";" in file_identifier:
            file_identifier = file_identifier.split(";")[0]

        return DirectoryRecord(
            length=length,
            extended_attr_length=extended_attr_length,
            extent_location=extent_location,
            data_length=data_length,
            recording_date=recording_date,
            flags=flags,
            file_unit_size=file_unit_size,
            interleave_gap_size=interleave_gap_size,
            volume_sequence_number=volume_sequence_number,
            file_identifier_length=file_identifier_length,
            file_identifier=file_identifier,
            is_directory=bool(flags & FLAG_DIRECTORY),
            is_hidden=bool(flags & FLAG_HIDDEN),
            raw_identifier=raw_identifier,
        )

    def _iterate_directory(self, extent_location: int, data_length: int) -> Generator[DirectoryRecord, None, None]:
        """Iterate over directory contents.

        Args:
            extent_location: Directory extent location
            data_length: Directory data length

        Yields:
            DirectoryRecord objects
        """
        sectors_to_read = (data_length + SECTOR_SIZE - 1) // SECTOR_SIZE
        data = self._read_sector(extent_location, sectors_to_read)

        offset = 0
        while offset < data_length:
            # Skip to next sector if record length is 0 at sector boundary
            if data[offset] == 0:
                next_sector_offset = ((offset // SECTOR_SIZE) + 1) * SECTOR_SIZE
                if next_sector_offset >= data_length:
                    break
                offset = next_sector_offset
                continue

            record = self._parse_directory_record(data, offset)
            if record is None:
                break

            yield record
            offset += record.length

    def _get_root_directory_record(self) -> DirectoryRecord:
        """Get root directory record.

        Returns:
            Root DirectoryRecord
        """
        descriptor = self.joliet_descriptor if self.use_joliet else self.primary_descriptor
        return self._parse_directory_record(descriptor.root_directory_record)

    def list_files(self) -> Generator[DirectoryRecord, None, None]:
        """List all files in ISO (non-recursive for flat listing).

        Yields:
            DirectoryRecord objects for files only
        """
        root = self._get_root_directory_record()
        yield from self._list_files_recursive(root.extent_location, root.data_length, "")

    def _list_files_recursive(
        self, extent_location: int, data_length: int, current_path: str
    ) -> Generator[DirectoryRecord, None, None]:
        """Recursively list files.

        Args:
            extent_location: Directory extent location
            data_length: Directory data length
            current_path: Current path prefix

        Yields:
            DirectoryRecord objects with updated file_identifier as full path
        """
        for record in self._iterate_directory(extent_location, data_length):
            if record.file_identifier in (".", ".."):
                continue

            # Build full path for caching
            if current_path:
                full_path = f"{current_path}/{record.file_identifier}"
            else:
                full_path = record.file_identifier

            if record.is_directory:
                yield from self._list_files_recursive(record.extent_location, record.data_length, full_path)
            else:
                # Cache the record for later extraction
                self._file_cache[full_path] = record
                # Return a copy with the full path
                yield DirectoryRecord(
                    length=record.length,
                    extended_attr_length=record.extended_attr_length,
                    extent_location=record.extent_location,
                    data_length=record.data_length,
                    recording_date=record.recording_date,
                    flags=record.flags,
                    file_unit_size=record.file_unit_size,
                    interleave_gap_size=record.interleave_gap_size,
                    volume_sequence_number=record.volume_sequence_number,
                    file_identifier_length=record.file_identifier_length,
                    file_identifier=full_path,
                    is_directory=record.is_directory,
                    is_hidden=record.is_hidden,
                    raw_identifier=record.raw_identifier,
                )

    def extract_file(self, file_path: str) -> Optional[bytes]:
        """Extract a file from the ISO.

        Args:
            file_path: Path to file within ISO

        Returns:
            File data or None if not found
        """
        # Check cache first
        record = self._file_cache.get(file_path)

        if record is None:
            # Try to find the file by listing
            for rec in self.list_files():
                if rec.file_identifier == file_path:
                    record = self._file_cache.get(file_path)
                    break

        if record is None:
            return None

        if record.is_directory:
            return None

        # Read file data
        self.fp.seek(record.extent_location * SECTOR_SIZE)
        return self.fp.read(record.data_length)


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """ISO 9660 archive handler plugin.

    This plugin provides functionality for:
    - Detecting ISO 9660 image format
    - Listing files within ISO images
    - Extracting files from ISO images
    """

    def __init__(self):
        """Initialize the ISO plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="ISO Archive Engine",
            kmd_name="iso",
        )

    def _custom_init(self) -> int:
        """Custom initialization for ISO plugin.

        Returns:
            0 for success
        """
        return 0

    def _custom_uninit(self) -> int:
        """Custom cleanup for ISO plugin.

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

    def __get_handle(self, filename: str) -> Optional[ISO9660Handle]:
        """Get or create handle for ISO file.

        Args:
            filename: Path to ISO file

        Returns:
            ISO9660Handle object or None
        """
        if filename in self.handle:
            return self.handle.get(filename)

        iso_handle = ISO9660Handle(filename)
        if iso_handle.open():
            self.handle[filename] = iso_handle
            return iso_handle

        return None

    def format(self, filehandle, filename, filename_ex) -> Optional[Dict[str, Any]]:
        """Analyze and detect ISO format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to ISO file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        ret = {}

        try:
            mm = filehandle

            # ISO 9660 signature is at offset 32769 (sector 16 + 1 byte)
            # Volume descriptor starts at sector 16
            if len(mm) > SYSTEM_AREA_SECTORS * SECTOR_SIZE + 6:
                # Check for CD001 signature at sector 16
                offset = SYSTEM_AREA_SECTORS * SECTOR_SIZE
                if mm[offset + 1 : offset + 6] == ISO_SIGNATURE:
                    ret["ff_iso"] = "iso"
                    return ret

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

    def arclist(self, filename: str, fileformat: Dict[str, Any], password: Optional[str] = None) -> List[List[str]]:
        """List files in the ISO image.

        Args:
            filename: Path to ISO file
            fileformat: Format info from format() method
            password: Not used for ISO (no encryption support)

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        try:
            if "ff_iso" in fileformat:
                iso_handle = self.__get_handle(filename)
                if iso_handle:
                    for record in iso_handle.list_files():
                        # CWE-22: Path traversal prevention
                        if k2security.is_safe_archive_member(record.file_identifier):
                            file_scan_list.append(["arc_iso", record.file_identifier])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id: str, arc_name: str, fname_in_arc: str) -> Optional[bytes]:
        """Extract a file from the ISO image.

        Args:
            arc_engine_id: Engine ID ('arc_iso')
            arc_name: Path to ISO file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.debug("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_iso":
            return None

        try:
            iso_handle = self.handle.get(arc_name)
            if iso_handle is None:
                return None

            return iso_handle.extract_file(fname_in_arc)

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open ISO handles."""
        for fname in list(self.handle.keys()):
            try:
                iso_handle = self.handle[fname]
                if hasattr(iso_handle, "close"):
                    iso_handle.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
