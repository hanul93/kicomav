# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
VHD (Virtual Hard Disk) Archive Engine Plugin

This plugin handles VHD disk images for scanning files.
Supports:
- Fixed VHD and Dynamic VHD formats
- MBR and GPT partition tables
- FAT12, FAT16, FAT32 file systems

VHD files are commonly used by malware to bypass MOTW protection.
"""

import struct
import os
import re
import logging
from enum import IntEnum
from typing import Optional, Dict, Any, List, Tuple, BinaryIO
from dataclasses import dataclass

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

# VHD Constants
VHD_SECTOR_SIZE = 512
VHD_FOOTER_SIZE = 512
VHD_DYNAMIC_HEADER_SIZE = 1024
VHD_COOKIE = b"conectix"
VHD_DYNAMIC_COOKIE = b"cxsparse"


class VHDType(IntEnum):
    """VHD disk types"""

    NONE = 0
    RESERVED = 1
    FIXED = 2
    DYNAMIC = 3
    DIFFERENCING = 4


@dataclass
class VHDFooter:
    """VHD Footer structure"""

    cookie: bytes
    features: int
    file_format_version: int
    data_offset: int
    timestamp: int
    creator_application: str
    creator_version: int
    creator_host_os: str
    original_size: int
    current_size: int
    disk_geometry: Tuple[int, int, int]
    disk_type: VHDType
    checksum: int
    unique_id: bytes
    saved_state: int


@dataclass
class DynamicDiskHeader:
    """Dynamic Disk Header structure"""

    cookie: bytes
    data_offset: int
    table_offset: int
    header_version: int
    max_table_entries: int
    block_size: int
    checksum: int
    parent_unique_id: bytes
    parent_timestamp: int


@dataclass
class PartitionEntry:
    """MBR Partition Table Entry"""

    bootable: bool
    partition_type: int
    start_lba: int
    total_sectors: int

    @property
    def size_bytes(self) -> int:
        return self.total_sectors * VHD_SECTOR_SIZE


@dataclass
class GPTPartitionEntry:
    """GPT Partition Entry"""

    partition_type_guid: bytes
    unique_guid: bytes
    first_lba: int
    last_lba: int
    attributes: int
    name: str

    @property
    def start_lba(self) -> int:
        return self.first_lba

    @property
    def total_sectors(self) -> int:
        return self.last_lba - self.first_lba + 1

    @property
    def size_bytes(self) -> int:
        return self.total_sectors * VHD_SECTOR_SIZE


@dataclass
class FATBootSector:
    """FAT Boot Sector information"""

    oem_name: str
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    root_entry_count: int
    total_sectors: int
    media_type: int
    fat_size: int
    sectors_per_track: int
    num_heads: int
    hidden_sectors: int
    volume_label: str
    fs_type: str
    fat_type: str


@dataclass
class FATDirectoryEntry:
    """FAT Directory Entry"""

    name: str
    extension: str
    attributes: int
    start_cluster: int
    file_size: int
    is_directory: bool
    is_hidden: bool
    is_system: bool
    is_volume_label: bool
    is_deleted: bool

    @property
    def full_name(self) -> str:
        if self.extension:
            return f"{self.name}.{self.extension}"
        return self.name


class VHDHandle:
    """VHD file handle for archive operations."""

    def __init__(self, filename: str):
        """Initialize VHD handle."""
        self.filename = filename
        self.file_handle: Optional[BinaryIO] = None
        self.footer: Optional[VHDFooter] = None
        self.dynamic_header: Optional[DynamicDiskHeader] = None
        self.bat: List[int] = []
        self.partitions: List[PartitionEntry] = []
        self.gpt_partitions: List[GPTPartitionEntry] = []
        self.is_gpt: bool = False
        self._file_cache: Dict[str, Dict[str, Any]] = {}

    def open(self) -> bool:
        """Open and parse the VHD file."""
        try:
            self.file_handle = open(self.filename, "rb")

            if not self._read_footer():
                self.close()
                return False

            if self.footer.disk_type in (VHDType.DYNAMIC, VHDType.DIFFERENCING):
                self._read_dynamic_header()
                self._read_bat()

            if not self._parse_mbr():
                self.close()
                return False

            self._build_file_cache()
            return True

        except (IOError, OSError) as e:
            logger.debug("Failed to open VHD file %s: %s", self.filename, e)
            return False
        except Exception as e:
            logger.debug("Failed to parse VHD file %s: %s", self.filename, e)
            return False

    def close(self):
        """Close the VHD file handle."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
        self._file_cache.clear()
        self.partitions.clear()
        self.gpt_partitions.clear()
        self.bat.clear()

    def _read_footer(self) -> bool:
        """Read and parse VHD footer."""
        try:
            # Footer is at the end of the file
            self.file_handle.seek(-VHD_FOOTER_SIZE, 2)
            footer_data = self.file_handle.read(VHD_FOOTER_SIZE)

            if len(footer_data) < VHD_FOOTER_SIZE:
                return False

            cookie = footer_data[0:8]
            if cookie != VHD_COOKIE:
                # Try reading from the beginning (fixed VHD copy)
                self.file_handle.seek(0)
                footer_data = self.file_handle.read(VHD_FOOTER_SIZE)
                cookie = footer_data[0:8]
                if cookie != VHD_COOKIE:
                    return False

            self.footer = self._parse_footer(footer_data)
            return True

        except Exception as e:
            logger.debug("Failed to read footer: %s", e)
            return False

    def _parse_footer(self, data: bytes) -> VHDFooter:
        """Parse VHD footer structure."""
        cylinders = struct.unpack(">H", data[56:58])[0]
        heads = data[58]
        sectors = data[59]

        return VHDFooter(
            cookie=data[0:8],
            features=struct.unpack(">I", data[8:12])[0],
            file_format_version=struct.unpack(">I", data[12:16])[0],
            data_offset=struct.unpack(">Q", data[16:24])[0],
            timestamp=struct.unpack(">I", data[24:28])[0],
            creator_application=data[28:32].decode("ascii", errors="replace").strip(),
            creator_version=struct.unpack(">I", data[32:36])[0],
            creator_host_os=data[36:40].decode("ascii", errors="replace").strip(),
            original_size=struct.unpack(">Q", data[40:48])[0],
            current_size=struct.unpack(">Q", data[48:56])[0],
            disk_geometry=(cylinders, heads, sectors),
            disk_type=VHDType(struct.unpack(">I", data[60:64])[0]),
            checksum=struct.unpack(">I", data[64:68])[0],
            unique_id=data[68:84],
            saved_state=data[84],
        )

    def _read_dynamic_header(self) -> bool:
        """Read dynamic disk header."""
        if not self.footer or self.footer.disk_type == VHDType.FIXED:
            return False

        try:
            self.file_handle.seek(self.footer.data_offset)
            header_data = self.file_handle.read(VHD_DYNAMIC_HEADER_SIZE)

            if len(header_data) < VHD_DYNAMIC_HEADER_SIZE:
                return False

            cookie = header_data[0:8]
            if cookie != VHD_DYNAMIC_COOKIE:
                return False

            self.dynamic_header = DynamicDiskHeader(
                cookie=cookie,
                data_offset=struct.unpack(">Q", header_data[8:16])[0],
                table_offset=struct.unpack(">Q", header_data[16:24])[0],
                header_version=struct.unpack(">I", header_data[24:28])[0],
                max_table_entries=struct.unpack(">I", header_data[28:32])[0],
                block_size=struct.unpack(">I", header_data[32:36])[0],
                checksum=struct.unpack(">I", header_data[36:40])[0],
                parent_unique_id=header_data[40:56],
                parent_timestamp=struct.unpack(">I", header_data[56:60])[0],
            )
            return True

        except Exception as e:
            logger.debug("Failed to read dynamic header: %s", e)
            return False

    def _read_bat(self) -> bool:
        """Read Block Allocation Table."""
        if not self.dynamic_header:
            return False

        try:
            self.file_handle.seek(self.dynamic_header.table_offset)
            bat_size = self.dynamic_header.max_table_entries * 4
            bat_data = self.file_handle.read(bat_size)

            self.bat = []
            for i in range(self.dynamic_header.max_table_entries):
                offset = i * 4
                entry = struct.unpack(">I", bat_data[offset : offset + 4])[0]
                self.bat.append(entry)

            return True

        except Exception as e:
            logger.debug("Failed to read BAT: %s", e)
            return False

    def _read_sector(self, sector_num: int) -> bytes:
        """Read a sector from the virtual disk."""
        if self.footer.disk_type == VHDType.FIXED:
            return self._read_fixed_sector(sector_num)
        elif self.footer.disk_type == VHDType.DYNAMIC:
            return self._read_dynamic_sector(sector_num)
        else:
            return b"\x00" * VHD_SECTOR_SIZE

    def _read_fixed_sector(self, sector_num: int) -> bytes:
        """Read sector from fixed VHD."""
        offset = sector_num * VHD_SECTOR_SIZE
        self.file_handle.seek(offset)
        return self.file_handle.read(VHD_SECTOR_SIZE)

    def _read_dynamic_sector(self, sector_num: int) -> bytes:
        """Read sector from dynamic VHD."""
        if not self.dynamic_header or not self.bat:
            return b"\x00" * VHD_SECTOR_SIZE

        block_size = self.dynamic_header.block_size
        sectors_per_block = block_size // VHD_SECTOR_SIZE

        block_num = sector_num // sectors_per_block
        sector_in_block = sector_num % sectors_per_block

        if block_num >= len(self.bat):
            return b"\x00" * VHD_SECTOR_SIZE

        block_offset = self.bat[block_num]

        # 0xFFFFFFFF means block is not allocated (sparse)
        if block_offset == 0xFFFFFFFF:
            return b"\x00" * VHD_SECTOR_SIZE

        # Block has a bitmap at the start
        bitmap_size = (sectors_per_block + 7) // 8
        bitmap_sectors = (bitmap_size + VHD_SECTOR_SIZE - 1) // VHD_SECTOR_SIZE

        data_offset = (
            (block_offset * VHD_SECTOR_SIZE) + (bitmap_sectors * VHD_SECTOR_SIZE) + (sector_in_block * VHD_SECTOR_SIZE)
        )

        self.file_handle.seek(data_offset)
        return self.file_handle.read(VHD_SECTOR_SIZE)

    def _read_sectors(self, start_sector: int, count: int) -> bytes:
        """Read multiple consecutive sectors."""
        data = b""
        for i in range(count):
            data += self._read_sector(start_sector + i)
        return data

    def _parse_mbr(self) -> bool:
        """Parse MBR partition table."""
        mbr = self._read_sector(0)

        if mbr[510:512] != b"\x55\xAA":
            return False

        self.partitions = []

        for i in range(4):
            offset = 446 + (i * 16)
            entry_data = mbr[offset : offset + 16]

            partition = self._parse_partition_entry(entry_data)
            if partition.partition_type != 0:
                self.partitions.append(partition)

        # Check for GPT protective MBR
        if len(self.partitions) == 1 and self.partitions[0].partition_type == 0xEE:
            if self._parse_gpt():
                self.is_gpt = True
                return True

        return len(self.partitions) > 0

    def _parse_partition_entry(self, data: bytes) -> PartitionEntry:
        """Parse a single MBR partition entry."""
        return PartitionEntry(
            bootable=data[0] == 0x80,
            partition_type=data[4],
            start_lba=struct.unpack("<I", data[8:12])[0],
            total_sectors=struct.unpack("<I", data[12:16])[0],
        )

    def _parse_gpt(self) -> bool:
        """Parse GPT partition table."""
        gpt_header = self._read_sector(1)

        if gpt_header[0:8] != b"EFI PART":
            return False

        partition_entry_lba = struct.unpack("<Q", gpt_header[72:80])[0]
        num_partition_entries = struct.unpack("<I", gpt_header[80:84])[0]
        partition_entry_size = struct.unpack("<I", gpt_header[84:88])[0]

        self.gpt_partitions = []
        entries_per_sector = VHD_SECTOR_SIZE // partition_entry_size
        sectors_needed = (num_partition_entries + entries_per_sector - 1) // entries_per_sector

        partition_data = self._read_sectors(partition_entry_lba, sectors_needed)

        for i in range(num_partition_entries):
            offset = i * partition_entry_size
            entry_data = partition_data[offset : offset + partition_entry_size]

            if len(entry_data) < 128:
                break

            type_guid = entry_data[0:16]
            if type_guid == b"\x00" * 16:
                continue

            unique_guid = entry_data[16:32]
            first_lba = struct.unpack("<Q", entry_data[32:40])[0]
            last_lba = struct.unpack("<Q", entry_data[40:48])[0]
            attributes = struct.unpack("<Q", entry_data[48:56])[0]

            name_bytes = entry_data[56:128]
            try:
                name = name_bytes.decode("utf-16-le").rstrip("\x00")
            except Exception:
                name = ""

            gpt_entry = GPTPartitionEntry(
                partition_type_guid=type_guid,
                unique_guid=unique_guid,
                first_lba=first_lba,
                last_lba=last_lba,
                attributes=attributes,
                name=name,
            )

            self.gpt_partitions.append(gpt_entry)

        return len(self.gpt_partitions) > 0

    def _parse_fat_boot_sector(self, start_lba: int, total_sectors: int) -> Optional[FATBootSector]:
        """Parse FAT boot sector."""
        boot = self._read_sector(start_lba)

        if boot[510:512] != b"\x55\xAA":
            return None

        bytes_per_sector = struct.unpack("<H", boot[11:13])[0]
        if bytes_per_sector not in (512, 1024, 2048, 4096):
            return None

        sectors_per_cluster = boot[13]
        reserved_sectors = struct.unpack("<H", boot[14:16])[0]
        num_fats = boot[16]
        root_entry_count = struct.unpack("<H", boot[17:19])[0]
        total_sectors_16 = struct.unpack("<H", boot[19:21])[0]
        fat_size_16 = struct.unpack("<H", boot[22:24])[0]
        total_sectors_32 = struct.unpack("<I", boot[32:36])[0]

        total_sectors_fs = total_sectors_16 if total_sectors_16 else total_sectors_32

        if fat_size_16 == 0:
            # FAT32
            fat_size = struct.unpack("<I", boot[36:40])[0]
            volume_label = boot[71:82].decode("ascii", errors="replace").strip()
            fs_type = boot[82:90].decode("ascii", errors="replace").strip()
            fat_type = "FAT32"
        else:
            fat_size = fat_size_16
            volume_label = boot[43:54].decode("ascii", errors="replace").strip()
            fs_type = boot[54:62].decode("ascii", errors="replace").strip()

            root_dir_sectors = ((root_entry_count * 32) + bytes_per_sector - 1) // bytes_per_sector
            data_sectors = total_sectors_fs - (reserved_sectors + (num_fats * fat_size) + root_dir_sectors)
            cluster_count = data_sectors // sectors_per_cluster if sectors_per_cluster else 0

            fat_type = "FAT12" if cluster_count < 4085 else "FAT16"

        return FATBootSector(
            oem_name=boot[3:11].decode("ascii", errors="replace").strip(),
            bytes_per_sector=bytes_per_sector,
            sectors_per_cluster=sectors_per_cluster,
            reserved_sectors=reserved_sectors,
            num_fats=num_fats,
            root_entry_count=root_entry_count,
            total_sectors=total_sectors_fs,
            media_type=boot[21],
            fat_size=fat_size,
            sectors_per_track=struct.unpack("<H", boot[24:26])[0],
            num_heads=struct.unpack("<H", boot[26:28])[0],
            hidden_sectors=struct.unpack("<I", boot[28:32])[0],
            volume_label=volume_label,
            fs_type=fs_type,
            fat_type=fat_type,
        )

    def _list_fat_directory(
        self, start_lba: int, total_sectors: int, boot: FATBootSector, start_cluster: int = 0, path: str = "/"
    ) -> List[Tuple[str, FATDirectoryEntry]]:
        """List files in a FAT directory."""
        files = []

        fat_start = start_lba + boot.reserved_sectors
        root_dir_sectors = ((boot.root_entry_count * 32) + boot.bytes_per_sector - 1) // boot.bytes_per_sector

        if boot.fat_type == "FAT32":
            data_start = fat_start + (boot.num_fats * boot.fat_size)
            if start_cluster == 0:
                start_cluster = 2
            entries = self._read_cluster_chain_data(start_lba, boot, start_cluster, data_start)
        else:
            root_start = fat_start + (boot.num_fats * boot.fat_size)
            data_start = root_start + root_dir_sectors

            if start_cluster == 0:
                entries = self._read_sectors(root_start, root_dir_sectors)
            else:
                entries = self._read_cluster_chain_data(start_lba, boot, start_cluster, data_start)

        long_name_parts = []
        offset = 0

        while offset < len(entries):
            entry_data = entries[offset : offset + 32]
            if len(entry_data) < 32:
                break

            first_byte = entry_data[0]

            if first_byte == 0x00:
                break

            if first_byte == 0xE5:
                offset += 32
                long_name_parts = []
                continue

            attributes = entry_data[11]

            if attributes == 0x0F:
                lfn_part = self._parse_lfn_entry(entry_data)
                long_name_parts.insert(0, lfn_part)
                offset += 32
                continue

            entry = self._parse_dir_entry(entry_data, long_name_parts)
            long_name_parts = []

            if entry and not entry.is_volume_label:
                if entry.name not in (".", ".."):
                    full_path = f"{path.rstrip('/')}/{entry.full_name}"
                    files.append((full_path, entry))

                    if entry.is_directory and entry.start_cluster >= 2:
                        subfiles = self._list_fat_directory(
                            start_lba, total_sectors, boot, entry.start_cluster, full_path
                        )
                        files.extend(subfiles)

            offset += 32

        return files

    def _parse_lfn_entry(self, data: bytes) -> str:
        """Parse long filename entry."""
        chars = []
        for i in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]:
            if i + 1 < len(data):
                char = struct.unpack("<H", data[i : i + 2])[0]
                if char == 0 or char == 0xFFFF:
                    break
                chars.append(chr(char))
        return "".join(chars)

    def _parse_dir_entry(self, data: bytes, lfn_parts: List[str]) -> Optional[FATDirectoryEntry]:
        """Parse standard 8.3 directory entry."""
        if data[0] == 0x00 or data[0] == 0xE5:
            return None

        attributes = data[11]

        if lfn_parts:
            full_name = "".join(lfn_parts)
            name = full_name
            extension = ""
            if "." in full_name and not full_name.startswith("."):
                parts = full_name.rsplit(".", 1)
                name = parts[0]
                extension = parts[1] if len(parts) > 1 else ""
        else:
            name = data[0:8].decode("ascii", errors="replace").rstrip()
            extension = data[8:11].decode("ascii", errors="replace").rstrip()

        start_cluster_low = struct.unpack("<H", data[26:28])[0]
        start_cluster_high = struct.unpack("<H", data[20:22])[0]
        start_cluster = (start_cluster_high << 16) | start_cluster_low

        file_size = struct.unpack("<I", data[28:32])[0]

        return FATDirectoryEntry(
            name=name,
            extension=extension,
            attributes=attributes,
            start_cluster=start_cluster,
            file_size=file_size,
            is_directory=bool(attributes & 0x10),
            is_hidden=bool(attributes & 0x02),
            is_system=bool(attributes & 0x04),
            is_volume_label=bool(attributes & 0x08),
            is_deleted=(data[0] == 0xE5),
        )

    def _read_cluster_chain_data(
        self, start_lba: int, boot: FATBootSector, start_cluster: int, data_start: int
    ) -> bytes:
        """Read data following a cluster chain."""
        data = b""
        cluster = start_cluster
        max_clusters = 10000
        visited = set()

        while cluster >= 2 and max_clusters > 0:
            if cluster in visited:
                break
            visited.add(cluster)

            cluster_sector = data_start + ((cluster - 2) * boot.sectors_per_cluster)
            cluster_data = self._read_sectors(cluster_sector, boot.sectors_per_cluster)
            data += cluster_data

            cluster = self._get_next_cluster(start_lba, boot, cluster)
            max_clusters -= 1

        return data

    def _get_next_cluster(self, start_lba: int, boot: FATBootSector, cluster: int) -> int:
        """Get next cluster number from FAT."""
        fat_start = start_lba + boot.reserved_sectors

        if boot.fat_type == "FAT32":
            fat_offset = cluster * 4
            fat_sector = fat_start + (fat_offset // boot.bytes_per_sector)
            offset_in_sector = fat_offset % boot.bytes_per_sector

            sector_data = self._read_sector(fat_sector)
            next_cluster = struct.unpack("<I", sector_data[offset_in_sector : offset_in_sector + 4])[0]
            next_cluster &= 0x0FFFFFFF

            if next_cluster >= 0x0FFFFFF8:
                return 0
            return next_cluster

        elif boot.fat_type == "FAT16":
            fat_offset = cluster * 2
            fat_sector = fat_start + (fat_offset // boot.bytes_per_sector)
            offset_in_sector = fat_offset % boot.bytes_per_sector

            sector_data = self._read_sector(fat_sector)
            next_cluster = struct.unpack("<H", sector_data[offset_in_sector : offset_in_sector + 2])[0]

            if next_cluster >= 0xFFF8:
                return 0
            return next_cluster

        else:  # FAT12
            fat_offset = cluster + (cluster // 2)
            fat_sector = fat_start + (fat_offset // boot.bytes_per_sector)
            offset_in_sector = fat_offset % boot.bytes_per_sector

            sector_data = self._read_sectors(fat_sector, 2)

            if cluster & 1:
                next_cluster = struct.unpack("<H", sector_data[offset_in_sector : offset_in_sector + 2])[0] >> 4
            else:
                next_cluster = struct.unpack("<H", sector_data[offset_in_sector : offset_in_sector + 2])[0] & 0x0FFF

            if next_cluster >= 0xFF8:
                return 0
            return next_cluster

    def _extract_file_data(self, start_lba: int, boot: FATBootSector, entry: FATDirectoryEntry) -> Optional[bytes]:
        """Extract file data from VHD."""
        if entry.is_directory:
            return None

        fat_start = start_lba + boot.reserved_sectors

        if boot.fat_type == "FAT32":
            data_start = fat_start + (boot.num_fats * boot.fat_size)
        else:
            root_dir_sectors = ((boot.root_entry_count * 32) + boot.bytes_per_sector - 1) // boot.bytes_per_sector
            data_start = fat_start + (boot.num_fats * boot.fat_size) + root_dir_sectors

        data = self._read_cluster_chain_data(start_lba, boot, entry.start_cluster, data_start)
        return data[: entry.file_size]

    def _build_file_cache(self):
        """Build cache of files from the VHD."""
        self._file_cache.clear()

        if self.is_gpt and self.gpt_partitions:
            partitions_to_process = [(p.first_lba, p.total_sectors) for p in self.gpt_partitions]
        else:
            partitions_to_process = [(p.start_lba, p.total_sectors) for p in self.partitions]

        for start_lba, total_sectors in partitions_to_process:
            boot = self._parse_fat_boot_sector(start_lba, total_sectors)
            if not boot:
                continue

            try:
                files = self._list_fat_directory(start_lba, total_sectors, boot)
                for path, entry in files:
                    if not entry.is_directory:
                        # Sanitize path
                        safe_path = self._sanitize_path(path)
                        self._file_cache[safe_path] = {
                            "entry": entry,
                            "boot": boot,
                            "start_lba": start_lba,
                        }
            except Exception as e:
                logger.debug("Failed to list files in partition: %s", e)

    @staticmethod
    def _sanitize_path(path: str) -> str:
        """Sanitize file path."""
        path = re.sub(r'[<>:"|?*\x00-\x1f]', "_", path)
        # Remove leading slashes for archive member safety
        path = path.lstrip("/\\")
        return path.strip()

    def list_files(self) -> List[str]:
        """Get list of extractable files."""
        return list(self._file_cache.keys())

    def extract_file(self, filepath: str) -> Optional[bytes]:
        """Extract file data by path."""
        if filepath not in self._file_cache:
            return None

        try:
            cache_entry = self._file_cache[filepath]
            entry = cache_entry["entry"]
            boot = cache_entry["boot"]
            start_lba = cache_entry["start_lba"]

            return self._extract_file_data(start_lba, boot, entry)

        except Exception as e:
            logger.debug("Failed to extract file %s: %s", filepath, e)
            return None


def is_valid_vhd(data: bytes) -> bool:
    """Check if data is a valid VHD file."""
    if len(data) < VHD_FOOTER_SIZE:
        return False

    # Check footer at end (most common)
    if len(data) >= VHD_FOOTER_SIZE:
        footer_start = len(data) - VHD_FOOTER_SIZE
        if data[footer_start : footer_start + 8] == VHD_COOKIE:
            return True

    # Check footer at beginning (fixed VHD copy)
    if data[0:8] == VHD_COOKIE:
        return True

    return False


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """VHD archive handler plugin.

    This plugin provides functionality for:
    - Detecting VHD format (Fixed and Dynamic)
    - Supporting MBR and GPT partition tables
    - Supporting FAT12, FAT16, FAT32 file systems
    - Listing files within VHD images
    - Extracting files from VHD images
    """

    def __init__(self):
        """Initialize the VHD plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="VHD Archive Engine",
            kmd_name="vhd",
        )

    def _custom_init(self) -> int:
        """Custom initialization for VHD plugin."""
        return 0

    def _custom_uninit(self) -> int:
        """Custom cleanup for VHD plugin."""
        self.arcclose()
        return 0

    def getinfo(self):
        """Get plugin information."""
        info = super().getinfo()
        info["engine_type"] = kernel.ARCHIVE_ENGINE
        return info

    def __get_handle(self, filename: str) -> Optional[VHDHandle]:
        """Get or create handle for VHD file."""
        if filename in self.handle:
            return self.handle.get(filename)

        vhd_handle = VHDHandle(filename)
        if vhd_handle.open():
            self.handle[filename] = vhd_handle
            return vhd_handle

        return None

    def format(self, filehandle, filename, filename_ex) -> Optional[Dict[str, Any]]:
        """Analyze and detect VHD format."""
        ret = {}

        try:
            mm = filehandle

            if is_valid_vhd(bytes(mm)):
                ret["ff_vhd"] = "vhd"
                return ret

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

    def arclist(self, filename: str, fileformat: Dict[str, Any], password: Optional[str] = None) -> List[List[str]]:
        """List files in the VHD image."""
        file_scan_list = []

        try:
            if "ff_vhd" in fileformat:
                vhd_handle = self.__get_handle(filename)
                if vhd_handle:
                    for file_path in vhd_handle.list_files():
                        # CWE-22: Path traversal prevention
                        if k2security.is_safe_archive_member(file_path):
                            file_scan_list.append(["arc_vhd", file_path])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id: str, arc_name: str, fname_in_arc: str) -> Optional[bytes]:
        """Extract a file from the VHD image."""
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.debug("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_vhd":
            return None

        try:
            vhd_handle = self.handle.get(arc_name)
            if vhd_handle is None:
                return None

            return vhd_handle.extract_file(fname_in_arc)

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open VHD handles."""
        for fname in list(self.handle.keys()):
            try:
                vhd_handle = self.handle[fname]
                if hasattr(vhd_handle, "close"):
                    vhd_handle.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
