# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
InstallShield Archive Engine Plugin

This plugin handles InstallShield format for scanning and manipulation.
"""

import contextlib
import logging
import os
import struct
import zlib
from io import BytesIO

from kicomav.plugins import cryptolib
from kicomav.plugins import kavutil
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# InstallShield Functions
# -------------------------------------------------------------------------
# Constants
PREFER_BLOCK_SIZE = 4096 * 64
ISSIG = b"InstallShield"
ISSIG_strm = b"ISSetupStream"
_MAX_PATH = 260


def gen_key(seed: str) -> bytes:
    """Generate key from seed"""
    MAGIC_DEC = [0x13, 0x35, 0x86, 0x07]
    seed_bytes = seed.encode("utf-8")
    key = bytearray()
    for i, byte in enumerate(seed_bytes):
        key.append(byte ^ MAGIC_DEC[i % len(MAGIC_DEC)])
    return bytes(key)


def decode_byte(byte: int, key_byte: int) -> int:
    """Decode single byte"""
    # C code: return ~(key ^ (Byte * 16 | Byte >> 4));
    # Byte * 16 is left shift by 4, Byte >> 4 is right shift by 4
    rotated = ((byte << 4) & 0xFF) | (byte >> 4)
    xored = key_byte ^ rotated
    return (~xored) & 0xFF


def decode_data(data: bytes, offset: int, key: bytes) -> bytes:
    """Decode data with key"""
    result = bytearray(data)
    key_len = len(key)
    for i in range(len(result)):
        result[i] = decode_byte(result[i], key[(i + offset) % key_len])
    return bytes(result)


def decode_data_ustrm(data: bytes, offset: int, key: bytes) -> bytes:
    """Decode data for unicode stream (1024 byte blocks)"""
    result = bytearray()
    key_len = len(key)
    decoded_len = 0
    data_len = len(data)

    while decoded_len < data_len:
        decode_start = (decoded_len + offset) % 1024
        task_len = min(1024 - decode_start, data_len - decoded_len)

        # Decode this block
        block = data[decoded_len : decoded_len + task_len]
        decoded_block = decode_data(block, decode_start % key_len, key)
        result.extend(decoded_block)

        decoded_len += task_len

    return bytes(result)


def decode_file(
    fp_r,
    offset_r: int,
    length: int,
    encoded_block_len: int,
    key: bytes = None,
    decode_fun=None,
    need_decode: bool = False,
) -> (int, bytes):
    """Decode and return file content (optimized: list-append batching)"""
    if length <= 0:
        return 0, b""

    fp_r.seek(offset_r)

    len_read = min(PREFER_BLOCK_SIZE, encoded_block_len) if encoded_block_len else PREFER_BLOCK_SIZE
    offset_w = 0
    len_encoded_done = 0

    chunks = []  # use list to avoid O(n^2) bytes concatenation

    while length > 0:
        current_len_read = min(len_read, length)
        if encoded_block_len and encoded_block_len > length:
            encoded_block_len = length

        len_left = encoded_block_len if encoded_block_len else current_len_read
        len_encoded_done = 0

        while len_left > 0:
            chunk_size = min(len_read, len_left)
            pbuffer = fp_r.read(chunk_size)
            if not pbuffer:
                break

            if need_decode and key and decode_fun:
                pbuffer = decode_fun(pbuffer, len_encoded_done, key)

            chunks.append(pbuffer)

            offset_r += len(pbuffer)
            offset_w += len(pbuffer)
            len_encoded_done += len(pbuffer)
            len_left -= len(pbuffer)

        if encoded_block_len:
            length -= encoded_block_len
        else:
            length -= current_len_read

    return offset_r, b"".join(chunks)


def get_is_file_attributes(fp, data_offset: int, is_hdr_type: int):
    """Get IS file attributes (standard format)"""
    fp.seek(data_offset)
    data = fp.read(ISFileAttributes.SIZE)

    if len(data) != ISFileAttributes.SIZE:
        return data_offset, None, ""

    attr = ISFileAttributes(data)
    return data_offset + ISFileAttributes.SIZE, attr, ""


def get_is_file_attributes_ustrm(fp, data_offset: int, is_hdr_type: int):
    """Get IS file attributes (unicode stream format)"""
    fp.seek(data_offset)
    data = fp.read(ISFileAttributesX.SIZE)

    if len(data) != ISFileAttributesX.SIZE:
        return data_offset, None, ""

    attr_x = ISFileAttributesX(data)

    # Validate filename length
    if attr_x.filename_len <= 0 or attr_x.filename_len >= _MAX_PATH * 2:
        return data_offset, None, ""

    # Skip extra data for type 4
    if is_hdr_type == 4:
        fp.seek(ISFileAttributesX.SIZE, 1)

    # Read unicode filename
    filename_data = fp.read(attr_x.filename_len)
    if len(filename_data) != attr_x.filename_len:
        return data_offset, None, ""

    try:
        # Decode UTF-16LE filename
        filename = filename_data.decode("utf-16le").rstrip("\x00")
        attr_x.file_name = filename
    except:
        attr_x.file_name = f"0x{data_offset:X}"

    # Also store seed for decryption (UTF-8 encoded filename)
    try:
        g_Seed = filename_data.decode("utf-16le").rstrip("\x00")
    except:
        g_Seed = ""

    new_offset = fp.tell()

    return new_offset, attr_x, g_Seed


def rol1(byte, count):
    """Rotate left 1 byte"""
    return ((byte << count) | (byte >> (8 - count))) & 0xFF


def decrypt(encrypted_data, key: bytes) -> bytes:
    decrypted = bytearray(len(encrypted_data))
    n = 0
    key_len = len(key)

    for i in range(len(encrypted_data)):
        v52 = encrypted_data[i]
        v52 = rol1(v52, 3)
        decrypted[i] = v52 ^ key[n]

        n += 1
        if n >= key_len:
            n = 0

    return bytes(decrypted)


def decode_exe(fp, key: bytes, exe_start_off: int, exe_end_off: int) -> bytes:
    """Decode embedded setup.exe"""
    fp.seek(exe_start_off)
    encrypted_exe_data = fp.read(0x300)

    if len(encrypted_exe_data) < 0x300:
        return b""

    return decrypt(encrypted_exe_data, key[:16])


def inflate_file(compressed_data: bytes) -> (bool, bytes):
    """Inflate (decompress) a zlib compressed file"""
    # Check if data actually looks compressed (has zlib header)
    # zlib header usually starts with 0x78 (common: 0x789C, 0x78DA, 0x785E, 0x7801)
    if len(compressed_data) < 2:
        return False, None

    try:
        decompressed_data = zlib.decompress(compressed_data)
    except zlib.error:
        return False, None

    return True, decompressed_data


class ISHeader:
    """InstallShield Archive Header - 46 bytes (0x2E)"""

    SIZE = 46

    def __init__(self, data: bytes):
        # char SIG[14], uint16_t num_files, uint32_t type, uint8_t x4[8], uint16_t x5, uint8_t x6[16]
        fields = struct.unpack("<14sHI8sH16s", data[:46])
        self.sig = fields[0].rstrip(b"\x00")
        self.num_files = fields[1]
        self.type = fields[2]
        self.x4 = fields[3]
        self.x5 = fields[4]
        self.x6 = fields[5]


class ISFileAttributes:
    """IS File Attributes - 312 bytes (0x138)"""

    SIZE = 312

    def __init__(self, data: bytes):
        # char file_name[260], uint32_t encoded_flags, uint32_t x3, uint32_t file_len,
        # uint8_t x5[8], uint16_t is_unicode_launcher, uint8_t x7[30]
        fields = struct.unpack("<260sIII8sH30s", data[:312])
        self.file_name = fields[0].rstrip(b"\x00").decode("utf-8", errors="ignore")
        self.encoded_flags = fields[1]
        self.x3 = fields[2]
        self.file_len = fields[3]
        self.x5 = fields[4]
        self.is_unicode_launcher = fields[5]
        self.x7 = fields[6]


class ISFileAttributesX:
    """IS File Attributes X - 24 bytes (0x18) for ISSetupStream"""

    SIZE = 24

    def __init__(self, data: bytes):
        # uint32_t filename_len, uint32_t encoded_flags, uint8_t x3[2], uint32_t file_len,
        # uint8_t x5[8], uint16_t is_unicode_launcher
        fields = struct.unpack("<II2sI8sH", data[:24])
        self.filename_len = fields[0]
        self.encoded_flags = fields[1]
        self.x3 = fields[2]
        self.file_len = fields[3]
        self.x5 = fields[4]
        self.is_unicode_launcher = fields[5]
        self.file_name = ""


class InstallShield:
    def __init__(self, fname, data_off: int):
        self.fname = fname
        self.data_off = data_off
        self.fp = None
        self.header = None
        self.fsize = 0
        self.num_files = 0
        self.install_name = []
        self.g_Seed = ""

    def __del__(self):
        if self.fp:
            self.close()

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def parse(self):
        with contextlib.suppress(IOError, OSError, ValueError):
            self.fp = open(self.fname, "rb")
            self.fp.seek(self.data_off)

            data = self.fp.read(ISHeader.SIZE)
            is_hdr = ISHeader(data)

            # Check signature
            if is_hdr.sig == ISSIG or is_hdr.sig == ISSIG_strm:
                # Check type
                if is_hdr.type > 4:
                    return False

                offset = self.data_off + ISHeader.SIZE
                self.data_off = offset

                # Determine format
                self.is_stream = is_hdr.sig == ISSIG_strm
                self.encoded_block_len = 0x4000 if self.is_stream else PREFER_BLOCK_SIZE
                get_attr_fun = get_is_file_attributes_ustrm if self.is_stream else get_is_file_attributes
                self.decode_fun = decode_data_ustrm if self.is_stream else decode_data

                self.num_files = is_hdr.num_files
                # print(f"Files total: {self.num_files}")
                # print("Extracting:")

                self.is_hdr = is_hdr

                for i in range(self.num_files):
                    # Get file attributes
                    offset, file_attr, self.g_Seed = get_attr_fun(self.fp, self.data_off, self.is_hdr.type)

                    if offset <= self.data_off or file_attr is None:
                        break

                    self.data_off = offset
                    file_data_offset = offset
                    self.data_off += file_attr.file_len

                    self.install_name.append(
                        (
                            file_data_offset,
                            file_attr.file_len,
                            file_attr.file_name,
                            file_attr,
                            self.data_off,
                            "HEADER_FNAME",
                        )
                    )

            else:
                # Check CAB signature
                header_size = kavutil.get_uint32(data, 0)
                cab_off = self.data_off + header_size + 4
                self.fp.seek(cab_off)
                cab_sig = self.fp.read(0x10)

                if cab_sig[0:4] == b"MSCF":
                    cab_size = kavutil.get_uint32(cab_sig, 8)

                    self.install_name.append(
                        (
                            cab_off,
                            cab_size,
                            "InstallShield_Data.cab",
                            None,
                            None,
                            "HEADER_CAB",
                        )
                    )

            # Check exist of setup.exe
            self.fp.seek(-0x30, 2)
            tail_header = self.fp.read(0x30)
            exe_start_off = kavutil.get_uint32(tail_header, 0xC)
            exe_end_off = kavutil.get_uint32(tail_header, 0x1C)

            decrypted_exe_header = decode_exe(self.fp, tail_header, exe_start_off, exe_end_off)
            if decrypted_exe_header[:2] == b"MZ":
                self.install_name.append(
                    (
                        exe_start_off,
                        exe_end_off - exe_start_off,
                        "InstallShield_Setup.exe",
                        None,
                        decrypted_exe_header,
                        "ENCRYPT_EXE",
                    )
                )

            return True

        return False

    def namelist(self):
        flist = []

        flist.extend((f[2] for f in self.install_name))
        return flist

    def read(self, fname):
        for f in self.install_name:
            if f[2] == fname and self.fp:
                f_type = f[5]

                if f_type == "HEADER_FNAME":
                    file_data_offset, _, _, file_attr, data_offset, _ = f

                    # Prepare decoder
                    is_need_inflate = False
                    # seed = self.g_Seed if self.is_stream else file_attr.file_name
                    seed = file_attr.file_name
                    key = gen_key(seed)

                    # Determine encoding type
                    has_type_2_or_4 = file_attr.encoded_flags & 6
                    has_type_4 = file_attr.encoded_flags & 4
                    encoded_block_len_i = self.encoded_block_len
                    need_decode = False

                    if has_type_4 and has_type_2_or_4:
                        encoded_block_len_i = 1024
                        need_decode = True

                    offset, return_data = decode_file(
                        self.fp,
                        file_data_offset,
                        file_attr.file_len,
                        encoded_block_len_i,
                        key,
                        self.decode_fun,
                        need_decode,
                    )

                    if offset != data_offset:
                        self.fp.seek(data_offset)
                    else:
                        n_2trans = 1

                        # Second pass for certain types
                        if n_2trans and not has_type_4 and has_type_2_or_4:
                            # Convert to bytesio
                            fp_w = BytesIO(return_data)
                            fp_w.seek(0)

                            decode_fun_2 = decode_data if self.is_stream else self.decode_fun
                            offset, return_data = decode_file(
                                fp_w, 0, file_attr.file_len, file_attr.file_len, key, decode_fun_2, True
                            )

                            if offset != file_attr.file_len:
                                self.fp.seek(data_offset)

                            fp_w.close()

                        # Check if inflation needed
                        if file_attr.is_unicode_launcher:
                            is_need_inflate = True

                    # Inflate if needed
                    if is_need_inflate:
                        _, return_data = inflate_file(return_data)

                    return return_data

                elif f_type == "ENCRYPT_EXE":
                    exe_start_off, exe_len, _, _, decrypted_exe_header, _ = f
                    self.fp.seek(exe_start_off)
                    exe_data = self.fp.read(exe_len)
                    return decrypted_exe_header + exe_data[0x300:]

                elif f_type == "HEADER_CAB":
                    cab_off, cab_len, _, _, _, _ = f
                    self.fp.seek(cab_off)
                    cab_data = self.fp.read(cab_len)
                    return cab_data

        return None


class InstallShieldSetupEmbeddedFile:
    def __init__(self, filename, data_off=0):
        self.filename = filename
        self.data_off = data_off
        self.fp = None
        self.key = b"%eR@toPm|<#YKs$^"
        self.install_name = []
        self.CHUNK_SIZE = 1024

    def __del__(self):
        if self.fp:
            self.close()

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def parse(self):
        with contextlib.suppress(IOError, OSError, ValueError):
            self.fp = open(self.filename, "rb")
            self.fp.seek(self.data_off)
            data = self.fp.read()

            off = len(data) - 712
            n = 0

            while off >= 0:
                buf = data[off : off + 712]
                decrypted = cryptolib.ishield_decrypt(buf, self.key)

                key_size = kavutil.get_uint32(decrypted, 668)
                v2 = kavutil.get_uint32(decrypted, 12)
                file_name_size = kavutil.get_uint32(decrypted, 144)
                crc32_value = kavutil.get_uint32(decrypted, 704)
                file_size = kavutil.get_uint32(decrypted, 708)

                if key_size <= 0x20 and v2 <= 0x40 and file_name_size <= 0x104:
                    decrypted = cryptolib.reset_padding(decrypted, 668, key_size, 0x20)
                    decrypted = cryptolib.reset_padding(decrypted, 12, v2, 0x40)
                    decrypted = cryptolib.reset_padding(decrypted, 144, file_name_size, 0x104)
                    crc32_value_calculated = int(zlib.crc32(decrypted[:704]) & 0xFFFFFFFF)
                    if crc32_value == crc32_value_calculated and file_name_size != 0:
                        file_name = decrypted[148 : 148 + file_name_size].decode("utf-16le", errors="ignore")
                        file_name = os.path.expandvars(file_name)
                        file_name = os.path.basename(file_name)

                        dec_key = decrypted[668 + 4 : 668 + 4 + key_size]

                        self.install_name.append(
                            (
                                off - file_size,
                                file_size,
                                file_name,
                                dec_key,
                                None,
                                "EMBED_EXE",
                            )
                        )
                    off -= 712 + file_size
                else:
                    break

            return True
        return False

    def namelist(self):
        flist = []

        flist.extend((f[2] for f in self.install_name))
        return flist

    def read(self, fname):
        for f in self.install_name:
            offset, compressed_size, file_name, dec_key, _, _ = f
            decrypted_chunks = []

            if file_name != fname and self.fp:
                continue

            self.fp.seek(offset)

            remaining = compressed_size

            while remaining > 0:
                chunk_size = min(self.CHUNK_SIZE, remaining)
                chunk = self.fp.read(chunk_size)

                if len(chunk) != chunk_size:
                    break

                decrypted_chunk = decrypt(chunk, dec_key)
                decrypted_chunks.append(decrypted_chunk)

                remaining -= chunk_size

            decrypted_data = b"".join(decrypted_chunks)
            _, decrypted_data = inflate_file(decrypted_data)

            return decrypted_data

        return None


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """InstallShield archive handler plugin.

    This plugin provides functionality for:
    - Detecting InstallShield format
    - Listing files within InstallShield installers
    - Extracting files from InstallShield installers
    """

    def __init__(self):
        """Initialize the InstallShield plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="InstallShield Engine",
            kmd_name="ishield",
        )

    def __get_handle(self, filename, data_off=0):
        """Get or create handle for InstallShield file.

        Args:
            filename: Path to InstallShield file
            data_off: Data offset

        Returns:
            InstallShield object or None
        """
        if filename in self.handle:
            return self.handle.get(filename, None)

        try:
            zfile = InstallShield(filename, data_off)
            self.handle[filename] = zfile
            return zfile

        except (IOError, OSError) as e:
            logger.debug("Failed to open InstallShield file %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error opening InstallShield file %s: %s", filename, e)

        return None

    def __get_handle_setup_embedded_file(self, filename, data_off=0):
        """Get or create handle for InstallShield embedded file.

        Args:
            filename: Path to file
            data_off: Data offset

        Returns:
            InstallShieldSetupEmbeddedFile object or None
        """
        if filename in self.handle:
            return self.handle.get(filename, None)

        try:
            zfile = InstallShieldSetupEmbeddedFile(filename, data_off)
            self.handle[filename] = zfile
            return zfile

        except (IOError, OSError) as e:
            logger.debug("Failed to open InstallShield embedded file %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error opening InstallShield embedded file %s: %s", filename, e)

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

        try:
            if "ff_installshield" in fileformat:
                zfile = self.__get_handle(filename, fileformat["ff_installshield"]["Attached_Pos"])
                if zfile and zfile.parse():
                    for name in zfile.namelist():
                        # CWE-22: Path traversal prevention
                        if k2security.is_safe_archive_member(name):
                            file_scan_list.append(["arc_installshield", name])

            elif "ff_installshield_setup_stream" in fileformat:
                zfile = self.__get_handle(filename, fileformat["ff_installshield_setup_stream"]["Attached_Pos"])
                if zfile and zfile.parse():
                    for name in zfile.namelist():
                        # CWE-22: Path traversal prevention
                        if k2security.is_safe_archive_member(name):
                            file_scan_list.append(["arc_installshield", name])

            elif "ff_installshield_embedded_file" in fileformat:
                zfile = self.__get_handle_setup_embedded_file(filename)
                if zfile and zfile.parse():
                    for name in zfile.namelist():
                        # CWE-22: Path traversal prevention
                        if k2security.is_safe_archive_member(name):
                            file_scan_list.append(["arc_installshield_embedded_file", name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_installshield', 'arc_installshield_embedded_file')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        try:
            if arc_engine_id == "arc_installshield":
                zfile = self.__get_handle(arc_name)
                if zfile is None:
                    return None
                return zfile.read(fname_in_arc)

            elif arc_engine_id == "arc_installshield_embedded_file":
                zfile = self.__get_handle_setup_embedded_file(arc_name)
                if zfile is None:
                    return None
                return zfile.read(fname_in_arc)

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                zfile = self.handle.get(fname)
                if zfile:
                    zfile.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
