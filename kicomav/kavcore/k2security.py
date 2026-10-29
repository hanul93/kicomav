# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)
# Security utilities for KicomAV Engine

"""
KicomAV Security Utilities

his module provides the following security features:
- Path Traversal prevention (CWE-22)
- Zip Slip prevention
- File name validation
- Safe file deletion
- URL validation (SSRF prevention)
- File hash calculation
"""

import os
import hashlib
import pathlib
import ipaddress
import urllib.parse
import urllib.request
from typing import Optional, List, Callable


# -------------------------------------------------------------------------
# SecurityError Exception
# -------------------------------------------------------------------------
class SecurityError(Exception):
    """Security exception class"""

    pass


# -------------------------------------------------------------------------
# Path Validation Functions
# -------------------------------------------------------------------------
def validate_path(file_path: str, base_dir: str, allow_symlinks: bool = False) -> str:
    """
    Path validation - Path Traversal prevention (CWE-22)

    Args:
        file_path: Path to validate
        base_dir: Allowed base directory
        allow_symlinks: Allow symbolic links

    Returns:
        Normalized safe path

    Raises:
        SecurityError: Path validation failed
    """
    # 1. Convert to absolute path and normalize
    file_path = os.path.abspath(os.path.normpath(file_path))
    base_dir = os.path.abspath(os.path.normpath(base_dir))

    # 2. Verify if the path is inside base_dir
    # Use os.sep to support both Windows and Unix
    if not (file_path.startswith(base_dir + os.sep) or file_path == base_dir):
        raise SecurityError(f"Path outside base directory: {file_path}")

    # 3. Verify ../ pattern (check after normalization)
    path_parts = pathlib.Path(file_path).parts
    if ".." in path_parts:
        raise SecurityError(f"Parent directory reference in path: {file_path}")

    # 4. Verify symbolic links
    if not allow_symlinks and os.path.islink(file_path):
        real_path = os.path.realpath(file_path)
        if not (real_path.startswith(base_dir + os.sep) or real_path == base_dir):
            raise SecurityError(f"Symlink points outside base directory: {file_path}")

    return file_path


def safe_extract_member(archive_member_name: str, extract_base_dir: str) -> str:
    """
    Safe extraction of archive member - Zip Slip prevention (CWE-22)

    Args:
        archive_member_name: Name of the archive member
        extract_base_dir: Base directory for extraction

    Returns:
        Safe extraction path

    Raises:
        SecurityError: Path validation failed
    """
    # 1. Verify null byte
    if "\0" in archive_member_name:
        raise SecurityError(f"Null byte in filename: {archive_member_name}")

    # 2. Block absolute path
    if os.path.isabs(archive_member_name):
        raise SecurityError(f"Absolute path in archive: {archive_member_name}")

    # 3. Normalize path
    extract_path = os.path.normpath(os.path.join(extract_base_dir, archive_member_name))

    # 4. Verify path traversal
    return validate_path(extract_path, extract_base_dir, allow_symlinks=False)


# -------------------------------------------------------------------------
# Filename Validation Functions
# -------------------------------------------------------------------------
def safe_filename(filename: str, max_length: int = 255) -> bool:
    """
    Verify filename safety

    Args:
        filename: Filename to verify
        max_length: Maximum length

    Returns:
        Verification result (True)

    Raises:
        SecurityError: Verification failed
    """
    # 1. Verify null byte
    if "\0" in filename:
        raise SecurityError("Null byte in filename")

    # 2. Verify path separator
    if "/" in filename or "\\" in filename:
        raise SecurityError("Path separator in filename")

    # 3. Verify length
    if len(filename) > max_length:
        raise SecurityError(f"Filename too long: {len(filename)} > {max_length}")

    # 4. Verify dangerous characters (Windows reserved characters)
    dangerous_chars = ["<", ">", ":", '"', "|", "?", "*"]
    if any(c in filename for c in dangerous_chars):
        raise SecurityError(f"Dangerous character in filename: {filename}")

    # 5. Verify reserved names (Windows)
    reserved_names = [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    ]
    # Compare with the name without extension
    name_without_ext = os.path.splitext(filename)[0].upper()
    if name_without_ext in reserved_names:
        raise SecurityError(f"Reserved filename: {filename}")

    # 6. Verify empty filename
    if not filename or filename.strip() == "":
        raise SecurityError("Empty filename")

    # 7. Verify if the filename starts or ends with a period (Windows issue)
    if filename.endswith(".") or filename.endswith(" "):
        raise SecurityError(f"Filename ends with invalid character: {filename}")

    return True


# -------------------------------------------------------------------------
# File Operations
# -------------------------------------------------------------------------
def safe_remove_file(filepath: str, allowed_dir: str) -> bool:
    """
    Safe file deletion (CWE-73)

    Args:
        filepath: Path to delete
        allowed_dir: Allowed directory

    Returns:
        Deletion success status

    Raises:
        SecurityError: Verification failed
    """
    # 1. Verify path
    filepath = validate_path(filepath, allowed_dir, allow_symlinks=False)

    # 2. Verify file existence
    if not os.path.exists(filepath):
        return False

    # 3. Verify if it is a file (prevent directory deletion)
    if not os.path.isfile(filepath):
        raise SecurityError(f"Not a file: {filepath}")

    # 4. Verify if it is a symbolic link
    if os.path.islink(filepath):
        raise SecurityError(f"Cannot delete symlink: {filepath}")

    # 5. Safely delete
    os.remove(filepath)
    return True


def hash_file_sha256(filepath: str) -> str:
    """
    Calculate SHA256 hash of a file

    Args:
        filepath: Path to calculate hash

    Returns:
        SHA256 hash (hex string)
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# -------------------------------------------------------------------------
# URL Validation Functions
# -------------------------------------------------------------------------
def validate_url(
    url: str, allowed_schemes: Optional[List[str]] = None, allowed_domains: Optional[List[str]] = None
) -> bool:
    """
    URL validation - SSRF prevention (CWE-918)

    Args:
        url: URL to validate
        allowed_schemes: Allowed schemes list (default: ['https'])
        allowed_domains: Allowed domains list

    Returns:
        Verification result (True)

    Raises:
        SecurityError: Verification failed
    """
    if allowed_schemes is None:
        allowed_schemes = ["https"]

    # 1. Parse URL
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise SecurityError(f"Invalid URL: {e}")

    # 2. Verify scheme
    if parsed.scheme not in allowed_schemes:
        raise SecurityError(f"Disallowed URL scheme: {parsed.scheme}")

    # 3. Extract hostname
    hostname = parsed.hostname
    if not hostname:
        raise SecurityError("No hostname in URL")

    # 4. Verify IP address (block Private IP)
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private:
            raise SecurityError(f"Private IP address: {ip}")
        if ip.is_loopback:
            raise SecurityError(f"Loopback IP address: {ip}")
        if ip.is_link_local:
            raise SecurityError(f"Link-local IP address: {ip}")
        if ip.is_reserved:
            raise SecurityError(f"Reserved IP address: {ip}")
        # Block cloud metadata server (169.254.169.254)
        if str(ip) == "169.254.169.254":
            raise SecurityError(f"Cloud metadata IP address blocked: {ip}")
    except ValueError:
        # If it is a domain name, continue
        pass

    # 5. Verify domain whitelist
    if allowed_domains is not None:
        domain_allowed = False
        for domain in allowed_domains:
            if hostname == domain or hostname.endswith("." + domain):
                domain_allowed = True
                break
        if not domain_allowed:
            raise SecurityError(f"Domain not in whitelist: {hostname}")

    # 6. Block dangerous hostname
    dangerous_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    if hostname.lower() in dangerous_hosts:
        raise SecurityError(f"Dangerous hostname: {hostname}")

    return True


# -------------------------------------------------------------------------
# Archive Security Functions
# -------------------------------------------------------------------------
def is_safe_archive_member(member_name: str) -> bool:
    """
    Verify the safety of the archive member name quickly

    Args:
        member_name: Name of the archive member

    Returns:
        Safety status (True/False)
    """
    # Verify null byte
    if "\0" in member_name:
        return False

    # Verify absolute path
    if os.path.isabs(member_name):
        return False

    # Verify path traversal
    if ".." in pathlib.Path(member_name).parts:
        return False

    return True


def get_safe_extract_path(archive_member_name: str, extract_base_dir: str) -> Optional[str]:
    """
    Return a safe extraction path, or return None if it is not safe

    Args:
        archive_member_name: Name of the archive member
        extract_base_dir: Base directory for extraction

    Returns:
        Safe extraction path or None
    """
    try:
        return safe_extract_member(archive_member_name, extract_base_dir)
    except SecurityError:
        return None


# -------------------------------------------------------------------------
# Secure Download Functions (CWE-434, CWE-918)
# -------------------------------------------------------------------------
def safe_download_file(
    url: str,
    dest_path: str,
    base_dir: str,
    allowed_schemes: Optional[List[str]] = None,
    allowed_domains: Optional[List[str]] = None,
    fnhook: Optional[Callable] = None,
) -> str:
    """
    Secure file download (CWE-434, CWE-918 prevention)

    Validates URL for SSRF prevention and destination path for path traversal.

    Args:
        url: URL to download from
        dest_path: Destination file path
        base_dir: Allowed base directory for downloads
        allowed_schemes: Allowed URL schemes (default: ["https", "http"])
        allowed_domains: Allowed domains list (None = allow all public domains)
        fnhook: Progress callback function

    Returns:
        Safe download path

    Raises:
        SecurityError: URL or path validation failed
    """
    # Default to allow both http and https for updates
    if allowed_schemes is None:
        allowed_schemes = ["https", "http"]

    # 1. Validate URL (SSRF prevention - CWE-918)
    validate_url(url, allowed_schemes=allowed_schemes, allowed_domains=allowed_domains)

    # 2. Validate destination path (Path Traversal prevention - CWE-22)
    safe_dest = validate_path(dest_path, base_dir)

    # 3. Download file securely
    try:
        if fnhook is not None:
            urllib.request.urlretrieve(url, safe_dest, fnhook)
        else:
            urllib.request.urlretrieve(url, safe_dest)
    except Exception as e:
        raise SecurityError("failed")

    return safe_dest


def validate_download_filename(filename: str) -> str:
    """
    Validate download filename for dangerous characters and extensions

    Args:
        filename: Filename to validate

    Returns:
        Validated filename

    Raises:
        SecurityError: Invalid filename
    """
    # Check for null byte
    if "\0" in filename:
        raise SecurityError("Null byte in filename")

    # Check for path separators
    if "/" in filename or "\\" in filename:
        raise SecurityError("Path separator in filename")

    # Check for path traversal
    if ".." in filename:
        raise SecurityError("Path traversal in filename")

    # Check for empty filename
    if not filename or filename.strip() == "":
        raise SecurityError("Empty filename")

    # Check for reserved device names on Windows
    reserved_names = [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    ]
    name_without_ext = os.path.splitext(filename)[0].upper()
    if name_without_ext in reserved_names:
        raise SecurityError(f"Reserved filename: {filename}")

    return filename


# -------------------------------------------------------------------------
# Secure Marshal Deserialization (CWE-502)
# -------------------------------------------------------------------------
import hmac
import logging
import marshal
import zlib

_security_logger = logging.getLogger(__name__)

# KAVS file format constants
KAVS_MAGIC = b"KAVS"
KAVS_MAGIC_V2 = b"KAV2"  # New format with HMAC
KAVS_HMAC_SIZE = 32  # SHA-256 HMAC

# Maximum sizes for safety
MAX_SIGNATURE_FILE_SIZE = 50 * 1024 * 1024  # 50MB max for signature files
MAX_TOC_SIZE = 10 * 1024 * 1024  # 10MB max for PYZ TOC


class MarshalSecurityError(SecurityError):
    """Exception for marshal deserialization security errors."""

    pass


# Data-only types that KicomAV signature tools emit (sigtool_*.py use set()).
_SIG_SAFE_TYPES = (type(None), bool, int, float, complex, str, bytes, bytearray)


def _assert_signature_safe(obj, depth: int = 0, max_depth: int = 20) -> None:
    """Reject non-data objects (e.g. code objects) in deserialized signature data.

    marshal.loads() can yield code objects and other non-data types; signature
    data must only ever be scalars/containers. Allows the container types the
    signature tools emit (list/tuple/dict/set/frozenset).
    """
    if depth > max_depth:
        raise MarshalSecurityError("Signature structure too deep")
    if isinstance(obj, _SIG_SAFE_TYPES):
        return
    if isinstance(obj, (tuple, list, set, frozenset)):
        for item in obj:
            _assert_signature_safe(item, depth + 1, max_depth)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _assert_signature_safe(k, depth + 1, max_depth)
            _assert_signature_safe(v, depth + 1, max_depth)
        return
    raise MarshalSecurityError(f"Unsafe type in signature data: {type(obj).__name__}")


def safe_marshal_load_kavs(
    data: bytes,
    hmac_key: bytes = None,
    allow_unsigned: bool = True,
) -> any:
    """
    Securely load KAVS signature file data with integrity verification.

    Supports two formats:
    - KAVS (legacy): 4-byte magic + 8-byte metadata + zlib(marshal data)
    - KAV2 (secure): 4-byte magic + 32-byte HMAC + zlib(marshal data)

    Args:
        data: Raw file data
        hmac_key: HMAC key for signature verification (required for KAV2)
        allow_unsigned: Allow loading unsigned KAVS files (with warning)

    Returns:
        Deserialized Python object

    Raises:
        MarshalSecurityError: If verification fails or data is invalid
    """
    if not data:
        raise MarshalSecurityError("Empty data")

    if len(data) > MAX_SIGNATURE_FILE_SIZE:
        raise MarshalSecurityError(f"Signature file too large: {len(data)} bytes")

    magic = data[:4]

    # New secure format (KAV2)
    if magic == KAVS_MAGIC_V2:
        if hmac_key is None:
            raise MarshalSecurityError("HMAC key required for KAV2 format")

        if len(data) < 4 + KAVS_HMAC_SIZE + 1:
            raise MarshalSecurityError("KAV2 file too short")

        file_hmac = data[4 : 4 + KAVS_HMAC_SIZE]
        compressed_data = data[4 + KAVS_HMAC_SIZE :]

        # Verify HMAC
        expected_hmac = hmac.new(hmac_key, compressed_data, hashlib.sha256).digest()
        if not hmac.compare_digest(file_hmac, expected_hmac):
            raise MarshalSecurityError("HMAC verification failed - file may be tampered")

        try:
            decompressed = safe_zlib_decompress(
                compressed_data, max_size=MAX_SIGNATURE_FILE_SIZE, max_ratio=2**31)
            obj = marshal.loads(decompressed)
        except (zlib.error, ValueError, EOFError, DecompressionBombError) as e:
            raise MarshalSecurityError(f"Decompression/unmarshal failed: {e}")
        except Exception as e:  # marshal may raise MemoryError/TypeError/RecursionError
            raise MarshalSecurityError(f"Unmarshal error: {type(e).__name__}: {e}")
        _assert_signature_safe(obj)
        return obj

    # Legacy format (KAVS)
    elif magic == KAVS_MAGIC:
        if not allow_unsigned:
            raise MarshalSecurityError("Unsigned KAVS files not allowed")

        if len(data) < 13:  # 4 + 8 + at least 1 byte
            raise MarshalSecurityError("KAVS file too short")

        # Log warning for unsigned files
        _security_logger.debug("Loading unsigned KAVS file (legacy format)")

        try:
            # KAVS format: 4-byte magic + 8-byte metadata + compressed data
            compressed_data = data[12:]
            decompressed = safe_zlib_decompress(
                compressed_data, max_size=MAX_SIGNATURE_FILE_SIZE, max_ratio=2**31)
            obj = marshal.loads(decompressed)
        except (zlib.error, ValueError, EOFError, DecompressionBombError) as e:
            raise MarshalSecurityError(f"Decompression/unmarshal failed: {e}")
        except Exception as e:  # marshal may raise MemoryError/TypeError/RecursionError
            raise MarshalSecurityError(f"Unmarshal error: {type(e).__name__}: {e}")
        _assert_signature_safe(obj)
        return obj

    else:
        raise MarshalSecurityError(f"Unknown file format: {magic!r}")


def safe_marshal_load_toc(data: bytes, max_entries: int = 100000) -> any:
    """
    Securely load PYZ TOC (Table of Contents) data with type validation.

    This is used for parsing potentially untrusted PYZ archives during scanning.
    Only allows safe types (list, dict, str, bytes, int, float, tuple).

    Args:
        data: Raw TOC data
        max_entries: Maximum number of entries allowed

    Returns:
        Deserialized TOC (list or dict)

    Raises:
        MarshalSecurityError: If data is invalid or contains unsafe types
    """
    if not data:
        raise MarshalSecurityError("Empty TOC data")

    if len(data) > MAX_TOC_SIZE:
        raise MarshalSecurityError(f"TOC too large: {len(data)} bytes")

    try:
        toc = marshal.loads(data)
    except (ValueError, EOFError) as e:
        raise MarshalSecurityError(f"Failed to unmarshal TOC: {e}")
    except Exception as e:
        # A tiny TOC can encode a huge length prefix (list/tuple/str/bytes),
        # driving marshal.loads() into a massive allocation -> MemoryError.
        # The input-size cap above does not bound the decoded allocation, so
        # catch everything here instead of letting it escape to the scanner.
        raise MarshalSecurityError(f"Unmarshal TOC error: {type(e).__name__}: {e}")

    # Validate result type
    if not isinstance(toc, (list, dict)):
        raise MarshalSecurityError(f"Invalid TOC type: {type(toc).__name__}")

    # Validate entry count
    entry_count = len(toc)
    if entry_count > max_entries:
        raise MarshalSecurityError(f"TOC has too many entries: {entry_count}")

    # Validate contents don't contain code objects
    _validate_toc_contents(toc, depth=0, max_depth=10)

    return toc


def _validate_toc_contents(obj: any, depth: int, max_depth: int) -> None:
    """
    Recursively validate TOC contents for unsafe types.

    Args:
        obj: Object to validate
        depth: Current recursion depth
        max_depth: Maximum allowed depth

    Raises:
        MarshalSecurityError: If unsafe type is found
    """
    if depth > max_depth:
        raise MarshalSecurityError("TOC structure too deep")

    # Safe primitive types
    if obj is None or isinstance(obj, (str, bytes, int, float, bool)):
        return

    # Tuples are safe for TOC entries
    if isinstance(obj, tuple):
        for item in obj:
            _validate_toc_contents(item, depth + 1, max_depth)
        return

    # Lists need validation
    if isinstance(obj, list):
        for item in obj:
            _validate_toc_contents(item, depth + 1, max_depth)
        return

    # Dicts need validation
    if isinstance(obj, dict):
        for key, value in obj.items():
            _validate_toc_contents(key, depth + 1, max_depth)
            _validate_toc_contents(value, depth + 1, max_depth)
        return

    # Code objects are dangerous - reject
    if type(obj).__name__ == "code":
        raise MarshalSecurityError("Code object found in TOC - potential security risk")

    # Reject any other types
    raise MarshalSecurityError(f"Unsafe type in TOC: {type(obj).__name__}")


# -------------------------------------------------------------------------
# Subprocess Security Functions (CWE-78)
# -------------------------------------------------------------------------
def is_safe_subprocess_filename(filename: str) -> bool:
    """
    Validate filename for safe use in subprocess calls (CWE-78 prevention).

    Even when using subprocess with list arguments (not shell=True),
    this validation provides defense in depth against command injection.

    Args:
        filename: Filename to validate

    Returns:
        True if filename is safe for subprocess use, False otherwise
    """
    if not filename:
        return False

    # Check for null byte
    if "\0" in filename:
        return False

    # Check for path traversal
    if ".." in filename:
        return False

    # Check for absolute paths
    if os.path.isabs(filename):
        return False

    # Check for shell metacharacters (defense in depth)
    # Even with list-based subprocess, reject suspicious characters
    shell_metacharacters = set(";|&`$><")
    if any(c in filename for c in shell_metacharacters):
        return False

    return True


# -------------------------------------------------------------------------
# Decompression Bomb Protection
# -------------------------------------------------------------------------
# Maximum decompressed size (1GB)
MAX_DECOMPRESS_SIZE = 1024 * 1024 * 1024

# Maximum compression ratio (100:1) - zip bombs often have 1000:1 or higher
MAX_COMPRESSION_RATIO = 100


class DecompressionBombError(SecurityError):
    """Exception for decompression bomb detection."""

    pass


def safe_zlib_decompress(
    data: bytes,
    wbits: int = 15,
    max_size: int = MAX_DECOMPRESS_SIZE,
    max_ratio: int = MAX_COMPRESSION_RATIO,
) -> bytes:
    """
    Safely decompress zlib data with bomb protection.

    Prevents decompression bombs by checking:
    1. Maximum decompressed size
    2. Compression ratio (compressed vs decompressed size)

    Args:
        data: Compressed data
        wbits: zlib window bits (default 15, use -15 for raw deflate)
        max_size: Maximum allowed decompressed size in bytes
        max_ratio: Maximum allowed compression ratio

    Returns:
        Decompressed data

    Raises:
        DecompressionBombError: If decompression limits exceeded
    """
    import zlib

    compressed_size = len(data)

    # Use incremental decompression to detect bombs early
    decompressor = zlib.decompressobj(wbits)
    chunks = []
    total_size = 0

    try:
        # Decompress in chunks to monitor size growth
        chunk = decompressor.decompress(data, max_length=max_size)
        total_size += len(chunk)
        chunks.append(chunk)

        # Check for remaining data - if we've hit max_size and there's more, it exceeds limit
        while decompressor.unconsumed_tail:
            if total_size >= max_size:
                raise DecompressionBombError(f"Decompressed size exceeds limit: {total_size} >= {max_size}")

            remaining = max_size - total_size
            chunk = decompressor.decompress(decompressor.unconsumed_tail, max_length=remaining)
            total_size += len(chunk)
            chunks.append(chunk)

        # Check compression ratio
        if compressed_size > 0:
            ratio = total_size / compressed_size
            if ratio > max_ratio:
                raise DecompressionBombError(f"Suspicious compression ratio: {ratio:.1f}:1 > {max_ratio}:1")

        return b"".join(chunks)

    except zlib.error as e:
        raise DecompressionBombError(f"Decompression error: {e}")


# -------------------------------------------------------------------------
# File Write Size Validation
# -------------------------------------------------------------------------
# Maximum file write size (100MB default for update files)
MAX_WRITE_SIZE = 100 * 1024 * 1024


class FileSizeError(SecurityError):
    """Exception for file size validation errors."""

    pass


def safe_write_file(
    path: str,
    data: bytes,
    max_size: int = MAX_WRITE_SIZE,
) -> None:
    """
    Safely write data to file with size validation.

    Prevents disk exhaustion by limiting maximum write size.

    Args:
        path: Path to write file
        data: Data to write
        max_size: Maximum allowed file size in bytes

    Raises:
        FileSizeError: If data exceeds maximum size
    """
    if len(data) > max_size:
        raise FileSizeError(f"Data too large: {len(data)} bytes exceeds limit of {max_size} bytes")

    with open(path, "wb") as f:
        f.write(data)
