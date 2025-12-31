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
        raise SecurityError(f"failed")

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
