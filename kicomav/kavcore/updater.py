# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Updater Module

This module provides update functionality for KicomAV signatures and package.
"""

import contextlib
import datetime
import glob
import gzip
import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Set, Tuple

from . import k2security
from .config import get_config

# Module logger
logger = logging.getLogger(__name__)

# Default update URL
DEFAULT_UPDATE_URL = "https://raw.githubusercontent.com/hanul93/kicomav-db/master/update/"


@dataclass
class UpdateResult:
    """Result of an update operation.

    Attributes:
        success: Whether the update completed successfully
        updated_files: List of files that were updated
        removed_files: List of orphan files that were removed
        errors: List of error messages encountered
        package_update_available: Whether a newer kicomav package is available
        latest_version: Latest available package version (if checked)
        current_version: Currently installed package version
    """

    success: bool = True
    updated_files: List[str] = field(default_factory=list)
    removed_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    package_update_available: bool = False
    latest_version: Optional[str] = None
    current_version: Optional[str] = None


# Type alias for progress callback
ProgressCallback = Callable[[str, str], None]


def get_installed_version(package_name: str = "kicomav") -> Optional[str]:
    """Get the installed version of a package.

    Args:
        package_name: Name of the package to check

    Returns:
        Version string or None if not installed
    """
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version(package_name)
    except PackageNotFoundError:
        return None
    except Exception as e:
        logger.debug("Failed to get installed version: %s", e)
        return None


def get_latest_version(package_name: str = "kicomav") -> Optional[str]:
    """Get the latest version of a package from PyPI.

    Args:
        package_name: Name of the package to check

    Returns:
        Latest version string or None if unavailable
    """
    try:
        import requests

        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()["info"]["version"]
    except Exception as e:
        logger.debug("Failed to get latest version from PyPI: %s", e)
        return None


def check_package_update(
    package_name: str = "kicomav",
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Check if a package update is available.

    Args:
        package_name: Name of the package to check

    Returns:
        Tuple of (update_available, current_version, latest_version)
    """
    current = get_installed_version(package_name)
    latest = get_latest_version(package_name)

    if latest is None:
        return False, current, None

    if current is None:
        return True, None, latest

    update_available = current != latest
    return update_available, current, latest


def _check_need_update(filepath: str, expected_hash: str) -> bool:
    """Check if a file needs to be updated by comparing SHA1 hashes.

    Args:
        filepath: Path to the local file
        expected_hash: Expected SHA1 hash from update config

    Returns:
        True if update is needed, False otherwise
    """
    try:
        with open(filepath, "rb") as fp:
            data = fp.read()
        s = hashlib.sha1()
        s.update(data)
        return s.hexdigest().lower() != expected_hash.lower()
    except (IOError, OSError):
        return True  # File doesn't exist or can't be read


def _download_file(
    url: str,
    filename: str,
    path: str,
    gz: bool = False,
    progress_callback: Optional[ProgressCallback] = None,
) -> bool:
    """Download a single file.

    Args:
        url: Base URL for download
        filename: Name of file to download (can include subdirectory path)
        path: Local directory to save the file
        gz: Whether the file is gzipped on the server
        progress_callback: Optional callback for progress updates

    Returns:
        True if download succeeded, False otherwise
    """
    # Normalize path separators
    filename = filename.replace("\\", "/")

    # Split into directory path and actual filename
    if "/" in filename:
        subdir, actual_filename = filename.rsplit("/", 1)
        # Validate for path traversal
        if ".." in subdir:
            logger.warning("Path traversal detected in filename: %s", filename)
            return False
    else:
        subdir = ""
        actual_filename = filename

    # CWE-434: Validate filename before download
    try:
        k2security.validate_download_filename(actual_filename)
    except k2security.SecurityError as e:
        logger.warning("Invalid filename %s: %s", filename, e)
        return False

    # Create subdirectory if needed
    if subdir:
        subdir_path = os.path.join(path, subdir)
        os.makedirs(subdir_path, exist_ok=True)

    # Build download URL
    download_url = url + filename.replace("\\", "/")
    if gz:
        download_url += ".gz"

    # Get full path for saving
    save_path = os.path.join(path, filename)
    if gz:
        save_path += ".gz"

    if progress_callback:
        progress_callback(filename, "downloading")

    # Download the file
    try:
        base_path = os.path.join(path, subdir) if subdir else path
        k2security.safe_download_file(download_url, save_path, base_path)
    except k2security.SecurityError as e:
        logger.warning("Download failed for %s: %s", filename, e)
        return False

    # Handle gzipped files
    if gz:
        try:
            with gzip.open(save_path, "rb") as gz_file:
                data = gz_file.read()
            final_path = os.path.join(path, filename)
            with open(final_path, "wb") as out_file:
                out_file.write(data)
            # Delete the gz file
            base_path = os.path.join(path, subdir) if subdir else path
            with contextlib.suppress(k2security.SecurityError):
                k2security.safe_remove_file(save_path, base_path)
        except Exception as e:
            logger.warning("Failed to decompress %s: %s", filename, e)
            return False

    if progress_callback:
        progress_callback(filename, "updated")

    return True


def _get_signature_download_list(url: str, rules_path: str) -> Tuple[List[str], Set[str]]:
    """Get list of signature files that need updating.

    Args:
        url: Base URL for update config
        rules_path: Local rules directory path

    Returns:
        Tuple of (files_to_download, all_files_in_config)
    """
    down_list = []
    cfg_files: Set[str] = set()

    if not rules_path:
        return down_list, cfg_files

    try:
        # Download update.cfg to temp location
        temp_cfg_path = os.path.join(rules_path, "update.cfg")
        _download_file(url, "update.cfg", rules_path)

        with open(temp_cfg_path, "r") as f:
            buf = f.read()

        # Format: [sha1] [filepath]
        p_lists = re.compile(r"([A-Fa-f0-9]{40}) (.+)")
        lines = p_lists.findall(buf)

        for line in lines:
            fhash = line[0]
            fname = line[1].strip()

            cfg_files.add(fname)

            # Normalize path separators
            fname_normalized = fname.replace("/", os.sep).replace("\\", os.sep)
            local_file = os.path.join(rules_path, fname_normalized)

            # Special handling for whitelist.txt
            if fname == "whitelist.txt":
                if os.path.exists(local_file):
                    continue  # Keep local whitelist
                else:
                    down_list.append(fname)
                    continue

            # Check if update needed
            if _check_need_update(local_file, fhash):
                down_list.append(fname)

        # Keep update.cfg for timestamp tracking (do not delete)

    except Exception as e:
        logger.debug("Failed to get download list: %s", e)

    return down_list, cfg_files


def _get_local_files(rules_path: str) -> Set[str]:
    """Get all local files in rules path.

    Args:
        rules_path: Local rules directory path

    Returns:
        Set of relative file paths
    """
    local_files: Set[str] = set()
    for filepath in glob.glob(os.path.join(rules_path, "**", "*"), recursive=True):
        if os.path.isdir(filepath):
            continue
        rel_path = os.path.relpath(filepath, rules_path)
        rel_path = rel_path.replace("\\", "/")
        local_files.add(rel_path)
    return local_files


def _remove_orphan_files(
    rules_path: str,
    cfg_files: Set[str],
    progress_callback: Optional[ProgressCallback] = None,
) -> List[str]:
    """Remove local files not in update.cfg.

    Args:
        rules_path: Local rules directory path
        cfg_files: Set of files listed in update.cfg
        progress_callback: Optional progress callback

    Returns:
        List of removed files
    """
    removed = []
    local_files = _get_local_files(rules_path)
    cfg_files_normalized = {f.replace("\\", "/") for f in cfg_files}
    orphan_files = local_files - cfg_files_normalized

    for orphan in orphan_files:
        if orphan in ("whitelist.txt", "update.cfg"):
            continue

        orphan_path = os.path.join(rules_path, orphan)
        try:
            if "/" in orphan:
                subdir = orphan.rsplit("/", 1)[0]
                base_path = os.path.join(rules_path, subdir)
            else:
                base_path = rules_path

            k2security.safe_remove_file(orphan_path, base_path)
            removed.append(orphan)
            if progress_callback:
                progress_callback(orphan, "removed")
        except k2security.SecurityError:
            pass

    return removed


def _remove_empty_dirs(rules_path: str) -> None:
    """Remove empty directories in rules path.

    Args:
        rules_path: Local rules directory path
    """
    for root, dirs, files in os.walk(rules_path, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
            except OSError:
                pass


def update_signatures(
    rules_path: Optional[str] = None,
    url: Optional[str] = None,
    progress_callback: Optional[ProgressCallback] = None,
) -> UpdateResult:
    """Update signature files.

    Args:
        rules_path: Path to rules directory. If None, uses SYSTEM_RULES_BASE from config.
        url: Update server URL. If None, uses default URL.
        progress_callback: Optional callback called with (filename, status) for each file.

    Returns:
        UpdateResult with details of the update operation
    """
    result = UpdateResult()

    # Get rules path from config if not provided
    if rules_path is None:
        config = get_config()
        rules_path = config.system_rules_base

    if not rules_path:
        result.success = False
        result.errors.append("No rules path configured (SYSTEM_RULES_BASE not set)")
        return result

    if not os.path.exists(rules_path):
        result.success = False
        result.errors.append(f"Rules path does not exist: {rules_path}")
        return result

    # Use default URL if not provided
    if url is None:
        url = DEFAULT_UPDATE_URL

    try:
        # Get list of files to download
        down_list, cfg_files = _get_signature_download_list(url, rules_path)

        # Remove orphan files
        if cfg_files:
            removed = _remove_orphan_files(rules_path, cfg_files, progress_callback)
            result.removed_files = removed
            _remove_empty_dirs(rules_path)

        # Download updated files
        for filename in down_list:
            if _download_file(url, filename, rules_path, gz=False, progress_callback=progress_callback):
                result.updated_files.append(filename)
            else:
                result.errors.append(f"Failed to download: {filename}")

    except Exception as e:
        result.success = False
        result.errors.append(f"Update failed: {str(e)}")
        logger.exception("Signature update failed")

    return result


def update(progress_callback: Optional[ProgressCallback] = None, check_package: bool = True) -> UpdateResult:
    """Full update: check package version and update signatures.

    Args:
        progress_callback: Optional callback for progress updates
        check_package: Whether to check for package updates

    Returns:
        UpdateResult with details of the update operation
    """
    result = UpdateResult()

    # Check package update
    if check_package:
        update_available, current, latest = check_package_update()
        result.package_update_available = update_available
        result.latest_version = latest
        result.current_version = current

    # Update signatures
    sig_result = update_signatures(progress_callback=progress_callback)

    # Merge signature update results
    result.success = sig_result.success
    result.updated_files = sig_result.updated_files
    result.removed_files = sig_result.removed_files
    result.errors.extend(sig_result.errors)

    return result


def get_update_timestamp(rules_path: Optional[str] = None) -> Optional[datetime.datetime]:
    """Read UTC timestamp from update.cfg first line.

    The update.cfg file is expected to have a timestamp comment on the first line:
    # Sat Dec 27 03:05:44 2025 UTC

    Args:
        rules_path: Path to rules directory. If None, uses system_rules_base from config.

    Returns:
        datetime object with UTC timezone or None if not found or parse failed
    """
    if rules_path is None:
        config = get_config()
        rules_path = config.system_rules_base

    if not rules_path:
        return None

    cfg_path = os.path.join(rules_path, "update.cfg")
    if not os.path.exists(cfg_path):
        return None

    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()

        # Parse format: # Sat Dec 27 03:05:44 2025 UTC
        if first_line.startswith("#"):
            time_str = first_line[1:].strip()  # Remove "#"
            if time_str.endswith(" UTC"):
                time_str = time_str[:-4]  # Remove " UTC"
                return datetime.datetime.strptime(time_str, "%a %b %d %H:%M:%S %Y").replace(
                    tzinfo=datetime.timezone.utc
                )
    except Exception as e:
        logger.debug("Failed to parse update.cfg timestamp: %s", e)

    return None


def get_last_update_time() -> datetime.datetime:
    """Get last update time from update.cfg or fallback to __last_update__.

    Returns:
        datetime object with UTC timezone
    """
    cfg_time = get_update_timestamp()
    if cfg_time:
        return cfg_time

    # Fallback to __last_update__ from kicomav package
    try:
        from kicomav import __last_update__

        time_str = __last_update__
        if time_str.endswith(" UTC"):
            time_str = time_str[:-4]
        return datetime.datetime.strptime(time_str, "%a %b %d %H:%M:%S %Y").replace(tzinfo=datetime.timezone.utc)
    except Exception as e:
        logger.debug("Failed to parse __last_update__: %s", e)
        # Ultimate fallback: epoch time
        return datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
