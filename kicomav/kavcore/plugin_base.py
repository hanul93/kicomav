#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
KICOMAV Plugin Base Classes

This module provides abstract base classes for all KICOMAV plugins,
implementing common functionality and enforcing consistent interfaces.
"""

import os
import logging
import pathlib
from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Dict, Any, List, Optional, Tuple, BinaryIO, Union

# Module logger
logger = logging.getLogger(__name__)

from . import k2security
from . import k2const


# Default maximum scan size (100MB)
# Can be overridden via init() or set_max_scan_size()
DEFAULT_MAX_SCAN_SIZE = 100 * 1024 * 1024

# Special value to disable size limit
UNLIMITED_SCAN_SIZE = 0


# -------------------------------------------------------------------------
# Scan Result Constants
# -------------------------------------------------------------------------
class ScanResultCode(IntEnum):
    """Scan result codes for threat identification."""

    CLEAN = 0  # No threat detected (normal scan completion)
    INFECTED = 1  # Threat detected via signature
    HEURISTIC = 2  # Threat detected via heuristic analysis
    ERROR = -1  # Scan error occurred
    SKIPPED = -2  # File was skipped (too large, unsupported, etc.)


# Threat ID constants
THREAT_ID_DETECTED = 0  # Normal detection
THREAT_ID_NOT_FOUND = -1  # No threat found or error

# Empty scan result tuple (no threat found)
SCAN_RESULT_CLEAN = (False, "", THREAT_ID_NOT_FOUND, "")


class PluginBase(ABC):
    """Base class for all KICOMAV plugins.

    This abstract base class provides common initialization, cleanup,
    and information retrieval functionality for all plugin types.
    """

    def __init__(self, author: str = "Kei Choi", version: str = "1.0", title: str = "", kmd_name: str = ""):
        """Initialize the plugin with metadata.

        Args:
            author: Plugin author name
            version: Plugin version string
            title: Human-readable plugin title
            kmd_name: Internal plugin identifier
        """
        self.author = author
        self.version = version
        self.title = title
        self.kmd_name = kmd_name
        self.verbose = False
        self.rules_paths = {}  # {"system": "/path", "user": "/path" or None}
        self._max_scan_size = DEFAULT_MAX_SCAN_SIZE

    def init(
        self,
        rules_paths: Optional[Dict[str, Optional[str]]] = None,
        verbose: bool = False,
        max_scan_size: Optional[int] = None,
    ) -> int:
        """Initialize the plugin engine.

        Args:
            rules_paths: Dictionary with rule paths {"system": "/path", "user": "/path"}
            verbose: Enable verbose output
            max_scan_size: Maximum file size to scan in bytes.
                          None = use default (100MB)
                          0 = unlimited

        Returns:
            0 for success, non-zero for failure
        """
        # Validate rules_paths is dict (strict enforcement)
        if rules_paths is not None and not isinstance(rules_paths, dict):
            raise TypeError(f"rules_paths must be a dict, got {type(rules_paths).__name__}")

        self.rules_paths = rules_paths or {"system": None, "user": None}
        self.verbose = verbose

        if max_scan_size is not None:
            self._max_scan_size = max_scan_size

        # Call subclass-specific initialization
        return self._custom_init()

    def _get_rule_path(self, rule_type: str) -> List[pathlib.Path]:
        """Get rule paths for a specific rule type.

        Each plugin can use this to find its rule directory.
        For example, YARA plugin uses 'yara', KicomAV pattern uses 'kicomav'.

        Args:
            rule_type: Subfolder name ('yara', 'kicomav', etc.)

        Returns:
            List of valid Path objects for the rule type
        """
        paths = []
        for key in ["system", "user"]:
            base = self.rules_paths.get(key)
            if base:
                path = pathlib.Path(base) / rule_type
                if path.exists() and path.is_dir():
                    paths.append(path)
        return paths

    @property
    def max_scan_size(self) -> int:
        """Get maximum scan size in bytes.

        Returns:
            Maximum scan size (0 = unlimited)
        """
        return self._max_scan_size

    @max_scan_size.setter
    def max_scan_size(self, value: int):
        """Set maximum scan size.

        Args:
            value: Maximum size in bytes (0 = unlimited)
        """
        if value < 0:
            raise ValueError("max_scan_size must be non-negative")
        self._max_scan_size = value

    def _custom_init(self) -> int:
        """Subclass-specific initialization logic.

        Override this method in subclasses to add custom initialization.

        Returns:
            0 for success, non-zero for failure
        """
        return 0

    def uninit(self) -> int:
        """Terminate the plugin engine and cleanup resources.

        Returns:
            0 for success, non-zero for failure
        """
        self._cleanup_resources()
        return self._custom_uninit()

    def _custom_uninit(self) -> int:
        """Subclass-specific cleanup logic.

        Override this method in subclasses to add custom cleanup.

        Returns:
            0 for success, non-zero for failure
        """
        return 0

    def _cleanup_resources(self):
        """Common resource cleanup logic."""
        self.verbose = False

    def _validate_path_input(self, path: str, context: str = "path") -> bool:
        """Validate path input for basic security checks.

        Performs lightweight validation without requiring base_dir.
        For full path traversal protection, use k2security.validate_path().

        Args:
            path: Path string to validate
            context: Context for logging (e.g., "filename", "archive")

        Returns:
            True if path is safe, False otherwise
        """
        if not path:
            return True  # Empty path is handled elsewhere

        # Check for null bytes
        if "\0" in path:
            logger.warning("Null byte detected in %s: %s", context, repr(path))
            return False

        # Check for path traversal patterns
        path_parts = pathlib.Path(path).parts
        if ".." in path_parts:
            logger.warning("Path traversal detected in %s: %s", context, path)
            return False

        return True

    def _is_safe_archive_member(self, member_name: str) -> bool:
        """Check if archive member name is safe.

        Args:
            member_name: Name of the archive member

        Returns:
            True if safe, False otherwise
        """
        return k2security.is_safe_archive_member(member_name)

    def getinfo(self) -> Dict[str, Any]:
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        return {"author": self.author, "version": self.version, "title": self.title, "kmd_name": self.kmd_name}

    def listvirus(self, *args, **kwargs) -> List[str]:
        """Return list of detectable viruses/threats.

        Override in malware detector plugins.
        Archive and format plugins may leave this unimplemented.

        Returns:
            List of virus names this plugin can detect
        """
        return []

    def scan(self, filehandle: Union[bytes, BinaryIO], filename: str, *args, **kwargs) -> Tuple[bool, str, int, str]:
        """Scan a file for threats.

        Override in malware detector plugins.
        Archive and format plugins may leave this unimplemented.

        Args:
            filehandle: File data or handle to scan
            filename: Name of the file being scanned
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments

        Returns:
            Tuple of (threat_found, threat_name, threat_id, plugin_name)
        """
        return (False, "", -1, "")


class ArchivePluginBase(PluginBase):
    """Base class for archive processing plugins.

    Provides common functionality for handling various archive formats
    like ZIP, RAR, CAB, TAR, etc.

    Subclasses can either:
    1. Override high-level methods (format, arclist, unarc, mkarc) directly
       for complex multi-format plugins
    2. Implement helper methods (_get_signature, _parse_archive_format, etc.)
       for simple single-format plugins
    """

    def __init__(self, *args, **kwargs):
        """Initialize archive plugin."""
        super().__init__(*args, **kwargs)
        self.handle = {}  # Dict for multi-format support: {filename: handle}

    def format(self, filehandle: bytes, filename: str, filename_ex: str) -> Optional[Dict[str, Any]]:
        """Verify and parse archive format.

        Override this method for multi-format support or custom detection.

        Args:
            filehandle: File data to check
            filename: Original filename
            filename_ex: Extended filename information

        Returns:
            Dictionary with format information, None if not recognized
        """
        try:
            mm = filehandle
            signature = self._get_signature()

            if signature and len(mm) >= len(signature) and mm[: len(signature)] == signature:
                return self._parse_archive_format(mm, filename, filename_ex)
        except (IOError, OSError) as e:
            logger.debug("Archive format IO error for %s: %s", filename, e)
            raise k2const.PluginUnexpectedError(str(e)) from e
        except (ValueError, TypeError) as e:
            logger.debug("Archive format parse error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in archive format check for %s: %s", filename, e)
            raise k2const.PluginUnexpectedError(str(e)) from e

        return None

    def _get_signature(self) -> bytes:
        """Get the archive format signature.

        Override for single-format plugins.
        Return empty bytes if using custom format() implementation.

        Returns:
            Bytes representing the archive signature
        """
        return b""

    def _parse_archive_format(self, mm: bytes, filename: str, filename_ex: str) -> Dict[str, Any]:
        """Parse archive format and extract metadata.

        Override for single-format plugins.

        Args:
            mm: Memory-mapped file data
            filename: Original filename
            filename_ex: Extended filename information

        Returns:
            Dictionary containing archive metadata
        """
        return {}

    def arclist(self, filename: str, fileformat: Dict[str, Any], password: Optional[str] = None) -> List[Any]:
        """List files in the archive.

        Override this method for custom archive listing behavior.
        Return format can be List[Dict] or List[List] depending on needs.

        Args:
            filename: Path to archive file
            fileformat: Format information from format() method
            password: Optional password for encrypted archives

        Returns:
            List of file information (format depends on implementation)
        """
        file_scan_list = []

        try:
            with self._open_archive(filename, fileformat) as archive:
                for member in self._get_members(archive):
                    file_info = self._extract_member_info(member)
                    if file_info:
                        file_scan_list.append(file_info)
        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
            raise k2const.PluginUnexpectedError(str(e)) from e
        except (ValueError, KeyError) as e:
            logger.debug("Archive list parse error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)
            raise k2const.PluginUnexpectedError(str(e)) from e

        return file_scan_list

    def _open_archive(self, filename: str, fileformat: Dict[str, Any]):
        """Open archive file as context manager.

        Override for single-format plugins.

        Args:
            filename: Path to archive file
            fileformat: Format information

        Returns:
            Archive object (context manager)
        """
        raise NotImplementedError("Subclass must implement _open_archive or override arclist")

    def _get_members(self, archive) -> List[Any]:
        """Get list of archive members.

        Override for single-format plugins.

        Args:
            archive: Opened archive object

        Returns:
            List of archive members
        """
        return []

    def _extract_member_info(self, member) -> Any:
        """Extract information about an archive member.

        Override for single-format plugins.

        Args:
            member: Archive member object

        Returns:
            Member information (format depends on implementation)
        """
        return None

    def unarc(self, arc_engine_id: str, arc_name: str, fname_in_arc: str) -> Optional[bytes]:
        """Extract a file from the archive.

        Override this method for custom extraction behavior.

        Args:
            arc_engine_id: Engine ID for this archive (e.g., 'arc_zip')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data or None on error
        """
        # Validate archive member name for path traversal
        if not self._is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        try:
            return self._extract_file(arc_engine_id, arc_name, fname_in_arc)
        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
            raise k2const.PluginUnexpectedError(str(e)) from e
        except (ValueError, KeyError, IndexError) as e:
            logger.debug("Archive extract parse error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)
            raise k2const.PluginUnexpectedError(str(e)) from e

        return None

    def _extract_file(self, arc_engine_id: str, arc_name: str, fname_in_arc: str) -> Optional[bytes]:
        """Extract specific file from archive.

        Override for single-format plugins.

        Args:
            arc_engine_id: Engine ID for this archive
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data
        """
        return None

    def arcclose(self):
        """Close all open archive handles.

        Override if using different handle management.
        """
        for fname in list(self.handle.keys()):
            try:
                handle = self.handle[fname]
                if hasattr(handle, "close"):
                    handle.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)

    def _cleanup_resources(self):
        """Clean up archive-specific resources."""
        super()._cleanup_resources()
        self.arcclose()

    def mkarc(self, arc_engine_id: str, arc_name: str, file_infos: List[Any]) -> bool:
        """Create an archive with specified files.

        Override this method for custom archive creation.

        Args:
            arc_engine_id: Engine ID for archive type
            arc_name: Path for new archive
            file_infos: List of file information

        Returns:
            True if successful, False otherwise
        """
        try:
            return self._create_archive(arc_engine_id, arc_name, file_infos)
        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
            raise k2const.PluginUnexpectedError(str(e)) from e
        except (ValueError, TypeError) as e:
            logger.error("Archive creation data error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)
            raise k2const.PluginUnexpectedError(str(e)) from e

        return False

    def _create_archive(self, arc_engine_id: str, arc_name: str, file_infos: List[Any]) -> bool:
        """Create archive implementation.

        Override in subclasses that support archive creation.

        Args:
            arc_engine_id: Engine ID for archive type
            arc_name: Path for new archive
            file_infos: List of file information

        Returns:
            True if successful, False otherwise
        """
        return False


class MalwareDetectorBase(PluginBase):
    """Base class for malware detection plugins.

    Provides common functionality for signature-based and
    heuristic malware detection.
    """

    def __init__(self, *args, **kwargs):
        """Initialize malware detector."""
        super().__init__(*args, **kwargs)
        self.virus_names = []
        self.virus_info = []
        self.virus_patterns = {}

    def _custom_init(self) -> int:
        """Load virus database during initialization.

        Returns:
            0 for success, non-zero for failure
        """
        return self._load_virus_database()

    @abstractmethod
    def _load_virus_database(self) -> int:
        """Load virus signatures and patterns.

        Returns:
            0 for success, non-zero for failure
        """
        pass

    def listvirus(self, *args, **kwargs) -> List[str]:
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        return self.virus_names

    def scan(self, filehandle: Union[bytes, BinaryIO], filename: str, *args, **kwargs) -> Tuple[bool, str, int, str]:
        """Scan file for malware.

        Args:
            filehandle: File data or handle to scan
            filename: Name of the file being scanned
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments

        Returns:
            Tuple of (threat_found, threat_name, threat_id, plugin_name)
        """
        try:
            # Get file data with size limit
            if hasattr(filehandle, "read"):
                if self._max_scan_size > 0:
                    mm = filehandle.read(self._max_scan_size)
                    # Check if file was truncated
                    if hasattr(filehandle, "seek") and hasattr(filehandle, "tell"):
                        current_pos = filehandle.tell()
                        filehandle.seek(0, 2)  # Seek to end
                        file_size = filehandle.tell()
                        filehandle.seek(current_pos)  # Restore position
                        if file_size > self._max_scan_size:
                            logger.info(
                                "File %s truncated for scan: %d > %d bytes", filename, file_size, self._max_scan_size
                            )
                else:
                    mm = filehandle.read()
            else:
                mm = filehandle
                # Apply size limit to bytes data
                if self._max_scan_size > 0 and len(mm) > self._max_scan_size:
                    logger.info("Data %s truncated for scan: %d > %d bytes", filename, len(mm), self._max_scan_size)
                    mm = mm[: self._max_scan_size]

            # Signature-based scanning
            for vname, pattern in self.virus_patterns.items():
                if self._match_pattern(mm, pattern):
                    return True, vname, THREAT_ID_DETECTED, self.kmd_name

            # Heuristic scanning
            heuristic_result = self._heuristic_scan(mm, filename)
            if heuristic_result:
                return True, "Heuristic.Suspicious", THREAT_ID_DETECTED, self.kmd_name

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
            raise k2const.PluginUnexpectedError(str(e)) from e
        except (ValueError, TypeError) as e:
            logger.debug("Scan data error for %s: %s", filename, e)
        except MemoryError as e:
            logger.error("Scan memory error for %s (file too large?): %s", filename, e)
            raise k2const.PluginUnexpectedError(str(e)) from e
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)
            raise k2const.PluginUnexpectedError(str(e)) from e

        return SCAN_RESULT_CLEAN

    def _match_pattern(self, data: bytes, pattern: Any) -> bool:
        """Match data against a virus pattern.

        Override in subclasses that use the base scan() method with
        virus_patterns dictionary. Not needed if scan() is overridden.

        Args:
            data: File data to check
            pattern: Virus pattern to match

        Returns:
            True if pattern matches, False otherwise
        """
        return False

    def _heuristic_scan(self, data: bytes, filename: str) -> bool:
        """Perform heuristic scanning.

        Override in subclasses to add heuristic detection.

        Args:
            data: File data to analyze
            filename: Name of the file

        Returns:
            True if suspicious, False otherwise
        """
        return False

    def disinfect(self, filename: str, malware_id: int) -> bool:
        """Attempt to disinfect a file.

        Override in subclasses that support disinfection.

        Args:
            filename: Path to infected file
            malware_id: ID of detected malware

        Returns:
            True if disinfected, False otherwise
        """
        # Validate filename for path traversal
        if not self._validate_path_input(filename, "disinfect_filename"):
            return False

        return False

    def _cleanup_resources(self):
        """Clean up malware detector resources."""
        super()._cleanup_resources()
        # Use new assignments instead of clear() to avoid
        # affecting external references
        self.virus_names = []
        self.virus_info = []
        self.virus_patterns = {}


class FileFormatPluginBase(PluginBase):
    """Base class for file format processing plugins.

    Provides common functionality for handling specific file formats
    like PE, ELF, PDF, Office documents, etc.
    """

    def __init__(self, *args, **kwargs):
        """Initialize file format plugin."""
        super().__init__(*args, **kwargs)
        self.signatures = {}

    @abstractmethod
    def format(self, filehandle: bytes, filename: str, filename_ex: str) -> Dict[str, Any]:
        """Verify and parse file format.

        Args:
            filehandle: File data to check
            filename: Original filename
            filename_ex: Extended filename information

        Returns:
            Dictionary with format information, empty if not recognized
        """
        pass

    def get_format_name(self) -> str:
        """Get the format name handled by this plugin.

        Returns:
            Format name string
        """
        return self.kmd_name

    def _check_signature(self, data: bytes, offset: int = 0) -> Optional[str]:
        """Check data against known signatures.

        Args:
            data: Data to check
            offset: Offset to start checking from

        Returns:
            Signature name if matched, None otherwise
        """
        for sig_name, sig_bytes in self.signatures.items():
            sig_len = len(sig_bytes)
            if len(data) >= offset + sig_len:
                if data[offset : offset + sig_len] == sig_bytes:
                    return sig_name
        return None

    def extract_embedded(self, filehandle: bytes, filename: str) -> List[Tuple[str, bytes]]:
        """Extract embedded files or objects.

        Override in subclasses that support extraction.

        Args:
            filehandle: File data
            filename: Original filename

        Returns:
            List of tuples (name, data) for embedded objects
        """
        return []

    def repair(self, filename: str, fileformat: Dict[str, Any]) -> bool:
        """Attempt to repair a corrupted file.

        Override in subclasses that support file repair.

        Args:
            filename: Path to file to repair
            fileformat: Format information

        Returns:
            True if repaired, False otherwise
        """
        # Validate filename for path traversal
        if not self._validate_path_input(filename, "repair_filename"):
            return False

        return False
