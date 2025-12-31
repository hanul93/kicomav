# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Scanner Module

This module provides a high-level, easy-to-use interface for malware scanning.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Union

from .config import get_config
from .k2engine import Engine, EngineInstance

# Module logger
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a file scan operation.

    Attributes:
        path: Path to the scanned file
        infected: Whether malware was detected
        malware_name: Name of detected malware (if any)
        disinfected: Whether the file was successfully disinfected
        error: Error message if scan failed
    """

    path: str
    infected: bool = False
    malware_name: Optional[str] = None
    disinfected: bool = False
    error: Optional[str] = None


# Type alias for scan callback
ScanCallback = Callable[[ScanResult], None]


class Scanner:
    """High-level malware scanner interface.

    This class provides a simplified API for scanning files and directories
    for malware. It handles engine initialization and cleanup automatically.

    Example:
        # Simple file scan
        with Scanner() as scanner:
            result = scanner.scan_file("/path/to/file.exe")
            if result.infected:
                print(f"Detected: {result.malware_name}")

        # Directory scan with callback
        with Scanner() as scanner:
            results = scanner.scan_directory("/path/to/folder")
            for result in results:
                if result.infected:
                    print(f"{result.path}: {result.malware_name}")
    """

    def __init__(
        self,
        plugins_path: Optional[str] = None,
        verbose: bool = False,
    ):
        """Initialize the Scanner.

        Args:
            plugins_path: Path to plugins directory. If None, attempts to find
                          plugins in the default location relative to the package.
            verbose: Enable verbose output for debugging
        """
        self._engine: Optional[Engine] = None
        self._instance: Optional[EngineInstance] = None
        self._plugins_path = plugins_path
        self._verbose = verbose
        self._initialized = False

    def _find_plugins_path(self) -> Optional[str]:
        """Find the plugins directory.

        Returns:
            Path to plugins directory or None if not found
        """
        if self._plugins_path:
            return self._plugins_path

        # Try to find plugins relative to the package
        try:
            # Get the path of the kicomav package
            import kicomav

            package_dir = os.path.dirname(os.path.abspath(kicomav.__file__))
            plugins_dir = os.path.join(package_dir, "plugins")

            if os.path.isdir(plugins_dir):
                return plugins_dir
        except Exception:
            pass

        # Try common installation paths
        common_paths = [
            os.path.join(os.path.dirname(__file__), "..", "plugins"),
            "/usr/local/share/kicomav/plugins",
            "/usr/share/kicomav/plugins",
        ]

        for path in common_paths:
            abs_path = os.path.abspath(path)
            if os.path.isdir(abs_path):
                return abs_path

        return None

    def _ensure_initialized(self) -> bool:
        """Ensure the scanner engine is initialized.

        Returns:
            True if initialization succeeded, False otherwise
        """
        if self._initialized and self._instance is not None:
            return True

        try:
            # Find plugins path
            plugins_path = self._find_plugins_path()
            if not plugins_path:
                logger.error("Could not find plugins directory")
                return False

            # Create engine
            self._engine = Engine(verbose=self._verbose)

            # Set plugins
            if not self._engine.set_plugins(plugins_path):
                logger.error("Failed to load plugins from %s", plugins_path)
                return False

            # Create instance
            self._instance = self._engine.create_instance()
            if self._instance is None:
                logger.error("Failed to create engine instance")
                return False

            # Initialize instance
            if not self._instance.init():
                logger.error("Failed to initialize engine instance")
                return False

            self._initialized = True
            return True

        except Exception as e:
            logger.exception("Failed to initialize scanner: %s", e)
            return False

    def scan_file(self, path: Union[str, Path], disinfect: bool = False) -> ScanResult:
        """Scan a single file for malware.

        Args:
            path: Path to the file to scan
            disinfect: If True, attempt to disinfect infected files

        Returns:
            ScanResult with scan details
        """
        path_str = str(path)
        result = ScanResult(path=path_str)

        # Ensure file exists
        if not os.path.isfile(path_str):
            result.error = "File not found"
            return result

        # Initialize if needed
        if not self._ensure_initialized():
            result.error = "Failed to initialize scanner"
            return result

        try:
            # Track scan results
            scan_result = {"infected": False, "malware_name": None, "disinfected": False}

            # Callback to capture scan results
            def scan_callback(ret_value):
                if ret_value.get("result"):
                    scan_result["infected"] = True
                    scan_result["malware_name"] = ret_value.get("virus_name", "Unknown")

            # Callback for disinfection results
            def disinfect_callback(ret_value, disinfect_result):
                if disinfect_result:
                    scan_result["disinfected"] = True

            # Configure options
            self._instance.set_options({"opt_dis": disinfect})

            # Perform scan
            if disinfect:
                self._instance.scan(path_str, scan_callback, disinfect_callback)
            else:
                self._instance.scan(path_str, scan_callback)

            # Update result
            result.infected = scan_result["infected"]
            result.malware_name = scan_result["malware_name"]
            result.disinfected = scan_result["disinfected"]

        except Exception as e:
            result.error = str(e)
            logger.exception("Error scanning file %s: %s", path_str, e)

        return result

    def scan_directory(
        self,
        path: Union[str, Path],
        recursive: bool = True,
        disinfect: bool = False,
        callback: Optional[ScanCallback] = None,
    ) -> List[ScanResult]:
        """Scan a directory for malware.

        Args:
            path: Path to the directory to scan
            recursive: If True, scan subdirectories recursively
            disinfect: If True, attempt to disinfect infected files
            callback: Optional callback called for each scanned file

        Returns:
            List of ScanResult for all scanned files
        """
        path_str = str(path)
        results: List[ScanResult] = []

        # Ensure directory exists
        if not os.path.isdir(path_str):
            results.append(ScanResult(path=path_str, error="Directory not found"))
            return results

        # Initialize if needed
        if not self._ensure_initialized():
            results.append(ScanResult(path=path_str, error="Failed to initialize scanner"))
            return results

        try:
            # Collect files to scan
            files_to_scan = []
            if recursive:
                for root, dirs, files in os.walk(path_str):
                    for fname in files:
                        files_to_scan.append(os.path.join(root, fname))
            else:
                for fname in os.listdir(path_str):
                    fpath = os.path.join(path_str, fname)
                    if os.path.isfile(fpath):
                        files_to_scan.append(fpath)

            # Scan each file
            for fpath in files_to_scan:
                result = self.scan_file(fpath, disinfect=disinfect)
                results.append(result)

                if callback:
                    callback(result)

        except Exception as e:
            logger.exception("Error scanning directory %s: %s", path_str, e)
            results.append(ScanResult(path=path_str, error=str(e)))

        return results

    def get_statistics(self) -> dict:
        """Get scan statistics from the current session.

        Returns:
            Dictionary with scan statistics
        """
        if not self._instance:
            return {}

        try:
            result = self._instance.result
            return {
                "files_scanned": result.get("files", 0),
                "infected": result.get("infected_files", 0),
                "disinfected": result.get("cured_files", 0),
                "warnings": result.get("io_errors", 0),
            }
        except Exception:
            return {}

    def close(self) -> None:
        """Close the scanner and release resources."""
        if self._instance:
            try:
                self._instance.uninit()
            except Exception as e:
                logger.debug("Error during uninit: %s", e)
            self._instance = None

        if self._engine:
            try:
                del self._engine
            except Exception as e:
                logger.debug("Error during engine cleanup: %s", e)
            self._engine = None

        self._initialized = False

    def __enter__(self) -> "Scanner":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()

    def __del__(self) -> None:
        """Destructor to ensure cleanup."""
        self.close()
