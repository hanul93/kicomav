# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
Dummy Scan Engine Plugin

This is a test plugin that demonstrates the MalwareDetectorBase interface.
It detects files containing the dummy test pattern.
"""

import os
import logging
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Malware ID constants for this plugin
# -------------------------------------------------------------------------
class MalwareID:
    """Malware identification constants for dummy plugin."""

    DUMMY_TEST_FILE = 0  # Dummy test file detection


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """Dummy malware scanner plugin.

    This plugin demonstrates the MalwareDetectorBase interface by detecting
    files that contain a specific test pattern.
    """

    # Dummy pattern to detect
    DUMMY_PATTERN = b"Dummy Engine test file - KICOM Anti-Virus Project"
    DUMMY_VIRUS_NAME = "Dummy-Test-File (not a virus)"

    def __init__(self):
        """Initialize the dummy plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.2",
            title="Dummy Scan Engine",
            kmd_name="dummy",
        )
        self.sig_num = 1
        # Pre-register virus names for listvirus() (before init)
        self.virus_names = [self.DUMMY_VIRUS_NAME]

    def _load_virus_database(self) -> int:
        """Load virus signatures and patterns.

        Returns:
            0 for success, non-zero for failure
        """
        # Register the dummy pattern
        self.virus_patterns[self.DUMMY_VIRUS_NAME] = self.DUMMY_PATTERN
        self.virus_names = [self.DUMMY_VIRUS_NAME]

        if self.verbose:
            logger.info("Dummy plugin: Loaded %d signature(s)", len(self.virus_names))

        return 0

    def scan(self, filehandle, filename, fileformat=None, filename_ex=None):
        """Scan file for malware.

        Overrides base class to maintain compatibility with kernel interface.

        Args:
            filehandle: File data or handle to scan
            filename: Name of the file being scanned
            fileformat: Format information (optional, for compatibility)
            filename_ex: Extended filename (optional, for compatibility)

        Returns:
            Tuple of (threat_found, threat_name, malware_id, scan_state)
        """
        try:
            # Read file data
            if hasattr(filehandle, "read"):
                mm = filehandle.read(len(self.DUMMY_PATTERN))
            elif isinstance(filehandle, bytes):
                mm = filehandle[: len(self.DUMMY_PATTERN)]
            else:
                # Try to open the file directly
                with open(filename, "rb") as fp:
                    mm = fp.read(len(self.DUMMY_PATTERN))

            # Check for dummy pattern
            if mm == self.DUMMY_PATTERN:
                return True, self.DUMMY_VIRUS_NAME, kernel.DISINFECT_DELETE, kernel.INFECTED

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)

        return False, "", kernel.DISINFECT_NONE, kernel.NOT_FOUND

    def disinfect(self, filename: str, malware_id: int) -> bool:
        """Disinfect (delete) the infected file.

        Args:
            filename: Path to infected file
            malware_id: Malware ID from scan result

        Returns:
            True if successfully deleted, False otherwise
        """
        # Validate path input first
        if not self._validate_path_input(filename, "disinfect_filename"):
            return False

        # Only handle DISINFECT_DELETE
        if malware_id != kernel.DISINFECT_DELETE:
            return False

        try:
            # CWE-73: Safe file deletion
            filename_dir = os.path.dirname(filename) or os.getcwd()
            return k2security.safe_remove_file(filename, filename_dir)
        except (IOError, OSError) as e:
            logger.debug("Disinfect IO error for %s: %s", filename, e)
        except k2security.SecurityError as e:
            logger.warning("Disinfect security error for %s: %s", filename, e)

        return False

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = self.sig_num
        return info
