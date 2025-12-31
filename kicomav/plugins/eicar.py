# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
EICAR Scan Engine Plugin

This plugin detects the EICAR test file, which is a standard test file
used to verify antivirus software functionality.
"""

import os
import logging
from kicomav.plugins import kernel
from kicomav.plugins import cryptolib
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# EICAR constants
# -------------------------------------------------------------------------
VNAME_EICAR = "EICAR-Test-File (not a virus)"
EICAR_SIZE = 68
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """EICAR malware scanner plugin.

    This plugin detects the EICAR test file by checking the file size
    and MD5 hash against known values.
    """

    def __init__(self):
        """Initialize the EICAR plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.2",
            title="EICAR Scan Engine",
            kmd_name="eicar",
        )
        self.sig_num = 1
        # Pre-register virus names for listvirus() (before init)
        self.virus_names = [VNAME_EICAR]

    def _load_virus_database(self) -> int:
        """Load virus signatures and patterns.

        Returns:
            0 for success, non-zero for failure
        """
        # Register the EICAR pattern (MD5 hash)
        self.virus_patterns[VNAME_EICAR] = EICAR_MD5
        self.virus_names = [VNAME_EICAR]

        if self.verbose:
            logger.info("EICAR plugin: Loaded %d signature(s)", len(self.virus_names))

        return 0

    def scan(self, filehandle, filename, fileformat=None, filename_ex=None):
        """Scan file for EICAR test pattern.

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
                filehandle.seek(0)
                buf = filehandle.read(EICAR_SIZE)
            elif isinstance(filehandle, bytes):
                buf = filehandle[:EICAR_SIZE]
            else:
                # Try to open the file directly
                with open(filename, "rb") as fp:
                    buf = fp.read(EICAR_SIZE)

            # Check for EICAR pattern
            if len(buf) == EICAR_SIZE:
                fmd5 = cryptolib.md5(buf)
                if fmd5 == EICAR_MD5:
                    return True, VNAME_EICAR, kernel.DISINFECT_DELETE, kernel.INFECTED

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
