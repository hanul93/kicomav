# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
YARA Engine Plugin

This plugin handles malware detection using external YARA rules.
Supports loading multiple YARA rule files from plugins/rules/yara folder.
"""

import logging
import os
import warnings
import zipfile
from pathlib import Path

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

try:
    import yara

    LOAD_YARA = True
except ImportError:
    LOAD_YARA = False

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """YARA-based malware detector plugin.

    This plugin provides functionality for:
    - Detecting malware using external YARA rule files
    - Loading multiple YARA rules from rules/yara folder
    - Supporting custom YARA rules with KicomAV metadata
    """

    def __init__(self):
        """Initialize the YARA Engine plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Yara Engine",
            kmd_name="yaraex",
        )
        self.rules = None
        self.rule_count = 0
        self.loaded_files = []
        self.failed_files = []
        self.virus_names = []  # List of virus names for listvirus()

    def _get_yara_paths(self) -> list[Path]:
        """Get YARA rules paths from rules_paths configuration.

        Uses the parent class _get_rule_path helper to find 'yara' subfolders
        in both system and user rules base paths.

        Returns:
            List of valid Path objects for YARA rules directories
        """
        return self._get_rule_path("yara")

    def _load_virus_database(self) -> int:
        """Load virus patterns from multiple YARA rules.

        Loads all .yar and .yara files from paths specified in environment variables
        (SYSTEM_RULES_BASE, USER_RULES_BASE), including rules inside ZIP archives.

        Returns:
            0 for success, -1 for failure
        """
        # If the Yara module is not installed, handle engine loading failure
        if not LOAD_YARA:
            return -1

        # Get YARA rules paths from environment variables
        rules_dirs = self._get_yara_paths()

        if not rules_dirs:
            if self.verbose:
                logger.info("No YARA rules paths configured. Set SYSTEM_RULES_BASE or USER_RULES_BASE in .env")
            return -1

        # Collect .yar and .yara files from all configured paths (including subfolders)
        rule_files = []
        for rules_dir in rules_dirs:
            rule_files.extend(rules_dir.glob("**/*.yar"))
            rule_files.extend(rules_dir.glob("**/*.yara"))

        # Build sources dict with unique namespaces
        sources = {}

        # Helper function to add source with unique namespace
        def add_source(name, source_content, source_path):
            namespace = name
            counter = 1
            original_namespace = namespace
            while namespace in sources:
                namespace = f"{original_namespace}_{counter}"
                counter += 1
            sources[namespace] = (source_content, source_path)

        # Load from regular files
        for rule_file in rule_files:
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    source = f.read()
                add_source(rule_file.stem, source, str(rule_file))
            except Exception as e:
                self.failed_files.append((str(rule_file), str(e)))
                logger.debug("Failed to read %s: %s", rule_file, e)

        # Load from ZIP files in all configured paths
        zip_files = []
        for rules_dir in rules_dirs:
            zip_files.extend(rules_dir.glob("**/*.zip"))
        for zip_path in zip_files:
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    for name in zf.namelist():
                        name_lower = name.lower()
                        if name_lower.endswith(".yar") or name_lower.endswith(".yara"):
                            try:
                                source = zf.read(name).decode("utf-8")
                                rule_name = Path(name).stem
                                add_source(rule_name, source, f"{zip_path}:{name}")
                            except Exception as e:
                                self.failed_files.append((f"{zip_path}:{name}", str(e)))
                                logger.debug("Failed to read %s from %s: %s", name, zip_path, e)
            except zipfile.BadZipFile as e:
                self.failed_files.append((str(zip_path), str(e)))
                logger.debug("Bad ZIP file %s: %s", zip_path, e)
            except Exception as e:
                self.failed_files.append((str(zip_path), str(e)))
                logger.debug("Failed to open ZIP %s: %s", zip_path, e)

        if not sources:
            if self.verbose:
                logger.info("No YARA rule files found in configured paths: %s", rules_dirs)
            return -1

        # Validate each rule source individually
        # Note: Use sources instead of filepaths to avoid encoding issues with non-ASCII paths
        valid_sources = {}
        for namespace, (source, filepath) in sources.items():
            try:
                # Test compile individual source
                yara.compile(source=source)
                valid_sources[namespace] = source
                self.loaded_files.append(filepath)
            except yara.SyntaxError as e:
                self.failed_files.append((filepath, str(e)))
                logger.debug("YARA syntax error in %s: %s", filepath, e)
            except Exception as e:
                self.failed_files.append((filepath, str(e)))
                logger.debug("YARA load error in %s: %s", filepath, e)

        if not valid_sources:
            if self.verbose:
                logger.info("No valid YARA rules found")
            return -1

        # Compile all valid rules together
        try:
            self.rules = yara.compile(sources=valid_sources)

            # Count total rules and build virus names list
            self.rule_count = 0
            self.virus_names = []
            for rule in self.rules:
                self.rule_count += 1
                # Check for KicomAV metadata
                if "KicomAV" in rule.meta:
                    vname = rule.meta["KicomAV"]
                else:
                    # Fallback: use YARA.[rule_name] format
                    vname = f"YARA.{rule.identifier}"
                self.virus_names.append(vname)

            if self.verbose:
                logger.info(
                    "Loaded %d YARA rule files (%d rules), %d failed",
                    len(valid_sources),
                    self.rule_count,
                    len(self.failed_files),
                )

        except Exception as e:
            if self.verbose:
                print("[*] ERROR : YARA Rule compile")
            logger.debug("YARA rule compile error: %s", e)
            return -1

        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = self.rule_count
        return info

    def listvirus(self):
        """Get list of malware that can be detected by YARA rules.

        Returns:
            List of malware names from loaded YARA rules
        """
        vlist = self.virus_names.copy()
        vlist.sort()
        return vlist

    def scan(self, filehandle, filename, fileformat, filename_ex):
        """Scan for malware using YARA rules.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            fileformat: Format info from format() method
            filename_ex: Extended filename info

        Returns:
            Tuple of (found, malware_name, malware_id, result)
        """
        if self.rules is None:
            return False, "", -1, kernel.NOT_FOUND

        try:
            # Exclude YARA rule files themselves
            filename_lower = filename.lower()
            if filename_lower.endswith(".yar") or filename_lower.endswith(".yara"):
                return False, "", -1, kernel.NOT_FOUND

            # Use data parameter instead of filename to avoid encoding issues
            # Filter out "too many matches" warnings from YARA
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=RuntimeWarning, message="too many matches")
                ret = self.rules.match(data=filehandle)
            if len(ret):
                for t in ret:
                    # Check for KicomAV metadata
                    if vname := t.meta.get("KicomAV", None):
                        return True, vname, 0, kernel.INFECTED

                    # Fallback: use rule name if no KicomAV metadata
                    # Format: YARA.[namespace].[rule_name]
                    vname = f"YARA.{t.namespace}.{t.rule}"
                    return True, vname, 0, kernel.INFECTED

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)

        return False, "", -1, kernel.NOT_FOUND

    def disinfect(self, filename, malware_id):
        """Disinfect malware.

        Args:
            filename: Path to infected file
            malware_id: Malware ID to disinfect

        Returns:
            True if successful, False otherwise
        """
        try:
            if malware_id == 0:
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False
