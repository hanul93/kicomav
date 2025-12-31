# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
RAR Archive Engine Plugin

This plugin handles RAR archive format for scanning and manipulation.
Uses the rarfile Python package for RAR archive processing.
"""

import contextlib
import os
import tempfile
import shutil
import logging

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

try:
    import rarfile

    # Configure unrar tool path from environment
    unrar_tool = os.environ.get("UNRAR_TOOL")
    if unrar_tool:
        rarfile.UNRAR_TOOL = unrar_tool

    RARFILE_AVAILABLE = True
except ImportError:
    RARFILE_AVAILABLE = False


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """RAR archive handler plugin.

    This plugin provides functionality for:
    - Detecting RAR archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives (requires external rar tool)
    """

    def __init__(self):
        """Initialize the RAR plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="RAR Archive Engine",
            kmd_name="rar",
        )
        self.temp_path = {}
        self.root_temp_path = None
        self.password = None  # Password for encrypted archives

    def _custom_init(self) -> int:
        """Custom initialization for RAR plugin.

        Returns:
            0 for success, -1 for failure
        """
        if not RARFILE_AVAILABLE:
            if self.verbose:
                logger.info("rarfile package is not available")
            return -1

        pid = os.getpid()
        self.root_temp_path = os.path.join(tempfile.gettempdir(), "ktmp_rar_%05x" % pid)
        return 0

    def _custom_uninit(self) -> int:
        """Custom cleanup for RAR plugin.

        Returns:
            0 for success
        """
        self.arcclose()
        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["engine_type"] = kernel.ARCHIVE_ENGINE
        return info

    def __get_handle(self, filename, password=None):
        """Get or create handle for RAR file.

        Args:
            filename: Path to RAR file
            password: Optional password for encrypted archives

        Returns:
            RarFile object or None
        """
        if filename in self.handle:
            # Update password if provided
            if password and self.handle[filename]:
                self.handle[filename].setpassword(password)
            return self.handle[filename]

        try:
            rar_file = rarfile.RarFile(filename, "r")
            if password:
                rar_file.setpassword(password)
            self.handle[filename] = rar_file

            if self.root_temp_path and not os.path.exists(self.root_temp_path):
                os.makedirs(self.root_temp_path, exist_ok=True)

            self.temp_path[filename] = tempfile.mkdtemp(prefix="ktmp", dir=self.root_temp_path)
            return rar_file

        except rarfile.NotRarFile as e:
            logger.debug("Not a RAR file %s: %s", filename, e)
        except rarfile.BadRarFile as e:
            logger.debug("Bad RAR file %s: %s", filename, e)
        except (IOError, OSError) as e:
            logger.debug("Failed to open RAR file %s: %s", filename, e)
        except Exception as e:
            logger.debug("Error opening RAR file %s: %s", filename, e)

        return None

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect RAR format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        if not RARFILE_AVAILABLE:
            return None

        try:
            # RAR4 signature: Rar!\x1a\x07\x00
            # RAR5 signature: Rar!\x1a\x07\x01\x00
            if len(filehandle) >= 7:
                if filehandle[:7] == b"Rar!\x1a\x07\x00":
                    # RAR4 format
                    rar_version = 4
                elif len(filehandle) >= 8 and filehandle[:8] == b"Rar!\x1a\x07\x01\x00":
                    # RAR5 format
                    rar_version = 5
                else:
                    return None

                with rarfile.RarFile(filename, "r") as rar_file:
                    file_list = rar_file.namelist()

                fileformat = {
                    "size": len(filehandle),
                    "file_count": len(file_list),
                    "version": rar_version,
                }
                return {"ff_rar": fileformat}

        except rarfile.NotRarFile as e:
            logger.debug("Not a RAR file %s: %s", filename, e)
        except rarfile.BadRarFile as e:
            logger.debug("Bad RAR file %s: %s", filename, e)
        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.debug("Format detection error for %s: %s", filename, e)

        return None

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive.

        Args:
            filename: Path to archive file
            fileformat: Format info from format() method
            password: Optional password for encrypted archives

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_rar" not in fileformat:
            return file_scan_list

        # Store password for later use in unarc
        self.password = password

        try:
            rar_file = self.__get_handle(filename, password)
            if rar_file is None:
                return file_scan_list

            # Get file list and sort alphabetically for consistent ordering
            file_names = []
            for info in rar_file.infolist():
                # Skip directories
                if info.is_dir():
                    continue

                filename_in_rar = info.filename
                # CWE-22: Path traversal prevention
                if k2security.is_safe_archive_member(filename_in_rar):
                    file_names.append(filename_in_rar)

            # Sort file names for consistent ordering
            file_names.sort()
            for fname in file_names:
                file_scan_list.append(["arc_rar", fname])

        except rarfile.BadRarFile as e:
            logger.debug("Bad RAR file %s: %s", filename, e)
        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.debug("Archive list error for %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_rar')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_rar":
            return None

        rar_file = self.handle.get(arc_name)
        if rar_file is None:
            return None

        # Try 1: Extract without password first
        try:
            file_data = rar_file.read(fname_in_arc)
            if file_data:
                return file_data
        except rarfile.PasswordRequired:
            pass  # Will try with password below
        except rarfile.NoRarEntry:
            logger.debug("File %s not found in RAR archive", fname_in_arc)
            return None
        except rarfile.BadRarFile as e:
            logger.debug("Bad RAR file when extracting %s: %s", fname_in_arc, e)
            return None
        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
            return None
        except Exception as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)
            return None

        # Try 2: Extract with stored password
        if self.password:
            try:
                rar_file.setpassword(self.password)
                file_data = rar_file.read(fname_in_arc)
                if file_data:
                    return file_data
            except rarfile.PasswordRequired:
                logger.debug("Wrong password for %s in RAR archive", fname_in_arc)
                raise RuntimeError("password required")
            except rarfile.BadRarFile as e:
                logger.debug("Bad RAR file when extracting %s with password: %s", fname_in_arc, e)
            except (IOError, OSError) as e:
                logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
            except Exception as e:
                logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)
        else:
            logger.debug("Password required for %s in RAR archive", fname_in_arc)
            raise RuntimeError("password required")

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                rar_file = self.handle.get(fname)
                if rar_file:
                    rar_file.close()

                # Delete temporary directory
                temp_path = self.temp_path.get(fname)
                if temp_path and os.path.exists(temp_path):
                    with contextlib.suppress(OSError):
                        if os.path.isdir(temp_path):
                            shutil.rmtree(temp_path)
                        else:
                            os.remove(temp_path)

            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
                self.temp_path.pop(fname, None)

        # Delete root temporary directory
        if self.root_temp_path and os.path.exists(self.root_temp_path):
            with contextlib.suppress(OSError):
                shutil.rmtree(self.root_temp_path)

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create a RAR archive.

        Note: RAR archive creation requires the external rar tool.
        The rarfile package only supports reading RAR archives.

        Args:
            arc_engine_id: Engine ID ('arc_rar')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_rar":
            return False

        # Check if rar tool is available
        rar_tool = os.environ.get("RAR_TOOL")
        if not rar_tool:
            # Try common locations
            if os.name == "nt":
                common_paths = [
                    r"C:\Program Files\WinRAR\Rar.exe",
                    r"C:\Program Files (x86)\WinRAR\Rar.exe",
                ]
            else:
                common_paths = ["/usr/bin/rar", "/usr/local/bin/rar"]

            for path in common_paths:
                if os.path.exists(path):
                    rar_tool = path
                    break

        if not rar_tool or not os.path.exists(rar_tool):
            logger.debug("RAR tool not found, cannot create RAR archive")
            return False

        try:
            import subprocess

            # Create a temporary working directory
            work_dir = tempfile.mkdtemp(prefix="rar_mkarc_")

            try:
                # Copy files with their archive names to the working directory
                files_to_add = []
                for file_info in file_infos:
                    rname = file_info.get_filename()
                    a_name = file_info.get_filename_in_archive()

                    if os.path.exists(rname) and a_name:
                        # Copy the file to work_dir with the archive member name
                        dest_path = os.path.join(work_dir, a_name)
                        shutil.copy(rname, dest_path)
                        files_to_add.append(a_name)

                if not files_to_add:
                    return False

                # Create RAR archive using rar command
                # rar a -ep archive.rar file1 file2 ...
                # Run from work_dir so files are added with correct names
                cmd = [rar_tool, "a", "-ep", arc_name] + files_to_add
                result = subprocess.run(cmd, capture_output=True, timeout=60, cwd=work_dir)

                return result.returncode == 0

            finally:
                # Clean up work directory
                with contextlib.suppress(OSError):
                    shutil.rmtree(work_dir)

        except subprocess.TimeoutExpired:
            logger.debug("RAR creation timed out for %s", arc_name)
        except (IOError, OSError) as e:
            logger.debug("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.debug("Archive creation error for %s: %s", arc_name, e)

        return False
