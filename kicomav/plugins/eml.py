# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
EML Email Archive Engine Plugin

This plugin handles EML email files for scanning attachments.
Supports:
- Standard EML format (RFC 822)
- MIME attachments extraction
- Inline attachments
"""

import email
import re
import os
import logging
from email import policy
from email.parser import BytesParser
from typing import Optional, Dict, Any, List

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

# EML header patterns for validation
EML_HEADER_PATTERNS = {
    "from": re.compile(r"^From:\s*.+", re.IGNORECASE),
    "to": re.compile(r"^To:\s*.+", re.IGNORECASE),
    "subject": re.compile(r"^Subject:\s*.*", re.IGNORECASE),
    "date": re.compile(r"^Date:\s*.+", re.IGNORECASE),
    "message-id": re.compile(r"^Message-ID:\s*.+", re.IGNORECASE),
    "mime-version": re.compile(r"^MIME-Version:\s*.+", re.IGNORECASE),
    "content-type": re.compile(r"^Content-Type:\s*.+", re.IGNORECASE),
    "received": re.compile(r"^Received:\s*.+", re.IGNORECASE),
}

# Additional patterns
RETURN_PATH_PATTERN = re.compile(r"^Return-Path:\s*", re.IGNORECASE | re.MULTILINE)
X_HEADER_PATTERN = re.compile(r"^X-[\w-]+:\s*", re.IGNORECASE | re.MULTILINE)


class EMLHandle:
    """EML file handle for archive operations."""

    def __init__(self, filename: str):
        """Initialize EML handle.

        Args:
            filename: Path to EML file
        """
        self.filename = filename
        self.msg: Optional[email.message.EmailMessage] = None
        self._attachment_cache: Dict[str, Dict[str, Any]] = {}

    def open(self) -> bool:
        """Open and parse the EML file.

        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.filename, "rb") as f:
                self.msg = BytesParser(policy=policy.default).parse(f)
            self._build_attachment_cache()
            return True
        except (IOError, OSError) as e:
            logger.debug("Failed to open EML file %s: %s", self.filename, e)
            return False
        except Exception as e:
            logger.debug("Failed to parse EML file %s: %s", self.filename, e)
            return False

    def close(self):
        """Close the EML file handle."""
        self.msg = None
        self._attachment_cache.clear()

    def _build_attachment_cache(self):
        """Build cache of attachments from parsed email."""
        if self.msg is None:
            return

        for part in self.msg.walk():
            content_disposition = part.get("Content-Disposition", "")
            content_type = part.get_content_type()

            # Check if this part is an attachment
            is_attachment = False
            if "attachment" in content_disposition:
                is_attachment = True
            elif part.get_filename():
                is_attachment = True
            elif content_disposition and "inline" in content_disposition and part.get_filename():
                is_attachment = True

            if not is_attachment:
                continue

            # Get filename
            filename = part.get_filename()
            if not filename:
                # Generate filename from content type
                ext = content_type.split("/")[-1] if "/" in content_type else "bin"
                filename = f"attachment_{len(self._attachment_cache) + 1}.{ext}"

            # Sanitize filename (remove path traversal characters)
            filename = os.path.basename(filename)
            filename = re.sub(r'[<>:"/\\|?*]', "_", filename)

            # Handle duplicate filenames
            original_filename = filename
            counter = 1
            while filename in self._attachment_cache:
                name, ext = os.path.splitext(original_filename)
                filename = f"{name}_{counter}{ext}"
                counter += 1

            # Cache attachment info
            self._attachment_cache[filename] = {
                "part": part,
                "content_type": content_type,
            }

    def list_attachments(self) -> List[str]:
        """Get list of attachment filenames.

        Returns:
            List of attachment filenames
        """
        return list(self._attachment_cache.keys())

    def extract_attachment(self, filename: str) -> Optional[bytes]:
        """Extract attachment data by filename.

        Args:
            filename: Attachment filename

        Returns:
            Attachment data or None if not found
        """
        if filename not in self._attachment_cache:
            return None

        try:
            part = self._attachment_cache[filename]["part"]
            payload = part.get_payload(decode=True)
            return payload
        except Exception as e:
            logger.debug("Failed to extract attachment %s: %s", filename, e)
            return None


def is_valid_eml(data: bytes) -> bool:
    """Check if data is a valid EML file.

    Args:
        data: File data to check

    Returns:
        True if valid EML, False otherwise
    """
    try:
        # Read first 8KB for header analysis
        header_bytes = data[:8192]

        # Try to decode as text
        try:
            header_text = header_bytes.decode("utf-8", errors="ignore")
        except Exception:
            header_text = header_bytes.decode("latin-1", errors="ignore")

        # Check for EML header patterns
        found_headers = []
        lines = header_text.split("\n")

        for line in lines[:100]:  # Check first 100 lines
            for name, pattern in EML_HEADER_PATTERNS.items():
                if pattern.match(line):
                    if name not in found_headers:
                        found_headers.append(name)

        # Need at least 2 email headers to be considered EML
        if len(found_headers) >= 2:
            return True

        # Additional check: Return-Path or X-headers
        has_return_path = RETURN_PATH_PATTERN.search(header_text)
        has_x_header = X_HEADER_PATTERN.search(header_text)

        if has_return_path or (has_x_header and len(found_headers) >= 1):
            return True

        return False

    except Exception as e:
        logger.debug("EML validation error: %s", e)
        return False


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """EML email archive handler plugin.

    This plugin provides functionality for:
    - Detecting EML email format
    - Listing attachments within EML files
    - Extracting attachments from EML files
    """

    def __init__(self):
        """Initialize the EML plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="EML Archive Engine",
            kmd_name="eml",
        )

    def _custom_init(self) -> int:
        """Custom initialization for EML plugin.

        Returns:
            0 for success
        """
        return 0

    def _custom_uninit(self) -> int:
        """Custom cleanup for EML plugin.

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

    def __get_handle(self, filename: str) -> Optional[EMLHandle]:
        """Get or create handle for EML file.

        Args:
            filename: Path to EML file

        Returns:
            EMLHandle object or None
        """
        if filename in self.handle:
            return self.handle.get(filename)

        eml_handle = EMLHandle(filename)
        if eml_handle.open():
            self.handle[filename] = eml_handle
            return eml_handle

        return None

    def format(self, filehandle, filename, filename_ex) -> Optional[Dict[str, Any]]:
        """Analyze and detect EML format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to EML file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        ret = {}

        try:
            mm = filehandle

            if is_valid_eml(bytes(mm)):
                ret["ff_eml"] = "eml"
                return ret

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

    def arclist(self, filename: str, fileformat: Dict[str, Any], password: Optional[str] = None) -> List[List[str]]:
        """List attachments in the EML file.

        Args:
            filename: Path to EML file
            fileformat: Format info from format() method
            password: Not used for EML (no encryption support)

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        try:
            if "ff_eml" in fileformat:
                eml_handle = self.__get_handle(filename)
                if eml_handle:
                    for attachment_name in eml_handle.list_attachments():
                        # CWE-22: Path traversal prevention
                        if k2security.is_safe_archive_member(attachment_name):
                            file_scan_list.append(["arc_eml", attachment_name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id: str, arc_name: str, fname_in_arc: str) -> Optional[bytes]:
        """Extract an attachment from the EML file.

        Args:
            arc_engine_id: Engine ID ('arc_eml')
            arc_name: Path to EML file
            fname_in_arc: Name of attachment to extract

        Returns:
            Extracted attachment data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.debug("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_eml":
            return None

        try:
            eml_handle = self.handle.get(arc_name)
            if eml_handle is None:
                return None

            return eml_handle.extract_attachment(fname_in_arc)

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open EML handles."""
        for fname in list(self.handle.keys()):
            try:
                eml_handle = self.handle[fname]
                if hasattr(eml_handle, "close"):
                    eml_handle.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
