# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
HTML File Format Engine Plugin

This plugin handles HTML format for scanning, malware detection, and extraction.
"""

import contextlib
import logging
import os
import re

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

HTML_KEY_COUNT = 3  # Is there at least 3 HTML keywords?


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """HTML malware detector and archive handler plugin.

    This plugin provides functionality for:
    - Detecting HTML format
    - Scanning for HTML-based malware
    - Extracting scripts from HTML files
    """

    def __init__(self):
        """Initialize the HTML plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="HTML Engine",
            kmd_name="html",
        )
        self.p_html = None
        self.p_script = None
        self.p_html_malware = None

    def _custom_init(self) -> int:
        """Custom initialization for HTML plugin.

        Returns:
            0 for success
        """
        pat = r"<\s*html\b|\bdoctype\b|<\s*head\b|<\s*title\b|<\s*meta\b|\bhref\b|<\s*link\b|<\s*body\b|<\s*script\b|<\s*iframe\b"
        self.p_html = re.compile(pat, re.IGNORECASE)

        # script, iframe, php keywords
        pat = rb"<script.*?>[\d\D]*?</script>|<iframe.*?>[\d\D]*?</iframe>|<\?(php\b)?[\d\D]*?\?>"
        self.p_script = re.compile(pat, re.IGNORECASE)

        # HTML malware pattern
        self.p_html_malware = re.compile(rb"\?ob_start.+?>\s*<iframe")

        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = 1
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        return ["Trojan.HTML.IFrame.a"]

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect HTML format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            if filename_ex:
                with contextlib.suppress(IndexError):
                    if filename_ex.split("/")[-2] == "HTML":
                        return None

            mm = filehandle
            buf = mm[:4096]

            if kavutil.is_textfile(buf):
                buf = buf.decode("latin-1")
                ret = self.p_html.findall(buf) if self.p_html else []
                if len(set(ret)) >= HTML_KEY_COUNT:
                    fileformat = {"keyword": list(set(ret))}
                    return {"ff_html": fileformat}

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

    def scan(self, filehandle, filename, fileformat, filename_ex):
        """Scan for malware.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            fileformat: Format info from format() method
            filename_ex: Extended filename info

        Returns:
            Tuple of (found, malware_name, malware_id, result)
        """
        try:
            mm = filehandle
            buf = mm.read(4096) if hasattr(mm, "read") else mm[:4096]

            if kavutil.is_textfile(buf) and self.p_html_malware and self.p_html_malware.search(buf):
                return True, "Trojan.HTML.IFrame.a", 0, kernel.INFECTED

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

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive (scripts in HTML).

        Args:
            filename: Path to HTML file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_html" not in fileformat:
            return file_scan_list

        try:
            with open(filename, "rb") as fp:
                buf = fp.read()

            s_count = 1
            i_count = 1
            p_count = 1

            if self.p_script:
                for obj in self.p_script.finditer(buf):
                    t = obj.group()
                    p = t.lower()

                    if p.find(b"<script") != -1:
                        file_scan_list.append(["arc_html", "HTML/Script #%d" % s_count])
                        s_count += 1
                    elif p.find(b"<iframe") != -1:
                        file_scan_list.append(["arc_html", "HTML/IFrame #%d" % i_count])
                        i_count += 1
                    elif p.find(b"<?") != -1:
                        file_scan_list.append(["arc_html", "HTML/PHP #%d" % p_count])
                        p_count += 1

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive (script from HTML).

        Args:
            arc_engine_id: Engine ID ('arc_html')
            arc_name: Path to HTML file
            fname_in_arc: Name of script to extract

        Returns:
            Extracted script data, or None on error
        """
        if arc_engine_id != "arc_html":
            return None

        try:
            with open(arc_name, "rb") as fp:
                buf = fp.read()

            s_count = 1
            i_count = 1
            p_count = 1

            if self.p_script:
                for obj in self.p_script.finditer(buf):
                    t = obj.group()
                    pos = obj.span()
                    p = t.lower()

                    if p.find(b"<script") != -1:
                        k = "HTML/Script #%d" % s_count
                        s_count += 1
                    elif p.find(b"<iframe") != -1:
                        k = "HTML/IFrame #%d" % i_count
                        i_count += 1
                    elif p.find(b"<?") != -1:
                        k = "HTML/PHP #%d" % p_count
                        p_count += 1
                    else:
                        k = ""

                    if k == fname_in_arc:
                        return buf[pos[0] : pos[1]]

        except (IOError, OSError) as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create an archive.

        Args:
            arc_engine_id: Engine ID ('arc_html')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_html":
            return False

        try:
            all_script_info = []

            with open(arc_name, "rb") as fp:
                buf = fp.read()

            if self.p_script:
                for obj in self.p_script.finditer(buf):
                    t = obj.group()
                    pos = obj.span()
                    p = t.lower()

                    if p.find(b"<script") != -1:
                        all_script_info.append(["script", pos, t])
                    elif p.find(b"<iframe") != -1:
                        all_script_info.append(["iframe", pos, t])
                    elif p.find(b"<?") != -1:
                        all_script_info.append(["php", pos, t])

            org_buf = buf

            for idx, file_info in enumerate(file_infos):
                rname = file_info.get_filename()
                with contextlib.suppress(IOError):
                    if os.path.exists(rname):
                        with open(rname, "rb") as fp:
                            new_buf = fp.read()

                            if len(all_script_info[idx][2]) < len(new_buf):
                                return False

                            new_buf += b" " * (len(all_script_info[idx][2]) - len(new_buf))
                            all_script_info[idx][2] = new_buf
                    else:
                        new_buf = b" " * len(all_script_info[idx][2])
                        all_script_info[idx][2] = new_buf

            with open(arc_name, "wb") as fp:
                start_pos = 0
                for script_info in all_script_info:
                    pos = script_info[1]
                    fp.write(org_buf[start_pos : pos[0]])
                    fp.write(script_info[2])
                    start_pos = pos[1]

                fp.write(org_buf[start_pos:])

            return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False

    def arcclose(self):
        """Close all open archive handles."""
        pass  # No persistent handles to close
