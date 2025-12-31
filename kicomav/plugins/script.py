# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
Script Engine Plugin

This plugin handles script format detection, malware detection, and extraction.
"""

import contextlib
import hashlib
import logging
import os
import re

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

KICOMAV_BAT_MAGIC = b"<KicomAV:BAT>"


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """Script malware detector and archive handler plugin.

    This plugin provides functionality for:
    - Detecting script format (BAT, JavaScript, IFrame)
    - Scanning for script-based malware
    - Extracting scripts for further analysis
    """

    def __init__(self):
        """Initialize the Script Engine plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Script Engine",
            kmd_name="script",
        )
        self.p_text_format = None
        self.p_script_head = None
        self.p_script_in_html = None
        self.p_http = None
        self.p_script_cmt1 = None
        self.p_script_cmt2 = None
        self.p_script_cmt3 = None
        self.p_space = None
        self.p_bat_cmt1 = None
        self.p_bat_cmt2 = None

    def _custom_init(self) -> int:
        """Custom initialization for Script plugin.

        Returns:
            0 for success
        """
        # Check if the file format is text
        self.p_text_format = re.compile(r"\s*@?(\w+)", re.IGNORECASE)

        # Check if the file starts with <script, <iframe
        self.p_script_head = re.compile(r"\s*<\s*(script|iframe)", re.IGNORECASE)

        # Check if the script/iframe information is inside the html
        s = r"<\s*(script|iframe).*?>([\d\D]*?)<\s*/(script|iframe)\s*>"
        self.p_script_in_html = re.compile(s, re.IGNORECASE)

        # Regular expression for removing comments and spaces
        self.p_http = re.compile(rb"https?://")
        self.p_script_cmt1 = re.compile(rb"//.*")
        self.p_script_cmt2 = re.compile(rb"/\*.*?\*/", re.DOTALL)
        self.p_script_cmt3 = re.compile(rb"(#|\bREM\b).*", re.IGNORECASE)
        self.p_space = re.compile(rb"[\s]")

        # BAT comments
        self.p_bat_cmt1 = re.compile(rb"\bREM\s+.*", re.IGNORECASE)
        self.p_bat_cmt2 = re.compile(rb"[\^\`]", re.IGNORECASE)

        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        s_num = 0
        if kavutil.handle_pattern_md5:
            s_num = kavutil.handle_pattern_md5.get_sig_num("script")
        info["sig_num"] = s_num
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        vlist = kavutil.handle_pattern_md5.get_sig_vlist("script")
        if vlist is None:
            vlist = []
        vlist.sort()
        return vlist

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect script format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            fileformat = {}
            mm = filehandle

            buf = mm.read(4096) if hasattr(mm, "read") else mm[:4096]

            if kavutil.is_textfile(buf):
                buf_str = buf.decode("latin-1")
                if obj := self.p_text_format.match(buf_str):
                    t = obj.groups()[0].lower()
                    if t in ["cd", "echo"]:
                        return {"ff_bat": "BAT"}
                elif buf_str[:13] == KICOMAV_BAT_MAGIC.decode("latin-1"):
                    return {"ff_bat": "BAT"}

                if obj := self.p_script_head.match(buf_str):
                    if hasattr(mm, "seek"):
                        mm.seek(0)
                        mm_buf = mm.read()
                    else:
                        mm_buf = mm[:]
                    mm_buf = mm_buf.decode("latin-1")
                    if obj_script := self.p_script_in_html.search(mm_buf):
                        buf_script = obj_script.groups()[1].strip()
                        n_buf_script = len(buf_script)
                        fileformat["size"] = n_buf_script

                        if n_buf_script:
                            ret = (
                                {"ff_script": fileformat}
                                if obj_script.groups()[0].lower() == "script"
                                else {"ff_iframe": fileformat}
                            )
                        elif obj_script.groups()[0].lower() == "script":
                            ret = {"ff_script_external": fileformat}
                        else:
                            ret = {"ff_iframe_external": fileformat}
                    else:
                        fileformat["size"] = 0

                        if obj.group().lower().find("script") != -1:
                            ret = {"ff_script_external": fileformat}
                        else:
                            ret = {"ff_iframe_external": fileformat}

                    return ret

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

            if not (
                "ff_html" in fileformat
                or "ff_script" in fileformat
                or "ff_iframe" in fileformat
                or "ff_bat" in fileformat
                or "ff_script_external" in fileformat
                or "ff_iframe_external" in fileformat
            ):
                return False, "", -1, kernel.NOT_FOUND

            if hasattr(mm, "seek"):
                mm.seek(0)
                mm_buf = mm.read()
            else:
                mm_buf = mm[:]

            if "ff_bat" in fileformat and mm_buf[:13] == KICOMAV_BAT_MAGIC:
                p = re.compile(rb"set\s+(\w+)=", re.IGNORECASE)
                t_set = p.findall(mm_buf)
                t_count = 0
                for k in t_set:
                    p = re.compile(b"echo\s+.+?%s" % k)
                    if p.search(mm_buf):
                        t_count += 1

                if t_count > 5:
                    return True, "Trojan.BAT.Agent.gen", 0, kernel.INFECTED

            if kavutil.is_textfile(mm_buf[:4096]):
                buf = mm_buf

                buf = self.p_http.sub(b"", buf)
                buf = self.p_script_cmt1.sub(b"", buf)

                pos1 = buf.find(b"/*")
                pos2 = buf.rfind(b"*/") if pos1 != -1 else -1
                if 0 <= pos1 < pos2:
                    buf = self.p_script_cmt2.sub(b"", buf)

                buf = self.p_script_cmt3.sub(b"", buf)
                buf = self.p_space.sub(b"", buf)
                buf = buf.lower()

                size = len(buf)
                if kavutil.handle_pattern_md5.match_size("script", size):
                    fmd5 = hashlib.md5(buf).hexdigest()
                    if vname := kavutil.handle_pattern_md5.scan("script", size, fmd5):
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

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive (scripts in document).

        Args:
            filename: Path to script file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_script" in fileformat:
            file_scan_list.append(["arc_script", "JavaScript"])
        elif "ff_iframe" in fileformat:
            file_scan_list.append(["arc_iframe", "IFrame"])
        elif "ff_bat" in fileformat:
            file_scan_list.append(["arc_bat", "BAT"])

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive (script from document).

        Args:
            arc_engine_id: Engine ID ('arc_script', 'arc_iframe', 'arc_bat')
            arc_name: Path to script file
            fname_in_arc: Name of script to extract

        Returns:
            Extracted script data, or None on error
        """
        if arc_engine_id not in ["arc_script", "arc_iframe", "arc_bat"]:
            return None

        try:
            with open(arc_name, "rb") as fp:
                buf = fp.read()

            if arc_engine_id in ["arc_script", "arc_iframe"]:
                buf = buf.decode("latin-1")
                if obj := self.p_script_in_html.search(buf):
                    return obj.groups()[1].encode("latin-1")
            elif arc_engine_id == "arc_bat":
                buf = self.p_bat_cmt1.sub(b"", buf)
                data = self.p_bat_cmt2.sub(b"", buf)
                ret = KICOMAV_BAT_MAGIC + data
                return ret

        except (IOError, OSError) as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create an archive.

        Args:
            arc_engine_id: Engine ID ('arc_script', 'arc_iframe')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id not in ["arc_script", "arc_iframe"]:
            return False

        try:
            with open(arc_name, "rb") as fp:
                buf = fp.read()
                buf = buf.decode("latin-1")

            if obj := self.p_script_in_html.search(buf):
                return self.update_html_scripts(obj, buf, file_infos, arc_name)

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False

    def update_html_scripts(self, obj, buf, file_infos, arc_name):
        """Update HTML scripts in the archive."""
        t = obj.group()
        pos = obj.span()

        all_script_info = [["script", pos, t]]
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
                buf_part = org_buf[start_pos : pos[0]]
                fp.write(buf_part.encode("latin-1"))
                fp.write(script_info[2])
                start_pos = pos[1]
            fp.write(org_buf[start_pos:].encode("latin-1"))

        return True

    def arcclose(self):
        """Close all open archive handles."""
        pass
