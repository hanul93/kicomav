# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


# -------------------------------------------------------------------------
# Actual import modules
# -------------------------------------------------------------------------
import os
import sys

# Ensure project root is in sys.path for development mode
# This allows "from kicomav.plugins import ..." to work when running from source
_k2_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_k2_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import contextlib
import glob
import hashlib
import time
import struct
import datetime
import gzip
import re
import tempfile
from optparse import OptionParser
from rich.console import Console
from rich.text import Text
import requests

# Configuration is automatically loaded by kavcore.config module
# when it is imported. The .env file is loaded from ~/.kicomav/.env

# Support both installed package and development mode
from kicomav import __version__ as KICOMAV_VERSION
from kicomav import __last_update__ as KICOMAV_BUILDDATE
from kicomav import kavcore
from kicomav.kavcore import k2engine as kavcore_k2engine
from kicomav.kavcore import k2const as kavcore_k2const
from kicomav.kavcore import k2security
from kicomav.kavcore import updater as kavcore_updater

# Alias for compatibility
kavcore.k2engine = kavcore_k2engine
kavcore.k2const = kavcore_k2const
kavcore.updater = kavcore_updater

# -------------------------------------------------------------------------
# Main constants
# -------------------------------------------------------------------------
KAV_VERSION = KICOMAV_VERSION
_parts = KICOMAV_BUILDDATE.split()
KAV_BUILDDATE = f"{_parts[1]} {int(_parts[2])} {_parts[4]}"
KAV_LASTYEAR = _parts[4]

g_options = None  # Options
g_delta_time = None  # Scan time
display_scan_result = {"Prev": {}, "Next": {}}  # Structure to prevent duplicate output
display_update_result = ""  # Structure to display compression results

PLUGIN_ERROR = False  # Variable used to format output nicely when plugin engine loading fails

# -------------------------------------------------------------------------
# Classes and functions for colored output on console (using rich)
# -------------------------------------------------------------------------
console = Console()

# Color style constants for rich
STYLE_RED = "bold red"
STYLE_GREEN = "green"
STYLE_CYAN = "bright_cyan"
STYLE_BRIGHT_BLUE = "bright_blue"
STYLE_BRIGHT_GREEN = "bright_green"
STYLE_GREY = "white"
STYLE_GREY_BOLD = "bold white"


def cprint(msg, style):
    """Print colored message using rich console."""
    console.print(msg, style=style, end="", highlight=False)


def print_error(msg):
    console.print(f"[{STYLE_RED}]Error:[/{STYLE_RED}] {msg}", highlight=False)


# -------------------------------------------------------------------------
# getch()
# Receives a single character input. Methods differ by operating system.
# -------------------------------------------------------------------------
def getch():
    if os.name == "nt":
        import msvcrt

        return msvcrt.getch()
    else:
        import tty
        import termios

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return ch


# ---------------------------------------------------------------------
# CreateFolder: Creates a file (generates the full path if it does not exist)
# ---------------------------------------------------------------------
def create_folder(path):
    if os.path.exists(path) is not False:
        return False

    t_dir = path

    # Proceed until a folder exists
    while 1:
        if os.path.exists(t_dir) is False:
            t_dir, tmp = os.path.split(t_dir)
        else:
            break

    makedir = path.replace(t_dir, "")
    mkdir_list = makedir.split(os.sep)

    for m in mkdir_list:
        if len(m) != 0:
            t_dir += os.sep + m
            # print dir # Create folder
            os.mkdir(t_dir)

    return True


# -------------------------------------------------------------------------
# log_print(msg)
# Writes a given message to a log file.
# -------------------------------------------------------------------------
def log_print(msg, file_mode="at"):
    global g_options

    if g_options != "NONE_OPTION":
        log_mode = False
        log_fname = "k2.log"  # Default log file name

        if g_options.log_filename:
            log_fname = g_options.log_filename
            log_mode = True

        if g_options.opt_log:
            log_mode = True

        if log_mode:
            with open(log_fname, file_mode) as fp:
                fp.write(msg)


# -------------------------------------------------------------------------
# print_k2logo()
# Displays the antivirus logo.
# -------------------------------------------------------------------------
def print_k2logo():
    logo = f"""KICOM Anti-Virus II (for {sys.platform.upper()}) Ver {KAV_VERSION} ({KAV_BUILDDATE})
Copyright (C) 1995-{KAV_LASTYEAR} Kei Choi. All rights reserved.
"""

    print("------------------------------------------------------------")
    cprint(logo, STYLE_CYAN)
    print("------------------------------------------------------------")


# -------------------------------------------------------------------------
# Redefines Python's option parser.
# Allows fine-tuned error messages.
# -------------------------------------------------------------------------
class OptionParsingError(RuntimeError):
    def __init__(self, msg):
        self.msg = msg


class OptionParsingExit(Exception):
    def __init__(self, status, msg):
        self.msg = msg
        self.status = status


class ModifiedOptionParser(OptionParser):
    def error(self, msg):
        raise OptionParsingError(msg)

    def exit(self, status=0, msg=None):
        raise OptionParsingExit(status, msg)


# -------------------------------------------------------------------------
# define_options()
# Defines the antivirus options.
# -------------------------------------------------------------------------
def define_options():
    usage = "Usage: %prog path[s] [options]"
    parser = ModifiedOptionParser(add_help_option=False, usage=usage)

    parser.add_option("-f", "--files", action="store_true", dest="opt_files", default=True)
    parser.add_option("-r", "--arc", action="store_true", dest="opt_arc", default=False)
    parser.add_option("-G", action="store_true", dest="opt_log", default=False)
    parser.add_option("", "--log", metavar="FILE", dest="log_filename")
    parser.add_option("-I", "--list", action="store_true", dest="opt_list", default=False)
    parser.add_option("-e", "--app", action="store_true", dest="opt_app", default=False)
    parser.add_option("-F", "--infp", metavar="PATH", dest="infp_path")

    # Assigns malware names during quarantine
    parser.add_option("", "--qname", action="store_true", dest="opt_qname", default=False)

    # Assigns Sha256 names during quarantine
    parser.add_option("", "--qhash", action="store_true", dest="opt_qhash", default=False)

    parser.add_option("-R", "--nor", action="store_true", dest="opt_nor", default=False)
    parser.add_option("-V", "--vlist", action="store_true", dest="opt_vlist", default=False)
    parser.add_option("-p", "--prompt", action="store_true", dest="opt_prompt", default=False)
    parser.add_option("-d", "--dis", action="store_true", dest="opt_dis", default=False)
    parser.add_option("-l", "--del", action="store_true", dest="opt_del", default=False)
    parser.add_option("", "--no-color", action="store_true", dest="opt_nocolor", default=False)
    parser.add_option("", "--move", action="store_true", dest="opt_move", default=False)
    parser.add_option("", "--copy", action="store_true", dest="opt_copy", default=False)
    parser.add_option("", "--update", action="store_true", dest="opt_update", default=False)
    parser.add_option("", "--verbose", action="store_true", dest="opt_verbose", default=False)
    parser.add_option("", "--sigtool", action="store_true", dest="opt_sigtool", default=False)
    parser.add_option("", "--debug", action="store_true", dest="opt_debug", default=False)
    parser.add_option("", "--password", metavar="PWD", dest="opt_password")
    parser.add_option("", "--parallel", action="store_true", dest="opt_parallel", default=False)
    parser.add_option("", "--workers", metavar="N", type="int", dest="opt_workers", default=0)
    parser.add_option("-?", "--help", action="store_true", dest="opt_help", default=False)

    return parser


# -------------------------------------------------------------------------
# parser_options()
# Parses the options for the antivirus
# -------------------------------------------------------------------------
def parser_options():
    parser = define_options()  # Define antivirus options

    if len(sys.argv) < 2:
        return "NONE_OPTION", None
    try:
        (options, args) = parser.parse_args()
        if len(args) == 0:
            return options, None
    except OptionParsingError as e:  # When invalid options are used
        return "ILLEGAL_OPTION", e.msg
    except OptionParsingExit as e:
        return "ILLEGAL_OPTION", e.msg

    return options, args


# -------------------------------------------------------------------------
# print_usage()
# Prints the usage of the antivirus
# -------------------------------------------------------------------------
def print_usage():
    print("\nUsage: k2.py path[s] [options]")


# -------------------------------------------------------------------------
# print_options()
# Prints the options of the antivirus
# -------------------------------------------------------------------------
def print_options():
    options_string = """Options:
        -f,  --files           scan files *
        -r,  --arc             scan archives
        -G,  --log=file        create log file
        -I,  --list            display all files
        -e,  --app             append to log file
        -F,  --infp=path       set infected quarantine folder
        -R,  --nor             do not recurse into folders
        -V,  --vlist           display virus list
        -p,  --prompt          prompt for action
        -d,  --dis             disinfect files
        -l,  --del             delete infected files
             --no-color        don't print with color
             --move            move infected files in quarantine folder
             --copy            copy infected files in quarantine folder
             --qname           quarantine by name of malware
             --qhash           quarantine by sha256 hash of malware
             --password=PWD    set password for encrypted archives
             --parallel        enable parallel file scanning
             --workers=N       number of worker threads (default: CPU count)
             --update          update
        -?,  --help            this help
                               * = default option"""

    print(options_string)


# -------------------------------------------------------------------------
# Get the installed version of a package (delegates to kavcore.updater)
# -------------------------------------------------------------------------
def get_installed_version(package_name):
    return kavcore_updater.get_installed_version(package_name)


# -------------------------------------------------------------------------
# get_latest_version()
# Get the latest version of a package from PyPI (delegates to kavcore.updater)
# -------------------------------------------------------------------------
def get_latest_version(package_name):
    return kavcore_updater.get_latest_version(package_name)


# -------------------------------------------------------------------------
# check_kicomav_update()
# Check if kicomav package needs update
# Returns: True if up-to-date, False if update needed
# -------------------------------------------------------------------------
def check_kicomav_update():
    installed_version = get_installed_version("kicomav")
    latest_version = get_latest_version("kicomav")

    if latest_version is None:
        cprint("[", STYLE_GREY)
        cprint("Warning", STYLE_BRIGHT_BLUE)
        cprint("] Cannot check latest version of ", STYLE_GREY)
        cprint("kicomav", STYLE_GREEN)
        cprint(" from PyPI\n\n", STYLE_GREY)
        return True  # Continue with signature update if PyPI check fails

    if installed_version != latest_version:
        cprint("[", STYLE_GREY)
        cprint("notice", STYLE_BRIGHT_BLUE)
        cprint(f"] A new release of ", STYLE_GREY)
        cprint("kicomav", STYLE_GREEN)
        cprint(" is available: ", STYLE_GREY)
        cprint(f"{installed_version}", STYLE_RED)
        cprint(" -> ", STYLE_GREY)
        cprint(f"{latest_version}\n", STYLE_GREEN)

        cprint("[", STYLE_GREY)
        cprint("notice", STYLE_BRIGHT_BLUE)
        cprint(f"] To update, run: ", STYLE_GREY)
        cprint("pip install --upgrade kicomav\n\n", STYLE_GREEN)
        return False  # Update required

    return True


# -------------------------------------------------------------------------
# get_signature_download_list()
# Get the list of signature files to update from SYSTEM_RULES_BASE path
# Returns: (down_list, cfg_files) - files to download and all files in cfg
# -------------------------------------------------------------------------
def get_signature_download_list(url, rules_path):
    down_list = []
    cfg_files = set()  # All files listed in update.cfg

    if not rules_path:
        return down_list, cfg_files

    with contextlib.suppress(Exception):
        # Download the update configuration file to a temp location
        temp_cfg_path = os.path.join(rules_path, "update.cfg")
        download_file(url, "update.cfg", rules_path)

        buf = open(temp_cfg_path, "r").read()
        # Format: [sha1] [filepath]
        p_lists = re.compile(r"([A-Fa-f0-9]{40}) (.+)")
        lines = p_lists.findall(buf)

        for line in lines:
            fhash = line[0]
            fname = line[1].strip()

            # Add to cfg_files set (for orphan detection)
            cfg_files.add(fname)

            # Normalize path separators for the current OS
            fname_normalized = fname.replace("/", os.sep).replace("\\", os.sep)

            # Special handling for whitelist.txt
            local_file = os.path.join(rules_path, fname_normalized)
            if fname == "whitelist.txt":
                if os.path.exists(local_file):
                    # Local whitelist exists - skip update (user settings priority)
                    continue
                else:
                    # Local whitelist doesn't exist - download it
                    down_list.append(fname)
                    continue

            # Compare the hash in the update config file with the local hash
            if chek_need_update(local_file, fhash) == 1:
                # If different, add to the update list
                down_list.append(fname)

        # Clean up update.cfg
        with contextlib.suppress(k2security.SecurityError):
            k2security.safe_remove_file(temp_cfg_path, rules_path)

    return down_list, cfg_files


# -------------------------------------------------------------------------
# get_local_files()
# Get all local files in rules_path (for orphan detection)
# -------------------------------------------------------------------------
def get_local_files(rules_path):
    local_files = set()
    for filepath in glob.glob(os.path.join(rules_path, "**", "*"), recursive=True):
        # Skip directories
        if os.path.isdir(filepath):
            continue
        # Convert to relative path from rules_path
        rel_path = os.path.relpath(filepath, rules_path)
        # Normalize to forward slashes for comparison
        rel_path = rel_path.replace("\\", "/")
        local_files.add(rel_path)
    return local_files


# -------------------------------------------------------------------------
# remove_orphan_files()
# Remove local files that are not in update.cfg (except whitelist.txt)
# -------------------------------------------------------------------------
def remove_orphan_files(rules_path, cfg_files):
    local_files = get_local_files(rules_path)

    # Normalize cfg_files paths
    cfg_files_normalized = {f.replace("\\", "/") for f in cfg_files}

    # Find orphan files (local only, not in cfg)
    orphan_files = local_files - cfg_files_normalized

    if not orphan_files:
        return

    for orphan in orphan_files:
        # Never delete whitelist.txt
        if orphan == "whitelist.txt":
            continue

        orphan_path = os.path.join(rules_path, orphan)
        try:
            # Determine base path for safe deletion
            if "/" in orphan:
                subdir = orphan.rsplit("/", 1)[0]
                base_path = os.path.join(rules_path, subdir)
            else:
                base_path = rules_path

            k2security.safe_remove_file(orphan_path, base_path)
            cprint(f"{orphan} ", STYLE_GREY)
            cprint("removed\n", STYLE_RED)
        except k2security.SecurityError:
            pass  # Skip files that can't be safely deleted


# -------------------------------------------------------------------------
# remove_empty_dirs()
# Remove empty directories in rules_path after orphan file cleanup
# -------------------------------------------------------------------------
def remove_empty_dirs(rules_path):
    # Walk bottom-up to remove nested empty directories
    for root, dirs, files in os.walk(rules_path, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                # Check if directory is empty
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
                    rel_path = os.path.relpath(dir_path, rules_path)
                    cprint(f"{rel_path}/ ", STYLE_GREY)
                    cprint("removed (empty)\n", STYLE_RED)
            except OSError:
                pass  # Skip directories that can't be removed


# -------------------------------------------------------------------------
# update_signatures()
# Update signature files (YARA rules) - CLI wrapper for kavcore.updater
# -------------------------------------------------------------------------
def update_signatures():
    cprint("", STYLE_GREY)

    # CLI progress callback
    def cli_progress(filename, status):
        if status == "downloading":
            cprint(f"{filename} ", STYLE_GREY)
        elif status == "updated":
            cprint(" update\n", STYLE_GREEN)
        elif status == "removed":
            cprint(f"{filename} ", STYLE_GREY)
            cprint("removed\n", STYLE_RED)

    # Use kavcore.updater for the actual update
    result = kavcore_updater.update_signatures(progress_callback=cli_progress)

    if not result.success:
        for error in result.errors:
            cprint("[", STYLE_GREY)
            cprint("Warning", STYLE_BRIGHT_BLUE)
            cprint(f"] {error}\n", STYLE_GREY)
        return

    if not result.updated_files and not result.removed_files:
        cprint("[", STYLE_GREY)
        cprint("No updates available", STYLE_GREEN)
        cprint("]\n", STYLE_GREY)
        return

    cprint("\n[", STYLE_GREY)
    cprint("Signature updates complete", STYLE_GREEN)
    cprint("]\n", STYLE_GREY)


# -------------------------------------------------------------------------
# update_kicomav()
# Updates Kicom Antivirus to the latest version
# Two-phase update: (1) Package update check, (2) Signature update
# -------------------------------------------------------------------------
def update_kicomav(path):
    print()

    try:
        # (1) Check kicomav package version
        if not check_kicomav_update():
            # Package update required - exit after showing pip command
            return

        # (2) Update signatures (YARA rules)
        update_signatures()

    except KeyboardInterrupt:
        cprint("\n[", STYLE_GREY)
        cprint("Update Stop", STYLE_GREY_BOLD)
        cprint("]\n", STYLE_GREY)
    except Exception as e:
        if g_options.opt_verbose:
            print(e)
        cprint("\n[", STYLE_GREY)
        cprint("Update failed", STYLE_RED)
        cprint("]\n", STYLE_GREY)


# Display update progress
def hook(blocknumber, blocksize, totalsize):
    cprint(".", STYLE_GREY)


# Downloads a single file (CWE-434, CWE-918 prevention)
# Supports subdirectory paths like "yara/subdir/file.yar"
def download_file(url, filename, path, gz=False, fnhook=None):
    # Normalize path separators to forward slash
    filename = filename.replace("\\", "/")

    # Split into directory path and actual filename
    if "/" in filename:
        subdir, actual_filename = filename.rsplit("/", 1)
        # Validate for path traversal
        if ".." in subdir:
            cprint(f" {filename} - invalid path: path traversal detected\n", STYLE_RED)
            return
    else:
        subdir = ""
        actual_filename = filename

    # CWE-434: Validate actual filename (without path) before download
    try:
        k2security.validate_download_filename(actual_filename)
    except k2security.SecurityError as e:
        cprint(f" {filename} - invalid filename: {e}\n", STYLE_RED)
        return

    # Create subdirectory if needed
    if subdir:
        subdir_path = os.path.join(path, subdir)
        os.makedirs(subdir_path, exist_ok=True)

    rurl = url

    # Convert the list in the update config file to a URL address
    rurl += filename.replace("\\", "/")
    if gz:
        rurl += ".gz"

    # Get the full path of the file to save
    pwd = os.path.join(path, filename)

    if gz:
        pwd += ".gz"

    if fnhook is not None:
        cprint(f"{filename} ", STYLE_GREY)

    # Download the file (CWE-918: SSRF prevention with URL validation)
    try:
        # Use the subdirectory path as base for security validation
        base_path = os.path.join(path, subdir) if subdir else path
        k2security.safe_download_file(rurl, pwd, base_path, fnhook=fnhook)
    except k2security.SecurityError as e:
        cprint(f" download failed: {e}\n", STYLE_RED)
        return

    if gz:
        data = gzip.open(pwd, "rb").read()
        fname = os.path.join(path, filename)
        open(fname, "wb").write(data)
        # Delete the gz file (CWE-73 safe deletion)
        base_path = os.path.join(path, subdir) if subdir else path
        with contextlib.suppress(k2security.SecurityError):
            k2security.safe_remove_file(pwd, base_path)

    if fnhook is not None:
        cprint(" update\n", STYLE_GREEN)


# Downloads k2.exe (CWE-434, CWE-918 prevention)
def download_file_k2(url, filename, path, gz=False, fnhook=None):
    # CWE-434: Validate filename before download
    try:
        k2security.validate_download_filename(filename)
    except k2security.SecurityError as e:
        cprint(f" {filename} - invalid filename: {e}\n", STYLE_RED)
        return None

    rurl = url

    # Convert the list in the update config file to a URL address
    rurl += filename.replace("\\", "/")
    if gz:
        rurl += ".gz"

    # Get the full path of the file to save
    pwd = os.path.join(path, filename)
    if gz:
        pwd += ".gz"

    if fnhook is not None:
        cprint(f"{filename} ", STYLE_GREY)

    # Download the file (CWE-918: SSRF prevention with URL validation)
    try:
        k2security.safe_download_file(rurl, pwd, path, fnhook=fnhook)
    except k2security.SecurityError as e:
        cprint(f" download failed: {e}\n", STYLE_RED)
        return None

    if gz:
        data = gzip.open(pwd, "rb").read()
        # Use mkstemp instead of mktemp to prevent race condition (CWE-377)
        fd, fname = tempfile.mkstemp(prefix="ktmp", suffix=".exe")
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        # Delete the gz file (CWE-73 safe deletion)
        with contextlib.suppress(k2security.SecurityError):
            k2security.safe_remove_file(pwd, path)

    if fnhook is not None:
        cprint(" update\n", STYLE_GREEN)

    return fname


# Compare the hash in the update config file with the local hash
def chek_need_update(file, hash):
    with contextlib.suppress(IOError):
        with open(file, "rb") as fp:
            data = fp.read()
        # Compare the hash (case-insensitive comparison)
        s = hashlib.sha1()
        s.update(data)
        if s.hexdigest().lower() == hash.lower():
            return 0  # Not an update target

    return 1  # Update target


# -------------------------------------------------------------------------
# Callback function for listvirus
# -------------------------------------------------------------------------
def listvirus_callback(plugin_name, vnames):
    terminal_width = get_terminal_sizex()
    engine_str = f"[{plugin_name}]"
    engine_len = len(engine_str)

    # Available space for malware name (1 space before engine name)
    available_width = terminal_width - engine_len - 1

    for vname in vnames:
        if len(vname) <= available_width:
            # Malware name fits, right-align engine name
            padding = terminal_width - len(vname) - engine_len
            print(f"{vname}{' ' * padding}{engine_str}")
        else:
            # Truncate malware name with ' ... ' in the middle
            ellipsis = " ... "
            half_len = (available_width - len(ellipsis)) // 2
            first_part = vname[:half_len]
            last_part = vname[-(available_width - half_len - len(ellipsis)) :]
            truncated = f"{first_part}{ellipsis}{last_part}"
            print(f"{truncated} {engine_str}")


# -------------------------------------------------------------------------
# Function to display malware results in a single line
# -------------------------------------------------------------------------
def get_terminal_sizex():
    default_sizex = 80

    # Source: https://gist.github.com/jtriley/1108174
    if os.name == "nt":
        with contextlib.suppress(Exception):
            from ctypes import windll, create_string_buffer

            h = windll.kernel32.GetStdHandle(-12)
            csbi = create_string_buffer(22)
            res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
            if res:
                (
                    bufx,
                    bufy,
                    curx,
                    cury,
                    wattr,
                    left,
                    top,
                    right,
                    bottom,
                    maxx,
                    maxy,
                ) = struct.unpack("hhhhHhhhhhh", csbi.raw)
                sizex = right - left + 1
                # sizey = bottom - top + 1
                return sizex
    else:

        def ioctl_GWINSZ(fd):
            with contextlib.suppress(Exception):
                import fcntl
                import termios

                cr = struct.unpack("hh", fcntl.ioctl(fd, termios.TIOCGWINSZ, "1234"))
                return cr

        cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
        if not cr:
            with contextlib.suppress(Exception):
                fd = os.open(os.ctermid(), os.O_RDONLY)
                cr = ioctl_GWINSZ(fd)
                os.close(fd)

        if not cr:
            try:
                cr = (os.environ["LINES"], os.environ["COLUMNS"])
            except Exception:
                return default_sizex
        return int(cr[1])  # , int(cr[0])

    return default_sizex  # default


def convert_display_filename(real_filename):
    # Name for display
    # Use stdout encoding for both encode and decode to avoid mismatch
    stdout_encoding = sys.stdout.encoding or sys.getdefaultencoding()
    display_filename = real_filename.encode(stdout_encoding, "replace")

    # In Python 3, bytes[0] returns int, so compare with ord() values
    if display_filename and display_filename[0] in [ord("/"), ord("\\")]:
        return display_filename[1:].decode(stdout_encoding, "replace")
    else:
        return display_filename.decode(stdout_encoding, "replace")


def get_display_width(s):
    """Calculate display width of a string (wide characters count as 2)."""
    import unicodedata

    width = 0
    for char in s:
        ea = unicodedata.east_asian_width(char)
        if ea in ("F", "W"):  # Fullwidth or Wide
            width += 2
        else:
            width += 1
    return width


def truncate_to_width(s, target_width):
    """Truncate string to fit within target display width."""
    import unicodedata

    width = 0
    result = []
    for char in s:
        ea = unicodedata.east_asian_width(char)
        char_width = 2 if ea in ("F", "W") else 1
        if width + char_width > target_width:
            break
        result.append(char)
        width += char_width
    return "".join(result)


def get_suffix_by_width(s, target_width):
    """Get suffix of string that fits within target display width."""
    import unicodedata

    chars = list(s)
    width = 0
    start_idx = len(chars)
    for i in range(len(chars) - 1, -1, -1):
        ea = unicodedata.east_asian_width(chars[i])
        char_width = 2 if ea in ("F", "W") else 1
        if width + char_width > target_width:
            break
        width += char_width
        start_idx = i
    return "".join(chars[start_idx:])


def display_line(filename, message, message_color):
    max_sizex = get_terminal_sizex() - 1
    filename += " "
    filename = convert_display_filename(filename)
    disp_width = get_display_width(filename)
    len_msg = len(message)

    if disp_width + 1 + len_msg < max_sizex:
        fname = f"{filename}"
    else:
        fname = truncate_filename_with_ellipsis(max_sizex, len_msg, filename, disp_width)

    # Use Text object to combine multiple styles in one line
    text = Text()
    text.append(f"{fname} ", style=STYLE_GREY)
    text.append(message, style=message_color)
    console.print(text)


def truncate_filename_with_ellipsis(max_sizex, len_msg, filename, disp_width):
    """Function to shorten long filenames to fit the screen size and insert ... in the middle"""
    able_size = max_sizex - len_msg
    able_size -= 5  # " ... "
    if able_size <= 0:
        return filename[:10] + " ... "
    half_size = able_size // 2
    fname1 = truncate_to_width(filename, half_size)
    fname2 = get_suffix_by_width(filename, able_size - half_size)

    return f"{fname1} ... {fname2}"


# -------------------------------------------------------------------------
# Callback function for scan
# -------------------------------------------------------------------------
def scan_callback(ret_value):
    global g_options
    global display_scan_result  # Structure to temporarily hold output

    from kicomav.plugins import kernel

    fs = ret_value["file_struct"]

    if len(fs.get_additional_filename()) != 0:
        f2 = convert_display_filename(fs.get_additional_filename())
        disp_name = f"{fs.get_master_filename()} ({f2})"
    else:
        disp_name = f"{fs.get_master_filename()}"

    if ret_value["result"]:
        if ret_value["scan_state"] == kernel.INFECTED:
            state = "infected"
            message_color = STYLE_RED
        elif ret_value["scan_state"] == kernel.SUSPECT:
            state = "suspect"
            message_color = STYLE_RED
        elif ret_value["scan_state"] == kernel.WARNING:
            state = "warning"
            message_color = STYLE_RED
        elif ret_value["scan_state"] == kernel.IDENTIFIED:
            state = "identified"
            message_color = STYLE_GREEN
        else:
            state = "unknown"
            message_color = STYLE_RED

        vname = ret_value["virus_name"]
        message = f"{state} : {vname}"
    elif ret_value["scan_state"] == kernel.ERROR:
        message = ret_value["virus_name"]
        message_color = STYLE_CYAN
    else:
        message = "ok"
        message_color = STYLE_GREY_BOLD

    # In normal cases, there is a possibility of duplication due to /<...> paths
    # Adjusted to prevent duplicate output
    if message == "ok":
        d_prev = display_scan_result.get("Prev", {})
        if d_prev == {}:
            update_scan_result_cache(disp_name, "Prev", message, message_color)
        elif d_prev["disp_name"] != disp_name:
            d_next = display_scan_result.get("Next", {})
            if d_next == {}:
                update_scan_result_cache(disp_name, "Next", message, message_color)
            elif d_next["disp_name"] != disp_name:
                # Print Prev
                print_and_clear_cached_result(d_prev, display_scan_result, "Prev")
                log_print(f"{d_prev['disp_name']}	{d_prev['message']}\n")

                # Move Next to Prev
                update_scan_result_cache(d_next["disp_name"], "Prev", d_next["message"], d_next["message_color"])

                update_scan_result_cache(disp_name, "Next", message, message_color)
    else:  # If malware is found, print all stored outputs
        print_display_scan_result(disp_name, message, message_color)

    if g_options.opt_move is False and g_options.opt_prompt:  # Is the prompt option set?
        while ret_value["result"]:
            if ret_value["scan_state"] == kernel.INFECTED:
                msg = "Disinfect/Delete/Ignore/Quit? (d/l/i/q) : "
            else:
                msg = "Delete/Ignore/Quit? (l/i/q) : "

            cprint(msg, STYLE_CYAN)
            log_print(msg)

            ch = getch().lower()
            print(ch)
            log_print(ch + "\n")

            if ret_value["scan_state"] == kernel.INFECTED and ch == "d":
                return kavcore.k2const.K2_ACTION_DISINFECT
            elif ch == "l":
                return kavcore.k2const.K2_ACTION_DELETE
            elif ch == "i":
                return kavcore.k2const.K2_ACTION_IGNORE
            elif ch == "q":
                return kavcore.k2const.K2_ACTION_QUIT
    elif g_options.opt_dis:  # Disinfect option
        return kavcore.k2const.K2_ACTION_DISINFECT
    elif g_options.opt_del:  # Delete option
        return kavcore.k2const.K2_ACTION_DELETE

    return kavcore.k2const.K2_ACTION_IGNORE


def update_scan_result_cache(disp_name, result_dict, message, message_color):
    """Function to temporarily store scan results"""
    global display_scan_result  # Structure to temporarily hold output

    display_scan_result[result_dict]["disp_name"] = disp_name
    display_scan_result[result_dict]["message"] = message
    display_scan_result[result_dict]["message_color"] = message_color


# Prints the results of the display_scan_result structure
def print_display_scan_result(disp_name, message, message_color):
    global display_scan_result  # Structure to temporarily hold output

    # Print Prev
    d_prev = display_scan_result.get("Prev", {})
    if d_prev != {} and d_prev["disp_name"] != disp_name:
        print_and_clear_cached_result(d_prev, display_scan_result, "Prev")
    # Print Next
    d_next = display_scan_result.get("Next", {})
    if d_next != {} and d_next["disp_name"] != disp_name:
        print_and_clear_cached_result(d_next, display_scan_result, "Next")
    # Print the final result
    if disp_name:
        display_line(disp_name, message, message_color)
        log_print(f"{disp_name}\t{message}\n")


def print_and_clear_cached_result(cached_result, display_scan_result, cache_key):
    """Function to print and clear cached scan results"""
    display_line(cached_result["disp_name"], cached_result["message"], cached_result["message_color"])
    log_print(f"{cached_result['disp_name']}\t{cached_result['message']}\n")
    display_scan_result[cache_key] = {}


# -------------------------------------------------------------------------
# Callback function for disinfect
# -------------------------------------------------------------------------
def disinfect_callback(ret_value, action_type):
    fs = ret_value["file_struct"]
    message = ""

    if len(fs.get_additional_filename()) != 0:
        disp_name = f"{fs.get_master_filename()} ({fs.get_additional_filename()})"
    else:
        disp_name = f"{fs.get_master_filename()}"

    if fs.is_modify():  # Modification successful?
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = "disinfected"
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = "deleted"

        message_color = STYLE_GREEN
    else:
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = "disinfection failed"
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = "deletion failed"

        message_color = STYLE_RED

    display_line(disp_name, message, message_color)
    log_print(f"{disp_name}\t{message}\n")


# -------------------------------------------------------------------------
# Callback function for update
# -------------------------------------------------------------------------
def update_callback(ret_file_info, is_success):
    global display_update_result

    # Print results that were not output
    print_display_scan_result(None, None, None)

    if ret_file_info.is_modify():  # If modified, print results
        if len(ret_file_info.get_additional_filename()) != 0:
            disp_name = f"{ret_file_info.get_master_filename()} ({ret_file_info.get_additional_filename()})"
        else:
            disp_name = f"{ret_file_info.get_master_filename()}"

        if is_success:
            if os.path.exists(ret_file_info.get_filename()):
                message = "updated"
            else:
                message = "deleted"

            message_color = STYLE_GREEN
        else:
            message = "update failed"
            message_color = STYLE_RED

        if display_update_result != disp_name:  # Do not print if the same as previous output
            display_line(disp_name, message, message_color)
            log_print(f"{disp_name}\t{message}\n")

            display_update_result = disp_name


# -------------------------------------------------------------------------
# Callback function for quarantine
# -------------------------------------------------------------------------
def quarantine_callback(filename, is_success, q_type):
    from kicomav.plugins import kernel

    q_message = {
        kavcore.k2const.K2_QUARANTINE_MOVE: ["quarantined", "quarantine failed"],
        kavcore.k2const.K2_QUARANTINE_COPY: ["copied", "copy failed"],
    }

    msg = q_message[q_type]

    disp_name = filename

    if is_success:
        message = msg[0]  # Success
        message_color = STYLE_GREEN
    else:
        message = msg[1]  # Failure
        message_color = STYLE_RED

    display_line(disp_name, message, message_color)
    log_print(f"{disp_name}\t{message}\n")


# -------------------------------------------------------------------------
# Callback function for plugin engine loading failure
# -------------------------------------------------------------------------
def import_error_callback(module_name):
    global PLUGIN_ERROR
    global g_options

    if g_options.opt_debug and not PLUGIN_ERROR:
        PLUGIN_ERROR = True
        print()
        print_error(f"Invalid plugin: '{module_name}'")


# -------------------------------------------------------------------------
# print_result(result)
# Prints the results of the malware scan.
# Input: result - Malware scan results
# -------------------------------------------------------------------------
def print_result(result):
    global g_options
    global g_delta_time

    print()
    print()

    cprint("Results:\n", STYLE_GREY_BOLD)
    cprint(f"Folders           :{result['Folders']}\n", STYLE_GREY_BOLD)
    cprint(f"Files             :{result['Files']}\n", STYLE_GREY_BOLD)
    cprint(f"Packed            :{result['Packed']}\n", STYLE_GREY_BOLD)
    cprint(f"Infected files    :{result['Infected_files']}\n", STYLE_GREY_BOLD)
    cprint(f"Suspect files     :{result['Suspect_files']}\n", STYLE_GREY_BOLD)
    cprint(f"Warnings          :{result['Warnings']}\n", STYLE_GREY_BOLD)
    cprint(f"Identified viruses:{result['Identified_viruses']}\n", STYLE_GREY_BOLD)
    if result["Disinfected_files"]:
        cprint(f"Disinfected files :{result['Disinfected_files']}\n", STYLE_GREY_BOLD)
    elif result["Deleted_files"]:
        cprint(f"Deleted files     :{result['Deleted_files']}\n", STYLE_GREY_BOLD)
    cprint(f"I/O errors        :{result['IO_errors']}\n", STYLE_GREY_BOLD)

    # Display scan time
    t = str(g_delta_time).split(":")
    t_h = int(float(t[0]))
    t_m = int(float(t[1]))
    t_s = int(float(t[2]))
    cprint(f"Scan time         :{t_h:02d}:{t_m:02d}:{t_s:02d}\n", STYLE_GREY_BOLD)

    print()


# -------------------------------------------------------------------------
# main()
# -------------------------------------------------------------------------
def main():
    global console
    global g_options

    # Parse options
    options, args = parser_options()
    g_options = options  # Set global options

    # Handle --no-color option
    if not isinstance(options, str) and options.opt_nocolor:
        console = Console(no_color=True)

    # Display logo
    print_k2logo()

    # Invalid options?
    if options == "NONE_OPTION":  # No options provided
        return print_usage_and_options()
    elif options == "ILLEGAL_OPTION":  # Undefined options used
        print_usage()
        print(f"Error: {args}")
        return 0

    # Program's running folder (use __file__ to get actual module location)
    k2_pwd = os.path.dirname(os.path.abspath(__file__))

    # Help option or no arguments
    if options.opt_help or not args:
        # Update scenario with no arguments?
        if options.opt_update:
            update_kicomav(k2_pwd)
            return 0

        if not options.opt_vlist:  # No malware list output
            return print_usage_and_options()

    # Create log file
    if g_options.opt_app is False:
        log_print("#\n# KicomAV scan report\n#\n", "wt")  # Create new file if not append mode
    else:
        log_print("\n#\n# KicomAV scan report\n#\n")

    log_print(f"# Time: {time.ctime()}\n")

    log_print("# Command line: ")
    for argv in sys.argv[1:]:
        log_print(f"{argv} ")
    log_print("\n")

    logo = f"KICOM Anti-Virus II (for {sys.platform.upper()}) Ver {KAV_VERSION} ({KAV_BUILDDATE})"
    log_print(f"# {logo}\n")

    # Post-update scanning
    if options.opt_update:
        update_kicomav()

    # Set quarantine folder
    if options.infp_path:
        path = os.path.abspath(options.infp_path)
        path = os.path.normcase(path)
        create_folder(path)
        options.infp_path = path

    with console.status("Loading KicomAV...", spinner="dots"):
        # Start antivirus engine
        k2 = kavcore.k2engine.Engine()  # Engine class

        # Set plugin engine
        plugins_path = os.path.join(k2_pwd, "plugins")
        if not k2.set_plugins(plugins_path, import_error_callback):
            return print_engine_error("KICOM Anti-Virus Engine set_plugins")
        kav = k2.create_instance()  # Create antivirus engine instance
        if not kav:
            return print_engine_error("KICOM Anti-Virus Engine create_instance")
        kav.set_options(options)  # Set options

        if not kav.init(import_error_callback):  # Initialize all plugin engines
            return print_engine_error("KICOM Anti-Virus Engine init")

    if options.opt_debug and PLUGIN_ERROR:
        print()

    # Print engine version
    c = kav.get_version()
    msg = f"\rLast updated {c.ctime()} UTC\n"
    cprint(msg, STYLE_GREY)

    # Print the number of diagnosable/treatable malware
    num_sig = format(kav.get_signum(), ",")
    msg = f"Signature number: {num_sig}\n\n"
    cprint(msg, STYLE_GREY)

    log_print(f"# Signature number: {num_sig}\n")
    log_print("#\n\n")

    if options.opt_vlist is True:  # Display malware list?
        kav.listvirus(listvirus_callback)
    elif args:
        scan_paths_and_print_result(kav, args, k2)
    kav.uninit()


def scan_paths_and_print_result(kav, args, k2_engine=None):
    """Scan the given paths and print the results"""
    global g_options

    kav.set_result()  # Initialize malware scan results

    # Check scan start time
    start_time = datetime.datetime.now()

    # Determine if parallel scanning should be used
    use_parallel = g_options.opt_parallel
    max_workers = g_options.opt_workers if g_options.opt_workers > 0 else (os.cpu_count() or 4)

    interrupted = False

    # Scan paths (supports multiple paths)
    try:
        for scan_path in args:  # First argument excluding options is the target
            scan_path = os.path.abspath(scan_path)

            if os.path.exists(scan_path):  # Does the folder or file exist?
                if use_parallel and k2_engine:
                    # Parallel scanning mode
                    status_msg = f"Parallel scanning ({max_workers} workers)..."
                    with console.status(status_msg, spinner="dots"):
                        ret = kav.scan_parallel(
                            scan_path,
                            max_workers,
                            k2_engine,
                            scan_callback,
                            disinfect_callback,
                            update_callback,
                            quarantine_callback,
                        )
                        if ret == 1:  # Interrupted
                            interrupted = True
                            break
                else:
                    # Sequential scanning mode (default)
                    with console.status("Scanning...", spinner="dots"):
                        kav.scan(
                            scan_path,
                            scan_callback,
                            disinfect_callback,
                            update_callback,
                            quarantine_callback,
                        )
            else:
                # Print results not displayed
                print_display_scan_result(None, None, None)
                print_error(f"Invalid path: '{scan_path}'")
    except KeyboardInterrupt:
        interrupted = True

    # Check scan end time
    end_time = datetime.datetime.now()

    global g_delta_time
    g_delta_time = end_time - start_time

    # Print results (ignore Ctrl+C during output to ensure results are shown)
    import signal

    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ignore Ctrl+C
    try:
        print_display_scan_result(None, None, None)
        ret = kav.get_result()
        print_result(ret)
    finally:
        signal.signal(signal.SIGINT, original_handler)  # Restore handler


def print_usage_and_options():
    """Print usage and options"""
    print_usage()
    print_options()
    return 0


def print_engine_error(error_msg):
    """Print engine initialization error"""
    print()
    print_error(error_msg)
    return 0


if __name__ == "__main__":
    main()
