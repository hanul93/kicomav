# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import contextlib
import os
import re
import struct
import glob
import marshal
import time
import math
import zlib
import zipfile


# -------------------------------------------------------------------------
# Message printing function
# -------------------------------------------------------------------------
def vprint(header, section=None, msg=None):
    if header:
        print(f"[*] {header}")

    if section:
        new_msg = f"{msg[:22]} ... {msg[-22:]}" if len(msg) > 50 else msg
        print(f"    [-] {section}: {new_msg}")


# -------------------------------------------------------------------------
# Malware pattern instance
# -------------------------------------------------------------------------
handle_pattern_md5 = None  # Malware pattern handle (MD5 hash)
handle_pattern_vdb = None  # Malware pattern handle (VDB)

# -------------------------------------------------------------------------
# Regular expression compilation
# -------------------------------------------------------------------------
p_text = re.compile(r'[\w\s!"#$%&\'()*+,\-./:;<=>?@\[\\\]\^_`{\|}~]')
p_md5_pattern_ext = re.compile(r"\.s(\d\d)$", re.IGNORECASE)


# -------------------------------------------------------------------------
# PatternMD5
# -------------------------------------------------------------------------
class PatternMD5:
    # ---------------------------------------------------------------------
    # __init__(self, rules_paths)
    # Initialize malware pattern
    # input  : rules_paths - Dict with rule paths {"system": "/path", "user": "/path"}
    # ---------------------------------------------------------------------
    def __init__(self, rules_paths):
        self.sig_sizes = {}
        self.sig_p1s = {}
        self.sig_p2s = {}
        self.sig_names = {}
        self.sig_times = {}  # Time information for memory management

        # Validate rules_paths is dict
        if rules_paths is not None and not isinstance(rules_paths, dict):
            raise TypeError(f"rules_paths must be a dict, got {type(rules_paths).__name__}")

        self.rules_paths = rules_paths or {}

        # Number of signatures per malware type: e.g., adware:1, emalware:39
        # This determines which group a size belongs to in the future (size % count) + 1
        self.sig_group_count = {}

        # Collect pattern files from all kicomav rule paths
        pattern_files = []
        for key in ["system", "user"]:
            base = self.rules_paths.get(key)
            if base:
                kicomav_path = os.path.join(base, "kicomav")
                if os.path.isdir(kicomav_path):
                    fl = glob.glob1(kicomav_path, "*.s??")
                    for name in fl:
                        pattern_files.append(os.path.join(kicomav_path, name))

        pattern_files.sort()
        for name in pattern_files:
            if obj := p_md5_pattern_ext.search(name):
                idx = obj.groups()[0]  # ex:01
                sig_key = os.path.split(name)[1].lower().split(".")[0]  # ex:script
                sp = self.__load_sig(name)
                if sp is None:
                    continue

                if len(sp):  # If there is more than one loaded pattern...
                    # Add group count
                    self.sig_group_count[sig_key] = self.sig_group_count.get(sig_key, 0) + 1

                    # Store malware pattern size
                    if sig_key in self.sig_sizes:
                        self.sig_sizes[sig_key].update(dict.fromkeys(sp))
                    else:
                        self.sig_sizes[sig_key] = dict.fromkeys(sp)

    # ---------------------------------------------------------------------
    # match_size(self, sig_key, sig_size)
    # Check if the specified malware pattern exists
    # input  : sig_key  - Specified malware pattern
    #          sig_size - Size
    # return : True or False if the specified size exists in the malware pattern
    # ---------------------------------------------------------------------
    def match_size(self, sig_key, sig_size):
        sig_key = sig_key.lower()  # Convert to lowercase to handle case sensitivity

        return sig_key in self.sig_sizes and sig_size in self.sig_sizes[sig_key]

    # ---------------------------------------------------------------------
    # scan(self, sig_key, sig_size, sig_md5)
    # Scan malware pattern
    # input  : sig_key  - Specified malware pattern
    #          sig_size - Size
    #          sig_md5  - MD5
    # return : Found malware name
    # ---------------------------------------------------------------------
    def scan(self, sig_key, sig_size, sig_md5):
        sig_key = sig_key.lower()  # Convert to lowercase to handle case sensitivity

        if self.match_size(sig_key, sig_size):  # Does the size exist?
            # idxs = self.sig_sizes[sig_key][sig_size]  # Check which file contains the 1st pattern
            idxs = ["%02d" % ((sig_size % self.sig_group_count[sig_key]) + 1)]

            fmd5 = bytes.fromhex(sig_md5)
            sig_p1 = fmd5[:6]  # 1st pattern
            sig_p2 = fmd5[6:]  # 2nd pattern

            for idx in idxs:
                # Compare 1st pattern
                # If 1st pattern is not loaded...
                if self.__load_sig_ex(self.sig_p1s, "i", sig_key, idx) is False:
                    continue

                if sig_p1 in self.sig_p1s[sig_key][idx]:  # Found 1st pattern
                    p2_offs = self.sig_p1s[sig_key][idx][sig_p1]

                    # Compare 2nd pattern
                    # If 2nd pattern is not loaded...
                    if self.__load_sig_ex(self.sig_p2s, "c", sig_key, idx) is False:
                        continue

                    for off in p2_offs:
                        offs = self.sig_p2s[sig_key][idx][off]
                        sig2 = offs[0]  # 2nd pattern
                        if sig2 == sig_p2 and (self.__load_sig_ex(self.sig_names, "n", sig_key, idx) is not False):
                            return self.sig_names[sig_key][idx][offs[1]].decode("utf-8")

        self.__save_mem()  # Reduce memory usage
        return None

    # ---------------------------------------------------------------------
    # __load_sig(self, fname)
    # Load malware pattern
    # input  : fname - Malware pattern file name
    # return : Malware pattern data structure
    # ---------------------------------------------------------------------
    def __load_sig(self, fname):
        try:
            with open(fname, "rb") as fp:
                data = fp.read()
                if data[:4] == b"KAVS":
                    return marshal.loads(zlib.decompress(data[12:]))
        except IOError:
            return None

    # ---------------------------------------------------------------------
    # __load_sig_ex(self, sig_dict, sig_prefix, sig_key, idx)
    # Load malware pattern
    # Also, it can determine whether it is loaded into a specific data structure.
    # input  : sig_dict - Data structure to load malware pattern
    #         sig_prefix - Extension prefix
    #         sig_key    - Malware pattern file name
    #         idx        - Extension number
    # return : Success of loading malware pattern
    # ---------------------------------------------------------------------
    def __load_sig_ex(self, sig_dict, sig_prefix, sig_key, idx):  # (self.sig_names, 'n', 'script', '01')
        if sig_key not in sig_dict:
            sig_dict[sig_key] = {}

        if idx not in sig_dict[sig_key]:
            # Load pattern from kicomav rule paths
            sp = None
            for key in ["system", "user"]:
                base = self.rules_paths.get(key)
                if base:
                    kicomav_path = os.path.join(base, "kicomav")
                    if os.path.isdir(kicomav_path):
                        try:
                            name_fname = os.path.join(kicomav_path, f"{sig_key}.{sig_prefix}{idx}")
                            sp = self.__load_sig(name_fname)
                            if sp is not None:
                                break
                        except IOError:
                            continue

            if sp is None:
                return False

            sig_dict[sig_key][idx] = sp

        # Record current time in sig_time
        if sig_key not in self.sig_times:
            self.sig_times[sig_key] = {}

        if sig_prefix not in self.sig_times[sig_key]:
            self.sig_times[sig_key][sig_prefix] = {}

        self.sig_times[sig_key][sig_prefix][idx] = time.time()

        return True

    # ---------------------------------------------------------------------
    # __save_mem(self)
    # Remove unused malware pattern from memory
    # ---------------------------------------------------------------------
    def __save_mem(self, interval=3 * 60):
        # Is there a pattern to clean up? (3 minutes or more unused pattern)
        n = time.time()
        for sig_key in list(self.sig_times.keys()):
            for sig_prefix in list(self.sig_times[sig_key].keys()):
                for idx in list(self.sig_times[sig_key][sig_prefix].keys()):
                    if n - self.sig_times[sig_key][sig_prefix][idx] > interval:
                        if sig_prefix == "i":  # 1st pattern
                            self.sig_p1s[sig_key].pop(idx)
                        elif sig_prefix == "c":  # 2nd pattern
                            self.sig_p2s[sig_key].pop(idx)
                        elif sig_prefix == "n":  # Malware name pattern
                            self.sig_names[sig_key].pop(idx)

                        self.sig_times[sig_key][sig_prefix].pop(idx)  # Time

    # ---------------------------------------------------------------------
    # get_sig_num(self, sig_key)
    # Get the cumulative number of malware patterns for a given sig_key
    # input  : sig_key - Malware pattern name (ex:script)
    # return : Number of malware patterns
    # ---------------------------------------------------------------------
    def get_sig_num(self, sig_key):
        sig_num = 0

        # Collect count files from all kicomav rule paths
        for key in ["system", "user"]:
            base = self.rules_paths.get(key)
            if base:
                kicomav_path = os.path.join(base, "kicomav")
                if os.path.isdir(kicomav_path):
                    fl = glob.glob1(kicomav_path, f"{sig_key}.c??")
                    for fname in fl:
                        fname = os.path.join(kicomav_path, fname)
                        try:
                            with open(fname, "rb") as fp:
                                buf = fp.read(12)
                                if buf[:4] == b"KAVS":
                                    sig_num += get_uint32(buf, 4)
                        except IOError:
                            continue

        return sig_num

    # ---------------------------------------------------------------------
    # get_sig_vlist(self, sig_key)
    # Get the malware name for a given sig_key
    # input  : sig_key - Malware pattern name (ex:script)
    # return : Malware name
    # ---------------------------------------------------------------------
    def get_sig_vlist(self, sig_key):
        sig_vname = []

        # Collect name files from all kicomav rule paths
        for key in ["system", "user"]:
            base = self.rules_paths.get(key)
            if base:
                kicomav_path = os.path.join(base, "kicomav")
                if os.path.isdir(kicomav_path):
                    fl = glob.glob1(kicomav_path, f"{sig_key}.n??")
                    for fname in fl:
                        fname = os.path.join(kicomav_path, fname)
                        try:
                            sig_vname += self.__load_sig(fname)
                        except IOError:
                            continue

        if not sig_vname:
            return None

        # Convert byte to string
        for i in range(len(sig_vname)):
            sig_vname[i] = sig_vname[i].decode("utf-8")

        return sig_vname


# -------------------------------------------------------------------------
# PatternVDB
# -------------------------------------------------------------------------
class PatternVDB:
    # ---------------------------------------------------------------------
    # __init__(self, rules_paths)
    # Initialize malware pattern
    # input  : rules_paths - Dict with rule paths {"system": "/path", "user": "/path"}
    # ---------------------------------------------------------------------
    def __init__(self, rules_paths):
        self.sig_sizes = {}
        self.sig_p1s = {}
        self.sig_p2s = {}
        self.sig_names = {}
        self.sig_times = {}  # Time information for memory management

        # Validate rules_paths is dict
        if rules_paths is not None and not isinstance(rules_paths, dict):
            raise TypeError(f"rules_paths must be a dict, got {type(rules_paths).__name__}")

        self.rules_paths = rules_paths or {}

        # Collect pattern files from all kicomav rule paths
        pattern_files = []
        for key in ["system", "user"]:
            base = self.rules_paths.get(key)
            if base:
                kicomav_path = os.path.join(base, "kicomav")
                if os.path.isdir(kicomav_path):
                    fl = glob.glob1(kicomav_path, "ve.s??")
                    for name in fl:
                        pattern_files.append(os.path.join(kicomav_path, name))

        pattern_files.sort()
        for name in pattern_files:
            if obj := p_md5_pattern_ext.search(name):
                idx = obj.groups()[0]  # ex:01
                sig_key = os.path.split(name)[1].lower().split(".")[0]  # ex:script
                sp = self.__load_sig(name)
                if sp is None:
                    continue

                if len(sp):  # If more than one loaded pattern...
                    if sig_key not in self.sig_sizes:
                        self.sig_sizes[sig_key] = {}

                    for psize in sp.keys():
                        if psize in self.sig_sizes[sig_key]:
                            self.sig_sizes[sig_key][psize][idx].append(psize)
                        else:
                            self.sig_sizes[sig_key][psize] = {idx: sp[psize]}

    # ---------------------------------------------------------------------
    # match_size(self, sig_key, sig_size)
    # Check if the specified malware pattern exists
    # input  : sig_key  - Specified malware pattern
    #          sig_size - Size
    # return : True or False if the specified size exists in the malware pattern
    # ---------------------------------------------------------------------
    def match_size(self, sig_key, sig_size):
        sig_key = sig_key.lower()  # Convert to lowercase to handle case sensitivity

        if sig_key in self.sig_sizes and sig_size in self.sig_sizes[sig_key].keys():
            return self.sig_sizes[sig_key][sig_size]

        return None

    # ---------------------------------------------------------------------
    # get_cs1(self, ve_id, idx)
    # Read 1st pattern
    # input  : ve_id - ve pattern file
    #          idx   - Internal index
    # return : 1st pattern
    # ---------------------------------------------------------------------
    def get_cs1(self, ve_id, idx):
        sig_key = "ve"

        if self.__load_sig_ex(self.sig_p1s, "i", sig_key, ve_id):
            return self.sig_p1s[sig_key][ve_id][idx]

        return None

    # ---------------------------------------------------------------------
    # get_cs2(self, ve_id, idx)
    # Read 2nd pattern
    # input  : ve_id - ve pattern file
    #          idx   - Internal index
    # return : 2nd pattern
    # ---------------------------------------------------------------------
    def get_cs2(self, ve_id, idx):
        sig_key = "ve"

        if self.__load_sig_ex(self.sig_p2s, "c", sig_key, ve_id):
            return self.sig_p2s[sig_key][ve_id][idx]

        return None

    # ---------------------------------------------------------------------
    # get_vname(self, ve_id, vname_id)
    # Return malware name
    # input  : ve_id    - ve pattern file
    #          vname_id - Internal index
    # return : 1st pattern
    # ---------------------------------------------------------------------
    def get_vname(self, ve_id, vname_id):
        sig_key = "ve"

        if self.__load_sig_ex(self.sig_names, "n", sig_key, ve_id):
            return self.sig_names[sig_key][ve_id][vname_id].decode("utf-8")

        return None

    # ---------------------------------------------------------------------
    # __load_sig(self, fname)
    # Load malware pattern
    # input  : fname - Malware pattern file name
    # return : Malware pattern data structure
    # ---------------------------------------------------------------------
    def __load_sig(self, fname):
        try:
            with open(fname, "rb") as fp:
                data = fp.read()
                if data[:4] == b"KAVS":
                    return marshal.loads(zlib.decompress(data[12:]))
        except IOError:
            return None

    # ---------------------------------------------------------------------
    # __load_sig_ex(self, sig_dict, sig_prefix, sig_key, idx)
    # Load malware pattern
    # Also, it can determine whether it is loaded into a specific data structure.
    # input  : sig_dict - Data structure to load malware pattern
    #         sig_prefix - Extension prefix
    #         sig_key    - Malware pattern file name
    #         idx        - Extension number
    # return : Success of loading malware pattern
    # ---------------------------------------------------------------------
    def __load_sig_ex(self, sig_dict, sig_prefix, sig_key, idx):  # (self.sig_names, 'n', 'script', '01')
        if sig_key not in sig_dict or idx not in sig_dict[sig_key]:
            # Load pattern from kicomav rule paths
            sp = None
            for key in ["system", "user"]:
                base = self.rules_paths.get(key)
                if base:
                    kicomav_path = os.path.join(base, "kicomav")
                    if os.path.isdir(kicomav_path):
                        try:
                            name_fname = os.path.join(kicomav_path, f"{sig_key}.{sig_prefix}{idx}")
                            sp = self.__load_sig(name_fname)
                            if sp is not None:
                                break
                        except IOError:
                            continue

            if sp is None:
                return False

            sig_dict[sig_key] = {idx: sp}

        # Record current time in sig_time
        if sig_key not in self.sig_times:
            self.sig_times[sig_key] = {}

        if sig_prefix not in self.sig_times[sig_key]:
            self.sig_times[sig_key][sig_prefix] = {}

        self.sig_times[sig_key][sig_prefix][idx] = time.time()

        return True

    # ---------------------------------------------------------------------
    # __save_mem(self)
    # Remove unused malware pattern from memory
    # ---------------------------------------------------------------------
    def __save_mem(self, interval=3 * 60):
        # Is there a pattern to clean up? (3 minutes or more unused pattern)
        n = time.time()
        for sig_key in list(self.sig_times.keys()):
            for sig_prefix in list(self.sig_times[sig_key].keys()):
                for idx in list(self.sig_times[sig_key][sig_prefix].keys()):
                    if n - self.sig_times[sig_key][sig_prefix][idx] > interval:
                        if sig_prefix == "i":  # 1st pattern
                            self.sig_p1s[sig_key].pop(idx)
                        elif sig_prefix == "c":  # 2nd pattern
                            self.sig_p2s[sig_key].pop(idx)
                        elif sig_prefix == "n":  # Malware name pattern
                            self.sig_names[sig_key].pop(idx)

                        self.sig_times[sig_key][sig_prefix].pop(idx)  # Time

    # ---------------------------------------------------------------------
    # get_sig_num(self, sig_key)
    # Get the cumulative number of malware patterns for a given sig_key
    # input  : sig_key - Malware pattern name (ex:script)
    # return : Number of malware patterns
    # ---------------------------------------------------------------------
    def get_sig_num(self, sig_key):
        sig_num = 0

        # Collect count files from all kicomav rule paths
        for key in ["system", "user"]:
            base = self.rules_paths.get(key)
            if base:
                kicomav_path = os.path.join(base, "kicomav")
                if os.path.isdir(kicomav_path):
                    fl = glob.glob1(kicomav_path, f"{sig_key}.c??")
                    for fname in fl:
                        fname = os.path.join(kicomav_path, fname)
                        try:
                            with open(fname, "rb") as fp:
                                buf = fp.read(12)
                                if buf[:4] == b"KAVS":
                                    sig_num += get_uint32(buf, 4)
                        except IOError:
                            continue

        return sig_num

    # ---------------------------------------------------------------------
    # get_sig_vlist(self, sig_key)
    # Get the malware name for a given sig_key
    # input  : sig_key - Malware pattern name (ex:script)
    # return : Malware name
    # ---------------------------------------------------------------------
    def get_sig_vlist(self, sig_key):
        sig_vname = []

        # Collect name files from all kicomav rule paths
        for key in ["system", "user"]:
            base = self.rules_paths.get(key)
            if base:
                kicomav_path = os.path.join(base, "kicomav")
                if os.path.isdir(kicomav_path):
                    fl = glob.glob1(kicomav_path, f"{sig_key}.n??")
                    for fname in fl:
                        fname = os.path.join(kicomav_path, fname)
                        try:
                            sig_vname += self.__load_sig(fname)
                        except IOError:
                            continue

        if not sig_vname:
            return None

        # Convert byte to string
        for i in range(len(sig_vname)):
            sig_vname[i] = sig_vname[i].decode("utf-8")

        return sig_vname


# -------------------------------------------------------------------------
# AhoCorasick class
# Source : https://gist.github.com/atdt/875e0dba6a15e3fa6018
# -------------------------------------------------------------------------
FAIL = -1


class AhoCorasick:
    def __init__(self):
        self.transitions = {}
        self.outputs = {}
        self.fails = {}

    def make_tree(self, keywords):
        new_state = 0

        for keyword in keywords:
            state = 0

            for j, char in enumerate(keyword):
                res = self.transitions.get((state, char), FAIL)
                if res == FAIL:
                    break
                state = res

            for char in keyword[j:]:
                new_state += 1
                self.transitions[(state, char)] = new_state
                state = new_state

            self.outputs[state] = [keyword]

        queue = []
        for (from_state, char), to_state in self.transitions.items():
            if from_state == 0 and to_state != 0:
                queue.append(to_state)
                self.fails[to_state] = 0

        while queue:
            r = queue.pop(0)
            for (from_state, char), to_state in self.transitions.items():
                if from_state == r:
                    queue.append(to_state)
                    state = self.fails[from_state]

                    while True:
                        res = self.transitions.get((state, char), state and FAIL)
                        if res != FAIL:
                            break
                        state = self.fails[state]

                    failure = self.transitions.get((state, char), state and FAIL)
                    self.fails[to_state] = failure
                    self.outputs.setdefault(to_state, []).extend(self.outputs.get(failure, []))

    def search(self, string):
        state = 0
        results = []
        for i, char in enumerate(string):
            while True:
                res = self.transitions.get((state, char), state and FAIL)
                if res != FAIL:
                    state = res
                    break
                state = self.fails[state]

            for match in self.outputs.get(state, ()):
                pos = i - len(match) + 1
                results.append((pos, match))

        return results


# -------------------------------------------------------------------------
# HexDump
# Display Hex dump for a specified area in a given file
# input  : fname : File name
#          start : Start position of the area to dump
#          size  : Size to dump
#          width : Number of characters per line
# -------------------------------------------------------------------------
class HexDump:
    def File(self, fname, start, size=0x200, width=16):
        with open(fname, "rb") as fp:
            fp.seek(start)
            buf = fp.read(size)
            self.Buffer(buf, start, size, width)

    # -------------------------------------------------------------------------
    # Buffer
    # Display Hex dump for a given buffer
    # input  : fbuf   : Buffer
    #          start : Start position of the area to dump
    #          size  : Size to dump
    #          width : Number of characters per line
    # -------------------------------------------------------------------------
    def Buffer(self, buf, start, size=0x200, width=16):
        # If the buffer is larger than the given size, adjust the argument
        if len(buf) < size:
            size = len(buf)
        row = start % width  # Column
        col = start // width  # Row
        # [row ... width*col]
        # [width*col ... width * (col+1)]
        r_size = 0
        line_start = row + (col * width)
        while True:
            line = buf[line_start : width * (col + 1)]

            if len(line) == 0:
                break
            if r_size + len(line) >= size:
                line = line[: size - r_size]
                r_size = size - len(line)
            # Address value
            output = "%08X : " % ((line_start // width) * width)
            # Hex value
            output += row * "   " + "".join("%02x " % c for c in line)
            output += "  " + (width - (row + len(line))) * "   "
            # Character value
            output += row * " "
            output += "".join([".", chr(c)][self.IsPrint(c)] for c in line)
            print(output)
            line_start = width * (col + 1)
            col += 1
            row = 0
            r_size += len(line)
            if r_size == size:
                break

    # -------------------------------------------------------------------------
    # IsPrint
    # Check if the given character is printable
    # input  : char  : Character
    # return : True  : Printable character
    #          False : Non-printable character
    # -------------------------------------------------------------------------
    def IsPrint(self, c):
        return c >= 0x20 and c < 0x80


# -------------------------------------------------------------------------
# is_textfile(buf)
# Determine if the given buffer is a text file
# input  : buf - Buffer
# return : True if it is a text file, False otherwise
# -------------------------------------------------------------------------
def is_textfile(buf):
    n_buf = len(buf)

    if n_buf == 0:
        return False

    buf = buf.decode("latin-1")

    n_text = len(p_text.findall(buf))

    return n_text / float(n_buf) > 0.8


# -------------------------------------------------------------------------
# get_uint16(buf, off):
# Read the value from the given buffer based on the offset as uint16
# input  : buf - Buffer
#          off - Offset
# return : uint16 converted value
# -------------------------------------------------------------------------
def get_uint16(buf, off, endian="<"):
    return struct.unpack(f"{endian}H", buf[off : off + 2])[0]


# -------------------------------------------------------------------------
# get_uint32(buf, off):
# Read the value from the given buffer based on the offset as uint32
# input  : buf - Buffer
#          off - Offset
# return : uint32 converted value
# -------------------------------------------------------------------------
def get_uint32(buf, off, endian="<"):
    return struct.unpack(f"{endian}L", buf[off : off + 4])[0]


# -------------------------------------------------------------------------
# get_uint64(buf, off):
# Read the value from the given buffer based on the offset as uint64
# input  : buf - Buffer
#          off - Offset
# return : uint64 converted value
# -------------------------------------------------------------------------
def get_uint64(buf, off, endian="<"):
    return struct.unpack(f"{endian}Q", buf[off : off + 8])[0]


# -------------------------------------------------------------------------
# normal_vname(vname):
# Process special characters in the given malware name
# input  : vname - Malware name
#          platform - Win32, MSIL, etc.
# return : New malware name
# -------------------------------------------------------------------------
def normal_vname(vname, platform=None):
    # vname = vname.replace('<n>', 'not-a-virus:')
    vname = vname.replace("<n>", "")

    if platform:
        vname = vname.replace("<p>", platform)

    return vname


# -------------------------------------------------------------------------
# uniq_string()
# Return a unique string in numeric format
# -------------------------------------------------------------------------
def uniq_string():
    return str(int(time.time() * 1000))


# ----------------------------------------------------------------------------
# make_zip(arc_name, file_infos)
# Logic to disinfect malware in a compressed file and re-compress it
# Actual compression logic is not implemented in non-compression engines (e.g., ALZ, EGG, etc.)
# The file is compressed using ZIP, and the extension is retained
# ----------------------------------------------------------------------------
def make_zip(arc_name, file_infos):
    with open(arc_name, "rb") as fp:
        if fp.read(2) != b"PK":
            return

    # CWE-404: Use with statement for proper resource cleanup
    with zipfile.ZipFile(arc_name, "w") as zfile:
        for file_info in file_infos:
            rname = file_info.get_filename()
            with contextlib.suppress(IOError):
                with open(rname, "rb") as fp:
                    buf = fp.read()
                    a_name = file_info.get_filename_in_archive()
                    zfile.writestr(a_name, buf, compress_type=zipfile.ZIP_DEFLATED)


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, rules_paths)
    # Initialize the plug-in engine
    # input  : rules_paths - Dict with rule paths {"system": "/path", "user": "/path"}
    #          verbose     - Debug mode (True or False)
    # return : 0 - success, non-zero - failure
    # ---------------------------------------------------------------------
    def init(self, rules_paths=None, verbose=False):  # Initialize the plug-in engine
        # Validate rules_paths is dict
        if rules_paths is not None and not isinstance(rules_paths, dict):
            raise TypeError(f"rules_paths must be a dict, got {type(rules_paths).__name__}")

        # Initialize malware pattern
        global handle_pattern_md5
        global handle_pattern_vdb

        handle_pattern_md5 = PatternMD5(rules_paths)
        handle_pattern_vdb = PatternVDB(rules_paths)

        return 0  # Initialize the plug-in engine successfully

    # ---------------------------------------------------------------------
    # uninit(self)
    # Terminate the plug-in engine
    # return : 0 - success, Nonzero - fail
    # ---------------------------------------------------------------------
    def uninit(self):  # Terminate the plug-in engine
        return 0  # Terminate the plug-in engine successfully

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Get the main information of the plug-in engine (author, version, ...)
    # return : Plug-in engine information
    # ---------------------------------------------------------------------
    def getinfo(self):  # Get the main information of the plug-in engine
        return {
            "author": "Kei Choi",
            "version": "1.1",
            "title": "KicomAV Utility Library",
            "kmd_name": "kavutil",
        }
