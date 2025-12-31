# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
OLE Archive Engine Plugin

This plugin handles OLE (Object Linking and Embedding) file format for scanning and manipulation.
"""

import contextlib
import logging
import os
import sys
import struct
import types

from kicomav.plugins import kernel
from kicomav.plugins import kavutil
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)

__version__ = "1.0"


class Error(Exception):
    pass


# ---------------------------------------------------------------------
# MisiBase64 encoder/decoder
# ---------------------------------------------------------------------
def MsiBase64Encode(x):
    ct = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
    return None if x > 63 else ord(ct[x])


def DecodeStreamName(name):
    och = []

    wch = [kavutil.get_uint16(name, i * 2) for i in range(len(name) // 2)]
    for ch in wch:
        if 0x3800 <= ch <= 0x4840:
            if ch >= 0x4800:  # 0x4800 - 0x483F
                # only one charecter can be decoded
                ch = MsiBase64Encode(ch - 0x4800)
                if not ch:
                    continue
            else:  # 0x3800 - 0x383F
                # the value contains two characters
                ch -= 0x3800
                och.append(MsiBase64Encode(ch & 0x3F))
                ch = MsiBase64Encode(((ch >> 6) & 0x3F))

        och.append(ch)

    name = b"".join(struct.pack("<H", ch) for ch in och)
    return name.decode("UTF-16LE", "replace")


# ---------------------------------------------------------------------
# Get internal link of OLE
# ---------------------------------------------------------------------
def get_block_link(no, bbd_or_sbd_fat):
    ret = []

    fat = bbd_or_sbd_fat

    next_b = no

    if next_b != 0xFFFFFFFE:
        ret.append(next_b)

        while True:
            try:
                next_b = fat[next_b]
                if next_b == 0xFFFFFFFE:
                    break

                if len(ret) % 10000 == 0 and next_b in ret:
                    break

                ret.append(next_b)
            except KeyError:
                break

    return ret


# ---------------------------------------------------------------------
# Read OLE block
# ---------------------------------------------------------------------
def get_bblock(buf, no, bsize):
    off = (no + 1) * bsize
    return buf[off : off + bsize]


# ---------------------------------------------------------------------
# Get BBD list of OLE
# ---------------------------------------------------------------------
def get_bbd_list_array(buf, verbose=False):
    bbd_list_array = buf[0x4C:0x200]  # Full bbd_list
    num_of_bbd_blocks = kavutil.get_uint32(buf, 0x2C)

    xbbd_start_block = kavutil.get_uint32(buf, 0x44)
    num_of_xbbd_blocks = kavutil.get_uint32(buf, 0x48)

    bsize = 1 << kavutil.get_uint16(buf, 0x1E)

    if verbose:
        kavutil.vprint(None, "Num of BBD Blocks", "%d" % num_of_bbd_blocks)
        kavutil.vprint(None, "XBBD Start", "%08X" % xbbd_start_block)
        kavutil.vprint(None, "Num of XBBD Blocks", "%d" % num_of_xbbd_blocks)

    if num_of_bbd_blocks > 109:  # If bbd list count is greater than 109, get xbbd
        next_b = xbbd_start_block

        for _ in range(num_of_xbbd_blocks):
            t_data = get_bblock(buf, next_b, bsize)
            bbd_list_array += t_data[:-4]
            next_b = kavutil.get_uint32(t_data, bsize - 4)

    return (
        bbd_list_array,  # [: num_of_bbd_blocks * 4],
        num_of_bbd_blocks,
        num_of_xbbd_blocks,
        xbbd_start_block,
    )


# ---------------------------------------------------------------------
# Return index of BBD list to offset
# ---------------------------------------------------------------------
def get_bbd_list_index_to_offset(buf, idx):
    num_of_bbd_blocks = kavutil.get_uint32(buf, 0x2C)

    xbbd_start_block = kavutil.get_uint32(buf, 0x44)
    # num_of_xbbd_blocks = kavutil.get_uint32(buf, 0x48)

    bsize = 1 << kavutil.get_uint16(buf, 0x1E)

    if idx >= num_of_bbd_blocks:  # If out of range, error
        return -1

    if idx <= 109:
        return 0x4C + (idx * 4)
    else:
        return calculate_xbbd_offset(idx, bsize, xbbd_start_block, buf)


def calculate_xbbd_offset(idx, bsize, xbbd_start_block, buf):
    """
    Calculates the offset in XBBD (Extended Big Block Depot) for a given index

    Args:
        idx: Index in BBD list (after first 109 entries)
        bsize: Block size
        xbbd_start_block: Starting block of XBBD
        buf: OLE file buffer

    Returns:
        Offset position in the file, or -1 if invalid
    """
    t_idx = idx - 109
    seg = (t_idx // ((bsize // 4) - 1)) + (1 if (t_idx % ((bsize // 4) - 1)) else 0)
    off = t_idx % ((bsize // 4) - 1)

    next_b = xbbd_start_block
    for _ in range(seg):
        if next_b == 0xFFFFFFFE:
            return -1

        t_buf = get_bblock(buf, next_b, bsize)
        next_b = kavutil.get_uint32(t_buf, bsize - 4)

    return (next_b + 1) * bsize + (off * 4)


# ---------------------------------------------------------------------
# Check if it is an OLE file
# ---------------------------------------------------------------------
def is_olefile(filename):
    with contextlib.suppress(IOError):
        with open(filename, "rb") as f:
            if f.read(8) == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
                return True

    return False


# ---------------------------------------------------------------------
# OleFile class
# ---------------------------------------------------------------------
class OleFile:
    def __init__(self, input_data, write_mode=False, verbose=False):
        self.verbose = verbose  # For debugging
        self.isfile = False  # Is file accessed?

        if not isinstance(input_data, str):
            raise Error("Input data is invalid.")

        if os.path.exists(input_data):
            self.isfile = True
            self.fname = input_data
            self.fp = open(input_data, "rb")
            buf = self.fp.read()
        else:
            buf = input_data
        # Write mode
        self.write_mode = write_mode

        # OLE main data
        self.mm = None
        self.bsize = None
        self.ssize = None
        self.bbd_list_array = None
        self.bbd = None
        self.bbd_fat = {}
        self.sbd = None
        self.root = None
        self.pps = None
        self.small_block = None
        self.root_list_array = None
        self.exploit = []  # Vulnerability existence

        # Temporary variables
        self.__deep = None
        self.__full_list = None

        self.init(buf)

    def init(self, buf):
        # OLE main data
        self.mm = buf
        self.bsize = 0
        self.ssize = 0

        # Temporary variables
        self.__deep = 0
        self.__full_list = []

        self.parse()  # Analyze OLE file

    def close(self):
        if self.isfile:
            self.fp.close()

            if self.write_mode:
                with open(self.fname, "wb") as f:
                    f.write(self.mm)

    # ---------------------------------------------------------------------
    # Parse OLE
    # ---------------------------------------------------------------------
    def parse(self):
        if self.mm[:8] != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
            raise Error("Not Ole signature")

        # Get big block, small block size
        self.bsize = 1 << kavutil.get_uint16(self.mm, 0x1E)
        self.ssize = 1 << kavutil.get_uint16(self.mm, 0x20)

        if self.verbose:
            kavutil.vprint("Header")
            kavutil.vprint(None, "Big Block Size", "%d" % self.bsize)
            kavutil.vprint(None, "Small Block Size", "%d" % self.ssize)
            print()
            kavutil.HexDump().Buffer(self.mm, 0, 0x60)
            print()

        if self.bsize % 0x200 != 0 or self.ssize != 0x40:  # Invalid file information
            return False

        # Read bbd
        self.bbd_list_array, num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block = get_bbd_list_array(
            self.mm, self.verbose
        )

        """
        # A lot of data is output, so it is commented out
        if self.verbose:
            print ()
            if num_of_bbd_blocks < 109:
                kavutil.HexDump().Buffer(self.mm, 0x4c, num_of_bbd_blocks * 4)
            else:
                kavutil.HexDump().Buffer(self.mm, 0x4c, num_of_bbd_blocks * 109)

                next_b = xbbd_start_block
                for i in range(num_of_xbbd_blocks):
                    t_data = get_bblock(self.mm, next_b, self.bsize)
                    print ()
                    kavutil.HexDump().Buffer(self.mm, (next_b+1) * self.bsize)
                    next_b = kavutil.get_uint32(t_data, self.bsize-4)
        """

        if len(self.bbd_list_array) // 4 < num_of_bbd_blocks:
            return False

        self.bbd = b""
        for i in range(num_of_bbd_blocks):
            no = kavutil.get_uint32(self.bbd_list_array, i * 4)
            self.bbd += get_bblock(self.mm, no, self.bsize)

        self.bbd_fat = {}
        for i in range(len(self.bbd) // 4):
            n = kavutil.get_uint32(self.bbd, i * 4)
            self.bbd_fat[i] = n

        if self.verbose:
            with open("bbd.dmp", "wb") as f:
                f.write(self.bbd)
            print()
            kavutil.vprint("BBD")
            print()
            kavutil.HexDump().Buffer(self.bbd, 0, 0x80)

        # Read root
        root_startblock = kavutil.get_uint32(self.mm, 0x30)
        root_list_array = get_block_link(root_startblock, self.bbd_fat)
        self.root_list_array = root_list_array

        self.root = b""
        for no in root_list_array:
            self.root += get_bblock(self.mm, no, self.bsize)

        if self.verbose:
            with open("root.dmp", "wb") as f:
                f.write(self.root)
            print()
            kavutil.vprint("ROOT")
            kavutil.vprint(None, "Start Blocks", "%d" % root_startblock)
            print()
            kavutil.HexDump().Buffer(self.root, 0, 0x80)

        # Read sbd
        sbd_startblock = kavutil.get_uint32(self.mm, 0x3C)
        num_of_sbd_blocks = kavutil.get_uint32(self.mm, 0x40)
        sbd_list_array = get_block_link(sbd_startblock, self.bbd_fat)

        self.sbd = b""
        for no in sbd_list_array:
            self.sbd += get_bblock(self.mm, no, self.bsize)

        self.sbd_fat = {}
        for i in range(len(self.sbd) // 4):
            n = kavutil.get_uint32(self.sbd, i * 4)
            self.sbd_fat[i] = n

        if self.verbose:
            with open("sbd.dmp", "wb") as f:
                f.write(self.sbd)
            print()
            kavutil.vprint("SBD")
            kavutil.vprint(None, "Start Blocks", "%d" % sbd_startblock)
            kavutil.vprint(None, "Num of SBD Blocks", "%d" % num_of_sbd_blocks)
            print()
            kavutil.HexDump().Buffer(self.sbd, 0, 0x80)

        # Read pps
        self.pps = []
        for i in range(len(self.root) // 0x80):
            p = {}
            pps = self.root[i * 0x80 : (i + 1) * 0x80]

            t_size = int(min(kavutil.get_uint16(pps, 0x40), 0x40))

            if t_size:
                # Possible name corruption when output
                if int(pps[0]) & 0xF0 == 0x00 and int(pps[1]) == 0x00:
                    name = b"_\x00" + pps[2 : t_size - 2]
                else:
                    name = pps[: t_size - 2]

                p["Name"] = DecodeStreamName(name)
            else:
                p["Name"] = ""

            p["Type"] = int(pps[0x42])
            p["Prev"] = kavutil.get_uint32(pps, 0x44)
            p["Next"] = kavutil.get_uint32(pps, 0x48)
            p["Dir"] = kavutil.get_uint32(pps, 0x4C)
            p["Start"] = kavutil.get_uint32(pps, 0x74)
            p["Size"] = kavutil.get_uint32(pps, 0x78)
            p["Valid"] = False

            # Check CVE-2012-0158
            # pps contains ListView.2's CLSID
            # Reference: https://securelist.com/the-curious-case-of-a-cve-2012-0158-exploit/37158/
            # Reference: https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=25657
            cve_clsids = [
                b"\x4B\xF0\xD1\xBD\x8B\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28",
                b"\xE0\xF5\x6B\x99\x44\x80\x50\x46\xAD\xEB\x0B\x01\x39\x14\xE9\x9C",
                b"\xE6\x3F\x83\x66\x83\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28",
                b"\x5F\xDC\x81\x91\x7D\xE0\x8A\x41\xAC\xA6\x8E\xEA\x1E\xCB\x8E\x9E",
                b"\xB6\x90\x41\xC7\x89\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28",
            ]
            if pps[0x50:0x60] in cve_clsids:
                self.exploit.append("Exploit.OLE.CVE-2012-0158")
                return False

            self.pps.append(p)

        # Check PPS tree
        if self.__valid_pps_tree() is False:
            return False

        if self.verbose:
            print()
            kavutil.vprint("Property Storage")
            """
            print '    %-2s %-20s %4s %-8s %-8s %-8s %-8s %-8s' % ('No', 'Name', 'Type', 'Prev', 'Next', 'Dir', 'SB',
                                                                   'Size')
            print '    ' + ('-' * 74)

            for p in self.pps:
                print '    ' + '%2d %-23s %d %8X %8X %8X %8X %8d' % (self.pps.index(p), p['Name'], p['Type'], p['Prev'],
                                                                     p['Next'], p['Dir'], p['Start'], p['Size'])
            """

            print(
                "    %-2s %-32s %4s %-4s %-4s %-4s %8s %8s"
                % ("No", "Name", "Type", "Prev", "Next", " Dir", "SB", "Size")
            )
            print("    " + ("-" * 74))

            for p in self.pps:
                if p["Valid"] is False:  # If not valid tree, next
                    continue

                t = ""
                t += "   - " if p["Prev"] == 0xFFFFFFFF else "%4d " % p["Prev"]
                t += "   - " if p["Next"] == 0xFFFFFFFF else "%4d " % p["Next"]
                t += "   - " if p["Dir"] == 0xFFFFFFFF else "%4d " % p["Dir"]
                t += "       - " if p["Start"] == 0xFFFFFFFF else "%8X " % p["Start"]

                # tname = p["Name"].encode(sys.stdout.encoding, "replace")
                print("    " + "%2d %-35s %d %22s %8d" % (self.pps.index(p), p["Name"], p["Type"], t, p["Size"]))

        # Get PPS full path
        self.__deep = 0
        self.__full_list = []

        with contextlib.suppress(IndexError):
            self.__get_pps_path()

        # Get small block link
        self.small_block = get_block_link(self.pps[0]["Start"], self.bbd_fat)
        if self.verbose:
            print()
            kavutil.vprint("Small Blocks")
            print(self.small_block)

        return True

    # ---------------------------------------------------------------------
    # Check PPS tree validity (internal)
    # ---------------------------------------------------------------------
    def __valid_pps_tree(self):
        scaned_pps_node = [0]  # To avoid analyzing already analyzed nodes
        f = []

        if len(self.pps) == 0:  # If no analyzed PPS, exit
            return False

        if self.pps[0]["Dir"] != 0xFFFFFFFF and self.pps[0]["Type"] == 5:
            f.append(self.pps[0]["Dir"])
            scaned_pps_node.append(self.pps[0]["Dir"])
            self.pps[0]["Valid"] = True

        if not f:  # If no valid PPS, exit
            return False

        while len(f):
            x = f.pop(0)

            try:
                if self.pps[x]["Type"] != 1 and self.pps[x]["Type"] != 2 and len(self.pps[x]["Name"]) == 0:
                    continue
            except IndexError:
                if (x & 0x90900000) == 0x90900000:  # CVE-2003-0820 vulnerability
                    self.exploit.append("Exploit.OLE.CVE-2003-0820")
                else:  # CVE-2003-0347 vulnerability
                    self.exploit.append("Exploit.OLE.CVE-2003-0347")
                return False

            self.pps[x]["Valid"] = True

            if self.pps[x]["Prev"] != 0xFFFFFFFF:
                if self.pps[x]["Prev"] in scaned_pps_node:
                    self.pps[x]["Prev"] = 0xFFFFFFFF
                else:
                    f.append(self.pps[x]["Prev"])
                    scaned_pps_node.append(self.pps[x]["Prev"])

            if self.pps[x]["Next"] != 0xFFFFFFFF:
                if self.pps[x]["Next"] in scaned_pps_node:
                    self.pps[x]["Next"] = 0xFFFFFFFF
                else:
                    f.append(self.pps[x]["Next"])
                    scaned_pps_node.append(self.pps[x]["Next"])

            if self.pps[x]["Dir"] != 0xFFFFFFFF:
                if self.pps[x]["Dir"] in scaned_pps_node:
                    self.pps[x]["Dir"] = 0xFFFFFFFF
                else:
                    f.append(self.pps[x]["Dir"])
                    scaned_pps_node.append(self.pps[x]["Dir"])

        return True

    # ---------------------------------------------------------------------
    # Get PPS full path (internal)
    # ---------------------------------------------------------------------
    def __get_pps_path(self, node=0, prefix=""):
        if node == 0:
            pps_name = ""
            name = prefix + pps_name
        else:
            if self.pps[node]["Valid"] is False:  # Process only valid PPS
                return 0

            pps_name = self.pps[node]["Name"]
            name = f"{prefix}/{pps_name}"
            p = {"Node": node, "Name": name[1:], "Type": self.pps[node]["Type"]}
            self.__full_list.append(p)

        if self.pps[node]["Dir"] != 0xFFFFFFFF:
            self.__deep += 1
            self.__get_pps_path(self.pps[node]["Dir"], name)
            self.__deep -= 1

        #        if self.pps[node]['Prev'] != 0xFFFFFFFFL:
        if self.pps[node]["Prev"] != 0xFFFFFFFF:
            self.__get_pps_path(self.pps[node]["Prev"], prefix)

        #        if self.pps[node]['Next'] != 0xFFFFFFFFL:
        if self.pps[node]["Next"] != 0xFFFFFFFF:
            self.__get_pps_path(self.pps[node]["Next"], prefix)

        return 0

    # ---------------------------------------------------------------------
    # Get PPS full path (only streams)
    # ---------------------------------------------------------------------
    def listdir(self, streams=True, storages=False):
        return [p["Name"] for p in self.__full_list if p["Type"] == 2 and streams or p["Type"] == 1 and storages]

    # ---------------------------------------------------------------------
    # Check if stream exists
    # ---------------------------------------------------------------------
    def exists(self, name):
        return any(p["Name"] == name for p in self.__full_list)

    # ---------------------------------------------------------------------
    # Open stream
    # ---------------------------------------------------------------------
    def openstream(self, name):
        # -----------------------------------------------------------------
        # Stream class
        # -----------------------------------------------------------------

        class Stream:
            def __init__(self, parent, node):
                self.parent = parent
                self.node = node
                self.read_size = 0
                self.fat = None

                # print self.parent.verbose

            # Return consecutive numbers
            # TODO : Optimize it
            def get_liner_value(self, num_list):
                start = None
                end = None

                if not start:
                    start = num_list.pop(0)

                e = start
                loop = False

                for x in num_list:
                    if e + 1 == x:
                        e = x
                        loop = True
                        continue
                    else:
                        while loop and e != num_list.pop(0):
                            pass
                        end = e
                        break
                else:
                    for _ in range(len(num_list)):
                        num_list.pop(0)
                    end = e

                return start, end

            def read(self):
                pps = self.parent.pps[self.node]
                sb = pps["Start"]
                size = pps["Size"]

                if size >= 0x1000:
                    self.read_size = self.parent.bsize
                    self.fat = self.parent.bbd_fat
                else:
                    self.read_size = self.parent.ssize
                    self.fat = self.parent.sbd_fat

                list_array = get_block_link(sb, self.fat)

                if size >= 0x1000:
                    t_list = list(list_array)
                    chunks = []
                    while len(t_list):
                        s, e = self.get_liner_value(t_list)
                        off = (s + 1) * self.read_size
                        chunks.append(self.parent.mm[off : off + self.read_size * (e - s + 1)])
                    data = b"".join(chunks)
                else:
                    chunks = []
                    for n in list_array:
                        div_n = self.parent.bsize // self.parent.ssize
                        off = (self.parent.small_block[n // div_n] + 1) * self.parent.bsize
                        off += (n % div_n) * self.parent.ssize
                        chunks.append(self.parent.mm[off : off + self.read_size])
                    data = b"".join(chunks)

                if self.parent.verbose:
                    print()
                    kavutil.vprint(pps["Name"])
                    kavutil.HexDump().Buffer(data, 0, 80)

                return data[:size]

            def close(self):
                pass

        # -----------------------------------------------------------------
        no = next((p["Node"] for p in self.__full_list if p["Name"] == name), -1)
        if no == -1:
            raise Error("PPS name is invalid.")

        return Stream(self, no)

    # ---------------------------------------------------------------------
    # Overwrite stream data
    # ---------------------------------------------------------------------
    def write_stream(self, name, data):
        no = next((p["Node"] for p in self.__full_list if p["Name"] == name), -1)
        if no == -1:
            raise Error(f"PPS name({name}) is invalid.")

        # self.init(self.mm)
        # return

        ow = OleWriteStream(
            self.mm,
            self.pps,
            self.bsize,
            self.ssize,
            self.bbd,
            self.bbd_fat,
            self.sbd,
            self.sbd_fat,
            self.root_list_array,
            self.small_block,
            self.verbose,
        )

        if t := ow.write(no, data):
            self.init(t)  # Reload OLE

    # ---------------------------------------------------------------------
    # Delete stream or storage
    # ---------------------------------------------------------------------
    def delete(self, name, delete_storage=False, reset_stream=False):
        no = next((p["Node"] for p in self.__full_list if p["Name"] == name), -1)
        if no == -1:
            raise Error("PPS name is invalid.")

        # print no

        ow = OleWriteStream(
            self.mm,
            self.pps,
            self.bsize,
            self.ssize,
            self.bbd,
            self.bbd_fat,
            self.sbd,
            self.sbd_fat,
            self.root_list_array,
            self.small_block,
            self.verbose,
        )

        target_pps = self.pps[no]
        if target_pps["Valid"]:
            if target_pps["Type"] == 2:  # Check if it is a valid PPS
                if reset_stream:
                    size = target_pps["Size"]
                    t = ow.write(no, b"\x00" * size)  # Wipe all data

                if t := ow.delete(no):
                    self.init(t)  # Reload OLE

            elif target_pps["Type"] == 1 and delete_storage:  # Check if it is a valid storage
                if t := ow.delete(no):
                    self.init(t)  # Reload OLE


# ---------------------------------------------------------------------
# OleWriteStream class
# ---------------------------------------------------------------------
class OleWriteStream:
    def __init__(
        self,
        mm,
        pps,
        bsize,
        ssize,
        bbd,
        bbd_fat,
        sbd,
        sbd_fat,
        root_list_array,
        small_block,
        verbose,
    ):
        self.verbose = verbose

        self.mm = mm
        self.pps = pps
        self.bsize = bsize
        self.ssize = ssize
        self.bbd = bbd
        self.bbd_fat = bbd_fat
        self.sbd = sbd
        self.sbd_fat = sbd_fat
        self.root_list_array = root_list_array
        self.small_block = small_block

    def __get_root_node(self, node):  # Find root node with the given information
        for i, pps in enumerate(self.pps):
            if pps["Prev"] == node or pps["Next"] == node or pps["Dir"] == node:
                return i

    def __get_max_node(self, node):  # Find node with the maximum value
        no = node

        while True:
            pps = self.pps[no]
            if pps["Next"] == 0xFFFFFFFF:  # If there is no right node, search ends
                break
            else:  # Always the right node is the larger value
                no = pps["Next"]

        return no

    def delete(self, del_no):
        del_pps = self.pps[del_no]
        prev_no = del_pps["Prev"]
        next_no = del_pps["Next"]
        dir_no = del_pps["Dir"]

        # Find root node
        root_no = self.__get_root_node(del_no)

        # Do both nodes exist?
        if prev_no != 0xFFFFFFFF and next_no != 0xFFFFFFFF:  # Both nodes exist
            # 1. prev node value is sent to root
            t_no = prev_no

            # 2. Find a node with no next node under prev node and register del_pps's next_no
            blank_next_no = self.__get_max_node(prev_no)
            self.__set_pps_header(blank_next_no, pps_next=next_no)

        elif prev_no != 0xFFFFFFFF:  # Prev only exists
            # 1. prev node value is sent to root
            t_no = prev_no

        elif next_no != 0xFFFFFFFF:  # Next only exists
            # 1. next node value is sent to root
            t_no = next_no

        else:  # prev_no == 0xffffffff and next_no == 0xffffffff:  # Single node
            # 1. 0xffffffff node value is sent to root
            t_no = 0xFFFFFFFF

        # Modify root node
        pps = self.pps[root_no]
        if pps["Prev"] == del_no:
            self.__set_pps_header(root_no, pps_prev=t_no)
        elif pps["Next"] == del_no:
            self.__set_pps_header(root_no, pps_next=t_no)
        else:  # Dir
            self.__set_pps_header(root_no, pps_dir=t_no)

        # Delete node value is all zero
        self.__set_pps_header(
            del_no,
            size=0,
            start=0xFFFFFFFF,
            pps_prev=0xFFFFFFFF,
            pps_next=0xFFFFFFFF,
            pps_dir=0xFFFFFFFF,
            del_info=True,
        )

        return self.mm

    def write(self, no, data):
        # Get original PPS information
        org_sb = self.pps[no]["Start"]
        org_size = self.pps[no]["Size"]

        # Prepare to write modified data
        if len(data) >= 0x1000:  # Use BBD
            # Support : BBD -> BBD (Dec)

            n = (len(data) // self.bsize) + (1 if (len(data) % self.bsize) else 0)
            t_data = data + (b"\x00" * ((n * self.bsize) - len(data)))  # Add extra size to data

            if org_size >= 0x1000:  # Original BBD
                if org_size >= len(data):
                    t_link = get_block_link(org_sb, self.bbd_fat)  # Collect previous links
                    t_link = self.__decrease_bbd_link(t_link, n)  # Decrease link to the required number

                else:
                    t_link = get_block_link(org_sb, self.bbd_fat)  # Collect previous links

                    t_num = 0
                    if (len(t_link) * self.bsize) < len(t_data):  # Need to add block?
                        t_size = len(t_data) - (len(t_link) * self.bsize)
                        t_num = (t_size // self.bsize) + (1 if (t_size % self.bsize) else 0)

                        self.__add_big_block_num(t_num)  # Add required block number

                    # Collect unused blocks after the last collected link
                    t_link = self.__modify_big_block_link(t_link, t_num)

                # Overwrite bsize in big block area
                self.__write_data_to_big_block(t_data, t_link)

                # Modify PPS size
                self.__set_pps_header(no, size=len(data))
            else:  # Original SBD
                # Support : SBD -> BBD, Sector change is meaningless for Dec, Inc

                t_num = len(t_data) // self.ssize  # How many blocks are needed?

                self.__add_big_block_num(t_num)  # Add required block number

                # BBD link is created for the first time, so there is no previous link.
                t_link = self.__modify_big_block_link(None, t_num)

                # Overwrite bsize in big block area
                self.__write_data_to_big_block(t_data, t_link)

                # Modify PPS size, start block
                self.__set_pps_header(no, size=len(data), start=t_link[0])

                # Delete previous SBD link
                # t_link = get_block_link(org_sb, self.sbd)  # Collect previous links
                t_link = get_block_link(org_sb, self.sbd_fat)  # Collect previous links

                sbd = self.sbd
                for no in t_link:
                    sbd = sbd[: no * 4] + b"\xff\xff\xff\xff" + sbd[(no + 1) * 4 :]

                self.__modify_sbd(sbd)

        elif org_size >= 0x1000:  # Original BBD
            # Support : BBD -> SBD, Sector change is meaningless for Dec, Inc

            n = (len(data) // self.ssize) + (1 if (len(data) % self.ssize) else 0)
            t_data = data + (b"\x00" * ((n * self.ssize) - len(data)))  # Add extra size to data

            t_num = len(t_data) // self.ssize  # How many blocks are needed?

            self.__add_small_block_num(t_num)  # Add required block number

            # SBD link is created for the first time, so there is no previous link.
            t_link = self.__modify_small_block_link(None, t_num)

            self.reload_info(self.mm)

            # Overwrite ssize in small block area
            self.__write_data_to_small_bolck(t_data, t_link)

            # Modify PPS size, start block
            self.__set_pps_header(no, size=len(data), start=t_link[0])

            # Delete previous BBD link
            # t_link = get_block_link(org_sb, self.bbd)  # Collect previous links
            t_link = get_block_link(org_sb, self.bbd_fat)  # Collect previous links

            bbd = self.bbd
            for no in t_link:
                bbd = bbd[: no * 4] + b"\xff\xff\xff\xff" + bbd[(no + 1) * 4 :]

            self.__modify_bbd(bbd)

        elif org_size >= len(data):
            # Support : SBD -> SBD (Dec)

            n = (len(data) // self.ssize) + (1 if (len(data) % self.ssize) else 0)
            t_data = data + (b"\x00" * ((n * self.ssize) - len(data)))  # Add extra size to data

            t_link = get_block_link(org_sb, self.sbd_fat)  # Collect previous links
            t_link = self.__decrease_sbd_link(t_link, n)  # Decrease link to the required number

            # Overwrite ssize in small block area
            self.__write_data_to_small_bolck(t_data, t_link)

            # Modify PPS size
            self.__set_pps_header(no, size=len(data))
        else:
            # Support : SBD -> SBD (Inc)

            n = (len(data) // self.ssize) + (1 if (len(data) % self.ssize) else 0)
            t_data = data + (b"\x00" * ((n * self.ssize) - len(data)))  # Add extra size to data

            # t_link = get_block_link(org_sb, self.sbd)  # Collect previous links
            t_link = get_block_link(org_sb, self.sbd_fat)  # Collect previous links

            t_num = 0
            if (len(t_link) * self.ssize) < len(t_data):  # Need to add block?
                t_size = len(t_data) - (len(t_link) * self.ssize)
                t_num = (t_size // self.ssize) + (1 if (t_size % self.ssize) else 0)

                self.__add_small_block_num(t_num)  # Add required block number

            # Collect unused blocks after the last collected link
            t_link = self.__modify_small_block_link(t_link, t_num)

            self.reload_info(self.mm)

            # Overwrite ssize in small block area
            self.__write_data_to_small_bolck(t_data, t_link)

            # Modify PPS size
            self.__set_pps_header(no, size=len(data))

        return self.mm

    def reload_info(self, mm):
        bbd_list_array, _, _, _ = get_bbd_list_array(mm)

        self.bbd = b""
        for i in range(len(bbd_list_array) // 4):
            n = kavutil.get_uint32(bbd_list_array, i * 4)
            self.bbd += get_bblock(self.mm, n, self.bsize)

        # Update small block
        self.bbd_fat = {}
        for i in range(len(self.bbd) // 4):
            n = kavutil.get_uint32(self.bbd, i * 4)
            self.bbd_fat[i] = n

        # New Small Block link is needed
        self.small_block = get_block_link(self.pps[0]["Start"], self.bbd_fat)

    # ---------------------------------------------------------------------
    # Write data to big block following big block link (internal)
    # ---------------------------------------------------------------------
    # def __write_data_to_big_block(self, t_data, t_link):
    #     for i, n in enumerate(t_link):
    #         off = (n + 1) * self.bsize
    #         self.mm = self.mm[:off] + t_data[i * self.bsize : (i + 1) * self.bsize] + self.mm[off + self.bsize :]
    def __write_data_to_big_block(self, t_data, t_link):
        """
        Write blocks into big-block area efficiently.
        Avoid repeated full-copy by doing in-place slice assignment when possible.
        """
        bsz = self.bsize
        mv_src = memoryview(t_data)

        # Fast path: try in-place write (bytearray or mmap supports slice assignment)
        try:
            for i, n in enumerate(t_link):
                off = (n + 1) * bsz
                self.mm[off : off + bsz] = mv_src[i * bsz : (i + 1) * bsz]
            return
        except TypeError:
            # self.mm is immutable (e.g., bytes); fall back to single-copy strategy
            pass

        # Fallback: make one mutable copy, write all blocks once, then finalize
        buf = bytearray(self.mm)
        for i, n in enumerate(t_link):
            off = (n + 1) * bsz
            buf[off : off + bsz] = mv_src[i * bsz : (i + 1) * bsz]

        # If the rest of the code expects bytes, convert back once.
        # Otherwise, you can keep it as bytearray for future in-place updates.
        self.mm = bytes(buf)

    # ---------------------------------------------------------------------
    # Write data to small block following small block link (internal)
    # ---------------------------------------------------------------------
    def __write_data_to_small_bolck(self, t_data, t_link):
        for i, n in enumerate(t_link):
            off = (self.small_block[n // 8] + 1) * self.bsize
            off += (n % 8) * self.ssize
            self.mm = self.mm[:off] + t_data[i * self.ssize : (i + 1) * self.ssize] + self.mm[off + self.ssize :]

    # ---------------------------------------------------------------------
    # Overwrite 1 Big Block at a specific position in OLE area (internal)
    # ---------------------------------------------------------------------
    def __set_bblock(self, no, data):
        off = (no + 1) * self.bsize
        if len(data) == self.bsize:
            self.mm = self.mm[:off] + data + self.mm[off + self.bsize :]
            return True

        return False

    # ---------------------------------------------------------------------
    # Adjust the size of a specific stream in PPS header (internal)
    # node : PPS index
    # size : Set size
    # start : Start link
    # ---------------------------------------------------------------------
    def __set_pps_header(
        self,
        node,
        size=None,
        start=None,
        pps_prev=None,
        pps_next=None,
        pps_dir=None,
        del_info=False,
    ):
        n = self.root_list_array[node // 4]

        buf = get_bblock(self.mm, n, self.bsize)

        off = (node % 4) * 0x80

        if del_info and off == 0x180:
            buf = buf[:off] + b"\x00" * 0x80
        elif del_info:
            buf = buf[:off] + b"\x00" * 0x80 + buf[off + 0x80 :]

        if size is not None:
            t_off = off + 0x78
            buf = buf[:t_off] + struct.pack("<L", size) + buf[t_off + 4 :]

        if start is not None:
            t_off = off + 0x74
            buf = buf[:t_off] + struct.pack("<L", start) + buf[t_off + 4 :]

        if pps_prev is not None:
            t_off = off + 0x44
            buf = buf[:t_off] + struct.pack("<L", pps_prev) + buf[t_off + 4 :]

        if pps_next is not None:
            t_off = off + 0x48
            buf = buf[:t_off] + struct.pack("<L", pps_next) + buf[t_off + 4 :]

        if pps_dir is not None:
            t_off = off + 0x4C
            buf = buf[:t_off] + struct.pack("<L", pps_dir) + buf[t_off + 4 :]

        self.__set_bblock(n, buf)

        if self.verbose:
            print()
            buf = get_bblock(self.mm, n, self.bsize)
            kavutil.HexDump().Buffer(buf, 0, 0x200)

    # ---------------------------------------------------------------------
    # Decrease SBD link
    # org_link_list : Original Small block link
    # num_link : Required total link number
    # ---------------------------------------------------------------------
    def __decrease_sbd_link(self, org_link_list, num_link):
        if len(org_link_list) > num_link:
            # Convert SBD to array
            t_link = []

            t_link.extend(kavutil.get_uint32(self.sbd, i * 4) for i in range(len(self.sbd) // 4))
            t = org_link_list[num_link:]
            org_link_list = org_link_list[:num_link]

            t_link[t[0]] = 0xFFFFFFFE  # Set link end

            # Remaining links are all set to 0xffffffff
            for i in t[1:]:
                t_link[i] = 0xFFFFFFFF

            # Convert SBD array to SBD buffer
            self.sbd = ""
            for i in t_link:
                self.sbd += struct.pack("<L", i)

            # Apply SBD to self.mm
            sbd_startblock = kavutil.get_uint32(self.mm, 0x3C)
            sbd_list_array = get_block_link(sbd_startblock, self.bbd_fat)

            for i, n in enumerate(sbd_list_array):
                self.__set_bblock(n, self.sbd[i * self.bsize : (i + 1) * self.bsize])

            return org_link_list
        elif len(org_link_list) == num_link:
            return org_link_list
        else:
            raise Error("Invalid call")

    # ---------------------------------------------------------------------
    # Decrease BBD link
    # org_link_list : Original Small block link
    # num_link : Required total link number
    # ---------------------------------------------------------------------
    def __decrease_bbd_link(self, org_link_list, num_link):
        if len(org_link_list) > num_link:
            # Convert BBD to array
            t_link = []

            t_link.extend(kavutil.get_uint32(self.bbd, i * 4) for i in range(len(self.bbd) // 4))
            t = org_link_list[num_link:]
            org_link_list = org_link_list[:num_link]

            t_link[t[0]] = 0xFFFFFFFE  # Set link end

            # Remaining links are all set to 0xffffffff
            for i in t[1:]:
                t_link[i] = 0xFFFFFFFF

            # Convert BBD array to BBD buffer
            self.bbd = b""
            for i in t_link:
                self.bbd += struct.pack("<L", i)

            # Apply BBD to self.mm
            t, num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block = get_bbd_list_array(self.mm, self.verbose)

            bbd_list_array = []
            bbd_list_array.extend(kavutil.get_uint32(t, i * 4) for i in range(len(t) // 4))
            for i, n in enumerate(bbd_list_array):
                self.__set_bblock(n, self.bbd[i * self.bsize : (i + 1) * self.bsize])
            return org_link_list
        elif len(org_link_list) == num_link:
            return org_link_list
        else:
            raise Error("Invalid call")

    # ---------------------------------------------------------------------
    # Add Big Block
    # num : Number of Big Block to add
    # ---------------------------------------------------------------------
    def __add_big_block_num(self, num):
        size = (len(self.mm) // self.bsize) * self.bsize  # File size
        self.mm = self.mm[:size]  # Remove unused data at the end
        attach_data = self.mm[size:]  # Remaining data at the end of the file

        # Get BBD link
        bbd_list_array, num_of_bbd_blocks, _, _ = get_bbd_list_array(self.mm)

        # Collect BBD
        bbd = b""
        for i in range(num_of_bbd_blocks):
            no = kavutil.get_uint32(bbd_list_array, i * 4)
            bbd += get_bblock(self.mm, no, self.bsize)

        bbd_link = []
        bbd_link.extend(kavutil.get_uint32(bbd, i * 4) for i in range(len(bbd) // 4))
        # Find unused BBD link
        free_link = [i for i, no in enumerate(bbd_link) if (no == 0xFFFFFFFF and i < size // self.bsize)]

        if len(free_link) >= num:  # Enough free space
            return  # No need to add

        # Check remaining number
        last_no = (size // self.bsize) - 2  # Actual last Big Block number
        n = (len(self.bbd) // 4 - 1) - last_no

        if n >= num:
            # If remaining number is greater than or equal to the number to add, add the number of blocks to the file
            self.mm += b"\x00" * self.bsize * num  # Actual required data block
            self.mm += attach_data
        else:
            add_num = num - n  # Required block number
            b_num = (add_num // (self.bsize // 4)) + (1 if (add_num % (self.bsize // 4)) else 0)
            old_num_bbd = kavutil.get_uint32(self.mm, 0x2C)

            if old_num_bbd + b_num <= 109:
                self.extend_big_block_allocation_case1(num, n, last_no, attach_data)
            else:
                self.extend_big_block_allocation_case2(num, n, last_no, attach_data)

    def clac_special_block_num(self, add_blocks_num):
        add_bbd_num = (add_blocks_num // (self.bsize // 4)) + (1 if (add_blocks_num % (self.bsize // 4)) else 0)
        nedd_xbbd_num = (add_bbd_num // ((self.bsize - 4) // 4)) + (1 if (add_bbd_num % ((self.bsize - 4) // 4)) else 0)

        return nedd_xbbd_num + add_bbd_num

    def extend_big_block_allocation_case1(self, add_blocks_num, free_blocks_num, last_no, attach_data):
        """
        Extends the big block allocation when additional space is needed

        Args:
            add_blocks_num: Number of blocks needed
            free_blocks_num: Number of remaining blocks
            last_no: Last block number
            attach_data: Data to be attached at the end

        Handles:
            - XBBD block allocation
            - BBD list extension
            - Special block processing
        """
        special_no = []  # Special Big Block number. The block must be processed as 0xfffffffd

        x_data = b""
        num = add_blocks_num
        n = free_blocks_num

        add_num = num - n  # Required block number
        add_data = b"\x00" * self.bsize * add_num

        # The number of BBD list to add is the number of Big Blocks that can be accommodated in one BBD
        b_num = (add_num // (self.bsize // 4)) + (1 if (add_num % (self.bsize // 4)) else 0)
        old_num_bbd = kavutil.get_uint32(self.mm, 0x2C)

        total_bbd_num = old_num_bbd + b_num  # Total BBD list number
        self.mm = self.mm[:0x2C] + struct.pack("<L", total_bbd_num) + self.mm[0x30:]

        last_no += 1

        # Add BBD
        bbd_no = []
        b_data = b"\xff" * self.bsize * b_num
        for _ in range(b_num):
            bbd_no.append(last_no)
            last_no += 1

        # Final combination
        self.mm += x_data + b_data + add_data + attach_data

        # Add BBD list to special block
        special_no += bbd_no

        # Process special block (bbd_list_array, num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block)
        bbd_list_array, num_of_bbd_blocks, _, _ = get_bbd_list_array(self.mm)

        bb_num = self.bsize // 4  # Number of Big Blocks that can be accommodated in one BBD list block
        for no in special_no:
            seg = no // bb_num
            off = no % bb_num
            # print hex(no), hex(seg), hex(off), hex(kavutil.get_uint32(bbd_list_array, seg*4))

            t_no = kavutil.get_uint32(bbd_list_array, seg * 4)
            t_off = ((t_no + 1) * self.bsize) + (off * 4)

            self.mm = self.mm[:t_off] + b"\xfd\xff\xff\xff" + self.mm[t_off + 4 :]

            # print repr(self.mm[t_off:t_off+4])

            # t = get_bblock(self.mm, t_no, self.bsize)
            # print repr(t)
            # t = kavutil.get_uint32(t, off*4)
            # print hex(t)

        # Register BBD to BBD List
        for i, no in enumerate(bbd_no):
            off = get_bbd_list_index_to_offset(self.mm, old_num_bbd + i)
            # print hex(off)
            self.mm = self.mm[:off] + struct.pack("<L", no) + self.mm[off + 4 :]

    def extend_big_block_allocation_case2(self, add_blocks_num, free_blocks_num, last_no, attach_data):
        """
        Extends the big block allocation when additional space is needed

        Args:
            add_blocks_num: Number of blocks needed
            free_blocks_num: Number of remaining blocks
            last_no: Last block number
            attach_data: Data to be attached at the end

        Handles:
            - XBBD block allocation
            - BBD list extension
            - Special block processing
        """
        special_no = []  # Special Big Block number. The block must be processed as 0xfffffffd
        need_special_num = self.clac_special_block_num(add_blocks_num)  # Calculate the number of special blocks needed

        add_blocks_num += need_special_num  # Number of blocks to add
        add_blocks_num -= free_blocks_num
        add_data = b"\x00" * self.bsize * add_blocks_num

        # Calculate BBD list additions
        add_bbd_num = (add_blocks_num // (self.bsize // 4)) + (1 if (add_blocks_num % (self.bsize // 4)) else 0)
        old_bbd_num = kavutil.get_uint32(self.mm, 0x2C)

        xbbd_start_block = kavutil.get_uint32(self.mm, 0x44)
        num_of_xbbd_blocks = kavutil.get_uint32(self.mm, 0x48)

        # Calculate the number of XBBD blocks needed
        nedd_xbbd_num = (add_bbd_num // ((self.bsize - 4) // 4)) + (1 if (add_bbd_num % ((self.bsize - 4) // 4)) else 0)
        if nedd_xbbd_num == 0:
            return

        last_no_for_xbbd = last_no

        special_no.extend(last_no + 1 + i for i in range(nedd_xbbd_num))

        # Create XBBD
        x_data = b""
        for i in range(nedd_xbbd_num):
            x_data += b"\xff\xff\xff\xff" * ((self.bsize // 4) - 1)
            if i != (nedd_xbbd_num - 1):
                x_data += struct.pack("<L", last_no + 1)
            else:
                x_data += b"\xfe\xff\xff\xff"
            last_no += 1

        # Create BBD
        b_data = b"\xff" * self.bsize * add_bbd_num

        for i in range(add_bbd_num):
            off = i * 4
            x_data = x_data[:off] + struct.pack("<L", last_no + nedd_xbbd_num) + x_data[off + 4 :]
            special_no.append(last_no + nedd_xbbd_num)
            last_no += 1

        self.mm = self.mm[:0x2C] + struct.pack("<L", old_bbd_num + add_bbd_num) + self.mm[0x30:]

        # Final combination
        self.mm += x_data + b_data + add_data + attach_data

        # Update XBBD link
        if xbbd_start_block == 0xFFFFFFFE:
            data = struct.pack("<LL", last_no_for_xbbd + 1, nedd_xbbd_num + num_of_xbbd_blocks)
            self.mm = self.mm[:0x44] + data + self.mm[0x4C:]
        else:
            self.__update_xbbd_link(
                nedd_xbbd_num,
                num_of_xbbd_blocks,
                xbbd_start_block,
                last_no_for_xbbd,
            )

        # Special block processing (bbd_list_array, num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block)
        bbd_list_array, num_of_bbd_blocks, _, _ = get_bbd_list_array(self.mm)

        bb_num = self.bsize // 4  # Number of Big Blocks that can fit in one BBD list block
        for no in special_no:
            seg = no // bb_num
            off = no % bb_num

            t_no = kavutil.get_uint32(bbd_list_array, seg * 4)
            t_off = ((t_no + 1) * self.bsize) + (off * 4)

            self.mm = self.mm[:t_off] + b"\xfd\xff\xff\xff" + self.mm[t_off + 4 :]

    def __update_xbbd_link(self, nedd_xbbd_num, num_of_xbbd_blocks, xbbd_start_block, last_no_for_xbbd):
        data = struct.pack("<L", nedd_xbbd_num + num_of_xbbd_blocks)
        self.mm = self.mm[:0x48] + data + self.mm[0x4C:]

        old_n = n = xbbd_start_block
        while n != 0xFFFFFFFE:
            old_n = n
            t = get_bblock(self.mm, n, self.bsize)
            n = kavutil.get_uint32(t, self.bsize - 4)

        off = ((old_n + 2) * self.bsize) - 4
        data = struct.pack("<L", last_no_for_xbbd + 1)
        self.mm = self.mm[:off] + data + self.mm[off:]

    # ---------------------------------------------------------------------
    # Add Small Block
    # num : Number of Big Block to add
    # ---------------------------------------------------------------------
    def __add_small_block_num(self, num):
        root = self.pps[0]
        r_size = root["Size"]

        # Create SBD link
        sbd_link = []
        sbd_link.extend(kavutil.get_uint32(self.sbd, i * 4) for i in range(len(self.sbd) // 4))

        # Find unused SBD link
        free_link = [i for i, no in enumerate(sbd_link) if (no == 0xFFFFFFFF and i < r_size // self.ssize)]

        if len(free_link) >= num:  # Enough free space...
            return  # No need to add
        else:  # Not enough free space. Therefore, Root must be increased
            self.increase_root_size_for_small_blocks(num, root, r_size)

    def increase_root_size_for_small_blocks(self, num, root, r_size):
        """
        Increases the root storage size to accommodate additional small blocks

        Args:
            num: Number of small blocks to add
            root: Root storage information
            r_size: Current root size

        Handles:
            - Calculating required big blocks
            - Extending big block allocation
            - Updating root storage size
        """
        size = num * self.ssize  # Required capacity
        add_big_num = (size // self.bsize) + (1 if (size % self.bsize) else 0)

        self.__add_big_block_num(add_big_num)  # Request to add Big Block

        r_no = root["Start"]
        t_link = get_block_link(r_no, self.bbd_fat)  # Get link of previous Small Block

        # Add required number of blocks to previous link to create a new link
        self.__modify_big_block_link(t_link, add_big_num)

        # Modify Root size
        self.__set_pps_header(0, size=r_size + add_big_num * self.bsize)

    # ---------------------------------------------------------------------
    # Request to add BBD link (BBD link of the original image is modified)
    # old_link : Original BBD link
    # add_num : Number of BBD link to add
    # ---------------------------------------------------------------------
    def __modify_big_block_link(self, old_link, add_num):
        if add_num < 0:
            return []

        # Get all BBD link
        bbd_list_array, num_of_bbd_blocks, _, _ = get_bbd_list_array(self.mm)

        # Collect BBD
        bbd = b""
        for i in range(num_of_bbd_blocks):
            no = kavutil.get_uint32(bbd_list_array, i * 4)
            bbd += get_bblock(self.mm, no, self.bsize)

        if self.verbose:
            with open("bbd.dm2", "wb") as f:
                f.write(bbd)

        bbd_link = []
        bbd_link.extend(kavutil.get_uint32(bbd, i * 4) for i in range(len(bbd) // 4))

        # Find unused BBD link
        free_link = [i for i, no in enumerate(bbd_link) if (no == 0xFFFFFFFF)]

        if old_link:
            ret_link = old_link + free_link[:add_num]  # Final BBD link
            t_link = old_link[-1:] + free_link[:add_num]  # Connect link to BBD
        else:
            # If there is no previous link...
            ret_link = free_link[:add_num]  # Final BBD link
            t_link = free_link[:add_num]  # Connect link to BBD

        for i in range(len(t_link) - 1):
            no = t_link[i + 1]
            data = struct.pack("<L", no)

            no = t_link[i]
            bbd = bbd[: no * 4] + data + bbd[(no + 1) * 4 :]

        no = t_link[-1]
        bbd = bbd[: no * 4] + b"\xfe\xff\xff\xff" + bbd[(no + 1) * 4 :]

        if self.verbose:
            with open("bbd.dm3", "wb") as f:
                f.write(bbd)

        # Overwrite BBD to original image
        self.__modify_bbd(bbd)

        return ret_link  # Connected link

    # ---------------------------------------------------------------------
    # Request to add SBD link (SBD link of the original image is modified)
    # old_link : Original SBD link
    # add_num : Number of SBD link to add
    # ---------------------------------------------------------------------
    def __modify_small_block_link(self, old_link, add_num):
        if add_num < 0:
            return []

        sbd = self.sbd

        if self.verbose:
            with open("sbd.dm2", "wb") as f:
                f.write(sbd)

        # Create SBD link
        sbd_link = []
        sbd_link.extend(kavutil.get_uint32(sbd, i * 4) for i in range(len(sbd) // 4))

        # Find unused SBD link
        free_link = [i for i, no in enumerate(sbd_link) if (no == 0xFFFFFFFF)]

        if old_link:
            ret_link = old_link + free_link[:add_num]  # Final SBD link
            t_link = old_link[-1:] + free_link[:add_num]  # Connect link to SBD
        else:
            # If there is no previous link...
            ret_link = free_link[:add_num]  # Final SBD link
            t_link = free_link[:add_num]  # Connect link to SBD

        for i in range(len(t_link) - 1):
            no = t_link[i + 1]
            data = struct.pack("<L", no)

            no = t_link[i]
            sbd = sbd[: no * 4] + data + sbd[(no + 1) * 4 :]

        no = t_link[-1]
        sbd = sbd[: no * 4] + b"\xfe\xff\xff\xff" + sbd[(no + 1) * 4 :]

        if n := len(sbd) % self.bsize:
            t = self.bsize - n
            sbd += b"\xff" * t

        if self.verbose:
            with open("sbd.dm3", "wb") as f:
                f.write(sbd)

        self.__modify_sbd(sbd)  # Apply modified SBD

        return ret_link  # Connected link

    # ---------------------------------------------------------------------
    # Modify SBD
    # sbd : Modified SBD image
    # ---------------------------------------------------------------------
    def __modify_sbd(self, sbd):
        # Overwrite SBD to original image
        sbd_no = kavutil.get_uint32(self.mm, 0x3C)
        # sbd_list_array = get_block_link(sbd_no, self.bbd)
        sbd_list_array = get_block_link(sbd_no, self.bbd_fat)
        # print sbd_list_array

        for i, no in enumerate(sbd_list_array):
            data = sbd[i * self.bsize : (i + 1) * self.bsize]
            off = (no + 1) * self.bsize
            self.mm = self.mm[:off] + data + self.mm[off + self.bsize :]

    # ---------------------------------------------------------------------
    # Modify BBD
    # bbd : Modified BBD image
    # ---------------------------------------------------------------------
    def __modify_bbd(self, bbd):
        self.bbd = bbd  # Check !!!
        bbd_list_array, _, _, _ = get_bbd_list_array(self.mm)

        for i in range(len(bbd_list_array) // 4):
            no = kavutil.get_uint32(bbd_list_array, i * 4)
            data = bbd[i * self.bsize : (i + 1) * self.bsize]
            off = (no + 1) * self.bsize
            self.mm = self.mm[:off] + data + self.mm[off + self.bsize :]


if __name__ == "__main__":
    # import zlib

    # o = OleFile('normal.hwp', write_mode=True, verbose=True)
    o = OleFile(
        "a82d381c20cfdf47d603b4b2b840136ed32f71d2757c64c898dc209868bb57d6",
        write_mode=True,
        verbose=True,
    )
    print(o.listdir())
    o.delete("_VBA_PROJECT_CUR/VBA")  # Modify Root, Next
    o.close()

    """
    o = OleFile('normal.hwp', verbose=True)

    pics = o.openstream('PrvImage')
    print get_block_link(o.pps[6]['Start'], o.sbd)
    # d2 = pics.read()
    o.close()
    """

    # Case of XBBD increasing
    # o = OleFile('xbbd2.ppt', write_mode=True, verbose=True)
    # o.test()

    """
    # Case of XBBD increasing
    # The number of cases is too many
    o = OleFile('normal.hwp', write_mode=True, verbose=True)
    pics = o.openstream('FileHeader')

    d = pics.read()
    d = d + d

    o.write_stream('FileHeader', d)

    o.close()
    """


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """OLE archive handler plugin.

    This plugin provides functionality for:
    - Detecting OLE file format
    - Listing streams within OLE files
    - Extracting streams from OLE files
    - Detecting OLE-based exploits
    """

    def __init__(self):
        """Initialize the OLE plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="OLE Library",
            kmd_name="ole",
        )

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["make_arc_type"] = kernel.MASTER_PACK
        info["sig_num"] = len(self.listvirus())
        return info

    def listvirus(self):
        """Get list of malware that can be diagnosed/removed.

        Returns:
            List of malware names
        """
        vlist = [
            "Exploit.OLE.CVE-2012-0158",
            "Exploit.OLE.CVE-2003-0820",
            "Exploit.OLE.CVE-2003-0347",
        ]
        vlist.sort()
        return vlist

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect OLE format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or empty dict if not recognized
        """
        ret = {}

        try:
            mm = filehandle

            # Check OLE header signature
            if mm[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
                self._analyze_ole_format_details(ret, mm, filename)

        except (IOError, OSError) as e:
            logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return ret

    def _analyze_ole_format_details(self, ret, mm, filename):
        """Analyze OLE file format details and detect specific file types (HWP).

        Args:
            ret: Dictionary to store format information
            mm: File buffer content
            filename: Name of the file being analyzed

        Adds following information to ret:
            - ff_ole: OLE format marker
            - ff_attach: Information about attached files (if any)
            - ff_hwp: HWP specific format information (if HWP file)
        """
        ret["ff_ole"] = "OLE"

        # Check if there is a file attached to OLE
        fsize = len(mm)
        bsize = 1 << kavutil.get_uint16(mm, 0x1E)
        rsize = (fsize // bsize) * bsize

        if fsize > rsize:
            fileformat = {
                "Attached_Pos": rsize,
                "Attached_Size": fsize - rsize,
            }
            ret["ff_attach"] = fileformat

        # Check if it's HWP
        o = OleFile(filename, verbose=self.verbose)
        with contextlib.suppress(Error):
            pics = o.openstream("FileHeader")
            d = pics.read()

            if d[:0x11] == b"HWP Document File":
                val = int(d[0x24])
                ret["ff_hwp"] = {
                    "compress": (val & 0x1 == 0x1),
                    "encrypt": (val & 0x2 == 0x2),
                    "viewtext": (val & 0x4 == 0x4),
                }
        o.close()

    def __get_handle(self, filename):
        """Get or create handle for OLE file.

        Args:
            filename: Path to OLE file

        Returns:
            OleFile object or None
        """
        if filename in self.handle:
            return self.handle.get(filename, None)

        try:
            zfile = OleFile(filename, verbose=self.verbose)
            self.handle[filename] = zfile
            return zfile
        except (IOError, OSError) as e:
            logger.debug("Failed to open OLE file %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error opening OLE file %s: %s", filename, e)

        return None

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive.

        Args:
            filename: Path to archive file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_ole" not in fileformat:
            return file_scan_list

        try:
            o = self.__get_handle(filename)
            if o is None:
                return file_scan_list

            for name in o.listdir():
                # CWE-22: Path traversal prevention
                if k2security.is_safe_archive_member(name):
                    file_scan_list.append(["arc_ole", name])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_ole')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_ole":
            return None

        try:
            o = self.__get_handle(arc_name)
            if o is None:
                return None

            fp = o.openstream(fname_in_arc)
            return fp.read()

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                zfile = self.handle.get(fname)
                if zfile:
                    zfile.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)

    def mkarc(self, arc_engine_id, arc_name, file_infos):
        """Create an OLE archive.

        Args:
            arc_engine_id: Engine ID ('arc_ole')
            arc_name: Path to archive file
            file_infos: List of file info structures

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != "arc_ole":
            return False

        try:
            o = OleFile(arc_name, write_mode=True)

            for file_info in file_infos:
                rname = file_info.get_filename()
                a_name = file_info.get_filename_in_archive()
                with contextlib.suppress(IOError):
                    if os.path.exists(rname):
                        with open(rname, "rb") as fp:
                            buf = fp.read()
                            o.write_stream(a_name, buf)
                    else:
                        # Delete processing
                        o.delete(a_name)

            o.close()
            return True

        except (IOError, OSError) as e:
            logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
