# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import re
import sys
import os
import struct
import marshal
import zlib

s = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep + "Engine" + os.sep + "kavcore"

sys.path.append(s)

import k2timelib


# -------------------------------------------------------------------------
# Number of signatures to create in one file
# -------------------------------------------------------------------------
MAX_COUNT = 100000

# -------------------------------------------------------------------------
# Regular expression for comments in virus.db file
# -------------------------------------------------------------------------
re_comment = rb"#.*"

# -------------------------------------------------------------------------
# Data structure
# -------------------------------------------------------------------------
size_sig = []  # Size and ID storage
p1_sig = {}  # MD5 first 6 bytes
p2_sig = []  # MD5 first 10 bytes
name_sig = []  # Virus name


def printProgress(_off, _all):
    if _off != 0:
        percent = (_off * 100.0) / _all

        s_num = int(percent / 5)
        space_num = 20 - s_num

        sys.stdout.write("[*] Download : [")
        sys.stdout.write("#" * s_num)
        sys.stdout.write(" " * space_num)
        sys.stdout.write("] ")
        sys.stdout.write("%3d%%  (%d/%d)\r" % (int(percent), _off, _all))


# -------------------------------------------------------------------------
# Analyze text line and create data structure for virus pattern
# -------------------------------------------------------------------------
def add_signature(line):
    t = line.split(b":")

    size = int(t[0])  # size
    fmd5 = bytes.fromhex(t[1].decode("utf-8"))  # Convert MD5 from text to binary
    name = t[2]

    # Add size
    size_sig.append(size)

    p1 = fmd5[:6]  # First 6 bytes
    p2 = fmd5[6:]  # Last 10 bytes

    p2_id = len(p2_sig)

    # Check if existing p1
    if p1 in p1_sig:
        p1_sig[p1].append(p2_id)
    else:
        p1_sig[p1] = [p2_id]

    if name in name_sig:  # If the name is already registered, get the id
        name_id = name_sig.index(name)
    else:
        name_id = len(name_sig)
        name_sig.append(name)

    p2_sig.append((p2, name_id))


# -------------------------------------------------------------------------
# Save information in data structure to virus pattern file
# -------------------------------------------------------------------------
def save_signature(fname, _id):
    # Get current date and time
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    # Convert date and time to 2 bytes
    val_date = struct.pack("<H", ret_date)
    val_time = struct.pack("<H", ret_time)

    # Save size file : ex) script.s01
    sname = "%s.s%02d" % (fname, _id)
    t = zlib.compress(marshal.dumps(set(size_sig)))  # Remove duplicate data and save
    t = b"KAVS" + struct.pack("<L", len(size_sig)) + val_date + val_time + t
    save_file(sname, t)

    # Save pattern p1 file : ex) script.i01
    sname = "%s.i%02d" % (fname, _id)
    t = zlib.compress(marshal.dumps(p1_sig))
    t = b"KAVS" + struct.pack("<L", len(p1_sig)) + val_date + val_time + t
    save_file(sname, t)

    # Save pattern p2 file : ex) script.c01
    sname = "%s.c%02d" % (fname, _id)
    t = zlib.compress(marshal.dumps(p2_sig))
    t = b"KAVS" + struct.pack("<L", len(p2_sig)) + val_date + val_time + t
    save_file(sname, t)

    # Save virus name file : ex) script.n01
    sname = "%s.n%02d" % (fname, _id)
    t = zlib.compress(marshal.dumps(name_sig))
    t = b"KAVS" + struct.pack("<L", len(name_sig)) + val_date + val_time + t
    save_file(sname, t)


# -------------------------------------------------------------------------
# Create a file
# -------------------------------------------------------------------------
def save_file(fname, data):
    with open(fname, "wb") as fp:
        fp.write(data)


# -------------------------------------------------------------------------
# Create a file by ID
# -------------------------------------------------------------------------
def save_sig_file(fname, _id):
    # Create a sig file using the given pattern file name
    t = os.path.abspath(fname)
    _, t = os.path.split(t)
    name = os.path.splitext(t)[0]
    save_signature(name, _id)

    # Initialize
    global size_sig
    global p1_sig
    global p2_sig
    global name_sig

    size_sig = []  # Size and ID storage
    p1_sig = {}  # First 6 bytes
    p2_sig = []  # First 10 bytes
    name_sig = []  # Virus name


# -------------------------------------------------------------------------
# Analyze text-based virus pattern DB file and create virus pattern files
# -------------------------------------------------------------------------
def make_signature(fname, _id):
    with open(fname, "rb") as fp:
        idx = 0

        while True:
            line = fp.readline()
            if not line:
                break

            # Remove comments and white spaces
            line = re.sub(re_comment, b"", line)
            line = line.strip()  # re.sub(r'\s', '', line)

            if len(line) == 0:
                continue  # If nothing, go to next line

            add_signature(line)

            idx += 1
            printProgress(idx, MAX_COUNT)

            if idx >= MAX_COUNT:
                print("[*] %s : %d" % (fname, _id))
                save_sig_file(fname, _id)
                idx = 0
                _id += 1

    save_sig_file(fname, _id)


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : sigtool_md5.py [sig text] [id]")
        exit(0)

    sin_fname = ""
    _id = 1

    if len(sys.argv) == 2:
        sin_fname = sys.argv[1]
        _id = 1
    elif len(sys.argv) == 3:
        sin_fname = sys.argv[1]
        _id = int(sys.argv[2])

    if os.path.exists(sin_fname):
        make_signature(sin_fname, _id)
