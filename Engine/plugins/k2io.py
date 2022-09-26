# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

import os
import mmap
import kernel


SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2


# -------------------------------------------------------------------------
# k2open(filename, mode)
# Open file
# input  : filename    - Name of file
#          mode        - Mode of access
# return : handle - success, None - fail
# -------------------------------------------------------------------------
def k2open(filename, mode):
    try:
        return open(filename, mode)
    except IOError:  # file not found
        return None


# -------------------------------------------------------------------------
# k2read(filehandle, size)
# Read file
# input  : filehandle  - Handle of file
#          size        - Number of bytes
# return : data - success, None - fail
# -------------------------------------------------------------------------
def k2read(filehandle, size):
    if filehandle:
        return filehandle.read(size)

    return None


def k2write(filehandle, data):
    if filehandle:
        return filehandle.write(k2byte(data))

    return None

# -------------------------------------------------------------------------
# k2seek(filehandle, offset, mode=SEEK_SET)
# Set file pointer
# input  : filehandle  - Handle of file
#          offset      - Offset of Set file pointer
#          mode        - 0(SET), 1(CUR), 2(END)
# return : offset - success, None - fail
# -------------------------------------------------------------------------
def k2seek(filehandle, offset, mode=SEEK_SET):
    if filehandle:
        return filehandle.seek(offset, mode)

    return None


# -------------------------------------------------------------------------
# k2close(filehandle)
# Close file
# input  : filehandle  - Handle of file
# return : True - success, False - fail
# -------------------------------------------------------------------------
def k2close(filehandle):
    if filehandle:
        filehandle.close()
        return True

    return False


# -------------------------------------------------------------------------
# k2getfilesize(filename)
# Get file size
# input  : filename    - Name of file
# return : size - success, None - fail
# -------------------------------------------------------------------------
def k2getfilesize(filename):
    if not os.path.exists(filename):
        return None

    return os.path.getsize(filename)


def k2fileexists(path):
    return os.path.exists(path)

# -------------------------------------------------------------------------
# k2unlink(filename)
# Delete file
# input  : filename    - Name of file
# return : True - success, False - fail
# -------------------------------------------------------------------------
def k2unlink(filename):
    if not os.path.exists(filename):
        return False

    try:
        os.remove(filename)
        return True
    except IOError:
        return False


def k2mmap(filehandle):
    return mmap.mmap(filehandle.fileno(), 0, access=mmap.ACCESS_READ)


# -------------------------------------------------------------------------
# k2byte(data)
# Convert String to Bytes(PY3)
# -------------------------------------------------------------------------
def k2byte(data):
    return data.encode('utf-8')


def k2ord(ch):
    return ch


def k2split(str1, sep):
    return str1.split(sep)


# -------------------------------------------------------------------------
# k2memcmp(str1, str2)
# Compare datas
# return : True - same datas
# -------------------------------------------------------------------------
def k2memcmp(str1, str2):
    return k2byte(str1) == k2byte(str2)


# -------------------------------------------------------------------------
# k2memcpy(data, offset, size):
# Copy memory data
# -------------------------------------------------------------------------
def k2memcpy(data, offset, size):
    tdata = k2byte(data)
    return tdata[offset:offset+size]


# -------------------------------------------------------------------------
# k2sizeof(data)
# Calculate size of data
# -------------------------------------------------------------------------
def k2sizeof(data):
    return len(k2byte(data))


def k2list():
    return list()


def k2list_append(hlist, item):
    hlist.append(item)


def k2list_get(hlist, start=0, end=None, step=1):
    if not end:
        end = len(hlist)

    return hlist[start:end:step]


def k2list_index(hlist, index):
    return hlist[index]


def k2dict():
    return dict()


def k2dict_append(hdict, key, value):
    hdict[key] = value


def k2dict_has(hdict, key):
    return key in hdict


def k2dict_get(hdict, key, default_value=None):
    return hdict.get(key, default_value)


def k2dict_keys(hdict):
    return hdict.keys()


def k2dict_pop(hdict, key):
    return hdict.pop(key)

# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(kernel.PluginsMain):
    def getinfo(self):
        info = dict()

        info['author'] = 'Kei Choi'
        info['version'] = '1.0'
        info['title'] = 'KicomAV Native IO'  # Plug-in engine description
        info['kmd_name'] = 'k2io'  # filename of Plug-in engine

        return info
