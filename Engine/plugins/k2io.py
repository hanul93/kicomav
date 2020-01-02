# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

import os
import kernel


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
