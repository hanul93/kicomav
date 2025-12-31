# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)


from abc import *  # for Abstract Base Classes


# Malware scan result
NOT_FOUND = 0
INFECTED = 1
SUSPECT = 2
WARNING = 3
IDENTIFIED = 4
ERROR = 99


# Disinfect method for malware
DISINFECT_NONE = -1
DISINFECT_DELETE = 0x8000
DISINFECT_MALWARE = 0x80000000  # Specific malware disinfection function setting


# Clean Malware for Compressed Files
MASTER_IGNORE = 0  # it is not currently supported
MASTER_PACK = 1  # Top-level file compression (reconstruction), can handle mkarc function
MASTER_DELETE = 2  # Delete top-level file


# Engine type
ARCHIVE_ENGINE = 80


# -------------------------------------------------------------------------
# class PluginsMain
# -------------------------------------------------------------------------
class PluginsMain:
    __metaclass__ = ABCMeta

    # ---------------------------------------------------------------------
    # init(self, rules_paths, verbose)
    # Initialize the plug-in engine
    # input  : rules_paths - Dict with rule paths {"system": "/path", "user": "/path"}
    #          verbose     - verbose (True or False)
    # return : 0 - success, Nonzero - fail
    # ---------------------------------------------------------------------
    def init(self, rules_paths, verbose=False):
        return 0

    # ---------------------------------------------------------------------
    # uninit(self)
    # Quit the plug-in engine
    # return : 0 - success, Nonzero - fail
    # ---------------------------------------------------------------------
    def uninit(self):
        return 0

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    @abstractmethod
    def getinfo(self):
        return {}


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(PluginsMain):
    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    def getinfo(self):
        return {
            "author": "Kei Choi",
            "version": "1.0",
            "title": "KicomAV Kernel",
            "kmd_name": "kernel",
        }
