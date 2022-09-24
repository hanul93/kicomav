# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@naver.com)


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
    # init(self, plugins_path, verbose)
    # Initialize the plug-in engine
    # input  : plugins_path - Location of the plug-in engine
    #          verbose         - verbose (True or False)
    # return : 0 - success, Nonzero - fail
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):
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
        return dict()


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
        info = dict()

        info['author'] = 'Kei Choi'
        info['version'] = '1.0'
        info['title'] = 'KicomAV Kernel'  # Plug-in engine description
        info['kmd_name'] = 'kernel'  # filename of Plug-in engine

        return info

