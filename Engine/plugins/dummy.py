# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import kernel
import k2io


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(kernel.PluginsMain):
    # ---------------------------------------------------------------------
    # init(self, plugins_path, verbose)
    # Initialize the plug-in engine
    # input  : plugins_path - Location of the plug-in engine
    #          verbose      - verbose (True or False)
    # return : 0 - success, Nonzero - fail
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):
        # Load db of malware's patterns
        self.virus_name = 'Dummy-Test-File (not a virus)'
        self.dummy_pattern = 'Dummy Engine test file - KICOM Anti-Virus Project'
        self.len_dummy_pattern = len(self.dummy_pattern)

        return 0

    # ---------------------------------------------------------------------
    # uninit(self)
    # Quit the plug-in engine
    # return : 0 - success, Nonzero - fail
    # ---------------------------------------------------------------------
    def uninit(self):
        # unload db
        del self.virus_name
        del self.dummy_pattern
        return 0

    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat, filename_ex)
    # Scan for malware
    # input  : filehandle  - Handle of file
    #          filename    - Name of file
    #          fileformat  - Format of file
    #          filename_ex - File name inside the compressed file
    # return : (malware found, malware name, malware ID, malware scan result)
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex):
        # Open file and read from file
        fp = k2io.k2open(filename, 'rb')
        if fp:
            buf = k2io.k2read(fp, self.len_dummy_pattern)  # Pattern size is 49 Bytes
            k2io.k2close(fp)

            # Compare malware patterns
            if k2io.k2memcmp(self.dummy_pattern, buf):
                return True, self.virus_name, kernel.DISINFECT_DELETE, kernel.INFECTED

        return False, '', kernel.DISINFECT_NONE, kernel.NOT_FOUND

    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id)
    # Disinfect for malware
    # input  : filename    - Name of file
    #          malware_id - Malware ID to Clean
    # return : True - success, False - fail
    # ---------------------------------------------------------------------
    def disinfect(self, filename, malware_id):
        # Is the malware_id received from scan result 0?
        if malware_id == kernel.DISINFECT_DELETE:
            if k2io.k2unlink(filename):
                return True

        return False

    # ---------------------------------------------------------------------
    # listvirus(self)
    # It shows a list of malware that can be scan and disinfect.
    # return : malware lists
    # ---------------------------------------------------------------------
    def listvirus(self):
        vlist = k2io.k2list()
        k2io.k2list_append(vlist, self.virus_name)
        return vlist

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    def getinfo(self):
        info = k2io.k2dict()

        k2io.k2dict_append(info, 'author', 'Kei Choi')
        k2io.k2dict_append(info, 'version', '1.1')
        k2io.k2dict_append(info, 'title', 'Dummy Scan Engine')
        k2io.k2dict_append(info, 'kmd_name', 'dummy')
        k2io.k2dict_append(info, 'sig_num', 1)  # Number of malware that can be scan & disinfect

        return info
