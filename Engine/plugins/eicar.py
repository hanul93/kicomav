# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import kernel
import k2io
import cryptolib


VNAME_EICAR = 'EICAR-Test-File (not a virus)'
EICAR_SIZE = 68
EICAR_MD5 = '44d88612fea8a8f36de82e1278abb02f'


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(kernel.PluginsMain):
    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat, filename_ex)
    # Scan for malware
    # input  : filehandle  - Handle of file
    #          filename    - Name of file
    #          fileformat  - Format of file
    #          filename_ex - File name inside the compressed file
    # return : (malware found, malware name, malware ID, malware scan result)
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex):  # 악성코드 검사
        buf = k2io.k2memcpy(filehandle, 0, EICAR_SIZE)

        if k2io.k2sizeof(buf) == EICAR_SIZE:
            fmd5 = cryptolib.md5(buf)

            # Compare MD5 hash
            if k2io.k2memcmp(fmd5, EICAR_MD5):
                return True, VNAME_EICAR, kernel.DISINFECT_DELETE, kernel.INFECTED

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
        if malware_id != kernel.DISINFECT_DELETE:
            return False

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
        k2io.k2list_append(vlist, VNAME_EICAR)
        return vlist

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    def getinfo(self):
        info = k2io.k2dict()

        k2io.k2dict_append(info, 'author', 'Kei Choi')
        k2io.k2dict_append(info, 'version', '1.2')
        k2io.k2dict_append(info, 'title', 'EICAR Scan Engine')
        k2io.k2dict_append(info, 'kmd_name', 'eicar')
        k2io.k2dict_append(info, 'sig_num', 1)

        return info

