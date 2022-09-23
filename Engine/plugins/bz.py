# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import bz2
import kernel
import k2io


# -------------------------------------------------------------------------
# class BZ2File
# -------------------------------------------------------------------------
class BZ2File:
    def __init__(self, filename, mode='r'):
        self.mode = mode

        if mode == 'r':
            self.decompress_data = None
            self.unused_data = None
            try:
                self.fp = k2io.k2open(filename, 'rb')
                self.mm = k2io.k2mmap(self.fp)
            except IOError:
                self.fp = None
                self.mm = None
        else:  # mode == 'w'
            self.bz2 = bz2.BZ2File(filename, 'w')

    def is_bz2(self):
        if self.mode != 'r':
            return False

        buf = k2io.k2memcpy(self.mm, 0, 3)  # read magic of bz2
        if k2io.k2memcmp(buf, 'BZh'):
            return True

        return False

    def is_attach(self):
        if self.mode != 'r':
            return False

        if not self.decompress_data:
            self.read()

        if self.unused_data:
            return True

        return False

    def read(self):
        if self.mode != 'r':
            return False

        if not self.is_bz2():
            return None

        if self.decompress_data:
            return self.decompress_data

        data = k2io.k2byte('')
        src = self.mm[:]
        while k2io.k2sizeof(src):
            try:
                b = bz2.BZ2Decompressor()
                data += b.decompress(src)
                src = b.unused_data
            except IOError:
                break

        if k2io.k2sizeof(src):
            self.unused_data = src

        if not k2io.k2memcmp(data, ''):
            self.decompress_data = data
            return self.decompress_data

        return None

    def get_attach_info(self):
        if self.mode != 'r':
            return False

        if not self.decompress_data:
            self.read()

        if self.unused_data:
            asize = len(self.unused_data)
            return len(self.mm) - asize, asize

        return None, None

    def write(self, data):
        if self.mode != 'w':
            return False

        self.bz2.write(data)
        return True

    def close(self):
        if self.mode == 'r':
            k2io.k2close(self.mm)
            k2io.k2close(self.fp)
        else:  # mode == 'w'
            self.bz2.close()


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
        self.handle = k2io.k2dict()
        return 0

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    def getinfo(self):
        info = k2io.k2dict()

        k2io.k2dict_append(info, 'author', 'Kei Choi')
        k2io.k2dict_append(info, 'version', '1.0')
        k2io.k2dict_append(info, 'title', 'Bz2 Archive Engine')
        k2io.k2dict_append(info, 'kmd_name', 'bz2')
        k2io.k2dict_append(info, 'engine_type', kernel.ARCHIVE_ENGINE)
        k2io.k2dict_append(info, 'make_arc_type', kernel.MASTER_PACK)

        return info

    # ---------------------------------------------------------------------
    # __get_handle(self, filename)
    # Get the handle of the archive file
    # input  : filename - Archive file name
    # return : compressed file handle
    # ---------------------------------------------------------------------
    def __get_handle(self, filename):
        if k2io.k2dict_has(self.handle, filename):  # Is there a previously open handle?
            zfile = k2io.k2dict_get(self.handle, filename)
            return zfile

        zfile = BZ2File(filename)
        k2io.k2dict_append(self.handle, filename, zfile)

        return zfile

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # Analyze the file format
    # input  : filehandle  - Handle of file
    #          filename    - Name of file
    #          filename_ex - File name inside the archive file
    # return : {File format analysis information} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        buf = k2io.k2memcpy(filehandle, 0, 3)  # read magic of bz2

        if k2io.k2memcmp(buf, b'BZh'):
            t = k2io.k2dict()
            k2io.k2dict_append(t, 'ff_bz2', 'bz2')

            bfile = BZ2File(filename)
            aoff, asize = bfile.get_attach_info()
            if aoff:
                at = k2io.k2dict()
                k2io.k2dict_append(at, 'Attached_Pos', aoff)
                k2io.k2dict_append(at, 'Attached_Size', asize)
                k2io.k2dict_append(t, 'ff_attach', at)
            bfile.close()

            return t

        return None

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # Get a list of files inside the archive file.
    # input  : filehandle  - Handle of file
    #          fileformat  - all fileformat informations
    # return : [[archive engine ID, filename inside a compressed file]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = k2io.k2list()

        # Is there a BZ2 format among the pre-parsed file formats?
        if k2io.k2dict_has(fileformat, 'ff_bz2'):
            t = k2io.k2list()
            k2io.k2list_append(t, 'arc_bz2')
            k2io.k2list_append(t, 'BZ2')

            k2io.k2list_append(file_scan_list, t)

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # Decompress the archive file
    # input  : arc_engine_id  - Archive engine ID
    #          arc_name       - Archive file name
    #          fname_in_arc   - Decompress file name in Archive file
    # return : Decompress data or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id != 'arc_bz2':
            return None

        bfile = self.__get_handle(arc_name)
        return bfile.read()

    # ---------------------------------------------------------------------
    # arcclose(self)
    # Close the compressed file handle
    # ---------------------------------------------------------------------
    def arcclose(self):
        tlist = k2io.k2list()
        for fname in k2io.k2dict_keys(self.handle):
            bfile = k2io.k2dict_get(self.handle, fname)
            bfile.close()
            k2io.k2list_append(tlist, fname)

        for fname in k2io.k2list_get(tlist):
            k2io.k2dict_pop(self.handle, fname)

    # ---------------------------------------------------------------------
    # mkarc(self, arc_engine_id, arc_name, file_infos)
    # Make archive file
    # input  : arc_engine_id  - Archive engine ID
    #          arc_name       - Archive file name
    #          file_infos     - Target archive file info structure
    # return : True - success, False - fail
    # ---------------------------------------------------------------------
    def mkarc(self, arc_engine_id, arc_name, file_infos):
        if arc_engine_id != 'arc_bz2':
            return False

        bfile = BZ2File(arc_name, 'w')
        file_info = k2io.k2list_index(file_infos, 0)

        rname = file_info.get_filename()
        fp = k2io.k2open(rname, 'rb')
        if fp:
            fsize = k2io.k2getfilesize(rname)
            data = k2io.k2read(fp, fsize)

            bfile.write(data)
            bfile.close()

            k2io.k2close(fp)

            return True

        return False
