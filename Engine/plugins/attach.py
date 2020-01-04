# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


from __future__ import print_function
import os
import kernel
import kavutil
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
        self.verbose = verbose
        return 0

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    def getinfo(self):
        info = k2io.k2dict()

        k2io.k2dict_append(info, 'author', 'Kei Choi')
        k2io.k2dict_append(info, 'version', '1.1')
        k2io.k2dict_append(info, 'title', 'Attach Engine')
        k2io.k2dict_append(info, 'kmd_name', 'attach')
        k2io.k2dict_append(info, 'make_arc_type', kernel.MASTER_PACK)

        return info

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # Get a list of files inside the archive file.
    # input  : filehandle  - Handle of file
    #          fileformat  - all fileformat informations
    # return : [[archive engine ID, filename inside a compressed file]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = k2io.k2list()

        if k2io.k2dict_has(fileformat, 'ff_attach'):
            t = k2io.k2dict_get(fileformat, 'ff_attach')
            pos = k2io.k2dict_get(t, 'Attached_Pos')
            size = k2io.k2dict_get(t, 'Attached_Size')

            t = k2io.k2list()
            k2io.k2list_append(t, 'arc_attach:%d:%d' % (pos, size))
            k2io.k2list_append(t, 'Attached')
            k2io.k2list_append(file_scan_list, t)

            if self.verbose:
                print('-' * 79)
                kavutil.vprint('Engine')
                kavutil.vprint(None, 'Engine', 'attach.kmd')
                kavutil.vprint(None, 'File name', os.path.split(filename)[-1])
                kavutil.vprint(None, 'Attach Point', '0x%08X' % pos)
                kavutil.vprint(None, 'Attach Size', '0x%08X' % size)

                with open(filename, 'rb') as fp:
                    fp.seek(pos)
                    buf = fp.read(0x80)

                    print()
                    kavutil.vprint('Attach Point (Raw)')
                    print()
                    kavutil.HexDump().Buffer(buf, 0, 0x80)

                print()

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
        eid = k2io.k2memcpy(arc_engine_id, 0, 11)
        if not k2io.k2memcmp(eid, 'arc_attach:'):
            return None

        t = k2io.k2split(arc_engine_id, ':')
        pos = int(k2io.k2list_index(t, 1))
        size = int(k2io.k2list_index(t, 2))

        fp = k2io.k2open(arc_name, 'rb')
        if fp:
            k2io.k2seek(fp, pos)
            data = k2io.k2read(fp, size)
            k2io.k2close(fp)

            return data

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # Close the compressed file handle
    # ---------------------------------------------------------------------
    def arcclose(self):
        pass

    # ---------------------------------------------------------------------
    # mkarc(self, arc_engine_id, arc_name, file_infos)
    # Make archive file
    # input  : arc_engine_id  - Archive engine ID
    #          arc_name       - Archive file name
    #          file_infos     - Target archive file info structure
    # return : True - success, False - fail
    # ---------------------------------------------------------------------
    def mkarc(self, arc_engine_id, arc_name, file_infos):
        eid = k2io.k2memcpy(arc_engine_id, 0, 11)
        if not k2io.k2memcmp(eid, 'arc_attach:'):
            return False

        t = k2io.k2split(arc_engine_id, ':')
        pos = int(k2io.k2list_index(t, 1))
        # size = int(k2io.k2list_index(t, 2))

        file_info = k2io.k2list_index(file_infos, 0)
        rname = file_info.get_filename()

        try:
            fp = k2io.k2open(arc_name, 'rb')
            fsize = k2io.k2getfilesize(arc_name)
            t_buf = k2io.k2read(fp, fsize)
            k2io.k2close(fp)

            if k2io.k2fileexists(rname):  # exists
                fp = k2io.k2open(rname, 'rb')
                fsize = k2io.k2getfilesize(rname)
                buf = k2io.k2read(fp, fsize)
                k2io.k2close(fp)

                data = t_buf[:pos] + buf
            else:
                data = t_buf[:pos]

            wp = k2io.k2open(arc_name, 'wb')
            k2io.k2write(wp, data)
            k2io.k2close(wp)  # create a clean file

            return True
        except IOError:
            pass

        return False
