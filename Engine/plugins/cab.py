# -*- coding:utf-8 -*-
# cabinet.py
# Copyright (c) 2008, CCP Games
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of CCP Games nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY CCP GAMES ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL CCP GAMES BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#   Based on the cabinet SDK, available from http://support.microsoft.com/kb/310618
#   Also reuses some code from zipfile.py
#   Uses ctypes to interface with the cabinet.dll file included with windows.


"""
Utility module to read windows cabinet files.
"""

# from __future__ import print_function
import tempfile
import shutil
import sys
import os.path
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

try:
    from ctypes import *
    from ctypes.wintypes import BOOL
    from functools import wraps

    LOAD_WINTYPES = True
except ImportError:
    LOAD_WINTYPES = False

import sys
import kernel

PY2 = sys.version_info[0] == 2


##################################
# First, we declare the cabinet FDI API in terms of ctypes
# FDI is the decompression part of the cabinet API

#windows types
USHORT = c_ushort


##Common fdi/fci types
UOFF = COFF = CHECKSUM = c_ulong

class CabinetError(RuntimeError): pass

class ERF(Structure):
    _pack_ = 4
    _fields_ = [("erfOper", c_int),
                ("erfType", c_int),
                ("fError", BOOL)]

    def __repr__(self):
        return "<ERF: erfOper:%s erfType:%s fError:%s"%(self.erfOper, self.erfType, self.fError)

    def __str__(self):
        return "%s %s %s"%(self.erfOper, self.erfType, self.fError)

    def __bool__(self):
        return self.fError #true if there is an error

    def clear(self):
        self.fError = 0

    def raise_error(self):
        if self.fError:
            raise CabinetError(self.erfOper, self.erfType)


CB_MAX_CHUNK         =    32768
CB_MAX_DISK          =0x7ffffff
CB_MAX_FILENAME      =      256
CB_MAX_CABINET_NAME  =      256
CB_MAX_CAB_PATH      =      256
CB_MAX_DISK_NAME     =      256


#tcompXXX - Compression types
TCOMP = c_ushort

tcompMASK_TYPE          =0x000F  ## Mask for compression type
tcompTYPE_NONE          =0x0000  ## No compression
tcompTYPE_MSZIP         =0x0001  ## MSZIP
tcompTYPE_QUANTUM       =0x0002  ## Quantum
tcompTYPE_LZX           =0x0003  ## LZX
tcompBAD                =0x000F  ## Unspecified compression type

tcompMASK_LZX_WINDOW    =0x1F00  ## Mask for LZX Compression Memory
tcompLZX_WINDOW_LO      =0x0F00  ## Lowest LZX Memory (15)
tcompLZX_WINDOW_HI      =0x1500  ## Highest LZX Memory (21)
tcompSHIFT_LZX_WINDOW   =     8  ## Amount to shift over to get int

tcompMASK_QUANTUM_LEVEL =0x00F0  ## Mask for Quantum Compression Level
tcompQUANTUM_LEVEL_LO   =0x0010  ## Lowest Quantum Level (1)
tcompQUANTUM_LEVEL_HI   =0x0070  ## Highest Quantum Level (7)
tcompSHIFT_QUANTUM_LEVEL=     4  ## Amount to shift over to get int

tcompMASK_QUANTUM_MEM   =0x1F00  ## Mask for Quantum Compression Memory
tcompQUANTUM_MEM_LO     =0x0A00  ## Lowest Quantum Memory (10)
tcompQUANTUM_MEM_HI     =0x1500  ## Highest Quantum Memory (21)
tcompSHIFT_QUANTUM_MEM  =     8  ## Amount to shift over to get int

tcompMASK_RESERVED      =0xE000  ## Reserved bits (high 3 bits)

def CompressionTypeFromTCOMP(tc):
    return ((tc) & tcompMASK_TYPE)

def CompressionLevelFromTCOMP(tc):
    return (((tc) & tcompMASK_QUANTUM_LEVEL) >> tcompSHIFT_QUANTUM_LEVEL)

def CompressionMemoryFromTCOMP(tc):
    return (((tc) & tcompMASK_QUANTUM_MEM) >> tcompSHIFT_QUANTUM_MEM)

def TCOMPfromTypeLevelMemory(t,l,m):
    return (((m) << tcompSHIFT_QUANTUM_MEM  ) |  \
            ((l) << tcompSHIFT_QUANTUM_LEVEL) |  \
             ( t                             ))

def LZXCompressionWindowFromTCOMP(tc):
    return (((tc) & tcompMASK_LZX_WINDOW) >> tcompSHIFT_LZX_WINDOW)

def TCOMPfromLZXWindow(w):
    return (((w) << tcompSHIFT_LZX_WINDOW ) |  \
            ( tcompTYPE_LZX ))

### end of common FDI/FCI types
def _enum(values):
    for i,v in enumerate(values):
        globals()[v] = i
    return c_int

FDIERROR = _enum(["FDIERROR_NONE", "FDIERROR_CABINET_NOT_FOUND", "FDIERROR_NOT_A_CABINET",
                   "FDIERROR_UNKNOWN_CABINET_VERSION", "FDIERROR_CORRUPT_CABINET",
                   "FDIERROR_ALLOC_FAIL", "FDIERROR_BAD_COMPR_TYPE", "FDIERROR_MDI_FAIL",
                   "FDIERROR_TARGET_FILE", "FDIERROR_RESERVE_MISMATCH", "FDIERROR_WRONG_CABINET",
                   "FDIERROR_USER_ABORT"])

_A_NAME_IS_UTF  =0x80
_A_EXEC         =0x40

#then FDI context handle
HFDI = c_void_p

#cabinet info
class FDICABINETINFO(Structure):
    _pack_ = 4
    _fields_ = [("cbCabinet", c_long),
                ("cFolders", USHORT),
                ("cFiles", USHORT),
                ("setID", USHORT),
                ("iCabinet", USHORT),
                ("fReserve", BOOL),
                ("hasprev", BOOL),
                ("hasnext", BOOL)]


FDIDECRYPTTYPE = _enum(["fdidtNEW_CABINET", "fdidtNEW_FOLDER", "fdidtDECRYPT"])


class FDIDECRYPT(Structure):
    class _U(Union):
        class Cabinet(Structure):
            _pack_ = 4
            _fields_ = [("pHeaderReserve", c_void_p),
                        ("cbHeaderReserve", USHORT),
                        ("setID", USHORT),
                        ("iCabinet", c_int)]

        class Folder(Structure):
            _pack_ = 4
            _fields_ = [("pFolderReserve", c_void_p),
                        ("cbFolderReserve", USHORT),
                        ("iFolder", USHORT)]

        class Decrypt(Structure):
            _pack_ = 4
            _fields_ = [("pDataReserve", c_void_p),
                        ("cbDataReserve", USHORT),
                        ("pData", c_void_p),
                        ("cbData", USHORT),
                        ("fSplit", BOOL),
                        ("cbPartial", USHORT)]

        _fields_ = [("cabinet", Cabinet), ("folder", Folder), ("decrypt", Decrypt)]

    _pack_ = 4
    _fields_ = [("fdidt", FDIDECRYPTTYPE),
                ("pvUser", py_object),
                ("u", _U)]
    _anonymous_ = ("u",)


#malloc and free callbacks
PFNALLOC = CFUNCTYPE(c_void_p, c_ulong)
PFNFREE  = CFUNCTYPE(None, c_void_p)

#file iofunction callbacks
PFNOPEN  = CFUNCTYPE(c_int, c_char_p, c_int, c_int)
PFNREAD  = CFUNCTYPE(c_uint, c_int, c_void_p, c_uint)
PFNWRITE = CFUNCTYPE(c_uint, c_int, c_void_p, c_uint)
PFNCLOSE = CFUNCTYPE(c_int, c_int)
PFNSEEK  = CFUNCTYPE(c_long, c_int, c_long, c_int)


#decryption callback (not used)
PFNFDIDECRYPT = CFUNCTYPE(c_int, POINTER(FDIDECRYPT))


#notification structure
class FDINOTIFICATION(Structure):
    _pack_ = 4
    _fields_ = [("cb", c_long),
                ("psz1", c_char_p),
                ("psz2", c_char_p),
                ("psz3", c_char_p),     #Points to a 256 character buffer
                ("pv", py_object),      #value for client
                ("hf", c_int),
                ("date", USHORT),
                ("time", USHORT),
                ("attribs", USHORT),
                ("setID", USHORT),      #cabinet set ID
                ("iCabinet", USHORT),   #cabinet number (0 based)
                ("iFolder", USHORT),    #folder number (0 based)
                ("fdie", FDIERROR) ]

FDINOTIFICATIONTYPE = _enum(["fdintCABINET_INFO", "fdintPARTIAL_FILE", "fdintCOPY_FILE",
                             "fdintCLOSE_FILE_INFO", "fdintNEXT_CABINET", "fdintENUMERATE"])


PFNFDINOTIFY = CFUNCTYPE(c_int, FDINOTIFICATIONTYPE, POINTER(FDINOTIFICATION))



#finally, the FDI api functions, from the CABINET.DLL file:

#FDICreate
try:
    FDICreate = cdll.cabinet.FDICreate
except Exception:
    raise ImportError("cabinet only works on windows")
FDICreate.restype = HFDI
FDICreate.argtypes = [PFNALLOC, PFNFREE, PFNOPEN, PFNREAD, PFNWRITE, PFNCLOSE, PFNSEEK,
                      c_int, POINTER(ERF)]

#FDIIsCabinet
FDIIsCabinet = cdll.cabinet.FDIIsCabinet
FDIIsCabinet.argtypes = [HFDI, c_int, POINTER(FDICABINETINFO)]
FDIIsCabinet.restype = BOOL

#FDICopy
#the decyrpt function isn't supported, so we just declare a void pointer which
#we must call with a null.
FDICopy = cdll.cabinet.FDICopy
#FDICopy.argtypes = [HFDI, c_char_p, c_char_p, c_int, PFNFDINOTIFY, PFNFDIDECRYPT, py_object]
FDICopy.argtypes = [HFDI, c_char_p, c_char_p, c_int, PFNFDINOTIFY, c_void_p, py_object]
FDICopy.restype = BOOL

#FDIDestropy
FDIDestroy = cdll.cabinet.FDIDestroy
FDIDestroy.argtypes = [HFDI]
FDIDestroy.restype = BOOL



###############################################
#Now, some utility classes to make all this usable


class FDIAllocator(object):
    """An allocator class that provides allocator callbacks for the FDI functions"""
    def __init__(self):
        self._allocs = {}
        self.malloc = PFNALLOC(self.pymalloc)
        self.free  = PFNFREE(self.pyfree)

    def pymalloc(self, size):
        try:
            s = create_string_buffer(size)
        except MemoryError:
            return c_void_p(0)
        p = addressof(s)
        self._allocs[p] = s
        return p

    def pyfree(self, p):
        if p:
            del self._allocs[p]


def FileErrwrap(f):
    """A decorator to handle exceptions in the file manager callbacks.  Stores them
       in self._excinfo
    """
    @wraps(f)
    def helper(self, *args):
        try:
            return f(self, *args)
        except BaseException as e:
            self._excinfo[:] = sys.exc_info()
            return -1

    return helper


class FDIFileManager(object):
    """A class that provides the file callbacks for the FDI routines and maintains
       mappings between ints and file objects.  Can be subclassed to provide special
       open semantics, e.g. to facilitate string io and such
    """
    def __init__(self, excinfo = None):
        self.filemap = {}
        if excinfo is None:
            excinfo = []
        self._excinfo = excinfo
        self.fileno = 100
        self.open =  PFNOPEN(self.pyopen)
        self.read =  PFNREAD(self.pyread)
        self.write = PFNWRITE(self.pywrite)
        self.seek =  PFNSEEK(self.pylseek)
        self.close = PFNCLOSE(self.pyclose)

    def raise_error(self):
        tmp = self._excinfo
        self._excinfo = []
        if tmp:
            raise tmp[1]

    def map(self, f):
        fd = self.fileno
        self.fileno+=1
        self.filemap[fd] = f
        return fd

    def unmap(self, fd):
        return self.filemap.pop(fd)

    @FileErrwrap
    def pyopen(self, filename, mode, prot):
        amode = "w" if mode & 0x1 else "r"
        if mode & 0x8000: amode += "b"
        f = open(filename, amode)
        return self.map(f)

    @FileErrwrap
    def pyclose(self, fd):
        self.unmap(fd).close()
        return 0

    @FileErrwrap
    def pyread(self, fd, buffer, count):
        data = self.filemap[fd].read(count)
        l = len(data)
        memmove(buffer, data, l)
        return l

    @FileErrwrap
    def pywrite(self, fd, buffer, count):
        tmp = string_at(buffer, count)
        self.filemap[fd].write(tmp)
        return count

    @FileErrwrap
    def pylseek(self, fd, offset, origin):
        self.filemap[fd].seek(offset, origin)
        return self.filemap[fd].tell()

class FileProxy(object):
    """A class that allows proxying of a file, thereby supporting many filepointers"""
    def __init__(self, f):
        self.f = f
        self.fp = 0

    def close(self):
        if self.f:
            self.f = None

    def read(self, size=None):
        self.f.seek(self.fp)
        if size is not None:
            r = self.f.read(size)
        else:
            r = self.f.read()
        self.fp = self.fp + len(r)
        return r

    def seek(self, offset, whence=0):
        self.f.seek(offset, whence)
        self.fp = self.f.tell()

    def tell(self):
        return self.fp


class FDIObjectFileManager(FDIFileManager):
    """a subclass which enables us to use a file object as a source"""
    fname = "_file_"
    def setfile(self, f):
        """set the buffer associated with this object and return its name"""
        self.file = f
        return self.fname

    #open creates a file object out of a stored string
    @FileErrwrap
    def pyopen(self, filename, mode, prot):
        if filename == self.fname:
            return self.map(FileProxy(self.file))
        return FDIFileManager.pyopen(self, filename, mode, prot)

def FileManager(fn):
    """Create a suitable file manager object to deal with the argument
    be it a filename, or a file like object"""
    if hasattr(fn, "read"):
        #oh, the filename really is a file object
        result = FDIObjectFileManager()
        fn = result.setfile(fn)
    else:
        result = FDIFileManager()
    return result, fn

def is_cabinetfile(filename):
    """Returns True if the given file is a cabinet.
    The argument can be a filename or a file object.
    """
    a = FDIAllocator()
    e = ERF()
    ci = FDICABINETINFO()
    f = FDIFileManager()
    if hasattr(filename, "read"):
        fileobj = filename
    else:
        fileobj = open(filename, "rb")
    try:
        fd = f.map(fileobj)

        hfdi = FDICreate(a.malloc, a.free, f.open, f.read, f.write, f.close, f.seek, 0, byref(e))
        try:
            if FDIIsCabinet(hfdi, fd, byref(ci)):
                return ci
            f.raise_error()
            e.raise_error()
            return False
        finally:
            FDIDestroy(hfdi)
    finally:
        if fileobj is not filename:
            fileobj.close()


class CabinetFile(object):
    """A class for reading cabinets.  Similar to zipfile.ZipFile.
    Only single-file cabinets are supported
    """
    def __init__(self, filename, mode='r'):
        self.a = FDIAllocator()
        self.e = ERF()

        self.f, self.filename = FileManager(filename)
        self.head, self.tail = os.path.split(os.path.normpath(self.filename))
        if self.head:
            self.head += "\\"
        if not PY2:
            self.head = self.head.encode(sys.getfilesystemencoding())
            self.tail = self.tail.encode(sys.getfilesystemencoding())

        self.hfdi = FDICreate(self.a.malloc, self.a.free,
                              self.f.open, self.f.read, self.f.write, self.f.close, self.f.seek,
                              0, byref(self.e))

    def __del__(self):
        #must have a del method to ensure that we call FDIDestroy
        if FDIDestroy: #module is not being torn down
            self.close()

    def close(self):
        if self.hfdi:
            FDIDestroy(self.hfdi)
            self.hfdi = None


    def __FDICopy(self, callback):
        #perform the actual fdicopy call, catching exceptions etc.
        excinfo = []
        def wrap(fdint, pnotify):
            try:
                return callback(fdint, pnotify)
            except Exception:
                excinfo[:] = sys.exc_info()
                return -1

        self.e.clear()
        r = FDICopy(self.hfdi, self.tail, self.head, 0, PFNFDINOTIFY(wrap), None, None)
        if not r:
            if excinfo:
                raise excinfo[1]
            self.f.raise_error() #maybe it is a filer error
            self.e.raise_error() #or an error in the error state
        return r

    def namelist(self):
        """Return a list of file names in the archive."""
        names = []
        def callback(fdint, pnotify):
            notify = pnotify.contents
            if fdint in [fdintCABINET_INFO, fdintENUMERATE]:
                return 0
            if fdint == fdintCOPY_FILE:
                names.append(notify.psz1)
                return 0 #don't copy
            return -1

        self.__FDICopy(callback)
        return names

    def infolist(self):
        """Return a list of class CabinetInfo instances for files in the
        archive.
        """
        infos = []
        def callback(fdint, pnotify):
            notify = pnotify.contents
            if fdint in [fdintCABINET_INFO, fdintENUMERATE]:
                return 0
            if fdint == fdintCOPY_FILE:
                i = CabinetInfo(notify.psz1, DecodeFATTime(notify.date, notify.time))
                i.file_size = notify.cb
                i.external_attr = notify.attribs
                infos.append(i)
                return 0 #don't copy
            return -1

        self.__FDICopy(callback)
        return infos

    def printdir(self):
        """Print a table of contents for the archive."""
        print("%-46s %19s %12s" % ("File Name", "Modified    ", "Size"))
        for cinfo in self.infolist():
            date = "%d-%02d-%02d %02d:%02d:%02d" % cinfo.date_time
            print("%-46s %s %12d" % (cinfo.filename, date, cinfo.file_size))

    def getinfo(self, name):
        """Return the instance of CabinetInfo given 'name'."""
        infos = self.infolist()
        mine = [i for i in infos if i.filename == name]
        if not mine:
            return None
        return mine[0]

    def read(self, name):
        """Return file bytes (as a string) for name."""
        result = []
        names = [name] if isinstance(name, basestring) else name
        def callback(fdint, pnotify):
            notify = pnotify.contents
            if fdint in [fdintCABINET_INFO, fdintENUMERATE]:
                return 0
            if fdint == fdintCOPY_FILE:
                if notify.psz1 in names:
                    sio = StringIO()
                    fd = self.f.map(sio)
                    return fd #signals that we want to copy!
                return 0 #don't copy
            if fdint == fdintCLOSE_FILE_INFO:
                sio = self.f.unmap(notify.hf)
                result.append(sio.getvalue()) #store the file outside
                return 1
            return -1

        self.__FDICopy(callback)
        return result[0] if isinstance(name, basestring) else result

    def extract(self, target, names=[]):
        """extract files into a target directory.
        Optionally, a set of names may be given
        """
        def callback(fdint, pnotify):
            notify = pnotify.contents
            if fdint in [fdintCABINET_INFO, fdintENUMERATE]:
                return 0
            if fdint == fdintCOPY_FILE:
                if not names or notify.psz1 in names:
                    pname = os.path.join(target, notify.psz1)
                    dir = os.path.dirname(pname)
                    if not os.path.exists(dir):
                        os.makedirs(dir)
                    f = open(pname, "wb")
                    return self.f.map(f)
                return 0
            if fdint == fdintCLOSE_FILE_INFO:
                f = self.f.unmap(notify.hf)
                f.close()
                return 1
            return -1

        self.__FDICopy(callback)

    def testcabinet(self):
        """verify that the archive is ok"""
        def callback(fdint, pnotify):
            #read and discard all data
            notify = pnotify.contents
            if fdint in [fdintCABINET_INFO, fdintENUMERATE]:
                return 0
            if fdint == fdintCOPY_FILE:
                sio = StringIO()
                fd = self.f.map(sio)
                return fd #signals that we want to copy!
            if fdint == fdintCLOSE_FILE_INFO:
                sio = self.f.unmap(notify.hf)
                sio.close()
                return 1
            return -1

        try:
            return self.__FDICopy(callback) != 0
        except (CabinetError, IOError):
            return False

class CabinetInfo(object):
    """A simple class to encapsulate information about cabinet members"""
    def __init__(self, filename=None, date_time=None):
        self.filename, self.date_time = filename, date_time
        self.file_size = 0
        self.external_attr = 0

    def __repr__(self):
        return "<CabinetInfo %s, size=%s, date=%r, attrib=%x>"%(self.filename, self.file_size, self.date_time, self.external_attr)

def DecodeFATTime(FATdate, FATtime):
    """Convert the 2x16 bits of time in the FAT system to a tuple"""
    day = FATdate & 0x1f
    month = (FATdate >> 5) & 0xf
    year = 1980 + (FATdate >> 9)
    sec = 2 * (FATtime & 0x1f)
    min = (FATtime >> 5) & 0x3f
    hour = FATtime >> 11
    return (year, day, month, hour, min, sec)


def main(args = None):
    import textwrap
    USAGE=textwrap.dedent("""\
        Usage:
            cabinet.py -l cabinet.cab        # Show listing of a cab file
            cabinet.py -t cabinet.cab        # Test if a cab file is valid
            cabinet.py -e cabinet.cab target # Extract cab file into target dir
        """)
        #    cabinet.py -c cabinet.cab src ... # Create cab file from sources
        #""")
    if args is None:
        args = sys.argv[1:]

    if not args or args[0] not in ('-l', '-e', '-t'):
        print(USAGE)
        sys.exit(1)

    if args[0] == '-l':
        if len(args) != 2:
            print(USAGE)
            sys.exit(1)
        zf = CabinetFile(args[1])
        zf.printdir()
        zf.close()

    elif args[0] == '-t':
        if len(args) != 2:
            print(USAGE)
            sys.exit(1)
        zf = CabinetFile(args[1])
        print(zf.testcabinet())
        print("Done testing")

    elif args[0] == '-e':
        if len(args) != 3:
            print(USAGE)
            sys.exit(1)

        zf = CabinetFile(args[1])
        out = args[2]
        zf.extract(out)
        zf.close()

    elif False and args[0] == '-c':
        # not supported
        if len(args) < 3:
            print(USAGE)
            sys.exit(1)

        def addToZip(zf, path, zippath):
            if os.path.isfile(path):
                zf.write(path, zippath, ZIP_DEFLATED)
            elif os.path.isdir(path):
                for nm in os.listdir(path):
                    addToZip(zf,
                            os.path.join(path, nm), os.path.join(zippath, nm))
            # else: ignore

        zf = ZipFile(args[1], 'w', allowZip64=True)
        for src in args[2:]:
            addToZip(zf, src, os.path.basename(src))

        zf.close()

# if __name__ == "__main__":
#     main()


# -------------------------------------------------------------------------
# KavMain 클래스
# -------------------------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    #         verbose      - 디버그 모드 (True or False)
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):  # 플러그인 엔진 초기화
        self.handle = {}
        self.temp_path = {}

        if not LOAD_WINTYPES:
            return -1

        pid = os.getpid()
        self.root_temp_path = os.path.join(tempfile.gettempdir(), 'ktmp%05x' % pid)

        return 0  # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.1'  # 버전
        info['title'] = 'Cab Archive Engine'  # 엔진 설명
        info['kmd_name'] = 'cab'  # 엔진 파일 이름
        info['engine_type'] = kernel.ARCHIVE_ENGINE  # 엔진 타입

        return info

    # ---------------------------------------------------------------------
    # __get_handle(self, filename)
    # 압축 파일의 핸들을 얻는다.
    # 입력값 : filename   - 파일 이름
    # 리턴값 : 압축 파일 핸들
    # ---------------------------------------------------------------------
    def __get_handle(self, filename):
        if filename in self.handle:  # 이전에 열린 핸들이 존재하는가?
            zfile = self.handle.get(filename, None)
        else:
            zfile = CabinetFile(filename)  # cab 파일 열기
            self.handle[filename] = zfile
            self.temp_path[filename] = tempfile.mktemp(prefix='ktmp', dir=self.root_temp_path)

        return zfile

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #          filename   - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        fileformat = {}  # 포맷 정보를 담을 공간

        mm = filehandle
        if mm[0:4] == 'MSCF':  # 헤더 체크
            fileformat['size'] = len(mm)  # 포맷 주요 정보 저장

            ret = {'ff_cab': fileformat}
            return ret

        return None

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 CAB 포맷이 있는가?
        if 'ff_cab' in fileformat:
            zfile = self.__get_handle(filename)

            cab_extract_path = self.temp_path.get(filename, None)
            if cab_extract_path:
                zfile.extract(cab_extract_path)

                try:
                    for name in zfile.namelist():
                        file_scan_list.append(['arc_cab', name])

                except CabinetError:
                    pass

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_cab':
            cab_extract_path = self.temp_path.get(arc_name, None)
            tname = os.path.join(cab_extract_path, fname_in_arc)
            if os.path.exists(tname):
                data = open(tname, 'rb').read()
                os.remove(tname)
                return data

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        for fname in self.handle.keys():
            zfile = self.handle[fname]
            zfile.close()

            cab_extract_path = self.temp_path.get(fname, None)
            if os.path.exists(cab_extract_path):
                shutil.rmtree(cab_extract_path)

            self.handle.pop(fname)
            self.temp_path.pop(fname)
