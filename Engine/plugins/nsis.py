# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import mmap
import struct
import tempfile
import zlib
import pylzma
import kernel
import kavutil
import cryptolib

import datetime
from ctypes import *

# ----------------------------------------------------------------------------
# NSIS용 구조체
# ----------------------------------------------------------------------------
BYTE = c_ubyte
WORD = c_ushort
LONG = c_long
DWORD = c_ulong
FLOAT = c_float
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_ulong
SIZE_T = c_ulong

class StructNsisHeader(Structure):
    _pack_ = 1
    _fields_ = [
        ('flag',            DWORD),
        ('pages',           DWORD),
        ('pages_num',       DWORD),
        ('sections',        DWORD),
        ('sections_num',    DWORD),
        ('entries',         DWORD),
        ('entries_num',     DWORD),
        ('strings',         DWORD),
        ('strings_num',     DWORD),
        ('langtables',      DWORD),
        ('langtables_num',  DWORD),
        ('ctlcolors',       DWORD),
        ('ctlcolors_num',   DWORD),
        ('bgfont',          DWORD),
        ('bgfont_num',      DWORD),
        ('data',            DWORD),
        ('data_num',        DWORD)
    ]


class StructNsisRecord(Structure):
    _pack_ = 1
    _fields_ = [
        ('which',       DWORD),
        ('parm0',       LONG),
        ('parm1',       LONG),
        ('parm2',       LONG),
        ('parm3',       LONG),
        ('parm4',       LONG),
        ('parm5',       LONG)
    ]


NsisVarNames = {
    # init with 1
    0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6', 7: '7', 8: '8', 9: '9',
    10: 'R0', 11: 'R1', 12: 'R2', 13: 'R3', 14: 'R4', 15: 'R5', 16: 'R6', 17: 'R7', 18: 'R8', 19: 'R9',
    20: 'CMDLINE', 21: 'INSTDIR', 22: 'OUTDIR', 23: 'EXEDIR', 24: 'LANGUAGE',

    # init with -1
    25: 'TEMP', 26: 'PLUGINSDIR', 27: 'EXEPATH', 28: 'EXEFILE', 29: 'HWNDPARENT', 30: '_CLICK',

    # init with 1
    31: '_OUTDIR'
    }


class NSIS:
    TYPE_LZMA = 0
    TYPE_BZIP = 1
    TYPE_ZLIB = 2

    def __init__(self, filename, verbose):
        self.verbose = verbose
        self.filename = filename
        self.fp = None
        self.mm = None

        self.nsis_header = None
        self.body_data = None
        self.case_type = 0

    def parse(self):
        self.fp = open(self.filename, 'rb')
        fsize = os.path.getsize(self.filename)
        if fsize == 0:
            return False

        self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

        flag = kavutil.get_uint32(self.mm, 0)
        head_size = kavutil.get_uint32(self.mm, 0x14)
        comp_size = kavutil.get_uint32(self.mm, 0x18)

        data, case_type = self.get_data()  # NSIS의 모든 데이터를 가진다.
        self.body_data = data
        self.case_type = case_type

        if self.verbose:
            print '-' * 79
            kavutil.vprint('Engine')
            kavutil.vprint(None, 'Engine', 'nsis.kmd')
            kavutil.vprint(None, 'File name', os.path.split(self.filename)[-1])

            print
            kavutil.vprint('NSIS')
            kavutil.vprint(None, 'Flag', '%d' % flag)
            kavutil.vprint(None, 'Uncompress Case', '%d' % case_type)

            print
            kavutil.vprint('Uncompress Data')
            print
            kavutil.HexDump().Buffer(data, 0, 0x80)

            s = self.nsis_header.namelist_ex()
            if len(s):
                print
                kavutil.vprint('File Extract')
                print
                for t in s:
                    (foff, fname, ftime, extract_type) = t
                    print "%08X | %-45s | %s" % (foff, fname, ftime if ftime != '' else 'N/A')

        return True

    def namelist(self):
        return self.nsis_header.namelist()

    def read(self, filename):
        if filename in self.nsis_header.files:
            data = None
            (foff, ftime, extract_type) = self.nsis_header.files[filename]

            if self.case_type == 1:  # case 1: 설치 파일 전부를 압축한 경우
                # print '#Case 1'
                # print hex(foff)
                # print hex(kavutil.get_uint32(self.body_data, foff) & 0x7fffffff)
                fsize = kavutil.get_uint32(self.body_data, foff) & 0x7fffffff
                return self.body_data[foff+4:foff+4+fsize]
            elif self.case_type == 2:  # case 2: 개별로 압축한 경우
                # print '#Case 2'
                # print hex(foff)
                # print hex(kavutil.get_uint32(self.body_data, foff) & 0x7fffffff)
                fsize = kavutil.get_uint32(self.body_data, foff) & 0x7fffffff
                fdata = self.body_data[foff+4:foff+4+fsize]
                comp_type = self.__get_comp_type(kavutil.get_uint32(fdata, 0))
                # print comp_type
                if comp_type == self.TYPE_LZMA:
                    try:  # 전체 압축한 경우인지 확인해 본다.
                        data = pylzma.decompress(fdata)
                    except TypeError:
                        pass
                elif comp_type == self.TYPE_ZLIB:
                    try:
                        data = zlib.decompress(fdata, -15)
                    except zlib.error:
                        pass
            return data
        else:
            return None

    def close(self):
        if self.mm:
            self.mm.close()
            self.mm = None

        if self.fp:
            self.fp.close()
            self.fp = None

    def get_data(self):
        # NSIS가 두가지 종류가 있는것으로 보여짐
        # 설치 파일 전부를 압축한 경우와 개별로 압축한 경우

        # case 1: 설치 파일 전부를 압축한 경우
        try:
            head_size = kavutil.get_uint32(self.mm, 0x14)
            comp_size = kavutil.get_uint32(self.mm, 0x18)
            comp_type = self.__get_comp_type(kavutil.get_uint32(self.mm, 0x1C))
            uncmp_data = self.do_decompress(comp_type, 0x1C, comp_size)
            if uncmp_data:
                if head_size == kavutil.get_uint32(uncmp_data, 0):
                    self.nsis_header = NSISHeader(uncmp_data[4:head_size + 4])
                    if self.nsis_header.parse():
                        return uncmp_data[head_size + 4:], 1
        except struct.error:
            pass

        # case 2: 개별로 압축한 경우
        try:
            head_size = kavutil.get_uint32(self.mm, 0x14)
            comp_size = kavutil.get_uint32(self.mm, 0x1C) & 0x7fffffff
            comp_type = self.__get_comp_type(kavutil.get_uint32(self.mm, 0x20))
            uncmp_data = self.do_decompress(comp_type, 0x20, comp_size)
            if uncmp_data:
                if head_size == len(uncmp_data):
                    self.nsis_header = NSISHeader(uncmp_data)
                    if self.nsis_header.parse():
                        return self.mm[0x20+comp_size:], 2
        except struct.error:
            pass

        return None, 0

    def do_decompress(self, comp_type, off, size):
        comp_success = True
        if comp_type == self.TYPE_LZMA:
            try:  # 전체 압축한 경우인지 확인해 본다.
                uncmp_data = pylzma.decompress(self.mm[off:off+size])
            except TypeError:
                comp_success = False
        elif comp_type == self.TYPE_ZLIB:
            try:  # 전체 압축한 경우인지 확인해 본다.
                uncmp_data = zlib.decompress(self.mm[off:off+size], -15)
            except zlib.error:
                comp_success = False
        else:
            uncmp_data = None
            comp_success = False

        if comp_success:
            return uncmp_data

    def __get_comp_type(self, data_size):
        if data_size & 0x7fffffff == 0x5d:
            return self.TYPE_LZMA
        elif data_size & 0xff == 0x31:
            return self.TYPE_BZIP
        else:
            return self.TYPE_ZLIB

    def __del(self):
        self.close()

class NSISHeader:
    def __init__(self, data):
        self.mm = data
        self.header_data = None

        self.nh = None
        self.strings_max = 0
        self.ver3 = None
        self.is_unicode = 0  # 1: str, 2:unicode

        # # nsis-2.09-src
        self.ns_skip_code = 252  # 0xfc : to consider next character as a normal character
        self.ns_var_code = 253  # 0xfd : for a variable
        self.ns_shell_code = 254  # 0xfe : for a shell folder path
        self.ns_lang_code = 255  # 0xff : for a langstring

        self.ns_codes_start = 0

        self.files = {}
        self.success = False

    def __set_value(self):
        # 유니코드 데이터 셋인가?
        if self.header_data[self.nh.strings:self.nh.strings + 2] == '\x00\x00':
            self.is_unicode = 2  # 유니코드 맞음
        else:
            self.is_unicode = 1

        self.strings_max = self.nh.langtables - self.nh.strings  # 최대 문자열 길이

        # NSIS 헤더의 정보중 데이터 영역의 특정 위치에 글자를 확인하여 Ver3인지 체크
        off = self.nh.strings + (0x11 * self.is_unicode)
        d = self.header_data[off:off + (14 * self.is_unicode)]
        self.ver3 = bool(self.__binary_unicode_to_str(d) == "CommonFilesDir")

        if self.ver3:
            self.ns_skip_code = -self.ns_skip_code & 0xff
            self.ns_var_code = -self.ns_var_code & 0xff
            self.ns_shell_code = -self.ns_shell_code & 0xff
            self.ns_lang_code = -self.ns_lang_code & 0xff
        # end if

        self.ns_codes_start = self.ns_skip_code

        self.__processentries()

    def __binary_str_to_unicode(self, s):
        if self.is_unicode == 2:
            s = s.decode('utf-8', errors='replace')
            s = str(buffer(s))

        return s

    def __binary_unicode_to_str(self, us):
        if self.is_unicode == 2:
            us = us.decode("utf-16", errors='replace').encode('cp949', errors='replace')

        return us

    def __get_user_var_name(self, n_data):
        if n_data < 0:
            return self.__get_string(n_data)

        static_user_vars = len(NsisVarNames)
        if n_data in range(static_user_vars):
            return '$' + NsisVarNames[n_data]
        else:
            return '$%d' % (n_data - static_user_vars)

    def __decode_short(self, off):
        a = ord(self.header_data[off])
        b = ord(self.header_data[off + 1])
        n_data = ((b & ~0x80) << 7) | (a & ~0x80)

        return n_data

    def __get_string(self, str_off):
        if str_off < 0:
            off = self.nh.langtables + 2 + 4 + -str_off * 4
            str_off = kavutil.get_uint32(self.header_data, off)

        if (str_off * self.is_unicode) in range(0, self.strings_max):
            str_data = ''

            off = self.nh.strings + (str_off * self.is_unicode)

            char = self.header_data[off:off + (1 * self.is_unicode)]
            off += (1 * self.is_unicode)

            while char != '\x00' * self.is_unicode and len(char) != 0:
                if self.is_unicode == 2:
                    ch = struct.unpack('<H', char)[0]
                else:
                    ch = ord(char)

                if (ch >= self.ns_codes_start) if self.ver3 else (ch < self.ns_codes_start):
                    str_data += char
                elif ch == self.ns_var_code:
                    n_data = self.__decode_short(off)
                    off += 2
                    str_data += self.__binary_str_to_unicode(self.__get_user_var_name(n_data))

                char = self.header_data[off:off + (1 * self.is_unicode)]
                off += (1 * self.is_unicode)
            # end while

            str_data = self.__binary_unicode_to_str(str_data)

            return str_data
        else:
            return ''

    def __processentries(self):
        off = self.nh.entries

        for i in range(self.nh.entries_num):
            nr = StructNsisRecord()
            memmove(addressof(nr), self.header_data[off:], sizeof(nr))
            off += sizeof(nr)

            if nr.which == 20:  # EW_EXTRACTFILE
                dt = ''
                try:
                    ft_dec = struct.unpack('>Q', struct.pack('>ll', nr.parm4, nr.parm3))[0]

                    # UnixTimeToFileTime http://support.microsoft.com/kb/167296
                    dt = datetime.datetime.fromtimestamp((ft_dec - 116444736000000000) / 10000000)
                except struct.error:
                    pass
                except ValueError:
                    pass

                file_name = self.__get_string(nr.parm1).replace('\\', '/')
                file_offset = nr.parm2

                self.files[file_name] = (file_offset, dt, nr.which)
            elif nr.which == 62:  # EW_WRITEUNINSTALLER
                file_name = self.__get_string(nr.parm0).replace('\\', '/')
                file_offset = nr.parm1

                # print hex(nr.parm2)
                # print hex(nr.parm3)
                # print hex(nr.parm4)
                # print hex(nr.parm5)

                self.files[file_name] = (file_offset, '', nr.which)

    def parse(self):
        if self.header_data:  # 이미 분석되었다면 분석하지 않는다.
            return self.success

        self.header_data = self.mm

        self.nh = StructNsisHeader()  # 헤더 읽기
        memmove(addressof(self.nh), self.header_data[0:], sizeof(self.nh))

        self.__set_value()  # 주요 값 셋팅

        self.success = True
        return self.success

    def namelist(self):
        return self.files.keys()

    def namelist_ex(self):
        fl = []

        for filename in self.files.keys():
            (file_offset, file_time, extract_type) = self.files[filename]
            fl.append((file_offset, filename, file_time, extract_type))

        fl.sort()
        return fl

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
        self.verbose = verbose
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
        info['version'] = '1.0'  # 버전
        info['title'] = 'NSIS Engine'  # 엔진 설명
        info['kmd_name'] = 'nsis'  # 엔진 파일 이름

        return info

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #          filename   - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        ret = {}

        mm = filehandle
        if mm[4:20] == '\xEF\xBE\xAD\xDENullsoftInst':
            ret = {'ff_nsis': 'NSIS'}

        return ret

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 ff_nsis 포맷이 있는가?
        if 'ff_nsis' in fileformat:
            n = NSIS(filename, self.verbose)
            if n.parse():
                for name in n.namelist():
                    file_scan_list.append(['arc_nsis', name])
                n.close()
        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_nsis':
            n = NSIS(arc_name, False)
            if n.parse():
                data = n.read(fname_in_arc)
                n.close()
                return data

        return None

    # ---------------------------------------------------------------------
    # feature(self, filehandle, filename, fileformat, malware_id)
    # 파일의 Feature를 추출한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    #         fileformat  - 파일 포맷
    #         filename_ex - 파일 이름 (압축 내부 파일 이름)
    #         malware_id  - 악성코드 ID
    # 리턴값 : Feature 추출 성공 여부
    # ---------------------------------------------------------------------
    def feature(self, filehandle, filename, fileformat, filename_ex, malware_id):  # Feature 추출
        try:
            mm = filehandle

            # 미리 분석된 파일 포맷중에 NSIS 포맷이 있는가?
            # 파일의 전체 영역에 대해 MD5를 구하기 위해 ff_attach를 확인한다.
            if 'ff_attach' in fileformat:
                foff = fileformat['ff_attach']['Attached_Pos']

                # NSIS가 맞나?
                if mm[foff+4:foff+20] == '\xEF\xBE\xAD\xDENullsoftInst':
                    buf = mm[:]
                    fmd5 = cryptolib.md5(buf).decode('hex')  # 파일 전체 MD5 생성
                    header = 'NSIS' + struct.pack('<L', malware_id) + fmd5

                    rname = tempfile.mktemp(prefix='ktmp')
                    open(rname, 'wb').write(mm[foff:])

                    max_len = 0
                    max_extract_data = ''  # 용량이 큰 파일

                    n = NSIS(rname, False)
                    if n.parse() is False:
                        n.close()
                        return False

                    for name in n.namelist():
                        data = n.read(name)
                        if data is None:
                            continue

                        data_len = len(data)
                        if max_len < data_len:
                            max_len = data_len
                            max_extract_data = data

                    # Feature 추출
                    f = kavutil.Feature()

                    data = ''
                    # 1. NSIS 내부 파일 중 용량이 제일 큰 파일을 찾아 엔트로피를 추출한다.
                    data += f.entropy(max_extract_data)

                    # 2. NSIS 헤더 정보를 추출한다.
                    data += n.nsis_header.header_data[:256]

                    # 3. NSIS 헤더의 문자열을 추출 후 2-gram 처리한다.
                    data += f.k_gram(n.nsis_header.header_data, 2)

                    # 4. NSIS 스크립트의 OPcode를 추출한다.
                    t = [0] * 256
                    off = n.nsis_header.nh.entries

                    for i in range(n.nsis_header.nh.entries_num):
                        nr = StructNsisRecord()
                        memmove(addressof(nr), n.nsis_header.header_data[off:], sizeof(nr))
                        off += sizeof(nr)

                        if t[nr.which & 0xff] < 0xff:
                            t[nr.which & 0xff] += 1  # Opcode 등장 회수를 누적

                    data += ''.join(map(chr, t))
                    n.close()

                    open('nsis.bin', 'ab').write(header + data)  # Feature 파일 생성
                    os.remove(rname)

                    return True
        except IOError:
            pass

        # Feature 추출 실패했음을 리턴한다.
        return False
