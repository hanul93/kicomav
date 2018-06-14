# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import zlib
import kernel
import kavutil
import cryptolib
import ole

import tempfile
import shutil
import struct
import math
from ctypes import *


# -------------------------------------------------------------------------
# 악성코드 ID
# -------------------------------------------------------------------------
MALWARE_ID_WORD95 = 0
MALWARE_ID_WORD97 = 1
MALWARE_ID_EXCEL95 = 2
MALWARE_ID_EXCEL97 = 3
MALWARE_ID_EXCEL_FORMULA95 = 4
MALWARE_ID_EXCEL_FORMULA97 = 5
MALWARE_ID_OLE = 99


# -------------------------------------------------------------------------
# 워드95 매크로 구조체 정의
# -------------------------------------------------------------------------
BYTE = c_ubyte
WORD = c_ushort
DWORD = c_uint
FLOAT = c_float
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_uint
SIZE_T = c_uint


class MCD(Structure):
    _pack_ = 1
    _fields_ = [
        ('cmg',          BYTE),
        ('bEncrypt',     BYTE),
        ('ibst',         WORD),
        ('ibsName',      WORD),
        ('ibstMenuHelp', WORD),
        ('fcFirst',      DWORD),
        ('dfc',          DWORD),
        ('fn',           DWORD),
        ('fcFirstSave',  DWORD)
    ]


# -------------------------------------------------------------------------
# 엔진 오류 메시지를 정의
# -------------------------------------------------------------------------
class Error(Exception):
    pass


# ---------------------------------------------------------------------
# 데이터 읽기
# ---------------------------------------------------------------------
def get_uint16(t_data, off):
    return struct.unpack('<H', t_data[off:off + 2])[0]


def get_uint32(t_data, off):
    return struct.unpack('<L', t_data[off:off + 4])[0]


def get_biff_record_size16(t_data, off):
    l = get_uint16(t_data, off+2)
    return t_data[off:off+4+l]


def get_record_size32(t_data, off):
    l = get_uint32(t_data, off+2)
    return t_data[off:off+6+l]


# ---------------------------------------------------------------------
# 데이터 생성
# ---------------------------------------------------------------------
def set_uint16(val):
    return struct.pack('<H', val)


def set_uint32(val):
    return struct.pack('<L', val)


# ---------------------------------------------------------------------
# Word97.Macro 치료
# ---------------------------------------------------------------------
def cure_word97_macro(data, verbose=False):
    if ord(data[0x0B]) & 0x01 == 0x01:
        if verbose:
            print 'PASSWORD'
        return False, None  # 문서에 암호가 설정되어 있음

    data = data[:0x15E] + '\x00\x00\x00\x00' + data[0x162:]
    return True, data


# ---------------------------------------------------------------------
# Excel95.Macro 치료
# ---------------------------------------------------------------------
def cure_excel95_macro(data):
    d1 = get_biff_record_size16(data, 0)
    d2 = get_biff_record_size16(data, len(d1))
    d3 = get_biff_record_size16(data, len(d1) + len(d2))

    if get_uint16(d2, 0) == 0x002F or get_uint16(d3, 0) == 0x002F:
        return False, None  # Sheet에 암호가 설정되어 있음

    # book에 존재하는 매크로를 치료한다.
    off = 0

    while off < len(data):
        t_data = get_biff_record_size16(data, off)
        val = get_uint16(t_data, 0)
        size = get_uint16(t_data, 2)

        # BIFF 레코드를 조작한다.
        if val == 0x0085:  # Sheet
            worksheet_pos = get_uint32(t_data, 4)
            if get_uint16(data, worksheet_pos+6) == 0x06:  # 매크로 포함된 Sheet : dt
                t_ret, data = cure_excel_worksheet(data, worksheet_pos)
                if t_ret is False:
                    return False, None

                data = data[:off+8] + set_uint16(0x0001) + data[off+10:]

                len_sheet_name = ord(data[off+10])
                data = data[:off+11] + (' ' * len_sheet_name) + data[off+11+len_sheet_name:]
        elif val == 0x00D3 or val == 0x01BA:  # ObProj or CodeName
            data = data[:off] + set_uint16(0x22) + data[off+2:]
        elif val == 0x000A or val == 0x0000:  # EOF
            break

        off += len(t_data)

    return True, data


# ---------------------------------------------------------------------
# Word95.Macro 치료
# ---------------------------------------------------------------------
def cure_word95_macro(data):
    # Word95인지 확인
    start_macro = get_uint32(data, 0x118)
    if ord(data[start_macro]) != 0xff:
        return False, None

    # 매크로 존재 여부 삭제 처리
    macro_magic = ord(data[0xa]) & 0xfe
    data = data[:0xa] + chr(macro_magic) + data[0xa+1:]
    data = data[:0x11c] + '\x02\x00\x00\x00' + data[0x11c+4:]

    off = start_macro + 1

    while True:
        # print hex(off)
        cmd = ord(data[off])
        off += 1

        if cmd == 0x01:  # chHplmcd
            num_macro = get_uint16(data, off)
            off += 2
            break
        elif cmd == 0x02:  # chHplacd
            off += (get_uint16(data, off) * 0x04) + 2
        elif cmd == 0x03 or cmd == 0x04:  # chHplkme or chHplkmeBad
            off += (get_uint16(data, off) * 0x0e) + 2
        elif cmd == 0x05:  # chHplmud
            off += (get_uint16(data, off) * 0x0c) + 2
        elif cmd == 0x10:  # chHsttb
            off += get_uint16(data, off)
        elif cmd == 0x11:  # chMacroNames
            k = get_uint16(data, off)
            off += 2

            for i in range(k):
                off += 2
                off += ord(data[off]) + 2
        elif cmd == 0x40:  # chTcgEnd
            return False, None

    # print num_macro  # 워드 매크로 개수

    mcd = []
    for i in range(num_macro):
        t = MCD()
        memmove(addressof(t), data[off:], sizeof(t))
        t.fn = 0
        data = data[:off] + buffer(t)[:] + data[off+sizeof(t):]
        mcd.append(t)
        off += sizeof(t)

    for i, macro in enumerate(mcd):
        t_size = macro.dfc
        t_off = macro.fcFirstSave
        data = data[:t_off] + ('\x00' * t_size) + data[t_off+t_size:]

    data = data[:start_macro + 1] + '\x40' + data[start_macro + 2:]

    return True, data


# ---------------------------------------------------------------------
# Excel97.Macro 치료
# ---------------------------------------------------------------------
def cure_excel97_macro(data, verbose=False):
    d1 = get_biff_record_size16(data, 0)
    d2 = get_biff_record_size16(data, len(d1))
    d3 = get_biff_record_size16(data, len(d1) + len(d2))

    if get_uint16(d2, 0) == 0x002F or get_uint16(d3, 0) == 0x002F:
        if verbose:
            print 'PASSWORD'
        return False, None  # Sheet에 암호가 설정되어 있음

    # Workbook에 존재하는 매크로를 치료한다.
    off = 0

    while off < len(data):
        t_data = get_biff_record_size16(data, off)
        val = get_uint16(t_data, 0)
        size = get_uint16(t_data, 2)

        # if size > 8192:  # 데이터 길이가 너무 길다
        #     return False, None

        # BIFF 레코드를 조작한다.
        if val == 0x0085:  # Sheet
            worksheet_pos = get_uint32(t_data, 4)
            if get_uint16(data, worksheet_pos+6) == 0x06:  # 매크로 포함된 Sheet : dt
                t_ret, data = cure_excel_worksheet(data, worksheet_pos)
                if t_ret is False:
                    if verbose:
                        print 'SHEET'
                    return False, None

                data = data[:off+8] + set_uint16(0x0001) + data[off+10:]
                data = data[:off+12] + (' ' * (size - 8)) + data[off+12+(size-8):]
        elif val == 0x00D3 or val == 0x01BA:  # ObProj or CodeName
            data = data[:off] + set_uint16(0x22) + data[off+2:]
        elif val == 0x000A or val == 0x0000:  # EOF
            break

        off += len(t_data)

    return True, data


# ---------------------------------------------------------------------
# Excel97.Formula 치료
# ---------------------------------------------------------------------
def cure_excel97_formula(data):
    d1 = get_biff_record_size16(data, 0)
    d2 = get_biff_record_size16(data, len(d1))
    d3 = get_biff_record_size16(data, len(d1) + len(d2))

    if get_uint16(d2, 0) == 0x002F or get_uint16(d3, 0) == 0x002F:
        return False, None  # Sheet에 암호가 설정되어 있음

    # Workbook에 존재하는 포뮬라를 치료한다.
    off = 0

    while off < len(data):
        t_data = get_biff_record_size16(data, off)
        val = get_uint16(t_data, 0)
        size = get_uint16(t_data, 2)

        # BIFF 레코드를 조작한다.
        if val == 0x0085:  # Sheet
            worksheet_pos = get_uint32(t_data, 4)
            us = get_uint16(data, off + 8)
            if us & 0x0f00 == 0x0100 or us == 0x40:
                data = data[:off + 8] + '\x02\x00' + data[off + 10:]
                data = data[:off + 12] + (' ' * (size - 8)) + data[off + 12 + (size - 8):]

                t_ret, data = cure_excel_worksheet(data, worksheet_pos, del_formula=True)
                if t_ret is False:
                    return False, None
        elif val == 0x0018:
            data = data[:off+4] + ('\x00' * size) + data[off+4+size:]
        elif val == 0x000A or val == 0x0000:  # EOF
            break

        off += len(t_data)

    return True, data


# ---------------------------------------------------------------------
# Excel Sheet 치료
# ---------------------------------------------------------------------
def cure_excel_worksheet(data, off, excel_version=MALWARE_ID_EXCEL95, del_formula=False):
    while off < len(data):
        t_data = get_biff_record_size16(data, off)
        val = get_uint16(t_data, 0)
        size = get_uint16(t_data, 2)

        if val == 0x0809:  # BOF
            data = data[:off+6] + set_uint16(0x10) + data[off+8:]
        elif val == 0x023E:  # Window2
            t = set_uint16(0x08BE) + ('\x00' * (size - 2))
            data = data[:off+4] + t + data[off+size+4:]
        elif val == 0x0006:
            if del_formula:  # 포뮬라 치료
                t_size = len(t_data[0x1b:]) - 2
                data = data[:off+0x1a] + '\x17' + set_uint16(t_size) + ('\x00' * t_size) + data[off+0x1d+t_size:]
        elif val == 0x000A or val == 0x0000:  # EOF
            break

        off += len(t_data)

    return True, data


# ---------------------------------------------------------------------
# 매크로 치료를 담당한다.
# ---------------------------------------------------------------------
def cure_office_macro(filename, malware_id):
    cure_macro_ref = {
        MALWARE_ID_WORD95: (None, 'WordDocument', cure_word95_macro),
        MALWARE_ID_WORD97: ('Macros', 'WordDocument', cure_word97_macro),
        MALWARE_ID_EXCEL95: ('_VBA_PROJECT', 'Book', cure_excel95_macro),
        MALWARE_ID_EXCEL97: ('_VBA_PROJECT_CUR', 'Workbook', cure_excel97_macro),
        MALWARE_ID_EXCEL_FORMULA97: (None, 'Workbook', cure_excel97_formula),
    }

    ret = False
    try:
        o = ole.OleFile(filename, write_mode=True)
        ole_lists = o.listdir(streams=True, storages=True)

        for name in ole_lists:
            pps = name.split('/')
            if cure_macro_ref[malware_id][0] and pps[-1] == cure_macro_ref[malware_id][0]:
                o.delete(name)
            elif pps[-1] == cure_macro_ref[malware_id][1]:
                pics = o.openstream(name)
                t_data = pics.read()
                t_ret, t_data = cure_macro_ref[malware_id][2](t_data, verbose=True)

                if t_ret:
                    o.write_stream(name, t_data)
                    ret = True
                else:
                    ret = False
        o.close()
    except IOError:
        pass

    return ret


# ---------------------------------------------------------------------
# dir 스트림을 분석한다.
# 입력값 : data - 압축 해제된 버퍼
# 리턴값 : Office97 내부에 각 매크로의 위치를 리턴
# ---------------------------------------------------------------------
def analysis_dir_stream(data, verbose=False):
    off = dir_informationrecord(data, 0, verbose)
    off = dir_referencesrecord(data, off, verbose)
    vba_modules = dir_modulesrecord(data, off, verbose)

    return vba_modules


def dir_informationrecord(data, off, verbose=False):
    val = get_uint16(data, off)
    if val != 0x0001:
        raise Error('dir:InformationRecord:SysKindRecord')
    off += 10

    val = get_uint16(data, off)
    if val != 0x0002:
        raise Error('dir:InformationRecord:LcidRecord')
    off += 10

    val = get_uint16(data, off)
    if val != 0x0014:
        raise Error('dir:InformationRecord:LcidInvokeRecord')
    off += 10

    val = get_uint16(data, off)
    if val != 0x0003:
        raise Error('dir:InformationRecord:CodePageRecord')
    off += 8

    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x0004:
        raise Error('dir:InformationRecord:NameRecord')
    off += len(t_data)

    if verbose:
        print 'Name : %s' % t_data[6:]

    # DocStringRecord에는 2개의 레코드가 존재함
    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x0005:
        raise Error('dir:InformationRecord:DocStringRecord #1')
    off += len(t_data)

    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x0040:
        raise Error('dir:InformationRecord:DocStringRecord #2')
    off += len(t_data)

    # HelpFilePathRecord에는 2개의 레코드가 존재함
    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x0006:
        raise Error('dir:InformationRecord:HelpFilePathRecord #1')
    off += len(t_data)

    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x003D:
        raise Error('dir:InformationRecord:HelpFilePathRecord #2')
    off += len(t_data)

    val = get_uint16(data, off)
    if val != 0x0007:
        raise Error('dir:InformationRecord:HelpContextRecord')
    off += 10

    val = get_uint16(data, off)
    if val != 0x0008:
        raise Error('dir:InformationRecord:LibFlagsRecord')
    off += 10

    val = get_uint16(data, off)
    if val != 0x0009:
        raise Error('dir:InformationRecord:VersionRecord')
    off += 12

    # ConstantsRecord에는 2개의 레코드가 존재함
    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x000C:
        raise Error('dir:InformationRecord:ConstantsRecord #1')
    off += len(t_data)

    t_data = get_record_size32(data, off)
    val = get_uint16(t_data, 0)
    if val != 0x003C:
        raise Error('dir:InformationRecord:ConstantsRecord #2')
    off += len(t_data)

    return off


def dir_referencesrecord(data, off, verbose=False):
    while True:
        _follow = False     # modify by sungho
        # NameRecord에는 2개의 레코드가 존재함
        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)

        if val != 0x0016:
            # raise Error('dir:ReferencesRecord:NameRecord #1')
            break

        off += len(t_data)

        if verbose:
            print 'ReferencesRecord Name : %s' % t_data[6:]

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x003E:
            raise Error('dir:ReferencesRecord:NameRecord #2')
        off += len(t_data)

        # ReferenceRecord
        val = get_uint16(data, off)
        if val == 0x0033:  # REFERENCEREGISTERED
            t_data = get_record_size32(data, off)
            off += len(t_data)
            t_data = get_record_size32(data, off)
            val = get_uint16(data, off)     # modify by sungho
            _follow = True

        # modify by sungho
        """ REFERENCEREGISTERED field is optional """
        if val == 0x002F:  # REFERENCECONTROL
            if _follow is False:
                t_data = get_record_size32(data, off)
            off += len(t_data)
            t_data = get_record_size32(data, off)
            if get_uint16(t_data, 0) == 0x0016:  # NameRecordExtended
                off += len(t_data)
                t_data = get_record_size32(data, off)
                if get_uint16(t_data, 0) == 0x003E:  # NameRecordExtended:Reserved
                    off += len(t_data)
                    t_data = get_record_size32(data, off)
                    if get_uint16(t_data, 0) == 0x0030:  # Reserved3
                        off += len(t_data)
                    else:
                        raise Error('dir:ReferencesRecord:ReferenceRecord:REFERENCECONTROL:Reserved3')
                else:
                    raise Error('dir:ReferencesRecord:ReferenceRecord:REFERENCECONTROL:NameRecordExtended:Reserved')
            else:
                raise Error('dir:ReferencesRecord:ReferenceRecord:REFERENCECONTROL:NameRecordExtended')

        elif val == 0x000D or val == 0x000E:  # REFERENCEPROJECT
            t_data = get_record_size32(data, off)
            off += len(t_data)
        else:
            raise Error('dir:ReferencesRecord:ReferenceRecord')

    return off


def dir_modulesrecord(data, off, verbose=False):
    vba_modules = []

    val = get_uint16(data, off)
    if val != 0x000F:
        raise Error('dir:ModulesRecord')
    off += 16

    while True:
        # 모듈 처리하기
        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0019:
            # raise Error('dir:ModulesRecord:NameRecord')
            break
        off += len(t_data)

        m_name = t_data[6:]

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0047:
            continue        # modify by sungho
            # raise Error('dir:ModulesRecord:NameUnicodeRecord')
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x001A:
            raise Error('dir:ModulesRecord:StreamNameRecord #1')
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0032:
            raise Error('dir:ModulesRecord:StreamNameRecord #2')
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x001C:
            raise Error('dir:ModulesRecord:DocStringRecord #1')
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0048:
            raise Error('dir:ModulesRecord:DocStringRecord #2')
        off += len(t_data)

        t_data = get_record_size32(data, off)
        val = get_uint16(t_data, 0)
        if val != 0x0031:
            raise Error('dir:ModulesRecord:OffsetRecord')

        m_off = get_uint32(t_data, 6)
        off += 40

        if verbose:
            print 'ModulesRecord Name : %s : %08X' % (m_name, m_off)

        vba_modules.append((m_name, m_off))

    return vba_modules


# ---------------------------------------------------------------------
# Office97의 매크로 소스코드를 압축 해제한다.
# data : 압축된 버퍼
# ---------------------------------------------------------------------
def decompress(data):
    if data[0] != chr(1):
        return False, None

    remainder = data[1:]

    decompressed = ''
    while len(remainder) != 0:
        decompressed_chunk, remainder = decompress_chunk(remainder)

        if decompressed_chunk is None:
            return False, decompressed

        decompressed += decompressed_chunk

    return True, decompressed


def parse_token_sequence(data):
    flags = ord(data[0])
    data = data[1:]
    result = []
    for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        if len(data) > 0:
            if flags & mask:
                result.append(data[0:2])
                data = data[2:]
            else:
                result.append(data[0])
                data = data[1:]
    return result, data


def offset_bits(data):
    number_of_bits = int(math.ceil(math.log(len(data), 2)))
    if number_of_bits < 4:
        number_of_bits = 4
    elif number_of_bits > 12:
        number_of_bits = 12
    return number_of_bits


def decompress_chunk(compressed_chunk):
    if len(compressed_chunk) < 2:
        return None, None

    header = ord(compressed_chunk[0]) + ord(compressed_chunk[1]) * 0x100
    size = (header & 0x0FFF) + 3
    flag_compressed = header & 0x8000
    data = compressed_chunk[2:2 + size - 2]

    if flag_compressed == 0:
        return data, compressed_chunk[size:]

    decompressed_chunk = ''
    while len(data) != 0:
        tokens, data = parse_token_sequence(data)
        for token in tokens:
            if len(token) == 1:
                decompressed_chunk += token
            else:
                if decompressed_chunk == '':
                    return None, None

                number_of_offset_bits = offset_bits(decompressed_chunk)
                copy_token = ord(token[0]) + ord(token[1]) * 0x100
                offset = 1 + (copy_token >> (16 - number_of_offset_bits))
                length = 3 + (((copy_token << number_of_offset_bits) & 0xFFFF) >> number_of_offset_bits)
                copy = decompressed_chunk[-offset:]
                copy = copy[0:length]
                length_copy = len(copy)

                while length > length_copy: #a#
                    if length - length_copy >= length_copy:
                        copy += copy[0:length_copy]
                        length -= length_copy
                    else:
                        copy += copy[0:length - length_copy]
                        length -= length - length_copy

                decompressed_chunk += copy

    return decompressed_chunk, compressed_chunk[size:]


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

        self.p_vba_cmt = re.compile(r'(\'|\bREM\b).*', re.IGNORECASE)
        self.p_vba_word = re.compile(r'\w{2,}')

        # 엑셀97 매크로 바이러스 의심
        '''
        # 아래 함수가 매크로 바이러스에는 최소 한개 이상 존재함
        | 033CF891 | sub                 | auto_open           |
        | 0B91220F | sub                 | workbook_open       |
        '''

        # 워드97 매크로 바이러스 의심
        '''
        # 아래 함수가 매크로 바이러스에는 최소 한개 이상 존재함
        | 4ECD2AA8 | sub                | document_open      |
        | 1A5D7046 | sub                | document_close     |
        | 030D71C1 | sub                | document_new       |
        | DD5903DB | sub                | autoexec           |

        | 839CE07A | vbproject          | vbcomponents       |
        | FC454C30 | vbcomponents       | item               |
        | 084E324F | codemodule         | insertlines        |

        | 700C7258 | base64             | abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789 |
        | 2B408807 | lib                | kernel32    |
        | 9CECF67D | alias              | createfilea |
        '''
        self.word97_macro_crcs = [set([0x839ce07a, 0xfc454c30, 0x084e324f]),
                                  set([0x700c7258, 0x2b408807, 0x9cecf67d])
        ]

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
        info['title'] = 'Macro Engine'  # 엔진 설명
        info['kmd_name'] = 'macro'  # 엔진 파일 이름
        info['sig_num'] = kavutil.handle_pattern_md5.get_sig_num('macro')+1  # 진단/치료 가능한 악성코드 수

        return info

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = kavutil.handle_pattern_md5.get_sig_vlist('macro')
        vlist.append('Virus.MSExcel.Laroux.Gen')
        vlist.sort()
        return vlist

    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat)
    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    #         fileformat  - 파일 포맷
    #         filename_ex - 파일 이름 (압축 내부 파일 이름)
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex):  # 악성코드 검사
        mm = filehandle
        o = None

        try:
            # 미리 분석된 파일 포맷중에 OLE 포맷이 있는가?
            if 'ff_ole' in fileformat:
                o = ole.OleFile(filename)

                # 취약점 공격인가?
                if len(o.exploit):
                    if o:
                        o.close()

                    return True, o.exploit[0], MALWARE_ID_OLE, kernel.INFECTED

                ole_lists = o.listdir()

                for pps_name in ole_lists:
                    if pps_name.lower().find('/vba/dir') != -1:  # 오피스 97 매크로 존재 여부
                        pics = o.openstream(pps_name)
                        data = pics.read()
                        ret, decom_data = decompress(data)  # dir 스트림 압축 해제
                        if ret:
                            vba_modules = analysis_dir_stream(decom_data)

                            t = pps_name.split('/')

                            for vba in vba_modules:
                                t[-1] = vba[0]
                                t_pps_name = '/'.join(t)

                                t_pics = o.openstream(t_pps_name)  # 매크로가 존재하는 스트림 열기
                                t_data = t_pics.read()
                                t_ret, buf = decompress(t_data[vba[1]:])  # 매크로 소스코드 획득 완료
                                buf = buf.replace('\r\n', '\n')

                                if t_ret:
                                    if self.verbose:
                                        # 매크로 소스코드 출력
                                        kavutil.vprint('Macro Source')
                                        kavutil.vprint(None, 'PPS', '%s' % t_pps_name)
                                        print buf

                                    buf = self.p_vba_cmt.sub('', buf)  # 주석문 제거
                                    buf = buf.lower()  # 영어 소문자로 통일

                                    key_words = self.p_vba_word.findall(buf)

                                    vba_keyword_crc32 = set()
                                    for i in range(len(key_words)-1):
                                        word = key_words[i] + key_words[i+1]
                                        c = zlib.crc32(word) & 0xffffffffL
                                        vba_keyword_crc32.add(c)

                                    # 테스트
                                    if self.verbose:
                                        max_len = len(key_words[0])

                                        t_word = []
                                        for i in range(len(key_words)-1):
                                            word = key_words[i] + key_words[i+1]
                                            c = zlib.crc32(word) & 0xffffffffL
                                            t_word.append([c, key_words[i], key_words[i+1]])

                                            if len(key_words[i+1]) > max_len:
                                                max_len = len(key_words[i+1])

                                        t_l = '+-' + ('-' * 8) + '-+-' + ('-' * max_len) + '-+-' + ('-' * max_len) + '-+'
                                        print t_l
                                        msg = '| %%-8s | %%-%ds | %%-%ds |' % (max_len, max_len)
                                        print msg % ('CRC32', 'Keyword #1', 'Keyword #2')
                                        print t_l

                                        msg = '| %%08X | %%-%ds | %%-%ds |' % (max_len, max_len)
                                        for n in t_word:
                                            print msg % (n[0], n[1], n[2])

                                        print t_l

                                    # Heuristic 검사
                                    for macro_crc in self.word97_macro_crcs:
                                        if macro_crc.issubset(vba_keyword_crc32):
                                            if o:
                                                o.close()
                                            return True, 'Virus.MSWord.Generic', MALWARE_ID_WORD97, kernel.SUSPECT

        except IOError:
            pass
        except ole.Error:
            pass

        if o:
            o.close()

        # 악성코드를 발견하지 못했음을 리턴한다.
        return False, '', -1, kernel.INFECTED

    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id)
    # 악성코드를 치료한다.
    # 입력값 : filename    - 파일 이름
    #        : malware_id - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    # ---------------------------------------------------------------------
    def disinfect(self, filename, malware_id):  # 악성코드 치료
        # OLE 취약점이면 바로 삭제
        if malware_id == MALWARE_ID_OLE:
            try:
                os.remove(filename)
                return True  # 치료 성공
            except IOError:
                return False

        # 치료 실패를 위해 임시 파일 생성
        t_name = tempfile.mktemp('k2ole')
        shutil.copy(filename, t_name)

        if malware_id == MALWARE_ID_EXCEL95:  # 엑셀95 치료?
            ret = cure_office_macro(filename, MALWARE_ID_EXCEL95)
        elif malware_id == MALWARE_ID_WORD95:  # 워드95 치료?
            ret = cure_office_macro(filename, MALWARE_ID_WORD95)
        elif malware_id == MALWARE_ID_EXCEL97:  # 엑셀97 치료?
            ret = cure_office_macro(filename, MALWARE_ID_EXCEL97)
        elif malware_id == MALWARE_ID_WORD97:  # 워드97 치료?
            ret = cure_office_macro(filename, MALWARE_ID_WORD97)
        else:  # 잘못된 악성코드 ID
            ret = False

        if ret:  # 치료 성공이면 임시 파일은 삭제
            os.remove(t_name)
        else:  # 실패면 임시 파일을 복원
            shutil.move(t_name, filename)

        return ret  # 치료 완료 리턴



