# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import ctypes
import struct
import kernel
import kavutil
import cryptolib

BYTE = ctypes.c_ubyte
WORD = ctypes.c_ushort
DWORD = ctypes.c_uint
FLOAT = ctypes.c_float
LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
LPTSTR = ctypes.POINTER(ctypes.c_char)
HANDLE = ctypes.c_void_p
PVOID = ctypes.c_void_p
LPVOID = ctypes.c_void_p
UINT_PTR = ctypes.c_uint
SIZE_T = ctypes.c_uint


class DOS_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('e_magic', WORD),
        ('e_cblp', WORD),
        ('e_cp', WORD),
        ('e_crlc', WORD),
        ('e_cparhdr', WORD),
        ('e_minalloc', WORD),
        ('e_maxalloc', WORD),
        ('e_ss', WORD),
        ('e_sp', WORD),
        ('e_csum', WORD),
        ('e_ip', WORD),
        ('e_cs', WORD),
        ('e_lfarlc', WORD),
        ('e_ovno', WORD),
        ('e_res', BYTE * 8),  # 8Byte
        ('e_oemid', WORD),
        ('e_oeminfo', WORD),
        ('e_res2', BYTE * 20),  # 20Byte
        ('e_lfanew', DWORD),
    ]


class FILE_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('Machine', WORD),
        ('NumberOfSections', WORD),
        ('CreationYear', DWORD),
        ('PointerToSymbolTable', DWORD),
        ('NumberOfSymbols', DWORD),
        ('SizeOfOptionalHeader', WORD),
        ('Characteristics', WORD),
    ]


class OPTIONAL_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('Magic', WORD),
        ('MajorLinkerVersion', BYTE),
        ('MinorLinkerVersion', BYTE),
        ('SizeOfCode', DWORD),
        ('SizeOfInitializedData', DWORD),
        ('SizeOfUninitializedData', DWORD),
        ('AddressOfEntryPoint', DWORD),
        ('BaseOfCode', DWORD),
        ('BaseOfData', DWORD),
        ('ImageBase', DWORD),
        ('SectionAlignment', DWORD),
        ('FileAlignment', DWORD),
        ('MajorOperatingSystemVersion', WORD),
        ('MinorOperatingSystemVersion', WORD),
        ('MajorImageVersion', WORD),
        ('MinorImageVersion', WORD),
        ('MajorSubsystemVersion', WORD),
        ('MinorSubsystemVersion', WORD),
        ('Reserved1', DWORD),
        ('SizeOfImage', DWORD),
        ('SizeOfHeaders', DWORD),
        ('CheckSum', DWORD),
        ('Subsystem', WORD),
        ('DllCharacteristics', WORD),
        ('SizeOfStackReserve', DWORD),
        ('SizeOfStackCommit', DWORD),
        ('SizeOfHeapReserve', DWORD),
        ('SizeOfHeapCommit', DWORD),
        ('LoaderFlags', DWORD),
        ('NumberOfRvaAndSizes', DWORD),
    ]


class DATA_DIRECTORY(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('VirtualAddress', DWORD),
        ('Size', DWORD),
    ]


class SECTION_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('Name', BYTE * 8),
        ('Misc_VirtualSize', DWORD),
        ('VirtualAddress', DWORD),
        ('SizeOfRawData', DWORD),
        ('PointerToRawData', DWORD),
        ('PointerToRelocations', DWORD),
        ('PointerToLinenumbers', DWORD),
        ('NumberOfRelocations', WORD),
        ('NumberOfLinenumbers', WORD),
        ('Characteristics', DWORD),
    ]


def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['reverse_mapping'] = reverse
    return type('Enum', (), enums)

image_directory_entry = enum('EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'SECURITY',
                             'BASERELOC', 'DEBUG',
                             'COPYRIGHT',  # Architecture on non-x86 platforms
                             'GLOBALPTR', 'TLS', 'LOAD_CONFIG', 'BOUND_IMPORT',
                             'IAT', 'DELAY_IMPORT', 'COM_DESCRIPTOR', 'RESERVED')


p_str = re.compile(r'[^\x00]*')  # NULL 문자 직전까지 복사


class PE:
    def __init__(self, mm, verbose, filename):
        self.filename = filename
        self.filesize = os.path.getsize(filename)
        self.verbose = verbose
        self.mm = mm
        self.sections = []  # 모든 섹션 정보 담을 리스트
        self.data_directories = []  # 모든 데이타 디렉토리 정보를 담을 리스트
        self.pe_file_align = 0

    # -------------------------------------------------------------------------
    # pe_parse(mm)
    # PE 파일을 파싱하여 주요 정보를 리턴한다.
    # 입력값 : mm - 파일 핸들
    # 리턴값 : {PE 파일 분석 정보} or None
    # -------------------------------------------------------------------------
    def parse(self):
        mm = self.mm

        pe_format = {'PE_Position': 0, 'EntryPoint': 0, 'SectionNumber': 0,
                     'Sections': None, 'EntryPointRaw': 0, 'FileAlignment': 0}

        try:
            if mm[0:2] != 'MZ':  # MZ로 시작하나?
                raise ValueError

            dos_header = DOS_HEADER()
            ctypes.memmove(ctypes.addressof(dos_header), mm[0:], ctypes.sizeof(dos_header))

            # PE 표식자 위치 알아내기
            pe_pos = dos_header.e_lfanew

            # PE 인가?
            if mm[pe_pos:pe_pos + 4] != 'PE\x00\x00':
                raise ValueError

            pe_format['PE_Position'] = pe_pos

            # File Header 읽기
            file_header = FILE_HEADER()
            file_header_size = ctypes.sizeof(file_header)  # file_header_size : 0x14
            ctypes.memmove(ctypes.addressof(file_header), mm[pe_pos + 4:], file_header_size)

            # Optional Header 읽기
            optional_header = OPTIONAL_HEADER()
            optional_header_size = ctypes.sizeof(optional_header)
            ctypes.memmove(ctypes.addressof(optional_header), mm[pe_pos + 4 + file_header_size:], optional_header_size)

            # Optional Header의 Magic ID?
            if optional_header.Magic != 0x10b:
                raise ValueError

            # Entry Point 구하기
            pe_ep = optional_header.AddressOfEntryPoint
            pe_format['EntryPoint'] = pe_ep

            # Image Base 구하기
            pe_img = optional_header.ImageBase
            pe_format['ImageBase'] = pe_img

            # File Alignment 구하기
            self.pe_file_align = optional_header.FileAlignment
            pe_format['FileAlignment'] = self.pe_file_align

            # Section 개수 구하기
            section_num = file_header.NumberOfSections
            pe_format['SectionNumber'] = section_num

            # Optional Header 크기 구하기
            opthdr_size = file_header.SizeOfOptionalHeader
            pe_format['OptionalHederSize'] = opthdr_size

            # Data Directory 읽기
            data_directory_size = ctypes.sizeof(DATA_DIRECTORY())  # data_directory_size : 8
            num_data_directory = (opthdr_size - optional_header_size) / data_directory_size
            off_data_directory = pe_pos + 4 + file_header_size + optional_header_size

            for i in range(num_data_directory):
                dx = DATA_DIRECTORY()
                ctypes.memmove(ctypes.addressof(dx),
                               mm[off_data_directory + (i * data_directory_size):],
                               data_directory_size)

                self.data_directories.append(dx)

            # 섹션 시작 위치
            section_pos = pe_pos + 4 + file_header_size + opthdr_size

            # 모든 섹션 정보 추출
            for i in range(section_num):
                section = {}

                section_header = SECTION_HEADER()
                section_header_size = ctypes.sizeof(section_header)  # section_header_size : 0x28

                s = section_pos + (section_header_size * i)
                ctypes.memmove(ctypes.addressof(section_header), mm[s:], section_header_size)

                sec_name = ctypes.cast(section_header.Name, ctypes.c_char_p)
                section['Name'] = sec_name.value.replace('\x00', '')
                section['VirtualSize'] = section_header.Misc_VirtualSize
                section['RVA'] = section_header.VirtualAddress
                section['SizeRawData'] = section_header.SizeOfRawData
                section['PointerRawData'] = section_header.PointerToRawData
                section['Characteristics'] = section_header.Characteristics

                self.sections.append(section)

            pe_format['Sections'] = self.sections

            # EntryPoint의 파일에서의 위치 구하기
            ep_raw, sec_idx = self.rva_to_off(pe_ep)
            pe_format['EntryPointRaw'] = ep_raw  # EP의 Raw 위치
            pe_format['EntryPoint_in_Section'] = sec_idx  # EP가 포함된 섹션

            # 리소스 분석
            try:
                rsrc_rva = self.data_directories[image_directory_entry.RESOURCE].VirtualAddress  # 리소스 위치(RVA)
                rsrc_size = self.data_directories[image_directory_entry.RESOURCE].Size  # 리소스 크기
            except IndexError:
                rsrc_rva = 0
                rsrc_size = 0

            if rsrc_rva:  # 리소스가 존재한가?
                try:
                    rsrc_off, rsrc_idx = self.rva_to_off(rsrc_rva)  # 리소스 위치 변환

                    if rsrc_off > self.filesize:
                        raise ValueError

                    t_size = self.sections[rsrc_idx]['SizeRawData']
                    if not (len(mm[rsrc_off:rsrc_off + rsrc_size]) == rsrc_size or \
                        len(mm[rsrc_off:rsrc_off + t_size]) == t_size):  # 충분한 리소스가 존재하지 않음
                        raise ValueError

                    # Type 체크
                    num_type_name = kavutil.get_uint16(mm, rsrc_off+0xC)
                    num_type_id = kavutil.get_uint16(mm, rsrc_off + 0xE)

                    for i in range(num_type_name + num_type_id):
                        type_id = kavutil.get_uint32(mm, rsrc_off + 0x10 + (i*8))
                        name_id_off = kavutil.get_uint32(mm, rsrc_off + 0x14 + (i * 8))

                        # Type이 사용자가 정의한 이름 or RCDATA?
                        if type_id & 0x80000000 == 0x80000000 or type_id == 0xA or type_id == 0:
                            if type_id & 0x80000000 == 0x80000000:
                                # 사용자가 정의한 이름 추출
                                string_off = (type_id & 0x7FFFFFFF) + rsrc_off
                                len_name = kavutil.get_uint16(mm, string_off)
                                rsrc_type_name = mm[string_off + 2:string_off + 2 + (len_name * 2):2]
                            elif type_id == 0xA:
                                rsrc_type_name = 'RCDATA'
                            else:
                                rsrc_type_name = '%d' % type_id

                            # Name ID
                            name_id_off = (name_id_off & 0x7FFFFFFF) + rsrc_off
                            if name_id_off > self.filesize:
                                raise ValueError

                            num_name_id_name = kavutil.get_uint16(mm, name_id_off + 0xC)
                            num_name_id_id = kavutil.get_uint16(mm, name_id_off + 0xE)

                            for j in range(num_name_id_name + num_name_id_id):
                                name_id_id = kavutil.get_uint32(mm, name_id_off + 0x10 + (j * 8))
                                language_off = kavutil.get_uint32(mm, name_id_off + 0x14 + (j * 8))

                                # 리소스 영역의 최종 이름 생성
                                if name_id_id & 0x80000000 == 0x80000000:
                                    string_off = (name_id_id & 0x7FFFFFFF) + rsrc_off
                                    if string_off > self.filesize:
                                        raise ValueError

                                    len_name = kavutil.get_uint16(mm, string_off)
                                    rsrc_name_id_name = mm[string_off + 2:string_off + 2 + (len_name * 2):2]
                                    string_name = rsrc_type_name + '/' + rsrc_name_id_name
                                else:
                                    string_name = rsrc_type_name + '/' + hex(name_id_id).upper()[2:]

                                # Language
                                language_off = (language_off & 0x7FFFFFFF) + rsrc_off
                                if language_off > self.filesize:
                                    raise ValueError

                                num_language_name = kavutil.get_uint16(mm, language_off + 0xC)
                                num_language_id = kavutil.get_uint16(mm, language_off + 0xE)

                                for k in range(num_language_name + num_language_id):
                                    # language_id = kavutil.get_uint32(mm, language_off + 0x10 + (k * 8))
                                    data_entry_off = kavutil.get_uint32(mm, language_off + 0x14 + (k * 8))

                                    data_entry_off = (data_entry_off & 0x7FFFFFFF) + rsrc_off

                                    data_rva = kavutil.get_uint32(mm, data_entry_off)
                                    data_off, _ = self.rva_to_off(data_rva)
                                    if data_off > self.filesize:
                                        continue

                                    data_size = kavutil.get_uint32(mm, data_entry_off + 4)
                                    if data_size > self.filesize:
                                        continue

                                    if data_size > 8192:  # 최소 8K 이상인 리소스만 데이터로 추출
                                        if 'Resource_UserData' in pe_format:
                                            pe_format['Resource_UserData'][string_name] = (data_off, data_size)
                                        else:
                                            pe_format['Resource_UserData'] = {string_name: (data_off, data_size)}
                except (struct.error, ValueError) as e:
                    pass

                # if 'Resource_UserData' in pe_format:
                #     print pe_format['Resource_UserData']

            # Import API 분석
            try:
                imp_rva = self.data_directories[image_directory_entry.IMPORT].VirtualAddress  # Import API 위치(RVA)
                imp_size = self.data_directories[image_directory_entry.IMPORT].Size  # Import API 크기
            except IndexError:
                imp_rva = 0
                imp_size = 0

            if imp_rva:  # Import API 존재
                imp_api = {}

                # print 'IMP : %08X' % imp_rva
                imp_off = self.rva_to_off(imp_rva)[0]
                # print hex(imp_off), imp_size
                imp_data = mm[imp_off:imp_off+imp_size]
                if len(imp_data) == imp_size:
                    for i in range(imp_size / 0x14):  # DLL 정보 크기가 0x14
                        try:
                            dll_rva = kavutil.get_uint32(imp_data, (i*0x14)+0xC)
                            api_rva = kavutil.get_uint32(imp_data, (i * 0x14))
                            bo = 2
                            if api_rva == 0:
                                api_rva = kavutil.get_uint32(imp_data, (i*0x14)+0x10)
                                bo = 0

                            # print hex(api_rva)
                            if dll_rva == 0:  # DLL 정보가 없음
                                break

                            t_off = self.rva_to_off(dll_rva)[0]
                            dll_name = p_str.search(mm[t_off:t_off+0x20]).group()
                            # print '[+]', dll_name
                            imp_api[dll_name] = []

                            t_off = self.rva_to_off(api_rva)[0]
                            while True:
                                try:
                                    api_name_rva = kavutil.get_uint32(mm, t_off)
                                except struct.error:
                                    break

                                if api_name_rva & 0x80000000 == 0x80000000:  # Odinal API
                                        t_off += 4
                                        continue

                                if api_name_rva == 0:
                                    break

                                t = self.rva_to_off(api_name_rva)[0]
                                # print hex(t_off), hex(t)
                                api_name = p_str.search(mm[t+bo:t+bo+0x20]).group()
                                # print '   ', api_name
                                imp_api[dll_name].append(api_name)
                                t_off += 4
                        except struct.error:
                            pass
                # end if

                pe_format['Import_API'] = imp_api

            # 디지털 인증서 분석
            try:
                cert_off = self.data_directories[image_directory_entry.SECURITY].VirtualAddress  # 유일하게 RVA가 아닌 오프셋
                cert_size = self.data_directories[image_directory_entry.SECURITY].Size  # 디지털 인증서 크기
            except IndexError:
                cert_off = 0
                cert_size = 0

            if cert_off:  # 디지털 인증서 존재
                if cert_off + cert_size <= len(mm[:]):  # UPack의 경우 이상한 값이 셋팅 됨
                    pe_format['CERTIFICATE_Offset'] = cert_off
                    pe_format['CERTIFICATE_Size'] = cert_size

            # Debug 정보 분석
            try:
                debug_rva = self.data_directories[image_directory_entry.DEBUG].VirtualAddress  # RVA
                debug_size = self.data_directories[image_directory_entry.DEBUG].Size  # 크기
                if debug_size < 0x1C:
                    raise ValueError
            except (IndexError, ValueError) as e:
                debug_rva = 0
                debug_size = 0

            if debug_rva:  # Debug 정보 존재
                t = self.rva_to_off(debug_rva)[0]
                debug_off = kavutil.get_uint32(mm, t + 0x18)
                debug_size = kavutil.get_uint32(mm, t + 0x10)

                debug_data = mm[debug_off:debug_off + debug_size]

                if debug_data[:4] == 'RSDS':
                    pe_format['PDB_Name'] = debug_data[0x18:]
                else:
                    pe_format['PDB_Name'] = 'Not support Type : %s' % debug_data[:4]

            if self.verbose:
                print '-' * 79
                kavutil.vprint('Engine')
                kavutil.vprint(None, 'Engine', 'pe.kmd')
                kavutil.vprint(None, 'File name', os.path.split(self.filename)[-1])
                kavutil.vprint(None, 'MD5', cryptolib.md5(mm[:]))

                print
                kavutil.vprint('PE')
                kavutil.vprint(None, 'EntryPoint', '%08X' % pe_format['EntryPoint'])
                kavutil.vprint(None, 'EntryPoint (Section)', '%d' % pe_format['EntryPoint_in_Section'])

                # 섹션 보기
                if section_num:
                    print
                    kavutil.vprint('Section Header')
                    print '    %-8s %-8s %-8s %-8s %-8s %-8s' % ('Name', 'VOFF', 'VSIZE', 'FOFF', 'FSIZE', 'EXEC')
                    print '    ' + ('-' * (9*6 - 1))

                    for s in self.sections:
                        print '    %-8s %08X %08X %08X %08X %-05s' % (s['Name'], s['RVA'], s['VirtualSize'],
                                                                     s['PointerRawData'], s['SizeRawData'],
                                                                     s['Characteristics'] & 0x20000000 == 0x20000000)

                if section_num:
                    print
                    kavutil.vprint('Section MD5')
                    print '    %-8s %-8s %-32s' % ('Name', 'FSIZE', 'MD5')
                    print '    ' + ('-' * ((9 * 2 - 1)+32))

                    for s in self.sections:
                        # if s['Characteristics'] & 0x20000000 == 0x20000000:
                        off = s['PointerRawData']
                        size = s['SizeRawData']
                        fmd5 = cryptolib.md5(mm[off:off+size]) if size else '-'
                        print '    %-8s %8d %s' % (s['Name'], size, fmd5)

                print
                kavutil.vprint('Entry Point (Raw)')
                print
                kavutil.HexDump().Buffer(mm[:], pe_format['EntryPointRaw'], 0x80)
                print
                if 'PDB_Name' in pe_format:
                    kavutil.vprint('PDB Information')
                    kavutil.vprint(None, 'Name', '%s' % repr(pe_format['PDB_Name']))
                    print repr(pe_format['PDB_Name'])
                    print

        except (ValueError, struct.error) as e:
            return None

        return pe_format

    def rva_to_off(self, t_rva):
        for section in self.sections:
            size = section['SizeRawData']
            rva = section['RVA']

            if rva <= t_rva < rva + size:
                if self.pe_file_align:
                    foff = (section['PointerRawData'] / self.pe_file_align) * self.pe_file_align
                else:
                    foff = section['PointerRawData']
                t_off = t_rva - rva + foff

                return t_off, self.sections.index(section)

        return t_rva, -1  # 어느 섹션에도 소속되지 않았다면.. 그냥 RVA 리턴


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

        # NSIS 코드 패턴
        '''
        81 7D DC EF BE AD DE                          cmp     [ebp+var_24], 0DEADBEEFh
        75 69                                         jnz     short loc_402D79
        81 7D E8 49 6E 73 74                          cmp     [ebp+var_18], 'tsnI'
        75 60                                         jnz     short loc_402D79
        81 7D E4 73 6F 66 74                          cmp     [ebp+var_1C], 'tfos'
        75 57                                         jnz     short loc_402D79
        81 7D E0 4E 75 6C 6C                          cmp     [ebp+var_20], 'lluN'
        '''

        self.p_nsis = '817DDCEFBEADDE7569817DE8496E7374'.decode('hex')

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
        info['version'] = '1.2'  # 버전
        info['title'] = 'PE Engine'  # 엔진 설명
        info['kmd_name'] = 'pe'  # 엔진 파일 이름

        # 리소스 파일에 악성코드가 존재하는 경우로 최상위 파일을 삭제한다.
        info['make_arc_type'] = kernel.MASTER_DELETE  # 악성코드 치료 후 재압축 유무
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
        fileformat = {}  # 포맷 정보를 담을 공간
        ret = {}

        pe = PE(filehandle, self.verbose, filename)
        try:
            pe_format = pe.parse()  # PE 파일 분석
        except MemoryError:
            pe_format = None

        if pe_format is None:
            return None

        fileformat['pe'] = pe_format
        ret = {'ff_pe': fileformat}

        # PE 파일 뒤쪽에 추가 정보가 있는지 검사한다.
        pe_size = 0

        pe_file_align = pe_format['FileAlignment']

        for sec in pe_format['Sections']:
            if pe_file_align:
                off = (sec['PointerRawData'] / pe_file_align) * pe_file_align
            else:
                off = sec['PointerRawData']
            size = sec['SizeRawData']
            if pe_size < off + size:
                pe_size = off + size

        file_size = len(filehandle)

        if 'CERTIFICATE_Offset' in pe_format:  # 파일 뒤에 인증서가 존재하는가?
            if pe_format['CERTIFICATE_Offset'] == pe_size:  # PE 끝나는 시점에 인증서가 있으면 인증서 포함해서 크기 처리
                t_pe_size = pe_format['CERTIFICATE_Offset'] + pe_format['CERTIFICATE_Size']
                if pe_size < t_pe_size:
                    pe_size = t_pe_size
                attach_size = file_size - pe_size
            else:
                attach_size = file_size - pe_size - pe_format['CERTIFICATE_Size']
        else:
            attach_size = file_size - pe_size

        if pe_size < file_size and pe_size != 0:
            mm = filehandle

            # NSIS 코드가 .text 영역에 존재하는지 체크한다.
            text_sec = pe_format['Sections'][0]
            if pe_file_align:
                off = (text_sec['PointerRawData'] / pe_file_align) * pe_file_align
            else:
                off = text_sec['PointerRawData']
            size = text_sec['SizeRawData']

            if size:
                if mm[off:off + size].find(self.p_nsis) != -1:
                    # PE 파일에 뒤쪽에 데이터가 있다면 NSIS 파일인지 분석하기
                    i = 1
                    while True:
                        t = mm[i * 0x200 + 4:i * 0x200 + 20]
                        if len(t) != 16:
                            break

                        if t == '\xEF\xBE\xAD\xDENullsoftInst':
                            ret['ff_nsis'] = {'Offset': i * 0x200}
                            break

                        i += 1

            # Attach 처리하기 (단 NSIS가 존재하면 처리하지 않음)
            if not('ff_nsis' in ret):
                fileformat = {  # 포맷 정보를 담을 공간
                    'Attached_Pos': pe_size,
                    'Attached_Size': attach_size
                }
                ret['ff_attach'] = fileformat

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

        # 미리 분석된 파일 포맷중에 첨부 파일 포맷이 있는가?
        if 'ff_pe' in fileformat:
            if 'Resource_UserData' in fileformat['ff_pe']['pe']:
                for key in fileformat['ff_pe']['pe']['Resource_UserData'].keys():
                    off, size = fileformat['ff_pe']['pe']['Resource_UserData'][key]
                    file_scan_list.append(['arc_pe_rcdata:%d:%d' % (off, size), key])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id.find('arc_pe_rcdata:') != -1:
            t = arc_engine_id.split(':')
            off = int(t[1])
            size = int(t[2])

            try:
                with open(arc_name, 'rb') as fp:
                    fp.seek(off)
                    data = fp.read(size)
            except IOError:
                return None

            return data

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        pass

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

            # 미리 분석된 파일 포맷중에 PE 포맷이 있는가?
            if 'ff_pe' in fileformat:
                buf = mm[:]
                fmd5 = cryptolib.md5(buf).decode('hex')  # 파일 전체 MD5 생성
                header = 'PE\x00\x00' + struct.pack('<L', malware_id) + fmd5

                pe = PE(mm, False, filename)
                pe_format = pe.parse()
                if not pe_format:
                    return None

                pe_off = pe_format['PE_Position']  # pe.DOS_HEADER.e_lfanew
                ep = pe_format['EntryPoint']  # pe.OPTIONAL_HEADER.AddressOfEntryPoint

                text_off = 0
                text_size = 0

                for sec in pe_format['Sections']:  # pe.sections:
                    rva = sec['RVA']  # sec.VirtualAddress
                    vsize = sec['VirtualSize']  # sec.Misc_VirtualSize
                    if rva <= ep <= rva + vsize:
                        text_off = sec['PointerRawData']  # sec.PointerToRawData
                        text_size = sec['SizeRawData']  # sec.SizeOfRawData
                        break

                # Feature 추출
                f = kavutil.Feature()

                data = ''
                # 1. text 섹션에 대해서 엔트로피를 추출한다.
                data += f.entropy(mm[text_off:text_off + text_size])

                # 2. PE 헤더 정보를 추출한다.
                data += mm[pe_off + 6:pe_off + 6 + 256]

                # 3. DATA 섹션 2-gram 추출하기
                data_off = 0
                data_size = 0

                for sec in pe_format['Sections']:  # pe.sections:
                    if sec['Characteristics'] & 0x40000040 == 0x40000040:  # if DATA and Read
                        data_off = sec['PointerRawData']  # sec.PointerToRawData
                        data_size = sec['SizeRawData']  # sec.SizeOfRawData
                        break

                data += f.k_gram(mm[data_off:data_off + data_size], 2)

                # 4. Import API 해시 추가하기
                def import_api(l_pe_format):
                    api_hash = set()

                    l_data = ''

                    if 'Import_API' in l_pe_format:
                        imp_api = pe_format['Import_API']
                        # print imp_api

                        for dll in imp_api.keys():
                            for api in dll:
                                api_name = ('%s:%s' % (dll, api)).lower()
                                api_hash.add(struct.pack('<H', cryptolib.CRC16().calculate(api_name)))

                        t = list(api_hash)
                        l_data = ''.join(t)

                    if len(l_data) < 256:
                        l_data += '\x00' * (256 - len(l_data))

                    return l_data[:256]

                data += import_api(pe_format)

                open('pe.bin', 'ab').write(header + data)  # Feature 파일 생성

                return True
        except IOError:
            pass

        # Feature 추출 실패했음을 리턴한다.
        return False
