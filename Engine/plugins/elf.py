# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)
# 참조 : https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

import os
import struct
import kavutil


# -------------------------------------------------------------------------
# 데이터 읽기 함수 (엔디안 때문에 Kavutil과 별도로 작성)
# -------------------------------------------------------------------------
def get_uint16(buf, off, endian='<'):
    return struct.unpack(endian+'H', buf[off:off+2])[0]


def get_uint32(buf, off, endian='<'):
    return struct.unpack(endian+'L', buf[off:off+4])[0]


def get_uint64(buf, off, endian='<'):
    return struct.unpack(endian+'Q', buf[off:off+8])[0]


# -------------------------------------------------------------------------
# ELF32 클래스
# -------------------------------------------------------------------------
class ELF32:
    def __init__(self, mm, endian, verbose, filename):
        self.verbose = verbose
        self.filename = filename
        self.mm = mm
        self.endian = endian
        self.program_headers = []
        self.sections = []
        self.ident = {0x00: 'System V',
                      0x01: 'HP-UX',
                      0x02: 'NetBSD',
                      0x03: 'Linux',
                      0x06: 'Solaris',
                      0x07: 'AIX',
                      0x08: 'IRIX',
                      0x09: 'FreeBSD',
                      0x0A: 'Tru64',
                      0x0B: 'Novell Modesto',
                      0x0C: 'OpenBSD',
                      0x0D: 'OpenVMS',
                      0x0E: 'NonStop Kernel',
                      0x0F: 'AROS',
                      0x10: 'Fenix OS',
                      0x11: 'CloudABI',
                      0x53: 'Sortix'}
        self.machine = {0x02: 'SPARC',
                        0x03: 'x86',
                        0x08: 'MIPS',
                        0x14: 'PowerPC',
                        0x28: 'ARM',
                        0x2A: 'SuperH',
                        0x32: 'IA-64',
                        0x3E: 'x86-64',
                        0xB7: 'AArch64',
                        0xF3: 'RISC-V'}

    def parse(self):
        fileformat = {}
        mm = self.mm

        try:
            # EP
            e_entry = get_uint32(mm, 0x18, self.endian)

            # ELF 헤더 정보
            e_ident = ord(mm[7])
            e_machine = get_uint16(mm, 0x12, self.endian)

            e_phoff = get_uint32(mm, 0x1C, self.endian)
            e_shoff = get_uint32(mm, 0x20, self.endian)
            e_phnum = get_uint16(mm, 0x2C, self.endian)
            e_shnum = get_uint16(mm, 0x30, self.endian)
            e_shstrndx = get_uint16(mm, 0x32, self.endian)

            # 프로그램 헤더 정보 구하기
            for i in range(e_phnum):
                program_header = {}

                program_header['Type'] = get_uint32(mm, e_phoff + (0x20 * i) + 0, self.endian)
                program_header['Flag'] = get_uint32(mm, e_phoff + (0x20 * i) + 0x18, self.endian)
                program_header['RVA'] = get_uint32(mm, e_phoff + (0x20 * i) + 0x8, self.endian)
                program_header['Offset'] = get_uint32(mm, e_phoff + (0x20 * i) + 0x4, self.endian)
                program_header['Size'] = get_uint32(mm, e_phoff + (0x20 * i) + 0x10, self.endian)

                self.program_headers.append(program_header)

            fileformat['ProgramHeaders'] = self.program_headers

            # 섹션 이름이 저장된 테이블
            name_table_off = get_uint32(mm, e_shoff + (0x28 * e_shstrndx) + 0x10, self.endian)
            name_table_size = get_uint32(mm, e_shoff + (0x28 * e_shstrndx) + 0x14, self.endian)
            name_table = mm[name_table_off:name_table_off+name_table_size]
            # print name_table.split('\x00')
            # print hex(name_table_off), hex(name_table_size)

            # 섹션 정보 구하기
            for i in range(e_shnum):
                section = {}

                name_off = get_uint32(mm, e_shoff + (0x28 * i), self.endian)
                section['Name'] = name_table[name_off:].split('\x00', 1)[0]
                section['Type'] = get_uint32(mm, e_shoff + (0x28 * i) + 4, self.endian)
                section['Flag'] = get_uint32(mm, e_shoff + (0x28 * i) + 8, self.endian)
                section['RVA'] = get_uint32(mm, e_shoff + (0x28 * i) + 0xC, self.endian)
                section['Offset'] = get_uint32(mm, e_shoff + (0x28 * i) + 0x10, self.endian)
                section['Size'] = get_uint32(mm, e_shoff + (0x28 * i) + 0x14, self.endian)

                self.sections.append(section)

            fileformat['Sections'] = self.sections
            fileformat['EntryPoint'] = e_entry

            # EntryPoint의 파일에서의 위치 구하기
            ep_raw, sec_idx = self.rva_to_off(e_entry)
            fileformat['EntryPointRaw'] = ep_raw  # EP의 Raw 위치
            fileformat['EntryPoint_in_Section'] = sec_idx  # EP가 포함된 섹션

            if self.verbose:
                print '-' * 79
                kavutil.vprint('Engine')
                kavutil.vprint(None, 'Engine', 'elf.kmd')
                kavutil.vprint(None, 'File name', os.path.split(self.filename)[-1])

                print
                kavutil.vprint('ELF32')

                if e_ident in self.ident:
                    msg1 = self.ident[e_ident]
                else:
                    msg1 = 'Unknown'

                if e_machine in self.machine:
                    msg2 = self.machine[e_machine]
                else:
                    msg2 = 'Unknown'

                kavutil.vprint(None, 'Identifies', '%s (%s)' % (msg1, msg2))

                kavutil.vprint(None, 'Entry Point', '0x%08X' % e_entry)
                kavutil.vprint(None, 'Entry Point (Raw)', '0x%08X' % ep_raw)
                kavutil.vprint(None, 'Program Header Off', '0x%08X' % e_phoff)
                kavutil.vprint(None, 'Program Header Num', '0x%04X' % e_phnum)
                kavutil.vprint(None, 'Section Header Off', '0x%08X' % e_shoff)
                kavutil.vprint(None, 'Section Header Num', '0x%04X' % e_shnum)

                if e_phnum:
                    print
                    kavutil.vprint('Program Header')
                    print '    %-8s %-8s %-8s %-8s %-8s' % ('Type', 'Flag', 'RVA', 'Offset', 'Size')
                    print '    ' + ('-' * 44)

                    for p in self.program_headers:
                        print '    %08X %08X %08X %08X %08X' % (p['Type'], p['Flag'], p['RVA'], p['Offset'], p['Size'])

                if e_shnum:
                    print
                    kavutil.vprint('Section Header')
                    print '    %-15s %-8s %-8s %-8s %-8s %-8s' % ('Name', 'Type', 'Flag', 'RVA', 'Offset', 'Size')
                    print '    ' + ('-' * (44 + 16))

                    for p in self.sections:
                        print '    %-15s %08X %08X %08X %08X %08X' % (p['Name'], p['Type'], p['Flag'], p['RVA'], p['Offset'], p['Size'])

                print
                kavutil.vprint('Entry Point (Raw)')
                print
                kavutil.HexDump().Buffer(mm[:], ep_raw, 0x80)
                print
        except (ValueError, struct.error) as e:
            pass

        return fileformat

    def rva_to_off(self, t_rva):
        if len(self.sections):
            t_section = self.sections
        elif len(self.program_headers):
            t_section = self.program_headers
        else:
            t_section = []

        for section in t_section:
            size = section['Size']
            rva = section['RVA']

            if rva <= t_rva < rva + size:
                t_off = t_rva - rva + section['Offset']

                return t_off, t_section.index(section)

        return t_rva, -1  # 어느 섹션에도 소속되지 않았다면.. 그냥 RVA 리턴


# -------------------------------------------------------------------------
# ELF64 클래스
# -------------------------------------------------------------------------
class ELF64:
    def __init__(self, mm, endian, verbose, filename):
        self.filename = filename
        self.verbose = verbose
        self.mm = mm
        self.endian = endian
        self.sections = []

    def parse(self):
        fileformat = {}
        mm = self.mm

        try:
            # EP
            e_entry = get_uint64(mm, 0x18, self.endian)

            # 섹션 헤더 정보
            e_phoff = get_uint64(mm, 0x20, self.endian)
            e_shoff = get_uint64(mm, 0x28, self.endian)
            e_phnum = get_uint16(mm, 0x38, self.endian)
            e_shnum = get_uint16(mm, 0x3C, self.endian)
            e_shstrndx = get_uint16(mm, 0x3E, self.endian)

            # 섹션 이름이 저장된 테이블
            name_table_off = get_uint64(mm, e_shoff + (0x40 * e_shstrndx) + 0x18, self.endian)
            name_table_size = get_uint64(mm, e_shoff + (0x40 * e_shstrndx) + 0x20, self.endian)
            name_table = mm[name_table_off:name_table_off+name_table_size]
            # print name_table.split('\x00')
            # print hex(name_table_off), hex(name_table_size)

            # 섹션 정보 구하기
            for i in range(e_shnum):
                section = {}

                name_off = get_uint32(mm, e_shoff + (0x40 * i), self.endian)
                section['Name'] = name_table[name_off:].split('\x00', 1)[0]
                section['Type'] = get_uint32(mm, e_shoff + (0x40 * i) + 4, self.endian)
                section['Flag'] = get_uint64(mm, e_shoff + (0x40 * i) + 8, self.endian)
                section['RVA'] = get_uint64(mm, e_shoff + (0x40 * i) + 0x10, self.endian)
                section['Offset'] = get_uint64(mm, e_shoff + (0x40 * i) + 0x18, self.endian)
                section['Size'] = get_uint64(mm, e_shoff + (0x40 * i) + 0x20, self.endian)

                self.sections.append(section)

            fileformat['Sections'] = self.sections
            fileformat['EntryPoint'] = e_entry

            # EntryPoint의 파일에서의 위치 구하기
            ep_raw, sec_idx = self.rva_to_off(e_entry)
            fileformat['EntryPointRaw'] = ep_raw  # EP의 Raw 위치
            fileformat['EntryPoint_in_Section'] = sec_idx  # EP가 포함된 섹션

            if self.verbose:
                print '-' * 79
                kavutil.vprint('Engine')
                kavutil.vprint(None, 'Engine', 'elf.kmd')
                kavutil.vprint(None, 'File name', os.path.split(self.filename)[-1])

                print
                kavutil.vprint('ELF64')

                kavutil.vprint(None, 'Entry Point', '0x%016X' % e_entry)
                kavutil.vprint(None, 'Entry Point (Raw)', '0x%016X' % ep_raw)
                kavutil.vprint(None, 'Program Header Off', '0x%016X' % e_phoff)
                kavutil.vprint(None, 'Program Header Num', '0x%04X' % e_phnum)
                kavutil.vprint(None, 'Section Header Off', '0x%016X' % e_shoff)
                kavutil.vprint(None, 'Section Header Num', '0x%04X' % e_shnum)

                if e_shnum:
                    print
                    kavutil.vprint('Section Header')
                    print '    %-15s %-8s %-16s %-16s %-16s %-16s' % ('Name', 'Type', 'Flag', 'RVA', 'Offset', 'Size')
                    print '    ' + ('-' * (76 + 16))

                    for p in self.sections:
                        print '    %-15s %08X %016X %016X %016X %016X' % (p['Name'], p['Type'], p['Flag'], p['RVA'], p['Offset'], p['Size'])

                print
                kavutil.vprint('Entry Point (Raw)')
                print
                kavutil.HexDump().Buffer(mm[:], ep_raw, 0x80)
                print
        except (ValueError, struct.error) as e:
            pass

        return fileformat

    def rva_to_off(self, t_rva):
        for section in self.sections:
            size = section['Size']
            rva = section['RVA']

            if rva <= t_rva < rva + size:
                t_off = t_rva - rva + section['Offset']

                return t_off, self.sections.index(section)

        return t_rva, -1  # 어느 섹션에도 소속되지 않았다면.. 그냥 RVA 리턴


# -------------------------------------------------------------------------
# ELF 통합 클래스
# -------------------------------------------------------------------------
class ELF:
    def __init__(self, mm, verbose, filename):
        self.filename = filename
        self.verbose = verbose
        self.mm = mm
        self.endian = None

    def parse(self):
        fileformat = None

        mm = self.mm

        try:
            if mm[0:4] != '\x7FELF':  # ELF 헤더인가?
                raise ValueError

            bit = ord(mm[4])  # bit 알아내기
            endian = ord(mm[5])  # Endian 알아내기

            if endian == 1:  # 1:little, 2:big
                self.endian = '<'
            elif endian == 2:
                self.endian = '>'
            else:
                raise ValueError

            if bit == 1:  # 32bit ELF
                e = ELF32(mm, self.endian, self.verbose, self.filename)
            elif bit == 2:  # 64bit ELF
                e = ELF64(mm, self.endian, self.verbose, self.filename)
            else:
                raise ValueError

            fileformat = e.parse()
        except ValueError:
            pass

        return fileformat


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
        info['title'] = 'ELF Engine'  # 엔진 설명
        info['kmd_name'] = 'elf'  # 엔진 파일 이름

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

        elf = ELF(filehandle, self.verbose, filename)
        elf_format = elf.parse()  # PE 파일 분석
        if elf_format is None:
            return None

        fileformat['elf'] = elf_format
        ret = {'ff_elf': fileformat}

        return ret

