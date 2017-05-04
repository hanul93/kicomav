# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import struct
import kavutil
import cryptolib


p_str = re.compile(r'[^\x00]+')  # NULL 문자 직전까지 복사


class PE:
    def __init__(self, mm, verbose, filename):
        self.filename = filename
        self.verbose = verbose
        self.mm = mm
        self.sections = []  # 모든 섹션 정보 담을 리스트
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

            pe_format['File_MD5'] = cryptolib.md5(mm[:])

            # PE 표식자 위치 알아내기
            pe_pos = kavutil.get_uint32(mm, 0x3C)

            # PE 인가?
            if mm[pe_pos:pe_pos + 4] != 'PE\x00\x00':
                raise ValueError

            pe_format['PE_Position'] = pe_pos

            # Optional Header의 Magic ID?
            if mm[pe_pos + 0x18:pe_pos + 0x18 + 2] != '\x0B\x01':
                raise ValueError

            # Entry Point 구하기
            pe_ep = kavutil.get_uint32(mm, pe_pos + 0x28)
            pe_format['EntryPoint'] = pe_ep

            # Image Base 구하기
            pe_img = kavutil.get_uint32(mm, pe_pos + 0x34)
            pe_format['ImageBase'] = pe_img

            # File Alignment 구하기
            self.pe_file_align = kavutil.get_uint32(mm, pe_pos + 0x3C)
            pe_format['FileAlignment'] = self.pe_file_align

            # Section 개수 구하기
            section_num = kavutil.get_uint16(mm, pe_pos + 0x6)
            pe_format['SectionNumber'] = section_num

            # Optional Header 크기 구하기
            opthdr_size = kavutil.get_uint16(mm, pe_pos + 0x14)
            pe_format['OptionalHederSize'] = opthdr_size

            # t섹션 시작 위치
            section_pos = pe_pos + 0x18 + opthdr_size

            # 모든 섹션 정보 추출
            for i in range(section_num):
                section = {}

                s = section_pos + (0x28 * i)

                section['Name'] = mm[s:s + 8].replace('\x00', '')
                section['VirtualSize'] = kavutil.get_uint32(mm, s+8)
                section['RVA'] = kavutil.get_uint32(mm, s+12)
                section['SizeRawData'] = kavutil.get_uint32(mm, s+16)
                section['PointerRawData'] = kavutil.get_uint32(mm, s+20)
                section['Characteristics'] = kavutil.get_uint32(mm, s+36)

                self.sections.append(section)

            pe_format['Sections'] = self.sections

            # EntryPoint의 파일에서의 위치 구하기
            ep_raw, sec_idx = self.rva_to_off(pe_ep)
            pe_format['EntryPointRaw'] = ep_raw  # EP의 Raw 위치
            pe_format['EntryPoint_in_Section'] = sec_idx  # EP가 포함된 섹션

            # 리소스 분석
            rsrc_rva = kavutil.get_uint32(mm, pe_pos + 0x88)  # 리소스 위치(RVA)
            rsrc_size = kavutil.get_uint32(mm, pe_pos + 0x8C)  # 리소스 크기

            if rsrc_rva:  # 리소스가 존재한가?
                try:
                    rsrc_off, _ = self.rva_to_off(rsrc_rva)  # 리소스 위치 변환
                    num_name = kavutil.get_uint16(mm, rsrc_off+0xC)
                    num_id = kavutil.get_uint16(mm, rsrc_off + 0xE)

                    for i in range(num_name + num_id):
                        rcdata_id = kavutil.get_uint32(mm, rsrc_off + 0x10 + (i*8))
                        if rcdata_id == 0xA:  # RCDATA 발견?
                            rcdata_off = kavutil.get_uint32(mm, rsrc_off + 0x14 + (i*8))
                            rcdata_entry_off = (rcdata_off & 0x7FFFFFFF) + rsrc_off

                            num_rcdata_name = kavutil.get_uint16(mm, rcdata_entry_off + 0xC)

                            for j in range(num_rcdata_name):
                                rcdata_name_off = kavutil.get_uint32(mm, rcdata_entry_off + 0x10 + (j * 8))
                                string_off = (rcdata_name_off & 0x7FFFFFFF) + rsrc_off
                                len_name = kavutil.get_uint16(mm, string_off)
                                string_name = mm[string_off+2:string_off+2+(len_name * 2):2]
                                # print string_name

                                if string_name == 'CABINET':
                                    rcdata_lang_off = kavutil.get_uint32(mm, rcdata_entry_off + 0x14 + (j * 8))
                                    rcdata_lang_off = (rcdata_lang_off & 0x7FFFFFFF) + rsrc_off

                                    rdata_entry_off = kavutil.get_uint32(mm, rcdata_lang_off + 0x14) + rsrc_off
                                    rcdata_rva = kavutil.get_uint32(mm, rdata_entry_off)
                                    rcdata_data_off, _ = self.rva_to_off(rcdata_rva)
                                    rcdata_data_size = kavutil.get_uint32(mm, rdata_entry_off+4)

                                    # print hex(rcdata_data_off), hex(rcdata_data_size)
                                    pe_format['CABINET_Offset'] = rcdata_data_off
                                    pe_format['CABINET_Size'] = rcdata_data_size
                                    break
                except struct.error:
                    pass

            # Import API 분석
            imp_rva = kavutil.get_uint32(mm, pe_pos + 0x80)  # Import API 위치(RVA)
            imp_size = kavutil.get_uint32(mm, pe_pos + 0x84)  # Import API 크기

            if imp_rva:  # Import API 존재
                imp_api = {}

                # print 'IMP : %08X' % imp_rva
                imp_off = self.rva_to_off(imp_rva)[0]
                # print hex(imp_off), imp_size
                imp_data = mm[imp_off:imp_off+imp_size]
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

                pe_format['Import_API'] = imp_api

            # 디지털 인증서 분석
            cert_off = kavutil.get_uint32(mm, pe_pos + 0x98)  # 디지털 인증서 위치(유일하게 RVA가 아닌 오프셋)
            cert_size = kavutil.get_uint32(mm, pe_pos + 0x9C)  # 디지털 인증서 크기

            if cert_off:  # 디지털 인증서 존재
                if cert_off + cert_size <= len(mm[:]):  # UPack의 경우 이상한 값이 셋팅 됨
                    pe_format['CERTIFICATE_Offset'] = cert_off
                    pe_format['CERTIFICATE_Size'] = cert_size

            if self.verbose:
                print '-' * 79
                kavutil.vprint('Engine')
                kavutil.vprint(None, 'Engine', 'pe.kmd')
                kavutil.vprint(None, 'File name', os.path.split(self.filename)[-1])
                kavutil.vprint(None, 'MD5', pe_format['File_MD5'])

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
                        if s['Characteristics'] & 0x20000000 == 0x20000000:
                            off = s['PointerRawData']
                            size = s['SizeRawData']
                            fmd5 = cryptolib.md5(mm[off:off+size])
                            print '    %-8s %8d %s' % (s['Name'], size, fmd5)

                print
                kavutil.vprint('Entry Point (Raw)')
                print
                kavutil.HexDump().Buffer(mm[:], pe_format['EntryPointRaw'], 0x80)
                print

        except ValueError:
            return None

        return pe_format

    def rva_to_off(self, t_rva):
        for section in self.sections:
            size = section['VirtualSize']
            rva = section['RVA']

            if rva <= t_rva < rva + size:
                foff = (section['PointerRawData'] / self.pe_file_align) * self.pe_file_align
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
        info['title'] = 'PE Engine'  # 엔진 설명
        info['kmd_name'] = 'pe'  # 엔진 파일 이름

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
        pe_format = pe.parse()  # PE 파일 분석
        if pe_format is None:
            return None

        fileformat['pe'] = pe_format
        ret = {'ff_pe': fileformat}

        # PE 파일 뒤쪽에 추가 정보가 있는지 검사한다.
        pe_size = 0

        pe_file_align = pe_format['FileAlignment']

        for sec in pe_format['Sections']:
            off = (sec['PointerRawData'] / pe_file_align) * pe_file_align
            size = sec['SizeRawData']
            if pe_size < off + size:
                pe_size = off + size

        file_size = len(filehandle)

        if 'CERTIFICATE_Offset' in pe_format:  # 파일 뒤에 인증서가 존재하는가?
            if pe_format['CERTIFICATE_Offset'] == pe_size:  # PE 끝나는 시점에 인증서가 있으면 인증서 포함해서 크기 처리
                t_pe_size = pe_format['CERTIFICATE_Offset'] + pe_format['CERTIFICATE_Size']
                if pe_size < t_pe_size:
                    pe_size = t_pe_size

        if pe_size < file_size and pe_size != 0:
            fileformat = {'Attached_Pos': pe_size}  # 포맷 정보를 담을 공간
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
            if 'CABINET_Offset' in fileformat['ff_pe']['pe']:
                off = fileformat['ff_pe']['pe']['CABINET_Offset']
                size = fileformat['ff_pe']['pe']['CABINET_Size']

                file_scan_list.append(['arc_pe_cab:%d:%d' % (off, size), 'CABINET'])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id.find('arc_pe_cab:') != -1:
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
