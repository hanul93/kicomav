# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)
# virus 유형의 악성코드 검사 엔진


import os
import types
import kernel
import kavutil
import cryptolib


# -------------------------------------------------------------------------
# Signature 파일의 구조
# -------------------------------------------------------------------------
# Flag + Word(해당 Flag에 Offset은 항상 0 위치의 2Byte)
# Flag
# 0 : 파일의 처음
# 1 : 실행 위치 (DOS-EP)
# 2 : 실행 위치 (PE-EP)
# 3 : 각 섹션의 처음 (PE, ELF 등)
# 4 : Attach의 처음
# Checksum1 : Flag, Offset, Length, CRC32
# Checksum2 : Flag, Offset, Length, CRC32
# MalwareName
# -------------------------------------------------------------------------
# Example:  0000 F8A8:02, 0000, 0000, XXXXXXXX:02, 0000, 0000, XXXXXXXX:MalwareName
# -------------------------------------------------------------------------


# -------------------------------------------------------------------------
# 주어진 버퍼에서 특정 크기별로 미리 패턴을 만들어 둔다.
# -------------------------------------------------------------------------
def gen_checksums(buf):
    patterns = []

    # 처음 10개는 앞쪽 6, 7, 8, 9 ... 0xF
    for i in range(1, 0x10):
        patterns.append(int(gen_checksum(buf, 0, i), 16))

    # 나머지 15개는 0x10, 0x18, 0x20 ... 0x80
    for i in range(0x10, 0x88, 8):
        patterns.append(int(gen_checksum(buf, 0, i), 16))

    return patterns


def gen_checksum(buf, off, size):
    return cryptolib.crc32(buf[off:off+size])


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

        self.flags_off = {}  # 각 flag의 위치 정보를 담는다.
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
        info['title'] = 'Virus Engine'  # 엔진 설명
        info['kmd_name'] = 've'  # 엔진 파일 이름
        info['sig_num'] = kavutil.handle_pattern_vdb.get_sig_num('ve') + 2  # 진단/치료 가능한 악성코드 수

        return info

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = kavutil.handle_pattern_vdb.get_sig_vlist('ve')

        vlists = []
        vlists.append('Virus.Win32.Small.a')
        vlists.append('Virus.Win32.SuperThreat.b')

        for vname in vlist:
            vlists.append(kavutil.normal_vname(vname))

        vlists.sort()
        return vlists

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
        try:
            self.flags_off = {}
            flags = []
            mm = filehandle

            # Virus.Win32.Small.a 검사
            ret, vname = self.__scan_virus_win32_small_a(filehandle, fileformat)
            if ret:
                return True, vname, 0, kernel.INFECTED

            # Flag별 Signature를 만든다.
            # Flag - 0 : 파일의 처음
            flags.append([int('0000' + mm[0:2].encode('hex'), 16), gen_checksums(mm[0:0x80])])
            self.flags_off[0] = [0]

            # Flag - 1 : DOS EP
            # TODO

            # 미리 분석된 파일 포맷중에 PE 포맷이 있는가?
            if 'ff_pe' in fileformat:
                # Flag - 2 : PE EP
                ff = fileformat['ff_pe']
                ep_off = ff['pe']['EntryPointRaw']
                flags.append([int('0002' + mm[ep_off:ep_off+2].encode('hex'), 16),
                              gen_checksums(mm[ep_off:ep_off+0x80])])
                self.flags_off[2] = [ep_off]

                # Flag - 3 : 각 섹션의 헤더
                flag3_off = []
                for idx, section in enumerate(ff['pe']['Sections']):
                    fsize = section['SizeRawData']
                    foff = section['PointerRawData']
                    flags.append([int('0003' + mm[foff:foff + 2].encode('hex'), 16),
                                  gen_checksums(mm[foff:foff+0x80])])
                    flag3_off.append(foff)
                self.flags_off[3] = flag3_off

            # Attach 영역이 존재하는가?
            if 'ff_attach' in fileformat:
                # Flag - 4 : Attach 영역
                pos = fileformat['ff_attach']['Attached_Pos']
                size = fileformat['ff_attach']['Attached_Size']
                if size > 0x80:
                    flags.append([int('0004' + mm[pos:pos+2].encode('hex'), 16),
                                  gen_checksums(mm[pos:pos + 0x80])])
                    self.flags_off[4] = [pos]

            cs_size = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x18,
                      0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60,
                      0x68, 0x70, 0x78, 0x80]

            if self.verbose:
                print '-' * 79
                kavutil.vprint('Engine')
                kavutil.vprint(None, 'Engine', 've.kmd')
                kavutil.vprint(None, 'File name', os.path.split(filename)[-1])
                kavutil.vprint(None, 'MD5', cryptolib.md5(mm[:]))

                print
                kavutil.vprint('VE')
                vdb_name = os.path.split(filename)[-1] + '.vdb'
                kavutil.vprint(None, 'VDB File name', vdb_name)

                fp = open(vdb_name, 'w')

                for flag in flags:
                    # kavutil.vprint(None, 'Flag', '%08X' % flag[0])
                    msg = 'Flag : %08x\n' % flag[0]
                    fp.write(msg)

                    for i, cs in enumerate(flag[1]):
                        # kavutil.vprint(None, 'CS = %02X' % cs_pos[i], cs)
                        msg = 'CS = %02x : %08x\n' % (cs_size[i], int(cs))
                        fp.write(msg)
                    fp.write('\n')

                fp.close()

            for flag in flags:
                p1 = kavutil.handle_pattern_vdb.match_size('ve', flag[0])  # 일치하는 Flag가 있나?
                # print '%08x :' % flag[0], p1
                # print flag[0] >> 16

                if p1:
                    for ve_id in p1.keys():
                        for idx in p1[ve_id]:
                            cs1 = kavutil.handle_pattern_vdb.get_cs1(ve_id, idx)

                            cs1_flag = cs1[0]
                            cs1_off = cs1[1]
                            cs1_size = cs1[2]
                            cs1_crc = cs1[3]

                            if flag[0] >> 16 == cs1_flag and cs1_off == 0 and cs1_size in cs_size:
                                i = cs_size.index(cs1_size)
                                # print '=', hex(flag[1][i])
                                if cs1_crc == flag[1][i]:  # 1차 패턴이 같은가?
                                    vname = self.__scan_cs2(mm, ve_id, idx)
                                    if vname:
                                        return True, vname, 0, kernel.INFECTED
                            else:
                                buf = self.__get_data_crc32(mm, cs1_flag, cs1_off, cs1_size)
                                if cs1_crc == int(gen_checksum(mm, cs1_off, cs1_size), 16):
                                    vname = self.__scan_cs2(mm, ve_id, idx)
                                    if vname:
                                        return True, vname, 0, kernel.INFECTED
        except IOError:
            pass

        kavutil.handle_pattern_vdb.__save_mem()  # 메모리 용량을 낮추기 위해 사용

        # 악성코드를 발견하지 못했음을 리턴한다.
        return False, '', -1, kernel.NOT_FOUND

    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id)
    # 악성코드를 치료한다.
    # 입력값 : filename    - 파일 이름
    #        : malware_id - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    # ---------------------------------------------------------------------
    def disinfect(self, filename, malware_id):  # 악성코드 치료
        try:
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if malware_id == 0:
                os.remove(filename)  # 파일 삭제
                return True  # 치료 완료 리턴
        except IOError:
            pass

        return False  # 치료 실패 리턴

    # ---------------------------------------------------------------------
    # __get_data_crc32(self, buf, flag, off, size)
    # 특정 위치의 crc32를 얻는다.
    # 입력값 : buf  - 버퍼
    #      : flag - 읽을 위치 정보 (Base 위치)
    #      : off  - 상대 거리
    #      : size - 계산할 버퍼 크기
    # 리턴값 : 계산된 crc32
    # ---------------------------------------------------------------------
    def __get_data_crc32(self, buf, flag, off, size):
        crc32s = []

        base_offs = self.flags_off.get(flag, [])
        for base_off in base_offs:
            crc32s.append(int(gen_checksum(buf, base_off + off, size), 16))

        return crc32s

    # ---------------------------------------------------------------------
    # __scan_cs2(self, mm, ve_id, idx)
    # 2차 패턴을 검사한다.
    # 입력값 : mm    - 버퍼
    #      : ve_id - ve 패턴의 파일
    #      : idx   - 내부 인덱스
    # 리턴값 : 발견된 악성코드 이름
    # ---------------------------------------------------------------------
    def __scan_cs2(self, mm, ve_id, idx):
        cs2 = kavutil.handle_pattern_vdb.get_cs2(ve_id, idx)
        cs2_flag = cs2[0]
        cs2_off = cs2[1]
        cs2_size = cs2[2]
        cs2_crc = cs2[3]
        vname_id = cs2[4]

        crc32s = self.__get_data_crc32(mm, cs2_flag, cs2_off, cs2_size)
        if cs2_crc in crc32s:  # 패턴 일치
            vname = kavutil.handle_pattern_vdb.get_vname(ve_id, vname_id)
            if vname:
                return kavutil.normal_vname(vname)

        return None

    # ---------------------------------------------------------------------
    # Virus.Win32.Small.a 검사한다.
    # 리턴값 : True(발견) or False(미발견)
    # ---------------------------------------------------------------------
    def __scan_virus_win32_small_a(self, mm, fileformat):
        if 'ff_pe' in fileformat:
            ff = fileformat['ff_pe']['pe']
            ep_off = ff['EntryPointRaw']

            if cryptolib.crc32(mm[ep_off:ep_off + 12]) == '4d49a25f':
                v_rva = kavutil.get_uint32(mm, ep_off + 12) + 1  # 악성코드 RVA
                v_rva -= ff['ImageBase']

                # v_rva가 마지막 섹션에 속하는 값인지 확인한다.
                sec = ff['Sections'][-1]
                if sec['RVA'] <= v_rva <= sec['RVA'] + sec['VirtualSize']:
                    pe_file_align = ff['FileAlignment']
                    if pe_file_align:
                        foff = (sec['PointerRawData'] / pe_file_align) * pe_file_align
                    else:
                        foff = sec['PointerRawData']

                    v_off = v_rva - sec['RVA'] + foff

                    x = cryptolib.crc32(mm[v_off:v_off + 0x30])
                    if x == '8d964738':
                        return True, 'Virus.Win32.Small.a'
                    elif x == '00000000' or x == 'f288b395':  # 파일이 깨진 경우이거나 모든 값이 0인 경우이다.
                        return True, 'Virus.Win32.SuperThreat.b'

        return False, None
