# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import mmap
import kernel
import kavutil


# -------------------------------------------------------------------------
# objdata 추출 관련 함수들
# -------------------------------------------------------------------------
p_rtf_tags = re.compile(r'\\([^\\{}]*)')
p_rtf_tag = re.compile(r'\\\s*(#|\*|[a-z\x00]*)(\d*)(.*)', re.I)
p_obj_tag = re.compile(r'\\objdata\b', re.I)


# {} 개수를 체크해서 최종 닫혀진 괄호까지의 데이터를 추출한다.
def extract_data(buf):
    return __sub_extract_data(buf)[0]


def join_data(tag, num, data):
    s = ''
    if tag:
        s += tag
    if num:
        s += num
    if data:
        s += data

    return s


def __keyword_sub(obj):
    s = ''

    tag, num, data = obj.groups()

    if tag.strip() in ['#', '*', '']:
        s += join_data(None, num, data)
    elif tag == 'bin':
        n = int(num, 16)
        d = data.lstrip()

        s += join_data(None, None, d[:n].encode('hex') + d[n:])
    else:
        pass
        # print '[*] Key :', tag
        # s += join_data(None, None, data)

    return s


def __keyword_process(data):
    s = ''

    buf_len = len(data)
    off = 0

    while off < buf_len:
        c = data[off]
        if c == '\\':
            p = p_rtf_tags.match(data[off:])
            if p:
                t = p.group()
                x = p_rtf_tag.sub(__keyword_sub, t)
                s += x
                off += len(t)
        else:
            s += c
            off += 1

    return s


def __sub_extract_data(data):
    ret = ''

    len_buf = len(data)
    off = 0
    while off < len_buf:
        c = data[off]
        off += 1

        if c == '{':
            x, l = __sub_extract_data(data[off:])
            ret += x
            off += l
        elif c == '}':
            return ret, off
        elif c == '\\':
            p = p_rtf_tags.search(data[off - 1:])
            if p:
                x = p.group()
                xx = __keyword_process(x)
                ret += xx
                off += len(x) - 1
        else:
            ret += c

    if len(ret):
        return ret, off


# -------------------------------------------------------------------------
# RtfFile 클래스
# -------------------------------------------------------------------------
class RtfFile:
    def __init__(self, filename, verbose=False):
        self.verbose = verbose  # 디버깅용
        self.filename = filename
        self.fp = None
        self.mm = None

        self.p = re.compile(r'[A-Fa-f0-9]+')

        self.num_objdata = 0  # RTF에 삽입된 objdata의 수
        self.objdata = {}  # objdata
        self.parse()

    def parse(self):
        try:
            self.fp = open(self.filename, 'rb')
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

            mm = self.mm

            if mm[:4] != '{\\rt':  # 헤더 체크
                self.close()
                return None

            self.num_objdata = len(p_obj_tag.findall(mm))
            if self.verbose:
                print '[*] objdata : %d' % self.num_objdata

            # objdata를 추출한다.
            i = 1
            for obj in p_obj_tag.finditer(mm):
                end_off = obj.span()[1]
                data = extract_data(mm[end_off:])

                hex_data = ''.join(self.p.findall(data))

                if hex_data[:16] == '0105000002000000':  # Magic
                    h = hex_data
                    name_len = int(h[22:24] + h[20:22] + h[18:20] + h[16:18], 16)
                    name = h[24:24 + (name_len * 2) - 2].decode('hex')
                    off = 24 + (name_len * 2) + 16  # Unknown 4Byte * 2
                    data_len = int(h[off + 6:off + 8] + h[off + 4:off + 6] + h[off + 2:off + 4] + h[off:off + 2], 16)

                    if self.verbose:
                        print name_len
                        print name
                        print hex(data_len)

                    t = h[24 + (name_len * 2) + 24:24 + (name_len * 2) + 24 + (data_len * 2)]

                    if self.verbose:
                        print hex(len(t))

                    obj_name = 'RTF #%d' % i
                    self.objdata[obj_name] = t.decode('hex')
                    i += 1
        except IOError:
            pass

    def close(self):
        if self.mm:
            self.mm.close()
            self.mm = None

        if self.fp:
            self.fp.close()
            self.fp = None

    def namelist(self):
        names = []

        if len(self.objdata):
            names = self.objdata.keys()
            names.sort()

        return names

    def read(self, fname):
        return self.objdata.get(fname, None)


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
        self.handle = {}  # 압축 파일 핸들

        cve_2010_3333_magic = r'\bpfragments\b'
        self.cve_2010_3333_magic = re.compile(cve_2010_3333_magic, re.IGNORECASE)

        cve_2010_3333_1 = r'pfragments\b[\d\D]*?\\sv\b[\d\D]*?(\d+)|\\sv\b[\d\D]*?(\d+)[\d\D]*?pfragments\b'
        self.prog_cve_2010_3333_1 = re.compile(cve_2010_3333_1, re.IGNORECASE)

        cve_2010_3333_2 = r'\\sn[\W]{1,20}?pfragments\b'
        self.prog_cve_2010_3333_2 = re.compile(cve_2010_3333_2, re.IGNORECASE)

        cve_2014_1761 = r'\\listoverridecount(\d+)'
        self.prog_cve_2014_1761 = re.compile(cve_2014_1761, re.IGNORECASE)

        eps_dropper = r'exec\s+(4d5a)?([0-9a-f]{2})+50450000'
        self.prog_eps_dropper = re.compile(eps_dropper, re.IGNORECASE)
        return 0  # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

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

        if mm[:4] == '{\\rt':  # RTF 파일
            ret['ff_rtf'] = 'RTF'

        return ret

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

        # 미리 분석된 파일 포맷중에 RTF 포맷이 있는가?
        if 'ff_rtf' in fileformat:
            # 검색 속도를 위해 pfragments가 존재하는지 먼저 확인
            if self.cve_2010_3333_magic.search(mm):
                # CVE-2010-3333 (1)
                t = self.prog_cve_2010_3333_1.search(mm)
                if t:
                    val = int(max(t.groups()))

                    if val != 2 and val != 4 and val != 8:
                        if self.verbose:
                            print '[*] RTF :', val

                        return True, 'Exploit.RTF.CVE-2010-3333.a', 0, kernel.INFECTED

                # CVE-2010-3333 (2)
                t = self.prog_cve_2010_3333_2.search(mm)
                if t:
                    return True, 'Exploit.RTF.CVE-2010-3333.b', 0, kernel.INFECTED

            # CVE-2014-1761
            t = self.prog_cve_2014_1761.search(mm)
            if t:
                val = int(t.groups()[0])

                if self.verbose:
                    print '[*] RTF :', val

                if val >= 25:
                    t1 = re.findall(r'{\\lfolevel}', mm)
                    if t1:
                        if self.verbose:
                            print '[*] N :', len(t1)
                        if len(t1) > val:
                            return True, 'Exploit.RTF.CVE-2014-1761', 0, kernel.INFECTED
        else:
            if kavutil.is_textfile(mm[:4096]):
                t = self.prog_eps_dropper.search(mm)
                if t:
                    return True, 'Trojan.PS.Agent', 0, kernel.INFECTED

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
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = list()  # 리스트형 변수 선언

        # 진단/치료하는 악성코드 이름 등록
        vlist.append('Exploit.RTF.CVE-2010-3333.a')
        vlist.append('Exploit.RTF.CVE-2010-3333.b')
        vlist.append('Exploit.RTF.CVE-2014-1761')
        vlist.append('Trojan.PS.Agent')

        return vlist

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.1'  # 버전
        info['title'] = 'RTF Engine'  # 엔진 설명
        info['kmd_name'] = 'rtf'  # 엔진 파일 이름
        info['make_arc_type'] = kernel.MASTER_DELETE  # 악성코드 치료 후 재압축 유무
        info['sig_num'] = len(self.listvirus())  # 진단/치료 가능한 악성코드 수

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
            zfile = RtfFile(filename)  # rtf 파일 열기
            self.handle[filename] = zfile

        return zfile

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 RTF 포맷이 있는가?
        if 'ff_rtf' in fileformat:
            zfile = self.__get_handle(filename)

            for name in zfile.namelist():
                file_scan_list.append(['arc_rtf', name])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_rtf':
            zfile = self.__get_handle(arc_name)
            data = zfile.read(fname_in_arc)
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
            self.handle.pop(fname)

    # ---------------------------------------------------------------------
    # mkarc(self, arc_engine_id, arc_name, file_infos)
    # 입력값 : arc_engine_id - 압축 가능 엔진 ID
    #         arc_name      - 최종적으로 압축될 압축 파일 이름
    #         file_infos    - 압축 대상 파일 정보 구조체
    # 리턴값 : 압축 성공 여부 (True or False)
    # ---------------------------------------------------------------------
    def mkarc(self, arc_engine_id, arc_name, file_infos):

        if arc_engine_id == 'arc_rtf':
            # 재 압축 할 수가 없으므로 삭제 처리해야 한다.
            return True

        return False
