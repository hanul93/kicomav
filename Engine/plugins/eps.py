# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import re
import os

import kernel
import kavutil


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
        self.handle = {}  # 압축 파일 핸들
        self.verbose = verbose

        self.p_eps = re.compile(rb'(\bexec\b)|(\bdef\b)|(\bexch\b)|(\bstring\b)|' +
                                rb'(\breadhexstring\b)|(\bcurrentfile\b)|(\bwritestring\b)|' +
                                rb'(\bhexstring\b)'
                               )
        self.p_hex1 = re.compile(rb'<\s*[0-9A-Fa-f\s]+>')
        self.p_hex2 = re.compile(rb'[0-9A-Fa-f]{10,}')

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

        buf = mm[:4096]
        if kavutil.is_textfile(buf):  # Text 파일인가?
            t = []
            for i in self.p_eps.finditer(mm):
                t.append(i.group())

            if len(t):
                ret['ff_eps'] = list(set(t))
                return ret

        return None

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
        zfile = None
        mm = filehandle

        try:
            if 'ff_eps' in fileformat:
                if self.verbose:
                    print ('-' * 79)
                    kavutil.vprint('Engine')
                    kavutil.vprint(None, 'Engine', 'eps.kmd')
                    kavutil.vprint(None, 'File name', os.path.split(filename)[-1])
                    print ()

                scan_ptns = []
                eps_keywords = fileformat['ff_eps']

                # Keyword 추출
                if self.verbose:
                    kavutil.vprint('EPS Keyword')
                    for i, name in enumerate(eps_keywords):
                        kavutil.vprint(None, 'Keyword #%d' % (i+1), name)
                    print ()

                if 'string' in eps_keywords:
                    scan_ptns.append(self.p_hex1)

                if 'hexstring' in eps_keywords or 'readhexstring' in eps_keywords:
                    scan_ptns.append(self.p_hex2)

                for i, ptn in enumerate(scan_ptns):
                    # Hex 문자열이 존재하는가?
                    t_hex = ptn.findall(mm)

                    if self.verbose and len(t_hex) > 0:
                        kavutil.vprint('HEX #%d' % (i+1))
                        for i, x in enumerate(t_hex):
                            kavutil.vprint(None, 'Hex String #%d' % (i+1), x)
                        print ()

                    # 화이트 리스트 제거
                    s_hex = ''.join(t_hex)
                    p = re.compile(r'\s|<|>')
                    t = p.sub('', s_hex)

                    if len(t) > 10 * 1024:  # 10K 이상인가?
                        return True, 'Trojan.EPS.Generic', 0, kernel.INFECTED
        except IOError:
            pass

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

        vlist.append('Trojan.EPS.Generic')

        return vlist

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.0'  # 버전
        info['title'] = 'Eps Engine'  # 엔진 설명
        info['kmd_name'] = 'eps'  # 엔진 파일 이름
        info['sig_num'] = len(self.listvirus())  # 진단/치료 가능한 악성코드 수

        return info
