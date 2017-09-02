# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import kernel


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

        cve_2010_3333 = r'\\\bsv\b.*?(\d+);'
        self.prog_cve_2010_3333 = re.compile(cve_2010_3333)

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

        if mm[:4] == '{\\rt':  # RTF 파일
            # CVE-2010-3333
            t = self.prog_cve_2010_3333.search(mm)
            if t:
                val = int(t.groups()[0])
                if val != 2 and val != 4 and val != 8:
                    if self.verbose:
                        print '[*] RTF :', val

                    return True, 'Exploit.RTF.CVE-2010-3333', 0, kernel.INFECTED

            # CVE-2014-1761
            t = self.prog_cve_2014_1761.search(mm)
            if t:
                val = t.groups()[0]
                if self.verbose:
                    print '[*] RTF :', val

                t1 = re.findall(r'{\\lfolevel}', mm)
                if t1:
                    if self.verbose:
                        print '[*] N :', len(t1)
                    if len(t1) > int(val):
                        return True, 'Exploit.RTF.CVE-2014-1761', 0, kernel.INFECTED
        else:
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
        vlist.append('Exploit.RTF.CVE-2010-3333')
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
        info['sig_num'] = 2  # 진단/치료 가능한 악성코드 수

        return info
