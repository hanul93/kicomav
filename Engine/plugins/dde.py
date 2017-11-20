# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import zipfile
import kernel


# -------------------------------------------------------------------------
# zip 파일의 특별한 파일명을 압축 해제하여 데이터를 리턴한다.
# -------------------------------------------------------------------------
def get_zip_data(zip_name, filename):
    data = None

    try:
        zfile = zipfile.ZipFile(zip_name)  # zip 파일 열기
        names = zfile.namelist()

        for name in names:
            if name.lower() == filename:
                data = zfile.read(name)
                break

        zfile.close()
    except zipfile.BadZipfile:
        pass

    return data


# -------------------------------------------------------------------------
# 실행 파일명이 포함된 문자열인지 확인한다.
# -------------------------------------------------------------------------
def is_include_exe(s):
    exts = ['.exe', '.cmd', '.vbs']

    s = s.lower()

    for ext in exts:
        if s.find(ext) != -1:
            return True

    return False


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
        # 악성코드 DDE 패턴
        self.dde_ptns = []

        s = r'<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>'
        self.dde_ptns.append(re.compile(s))

        s = r'<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>'
        self.dde_ptns.append(re.compile(s))

        # 의심 명령어
        s = r'<w:instrText>(.+?)</w:instrText>'
        self.cmd1 = re.compile(s, re.IGNORECASE)

        s = r'<w:fldSimple\s+?w:instr=\s*?"(.+?)"'
        self.cmd2 = re.compile(s, re.IGNORECASE)  # QUOTE  Case

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
        try:
            # 미리 분석된 파일 포맷중에 OLE 포맷이 있는가?
            if 'ff_ooxml' in fileformat:
                if fileformat['ff_ooxml'] == 'docx':
                    # docx 파일의 경우 DDE 악성코드 존재 가능성 있음
                    data = get_zip_data(filename, 'word/document.xml')

                    if data:
                        for p in self.dde_ptns:
                            s = p.search(data)
                            if s:
                                src = s.group()

                                # Case 1
                                cmds = self.cmd1.findall(src)
                                for cmd in cmds:
                                    t = cmd.lower()
                                    if is_include_exe(t):
                                        return True, 'Exploit.MSWord.DDE.a', 0, kernel.INFECTED

                                # Case 2
                                cmds = self.cmd2.findall(src)
                                for cmd in cmds:
                                    t = cmd.lower()
                                    if t.find('quote') != -1:
                                        t = t.replace('quote', '')
                                        t = t.strip()
                                        t1 = t.split(' ')
                                        t2 = ''.join([chr(int(x)) for x in t1])
                                        t3 = t2.lower()
                                        if is_include_exe(t3):
                                            return True, 'Exploit.MSWord.DDE.b', 0, kernel.INFECTED
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

        # 진단/치료하는 악성코드 이름 등록
        vlist.append('Exploit.MSWord.DDE.a')
        vlist.append('Exploit.MSWord.DDE.b')

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
        info['title'] = 'DDE Scan Engine'  # 엔진 설명
        info['kmd_name'] = 'dde'  # 엔진 파일 이름
        info['sig_num'] = 2  # 진단/치료 가능한 악성코드 수

        return info
