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


def InstrSub(obj):
    text = obj.groups()[0]

    off = text.find('QUOTE')  # QUOTE가 존재하나?
    if off != -1:
        t = text[off+5:].strip().split(' ')
        text = ''.join([chr(int(x)) for x in t])

    return text

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
        s = r'"begin"(.+?)"end"'
        self.p_dde_text = re.compile(s, re.IGNORECASE)

        s = r'<w:fldSimple\s+?w:instr=\s*?"(.+?)"\s*>'
        self.p_instr = re.compile(s, re.IGNORECASE)

        s = r'\bdde(auto)?\b'
        self.p_dde = re.compile(s, re.IGNORECASE)

        s = r'\\system32\b(.+)\.exe'
        self.p_cmd = re.compile(s, re.IGNORECASE)

        s = r'\<[\d\D]+?\>'
        self.p_tag = re.compile(s)

        s = r'\x13\s*dde(auto)?\b[^\x00]+'
        self.p_dde2 = re.compile(s, re.IGNORECASE)

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
                        if self.__scan_dde_docx(data):
                            return True, 'Exploit.MSWord.DDE.a', 0, kernel.INFECTED
                        elif self.__scan_cve_2017_0199_docx(data):
                            return True, 'Exploit.MSWord.CVE-2017-0199', 0, kernel.INFECTED
            elif filename_ex.lower() == 'worddocument':
                data = filehandle
                if self.__scan_dde_doc(data):
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
        vlist.append('Exploit.MSWord.CVE-2017-0199')

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
        info['sig_num'] = len(self.listvirus())  # 진단/치료 가능한 악성코드 수

        return info

    # ---------------------------------------------------------------------
    # DDE 악성코드를 진단한다.
    # ---------------------------------------------------------------------
    def __scan_dde_docx(self, data):
        # TEXT 영역을 추출한다.
        texts = self.p_dde_text.findall(data)
        if len(texts):
            buf = ''
            for text in texts:
                # 앞쪽 begin Tag 제거
                off = text.find('>')
                text = text[off + 1:]

                # 뒤쪽 end Tag 제거
                off = text.rfind('<')
                text = text[:off]

                # instr를 처리한다.
                text = self.p_instr.sub(InstrSub, text)

                # 모든 Tag 삭제
                buf += self.p_tag.sub('', text) + '\n'

            # print buf
            if len(buf):
                if self.p_dde.search(buf) and self.p_cmd.search(buf):
                    return True

        return False

    def __scan_dde_doc(self, data):
        s = self.p_dde2.search(data)
        if s:
            buf = s.group()
            if len(buf):
                if self.p_dde.search(buf) and self.p_cmd.search(buf):
                    return True

        return False

    # ---------------------------------------------------------------------
    # CVE-2017-0199 악성코드를 진단한다.
    # ---------------------------------------------------------------------
    def __scan_cve_2017_0199_docx(self, data):
        if data.find('<o:OLEObject Type="Link" ProgID="Word.Document.8"') != -1:
            return True

        return False
