# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import re
import os
import zlib
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
        # PDF 헤더
        pat = r'^s*%PDF-1.'
        self.p_pdf_header = re.compile(pat, re.IGNORECASE)

        # 해당 패턴이 존재하면 악성코드 검사를 시도한다.
        self.p_pdf_scanables = []
        pats = [r'/OpenAction\b', r'/Action\b']
        for pat in pats:
            self.p_pdf_scanables.append(re.compile(pat, re.IGNORECASE))

        # Stream을 가진 Object
        pat = r'(\d+)\s+0\s+obj\s*<<.+>>\s*?stream\s*([\d\D]+?)\s*endstream\s+endobj'
        self.p_pdf_obj = re.compile(pat, re.IGNORECASE)

        # /Filter
        pat = '/Filter\s*/(\w+)'
        self.p_pdf_filter = re.compile(pat, re.IGNORECASE)

        pat = r'this\.exportDataObject.+?cName:.+?nLaunch'
        self.p_pdf_trojan_js = re.compile(pat)

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
        info['version'] = '1.1'  # 버전
        info['title'] = 'PDF Engine'  # 엔진 설명
        info['kmd_name'] = 'pdf'  # 엔진 파일 이름
        info['sig_num'] = 1  # 진단/치료 가능한 악성코드 수

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
        # fileformat = {}  # 포맷 정보를 담을 공간

        mm = filehandle
        buf = mm[:4096]

        if self.p_pdf_header.match(buf):  # PDF 헤더로 시작하나?
            # PDF 문서
            ret = {'ff_pdf': 'PDF'}

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
        try:
            # 미리 분석된 파일 포맷중에 PDF 포맷이 있는가?
            if 'ff_pdf' in fileformat:
                mm = filehandle

                if self.p_pdf_trojan_js.search(mm):
                    return True, 'Trojan.PDF.Generic', 0, kernel.INFECTED
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

        vlist.append('Trojan.PDF.Generic')  # 진단/치료하는 악성코드 이름 등록

        return vlist

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 PDF 포맷이 있는가?
        if 'ff_pdf' in fileformat:
            try:
                with open(filename, 'rb') as fp:
                    buf = fp.read()

                    for p in self.p_pdf_scanables:
                        if p.search(buf):  # 패턴이 발견되었으면 악성코드 검사해야 한다.
                            break
                    else:
                        raise IOError
            except IOError:
                return []

            for obj in self.p_pdf_obj.finditer(buf):
                obj_id = obj.groups()[0]
                file_scan_list.append(['arc_pdf', 'PDF #%s' % obj_id])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_pdf':
            buf = ''

            try:
                with open(arc_name, 'rb') as fp:
                    buf = fp.read()
            except IOError:
                return None

            for obj in self.p_pdf_obj.finditer(buf):
                obj_id = obj.groups()[0]
                if obj_id == fname_in_arc[5:]:  # 압축 해제 대상인가?
                    data = obj.groups()[1]  # Stream 데이터 추출

                    t = self.p_pdf_filter.search(obj.group())
                    if (t is not None) and (t.groups()[0].lower() == 'flatedecode'):
                        try:
                            data = zlib.decompress(data)
                        except zlib.error:
                            pass

                    return data

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        pass
