# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import re
import zlib


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

        pat = r'\s/OpenAction\b'
        self.p_pdf_openaction = re.compile(pat, re.IGNORECASE)

        # Stream을 가진 Object
        pat = r'(\d+)\s+0\s+obj\s*<<.+>>\s*?stream\s*([\d\D]+?)\s*endstream\s+endobj'
        self.p_pdf_obj = re.compile(pat, re.IGNORECASE)

        # /Filter
        pat = '/Filter\s+/(\w+)'
        self.p_pdf_filter = re.compile(pat, re.IGNORECASE)

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
        info['title'] = 'PDF Engine'  # 엔진 설명
        info['kmd_name'] = 'pdf'  # 엔진 파일 이름

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
            buf = ''

            try:
                with open(filename, 'rb') as fp:
                    buf = fp.read()
                    if not self.p_pdf_openaction.search(buf):  # OpenAction이 없으면 검사하지 않음
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
