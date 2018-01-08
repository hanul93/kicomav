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
        self.REF_OBJ = 0  # 참조 OBJ의 Stream 추출하기
        self.IN_OBJ = 1  # 해당 문장이 포함된 OBJ의 Stream 추출하기

        # PDF 헤더
        pat = r'^s*%PDF-1.'
        self.p_pdf_header = re.compile(pat, re.IGNORECASE)

        # PDF내부의 OBJ의 위치 기록을 위해 사용한다.
        s = r'(\d+)\s+0\s+obj\s*<<[\d\D]+?endobj'
        self.p_obj = re.compile(s)
        self.pdf_obj_off = None

        # 해당 패턴이 존재하면 악성코드 검사를 시도한다.
        self.p_pdf_scanables = {}
        pats = {r'/JS\s+(\d+)\s+0\s+R\b': self.REF_OBJ,
                r'/Length\s+0\b': self.IN_OBJ
                }

        for pat in pats.keys():
            self.p_pdf_scanables[re.compile(pat, re.IGNORECASE)] = pats[pat]

        # Stream 추출
        pat = r'stream\s*([\d\D]+?)\s*endstream'
        self.p_stream = re.compile(pat, re.IGNORECASE)

        # /Filter
        pat = '/Filter\s*/(\w+)'
        self.p_pdf_filter = re.compile(pat, re.IGNORECASE)

        # PDF 트로이목마 진단용 패턴
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
        info['version'] = '1.2'  # 버전
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
        self.pdf_obj_off = None
        stream_obj_no = []
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 PDF 포맷이 있는가?
        if 'ff_pdf' in fileformat:
            try:
                buf = open(filename, 'rb').read()
                for pat in self.p_pdf_scanables.keys():
                    for p in pat.finditer(buf):
                        if self.p_pdf_scanables[pat] == self.REF_OBJ:
                            stream_obj_no.append(p.groups()[0])
                        else:  # self.IN_OBJ
                            self.__search_object_off(buf)

                            for obj_no in self.pdf_obj_off.keys():
                                start_off = self.pdf_obj_off[obj_no][0]
                                end_off = self.pdf_obj_off[obj_no][1]
                                if start_off < p.span()[0] < end_off:
                                    stream_obj_no.append(obj_no)
                                    break

                if len(stream_obj_no):  # Stream 추출 대상이 존재하는가?
                    stream_obj_no.sort()
                    for no in stream_obj_no:
                        file_scan_list.append(['arc_pdf', 'PDF #%s' % no])
            except (IOError, MemoryError) as e:
                return []

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_pdf' and self.pdf_obj_off is not None:
            try:
                obj_no = fname_in_arc[5:]  # 압축 해제 대상 추출

                buf = open(arc_name, 'rb').read()
                start_off, end_off = self.pdf_obj_off[obj_no]

                # Stream 추출
                p = self.p_stream.search(buf[start_off:end_off])
                if p:  # 찾았음
                    data = p.groups()[0]

                    # 필터가 존재하나?
                    pf = self.p_pdf_filter.search(buf[start_off:end_off])
                    if pf:
                        if pf.groups()[0].lower() == 'flatedecode':
                            try:
                                data = zlib.decompress(data)
                            except zlib.error:
                                pass

                    return data
            except (IOError, MemoryError) as e:
                pass

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        pass

    # ---------------------------------------------------------------------
    # __search_object_off(self, buf)
    # PDF OBJ의 위치를 기록한다. [내부용]
    # ---------------------------------------------------------------------
    def __search_object_off(self, buf):
        if self.pdf_obj_off:
            return

        self.pdf_obj_off = {}
        for p in self.p_obj.finditer(buf):
            obj_no = p.groups()[0]
            obj_off = p.span()
            self.pdf_obj_off[obj_no] = obj_off

        if len(self.pdf_obj_off) == 0:
            self.pdf_obj_off = None
