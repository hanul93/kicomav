# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import re
import tarfile
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
        self.p_tar_magic = re.compile(r'[\d\x20\x00]+')
        self.handle = {}  # 압축 파일 핸들
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
        info['title'] = 'Tar Archive Engine'  # 엔진 설명
        info['kmd_name'] = 'tar'  # 엔진 파일 이름
        info['engine_type'] = kernel.ARCHIVE_ENGINE  # 엔진 타입

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
            zfile = tarfile.open(filename)  # tar 파일 열기
            self.handle[filename] = zfile

        return zfile

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
        p = self.p_tar_magic.match(mm[100:157])  # tar 매직이 없어서 별도로 체크
        if p:  # 헤더 체크
            if len(p.group()) == 57:
                try:
                    tfile = tarfile.open(filename)  # tar 파일 열기
                    tfile.close()

                    ret['ff_tar'] = 'tar'
                    return ret
                except tarfile.ReadError:
                    pass

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

        # 미리 분석된 파일 포맷중에 tar 포맷이 있는가?
        if 'ff_tar' in fileformat:
            try:
                tfile = self.__get_handle(filename)

                for name in tfile.getnames():
                    file_scan_list.append(['arc_tar', name])

                return file_scan_list
            except tarfile.ReadError:
                pass

        return []

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_tar':
            tfile = self.__get_handle(arc_name)
            try:
                f = tfile.extractfile(fname_in_arc)
                data = f.read()
                return data
            except tarfile.ReadError:
                pass

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        for fname in self.handle.keys():
            tfile = self.handle[fname]
            tfile.close()
            self.handle.pop(fname)
