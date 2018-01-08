# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import zlib
import struct
import marshal
import types
import kernel
import kavutil
import cryptolib


class PyzFile:
    def __init__(self, filename, verbose=False):
        self.verbose = verbose  # 디버깅용
        self.filename = filename
        self.fp = None
        self.tocs = None
        self.parse()

    def parse(self):
        try:
            self.fp = open(self.filename, 'rb')
            fp = self.fp
            magic = fp.read(4)

            if magic != 'PYZ\x00':  # 헤더 체크
                fp.close()
                self.fp = None
                return None

            fp.seek(8)
            toc_off = struct.unpack('>L', fp.read(4))[0]  # PKZ 파일에서 TOC 위치

            fp.seek(toc_off)
            toc = fp.read()
            if toc[0] == '[' or toc[0] == '{':  # ListType or DictionaryType인가?
                self.tocs = marshal.loads(toc)
        except IOError:
            pass

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def namelist(self):
        names = []

        if self.tocs:
            if isinstance(self.tocs, types.DictionaryType):
                return self.tocs.keys()
            elif isinstance(self.tocs, types.ListType):
                for x in self.tocs:
                    names.append(x[0])

        return names

    def read(self, fname):
        try:
            if isinstance(self.tocs, types.DictionaryType):
                toc = self.tocs[fname]
                start = toc[1]
                size = toc[2]
                flag = True
            elif isinstance(self.tocs, types.ListType):
                for x in self.tocs:
                    if x[0] == fname:
                        start = x[1][1]
                        size = x[1][2]
                        flag = True
                        break

            self.fp.seek(start)
            data = self.fp.read(size)

            if flag:
                data = zlib.decompress(data)

            return data
        except KeyError:
            pass

        return None


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

        chars = r"A-Za-z0-9/\-=:.,_$%@'()[\]<> "
        shortest_run = 5

        regexp = '[%s]{%d,}' % (chars, shortest_run)
        self.p_string = re.compile(regexp)

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
        info['title'] = 'PYZ Engine'  # 엔진 설명
        info['kmd_name'] = 'pyz'  # 엔진 파일 이름
        # info['engine_type'] = kernel.ARCHIVE_ENGINE  # 엔진 타입
        # info['make_arc_type'] = kernel.MASTER_PACK  # 악성코드 치료 후 재압축 유무

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
            zfile = PyzFile(filename)  # pyz 파일 열기
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

        if mm[0:4] == 'PYZ\x00':  # 헤더 체크
            ret['ff_pyz'] = 'PYZ'
        elif mm[0:8] == '\x63\x00\x00\x00\x00\x00\x00\x00' or \
            mm[8:0x10] == '\x63\x00\x00\x00\x00\x00\x00\x00':
            ret['ff_pyc'] = 'PYC'

        return ret

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 PYZ 포맷이 있는가?
        if 'ff_pyz' in fileformat:
            zfile = self.__get_handle(filename)

            for name in zfile.namelist():
                file_scan_list.append(['arc_pyz', name])
            # zfile.close()

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_pyz':
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
            # 미리 분석된 파일 포맷중에 PE 포맷이 있는가?
            if 'ff_pyc' in fileformat:
                if self.verbose:
                    print '-' * 79
                    kavutil.vprint('Engine')
                    kavutil.vprint(None, 'Engine', 'pyz.kmd')

                mm = filehandle

                # String 추출
                if len(mm):
                    if self.verbose:
                        print
                        kavutil.vprint('String')

                    for match in self.p_string.finditer(mm):
                        find_str = match.group()
                        find_str_off = match.start()

                        # 중요 문자열 시작전에 해당 문자열의 길이가 존재함
                        x = kavutil.get_uint32(mm, find_str_off - 4)
                        if len(find_str) < x:
                            continue

                        buf = find_str[:x]
                        fsize = len(buf)

                        if self.verbose:
                            fmd5 = cryptolib.md5(buf)
                            kavutil.vprint(None, fmd5, '%3d : %s' % (fsize, buf))

                        if fsize and kavutil.handle_pattern_md5.match_size('emalware', fsize):
                            fmd5 = cryptolib.md5(buf)
                            # print fsize, fmd5
                            vname = kavutil.handle_pattern_md5.scan('emalware', fsize, fmd5)
                            if vname:
                                return True, vname, 0, kernel.INFECTED
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
