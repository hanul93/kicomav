# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import zlib
import mmap
import struct


MAGIC = 'MEI\014\013\012\013\016'


class CArchiveFile:
    def __init__(self, filename, verbose=False):
        self.verbose = verbose  # 디버깅용
        self.filename = filename
        self.fp = None
        self.mm = None
        self.tocs = {}

        self.parse()

    def parse(self):
        try:
            fp = open(self.filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            self.fp = fp
            self.mm = mm

            mpos = mm[-4096:].rfind(MAGIC)
            mbuf = mm[-4096 + mpos:]

            magic, totallen, tocpos, toclen, pyvers, pylib_name = struct.unpack('!8siiii64s', mbuf[:88])
            if magic == MAGIC:
                # print totallen, tocpos, toclen, pyvers, pylib_name

                pkg_start = 0  # len(mm) - totallen
                # print pkg_start, len(mm), totallen

                s = mm[pkg_start + tocpos:pkg_start + tocpos + toclen]
                p = 0

                while p < toclen:
                    slen, dpos, dlen, ulen, flag, typcd = struct.unpack('!iiiiBB', s[p:p + 18])
                    # print slen, dpos, dlen, ulen, flag, chr(typcd),
                    nmlen = slen - 18
                    p += 18
                    (nm,) = struct.unpack('%is' % nmlen, s[p:p + nmlen])
                    p += nmlen
                    nm = nm.rstrip(b'\0')
                    nm = nm.decode('utf-8')
                    # print nm

                    self.tocs[nm] = {
                        'Data Pos': dpos,
                        'Data Length': dlen,
                        'Flag': flag,
                    }
        except struct.error:
            pass
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
        if len(self.tocs):
            return self.tocs.keys()

        return []

    def read(self, fname):
        try:
            toc = self.tocs[fname]
            start = toc['Data Pos']
            size = toc['Data Length']
            flag = toc['Flag']

            data = self.mm[start:start+size]

            if flag:
                data = zlib.decompress(data)

            return data
        except (KeyError, zlib.error) as e:
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
        info['title'] = 'CArchive Engine'  # 엔진 설명
        info['kmd_name'] = 'carch'  # 엔진 파일 이름
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
            zfile = CArchiveFile(filename)  # pyz 파일 열기
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
        fileformat = {}  # 포맷 정보를 담을 공간

        mm = filehandle
        
        # CArchive는 파일 뒤에 Magic이 존재하므로
        # 압축 파일 이름 중에 Attached 된 형태일때만 CArchive Magic 검사
        if filename_ex.find('Attached') != -1:   
            if mm[-4096:].rfind(MAGIC) != -1:  # 헤더 체크
                ret = {'ff_carch': 'CArchive'}
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

        # 미리 분석된 파일 포맷중에 CArchive 포맷이 있는가?
        if 'ff_carch' in fileformat:
            zfile = self.__get_handle(filename)

            for name in zfile.namelist():
                file_scan_list.append(['arc_carch', name])
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
        if arc_engine_id == 'arc_carch':
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
