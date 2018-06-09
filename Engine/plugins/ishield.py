# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import struct
import zlib
import os
import py7zlib

import zipfile
import kernel
import kavutil


# ---------------------------------------------------------------------
# InstallShield 클래스
# ---------------------------------------------------------------------
class InstallShield:
    def __init__(self, fname):
        self.fname = fname
        self.fp = None
        self.fsize = 0
        self.install_name = []

    def __del__(self):
        if self.fp:
            self.close()

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def parse(self):
        try:
            self.fp = open(self.fname, 'rb')
            self.fsize = os.fstat(self.fp.fileno()).st_size

            cur_pos = 0

            # Magic 체크
            if self.fp.read(0xe) != 'InstallShield\x00':
                raise ValueError

            cur_pos += 0xe

            # InstallShield에 첨부된 파일 수
            data = self.fp.read(0x20)
            num_file = kavutil.get_uint32(data, 0)

            cur_pos += 0x20

            for i in range(num_file):
                data = self.fp.read(0x138)
                fname = data[:0x10b].replace('\x00', '')
                fsize = kavutil.get_uint32(data, 0x10c)
                foff = cur_pos + 0x138
                self.install_name.append((foff, fsize, fname))

                cur_pos += 0x138 + fsize
                self.fp.seek(cur_pos)

            return True
        except (IOError, OSError, ValueError) as e:
            pass

        return False

    def namelist(self):
        flist = []

        for f in self.install_name:
            flist.append(f[2])

        return flist

    def read(self, fname):
        for f in self.install_name:
            if f[2] == fname:
                foff = f[0]
                fsize = f[1]

                if self.fp:
                    self.fp.seek(foff)
                    data = self.fp.read(fsize)
                    return data

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
        info['title'] = 'InstallShield Engine'  # 엔진 설명
        info['kmd_name'] = 'ishield'  # 엔진 파일 이름

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
            zfile = InstallShield(filename)  # InstallShield 파일 열기
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
        data = mm[0:0xe]
        if data == 'InstallShield\x00':  # 헤더 체크
            ret['ff_installshield'] = 'InstallShield'
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

        # 미리 분석된 파일 포맷중에 InstallShield 포맷이 있는가?
        if 'ff_installshield' in fileformat:
            zfile = self.__get_handle(filename)

            if zfile.parse():
                for name in zfile.namelist():
                    file_scan_list.append(['arc_installshield', name])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_installshield':
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
