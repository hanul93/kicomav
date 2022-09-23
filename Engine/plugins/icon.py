# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

# ICON Spec-1 : http://www.daubnet.com/en/file-format-ico
# ICON Spec-2 : https://formats.kaitai.io/ico/index.html

import kernel
import kavutil

import os
import re

# p_name = re.compile(r'(\d+)x(\d+) (\d+) bit')
p_name = re.compile(rb'(\d+)x(\d+)')

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
        self.verbose = verbose
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
        info['title'] = 'Icon Engine'  # 엔진 설명
        info['kmd_name'] = 'icon'  # 엔진 파일 이름

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
        ret = {}

        mm = filehandle
        if mm[0:4] == '\x00\x00\x01\x00':  # 헤더 체크
            ret['ff_icon'] = kavutil.get_uint16(mm, 4)
            return ret

        return None

    # ---------------------------------------------------------------------
    # __get_handle(self, filename)
    # 압축 파일의 핸들을 얻는다.
    # 입력값 : filename   - 파일 이름
    # 리턴값 : 압축 파일 핸들
    # ---------------------------------------------------------------------
    def __get_handle(self, filename):
        # print type(self.handle)
        if filename in self.handle:  # 이전에 열린 핸들이 존재하는가?
            buf = self.handle.get(filename, None)
        else:
            buf = open(filename, 'rb').read()
            self.handle[filename] = buf

        return buf

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 ICON 포맷이 있는가?
        if 'ff_icon' in fileformat:
            num = fileformat['ff_icon']
            mm = self.__get_handle(filename)

            for i in range(num):
                off = 6 + (16 * i)
                w = ord(mm[off])
                h = ord(mm[off+1])
                c = kavutil.get_uint16(mm, off+6)

                # name = '%dx%d %d bit' % (w, h, c)
                name = '%dx%d' % (w, h)
                file_scan_list.append(['arc_icon', name])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_icon':
            mm = self.__get_handle(arc_name)
            num = kavutil.get_uint16(mm, 4)

            p = p_name.search(fname_in_arc)
            if p:
                fw = int(p.groups()[0])
                fh = int(p.groups()[1])
                # fc = int(p.groups()[2])

                for i in range(num):
                    off = 6 + (16 * i)
                    w = ord(mm[off])
                    h = ord(mm[off+1])
                    # c = kavutil.get_uint16(mm, off+6)

                    if w == fw and h == fh:  # and c == fc:
                        img_size = kavutil.get_uint32(mm, off+8)
                        img_off = kavutil.get_uint32(mm, off+12)
                        data = mm[img_off:img_off+img_size]

                        return data

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        for fname in self.handle.keys():
            hfile = self.handle[fname]
            # 버퍼라 close 하지 않고 del 처리만 하자
            del hfile
            self.handle.pop(fname)
