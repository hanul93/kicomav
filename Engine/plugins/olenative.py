# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)
# 참조 : https://github.com/unixfreak0037/officeparser/blob/master/officeparser.py (696~)


import os
import struct
import kernel
import kavutil
import ole


MAX_PATH = 512


def analysis_ole10native(mm, verbose=False):
    fileformat = {}

    try:
        size = kavutil.get_uint32(mm, 0)

        if mm[4:6] == '\x02\x00':
            if len(mm) == size + 4:
                fileformat['size'] = len(mm)  # 포맷 주요 정보 저장

                label = mm[6:6 + MAX_PATH].split('\x00', 1)[0]
                fileformat['label'] = label

                off = 6 + len(label) + 1
                fname = mm[off:off + MAX_PATH].split('\x00', 1)[0]

                off += len(fname) + 1
                off += 2  # flag

                unknown_size = ord(mm[off])
                off += 1 + unknown_size + 2

                command = mm[off:off + MAX_PATH].split('\x00', 1)[0]
                off += len(command) + 1

                data_size = kavutil.get_uint32(mm, off)

                fileformat['data_off'] = off + 4
                fileformat['data_size'] = data_size

                if len(mm) < off + data_size:  # 오류
                    raise ValueError

                if verbose:
                    print
                    kavutil.vprint('Ole10Native Stream')
                    kavutil.vprint(None, 'Size', '0x%08X' % size)
                    kavutil.vprint(None, 'Label', label)
                    kavutil.vprint(None, 'File Name', fname)
                    kavutil.vprint(None, 'Command Line', command)
                    kavutil.vprint(None, 'Data Offset', '0x%08X' % (off + 4))
                    kavutil.vprint(None, 'Data Size', '0x%08X' % data_size)

                    print
                    kavutil.vprint('Data Dump')
                    print
                    kavutil.HexDump().Buffer(mm[:], off + 4, 0x80)
                    print

                return fileformat
    except ValueError:
        pass
    except struct.error:
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
        info['title'] = 'Ole10Native Engine'  # 엔진 설명
        info['kmd_name'] = 'olenative'  # 엔진 파일 이름
        info['make_arc_type'] = kernel.MASTER_DELETE  # 악성코드 치료는 삭제로...

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

        if mm[:8] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':  # OLE 헤더와 동일
            o = None
            try:
                o = ole.OleFile(filename)
                if '\x01Ole10Native' in o.listdir():
                    pics = o.openstream('\x01Ole10Native')
                    buf = pics.read()

                    if self.verbose:
                        print '-' * 79
                        kavutil.vprint('Engine')
                        kavutil.vprint(None, 'Engine', 'olenative.kmd')
                        kavutil.vprint(None, 'File name', os.path.split(filename)[-1])

                    fileformat = analysis_ole10native(buf, self.verbose)
                    if fileformat:
                        ret = {'ff_ole10native': fileformat}
            except ole.Error:
                pass

            if o:
                o.close()

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

        # 미리 분석된 파일 포맷중에 ZIP 포맷이 있는가?
        if 'ff_ole10native' in fileformat:
            fformat = fileformat['ff_ole10native']
            name = fformat['label']  # OLE 내부에 숨겨진 파일 명

            off = fformat['data_off']
            data_size = fformat['data_size']

            arc_name = 'arc_ole10native:%s:%s' % (off, data_size)
            file_scan_list.append([arc_name, name])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id.find('arc_ole10native:') != -1:
            val = arc_engine_id.split(':')
            off = int(val[1])
            size = int(val[2])

            data = None
            o = None
            try:
                o = ole.OleFile(arc_name)
                if '\x01Ole10Native' in o.listdir():
                    pics = o.openstream('\x01Ole10Native')
                    buf = pics.read()

                    data = buf[off:]
            except ole.Error:
                pass

            if o:
                o.close()

            return data

        return None
