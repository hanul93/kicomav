# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import sys
import mmap
import zlib
import bz2
import kernel
import kavutil

# ---------------------------------------------------------------------
# EggFile 클래스
# ---------------------------------------------------------------------
SIZE_EGG_HEADER = 14

COMPRESS_METHOD_STORE = 0
COMPRESS_METHOD_DEFLATE = 1
COMPRESS_METHOD_BZIP2 = 2
COMPRESS_METHOD_AZO = 3
COMPRESS_METHOD_LZMA = 4


class EggFile:
    # -----------------------------------------------------------------
    # __init__(self, filename)
    # 압축을 해제할 Egg 파일을 지정한다.
    # -----------------------------------------------------------------
    def __init__(self, filename):
        self.fp = None
        self.mm = None
        self.data_size = 0
        self.egg_pos = None

        try:
            self.data_size = os.path.getsize(filename)
            self.fp = open(filename, 'rb')
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        except IOError:
            pass

    # -----------------------------------------------------------------
    # def close(self)
    # EGG 파일을 닫는다.
    # -----------------------------------------------------------------
    def close(self):
        if self.mm:
            self.mm.close()

        if self.fp:
            self.fp.close()

    # -----------------------------------------------------------------
    # read(self, filename)
    # EGG 파일 내부의 파일을 압축 해제한다.
    # 리턴값 : 압축 해제된 data 스트림
    # -----------------------------------------------------------------
    def read(self, filename):
        ret_data = None

        try:
            fname = self.__FindFirstFileName__()
            while fname:
                if fname == filename:
                    # print fname, '{OK]'

                    data, method, self.egg_pos = self.__ReadBlockData__()
                    if method == COMPRESS_METHOD_STORE:
                        ret_data = data
                        break
                    elif method == COMPRESS_METHOD_DEFLATE:
                        ret_data = zlib.decompress(data, -15)
                        break
                    elif method == COMPRESS_METHOD_BZIP2:
                        ret_data = bz2.decompress(data)
                        break
                    else:
                        # print method
                        pass

                fname = self.__FindNextFileName__()
        except:
            pass

        return ret_data

    # -----------------------------------------------------------------
    # namelist(self)
    # EGG 파일 내부의 파일명을 리턴한다.
    # 리턴값 : EGG 파일 내부의 압축 파일명을 담은 리스트
    # -----------------------------------------------------------------
    def namelist(self):
        name_list = []

        try:
            fname = self.__FindFirstFileName__()
            while fname:
                name_list.append(fname)
                fname = self.__FindNextFileName__()
        except:
            pass

        return name_list

    # -----------------------------------------------------------------
    # EggFile 클래스의 내부 멤버 함수들
    # -----------------------------------------------------------------

    # -----------------------------------------------------------------
    # __FindFirstFileName__(self)
    # Egg 파일 내부에 압축된 파일명의 첫번째 이름을 얻어온다.
    # 리턴값 : 압축된 첫번째 파일명
    # -----------------------------------------------------------------
    def __FindFirstFileName__(self):
        self.egg_pos = 0

        fname, self.egg_pos = self.__GetFileName__(self.egg_pos)

        return fname

    # -----------------------------------------------------------------
    # __FindNextFileName__(self)
    # Egg 파일 내부에 압축된 파일명의 다음 이름을 얻어온다.
    # 리턴값 : 압축된 다음 파일명
    # -----------------------------------------------------------------
    def __FindNextFileName__(self):
        fname, self.egg_pos = self.__GetFileName__(self.egg_pos)

        return fname

    # -----------------------------------------------------------------
    # __GetFileName__(self, egg_pos)
    # 주어진 위치 이후로 Filename Header를 찾아 분석한다.
    # 리턴값 : Filename Header내의 파일명, 현재 위치
    # -----------------------------------------------------------------
    def __GetFileName__(self, egg_pos):
        mm = self.mm
        data_size = self.data_size

        try:
            while egg_pos < data_size:
                # magic = struct.unpack('<L', mm[egg_pos:egg_pos+4])[0]
                magic = kavutil.get_uint32(mm, egg_pos)

                if magic == 0x0A8591AC:  # Filename Header
                    # print 'Filename Header'
                    size, fname = self.__EGG_Filename_Header__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                    return fname, egg_pos
                else:
                    egg_pos = self.__DefaultMagicIDProc__(magic, egg_pos)
                    if egg_pos == -1:
                        raise SystemError
        except SystemError:
            pass

        return None, -1

    # -----------------------------------------------------------------
    # __ReadBlockData__(self)
    # 현재 위치에서부터 Block Header를 찾아 분석한다.
    # 리턴값 : 압축된 data 스트림, 압축 방식, 현재 위치
    # -----------------------------------------------------------------
    def __ReadBlockData__(self):
        egg_pos = self.egg_pos
        mm = self.mm
        data_size = self.data_size

        try:
            while egg_pos < data_size:
                # magic = struct.unpack('<L', mm[egg_pos:egg_pos+4])[0]
                magic = kavutil.get_uint32(mm, egg_pos)

                if magic == 0x02B50C13:  # Block Header
                    # print 'Block Header'
                    size = self.__EGG_Block_Header_Size__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError

                    compress__method__m = ord(mm[egg_pos+4])
                    # Compress_Method_H = ord(mm[egg_pos+5])
                    # Uncompress_Size = struct.unpack('<L', mm[egg_pos+6:egg_pos+10])[0]
                    # compress__size = struct.unpack('<L', mm[egg_pos+10:egg_pos+14])[0]
                    compress__size = kavutil.get_uint32(mm, egg_pos+10)
                    # CRC = struct.unpack('<L', mm[egg_pos+14:egg_pos+18])[0]
                    compressed__data = mm[egg_pos+22:egg_pos+22+compress__size]
                    egg_pos += size
                    return compressed__data, compress__method__m, egg_pos
                else:
                    egg_pos = self.__DefaultMagicIDProc__(magic, egg_pos)
                    if egg_pos == -1:
                        raise SystemError
        except SystemError:
            pass

        return None, -1, -1

    # -----------------------------------------------------------------
    # __DefaultMagicIDProc__(self, Magic, egg_pos)
    # 주어진 위치의 Magic을 분석하고 파싱한다.
    # 리턴값 : 다음 Magic의 위치
    # -----------------------------------------------------------------
    def __DefaultMagicIDProc__(self, magic, egg_pos):
        mm = self.mm
        data_size = self.data_size

        try:
            if egg_pos < data_size:
                if magic == 0x41474745:  # EGG Header
                    # print 'EGG Header'
                    if self.__EGG_Header__(mm) == -1:
                        raise SystemError  # 헤더 체크
                    egg_pos += SIZE_EGG_HEADER
                elif magic == 0x0A8590E3:  # File Header
                    # print 'File Header'
                    egg_pos += 16
                elif magic == 0x02B50C13:  # Block Header
                    # print 'Block Header'
                    size = self.__EGG_Block_Header_Size__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                elif magic == 0x08D1470F:  # Encrypt Header
                    # print 'Encrypt Header'
                    size = self.__EGG_Encrypt_Header_Size__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                elif magic == 0x2C86950B:  # Windows File Information
                    # print 'Windows File Information'
                    egg_pos += 16
                elif magic == 0x1EE922E5:  # Posix File Information
                    # print 'Posix File Information'
                    egg_pos += 27
                elif magic == 0x07463307:  # Dummy Header
                    size = self.__EGG_Dummy_Header_Size__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                elif magic == 0x0A8591AC:  # Filename Header
                    # print 'Filename Header'
                    size, fname = self.__EGG_Filename_Header__(mm[egg_pos:])
                    if size == -1:
                        raise SystemError
                    egg_pos += size
                elif magic == 0x04C63672:  # Comment Header
                    # print 'Comment Header'
                    raise SystemError # 현 버전에서 지원 안됨
                elif magic == 0x24F5A262:  # Split Compression
                    # print 'Split Compression'
                    egg_pos += 15
                elif magic == 0x24E5A060:  # Solid Compression
                    # print 'Solid Compression'
                    egg_pos += 7
                elif magic == 0x08E28222:  # End of File Header
                    # print 'End of File Header'
                    egg_pos += 4
                else:
                    # print 'Not Support Header :', hex(egg_pos)
                    raise SystemError
        except SystemError:
            return -1

        return egg_pos

    # -----------------------------------------------------------------
    # __EGG_Header__(self, data)
    # Egg 파일의 헤더를 분석한다.
    # 리턴값 : 0 (성공), -1(실패)
    # -----------------------------------------------------------------
    def __EGG_Header__(self, data):
        try:
            # magic = struct.unpack('<L', data[0:4])[0]
            magic = kavutil.get_uint32(data, 0)
            if magic != 0x41474745:
                raise SystemError

            # version = struct.unpack('<H', data[4:6])[0]
            version = kavutil.get_uint16(data, 4)
            if version != 0x0100:
                raise SystemError

            # header_id = struct.unpack('<L', data[6:10])[0]
            header_id = kavutil.get_uint32(data, 6)
            if header_id == 0:
                raise SystemError

            # reserved = struct.unpack('<L', data[10:14])[0]
            reserved = kavutil.get_uint32(data, 10)
            if reserved != 0:
                raise SystemError

            return 0
        except SystemError:
            pass

        return -1

    # -----------------------------------------------------------------
    # __EGG_Encrypt_Header_Size__(self, data)
    # Egg 파일의 Encrypt Header를 분석하여 헤더 크기를 구한다.
    # 리턴값 : Encrypt Header 크기
    # -----------------------------------------------------------------
    def __EGG_Encrypt_Header_Size__(self, data):
        try:
            encrypt__method = ord(data[7])
            if encrypt__method == 0:
                return 24  # 4 + 1 + 2 + 1 + 12 + 4
            elif encrypt__method == 1:
                return 28  # 4 + 1 + 2 + 1 + 10 + 10
            elif encrypt__method == 2:
                return 36  # 4 + 1 + 2 + 1 + 18 + 10
            else:
                raise SystemError
        except SystemError:
            pass

        return -1

    # -----------------------------------------------------------------
    # __EGG_Dummy_Header_Size__(self, data)
    # Egg 파일의 Dummy Header를 분석하여 헤더 크기를 구한다.
    # 리턴값 : Dummy Header 크기
    # -----------------------------------------------------------------
    def __EGG_Dummy_Header_Size__(self, data):
        try:
            # dummy__size = struct.unpack('<H', data[5:7])[0]
            dummy__size = kavutil.get_uint16(data, 5)
            return 7 + dummy__size  # (5 + 2 + dummy__size)
        except:
            pass

        return -1

    # -----------------------------------------------------------------
    # __EGG_Filename_Header__(self, data)
    # Egg 파일의 Filename Header를 분석하여 헤더 크기를 구한다.
    # 리턴값 : Filename Header 크기, 압축된 파일명
    # -----------------------------------------------------------------
    def __EGG_Filename_Header__(self, data):
        size = -1
        fname = None

        try:
            # fname_size = struct.unpack('<H', data[5:7])[0]
            fname_size = kavutil.get_uint16(data, 5)
            fname = data[7:7+fname_size]
            size = 7 + fname_size
        except:
            pass

        fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
        return size, fname.decode('utf-8').encode(fsencoding)

    # -----------------------------------------------------------------
    # __EGG_Block_Header_Size__(self, data)
    # Egg 파일의 Block Header를 분석하여 헤더 크기를 구한다.
    # 리턴값 : Block Header 크기
    # -----------------------------------------------------------------
    def __EGG_Block_Header_Size__(self, data):
        size = -1

        try:
            block__size = (18 + 4)
            # compress__size = struct.unpack('<L', data[10:14])[0]
            compress__size = kavutil.get_uint32(data, 10)
            size = block__size + compress__size
        except:
            pass

        return size


# -------------------------------------------------------------------------
# KavMain 클래스
# -------------------------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 입력값 : plugins_path - 플러그인 엔진의 위치
    #         verbose      - 디버그 모드 (True or False)
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):  # 플러그인 엔진 초기화
        self.handle = {}
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
        info['title'] = 'Egg Archive Engine'  # 엔진 설명
        info['kmd_name'] = 'egg'  # 엔진 파일 이름
        info['engine_type'] = kernel.ARCHIVE_ENGINE # 엔진 타입

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
            zfile = EggFile(filename)  # egg 파일 열기
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
        if mm[0:4] == 'EGGA':  # 헤더 체크
            ret = {'ff_egg': 'EGG'}
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

        # 미리 분석된 파일 포맷중에 EGG 포맷이 있는가?
        if 'ff_egg' in fileformat:
            zfile = self.__get_handle(filename)

            for name in zfile.namelist():
                file_scan_list.append(['arc_egg', name])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_egg':
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
