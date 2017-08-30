# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import mmap
import zlib
import bz2
import kernel
import kavutil


# -------------------------------------------------------------------------
# AlzFile 클래스
# -------------------------------------------------------------------------
COMPRESS_METHOD_STORE = 0
COMPRESS_METHOD_BZIP2 = 1
COMPRESS_METHOD_DEFLATE = 2


class AlzFile:
    # ---------------------------------------------------------------------
    # __init__(self, filename)
    # 압축을 해제할 Alz 파일을 지정한다.
    # 입력값 : filename - ALZ 파일
    # ---------------------------------------------------------------------
    def __init__(self, filename):
        self.fp = None
        self.mm = None

        try:
            self.fp = open(filename, 'rb')
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        except IOError:
            pass

    # ---------------------------------------------------------------------
    # def close(self)
    # ALZ 파일을 닫는다.
    # ---------------------------------------------------------------------
    def close(self):
        if self.mm is not None:
            self.mm.close()
            self.mm = None

        if self.fp is not None:
            self.fp.close()
            self.mm = None

    # ---------------------------------------------------------------------
    # read(self, filename)
    # ALZ 파일 내부의 파일을 압축 해제한다.
    # 입력값 : filename - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 data 스트림
    # ---------------------------------------------------------------------
    def read(self, filename):
        ret_data = None

        try:
            fname, data = self.__FindFirstFileName__()
            while fname is not None:
                if fname == filename:  # 압축 해제할 파일을 찾았나?

                    data, method, _, _ = self.__Alz_LocalFileHeader__(data)  # 데이터 읽기
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

                fname, data = self.__FindNextFileName__()
        except IOError:
            pass

        return ret_data

    # ---------------------------------------------------------------------
    # namelist(self)
    # ALZ 파일 내부의 파일명을 리턴한다.
    # 리턴값 : ALZ 파일 내부의 압축 파일명을 담은 리스트
    # ---------------------------------------------------------------------
    def namelist(self):
        name_list = []
        ret_data = None

        try:
            fname, data = self.__FindFirstFileName__()
            while fname is not None:
                name_list.append(fname)
                fname, data = self.__FindNextFileName__()
        except IOError:
            pass

        return name_list

    # -----------------------------------------------------------------
    # AlzFile 클래스의 내부 멤버 함수들
    # -----------------------------------------------------------------

    # -----------------------------------------------------------------
    # __FindFirstFileName__(self)
    # Alz 파일 내부에 압축된 파일명의 첫번째 이름을 얻어온다.
    # 리턴값 : 압축된 첫번째 파일명, 압축 스트림
    # -----------------------------------------------------------------
    def __FindFirstFileName__(self):
        self.alz_pos = 8
        start = 8
        end = 0

        fname, self.alz_pos = self.__GetFileName__(self.alz_pos)
        if fname is None:
            return None, None

        end = self.alz_pos

        return fname, self.mm[start:end]

    # -----------------------------------------------------------------
    # __FindNextFileName__(self)
    # Alz 파일 내부에 압축된 파일명의 다음 이름을 얻어온다.
    # 리턴값 : 압축된 다음 파일명, 압축 스트림
    # -----------------------------------------------------------------
    def __FindNextFileName__(self):
        start = self.alz_pos
        fname, self.alz_pos = self.__GetFileName__(self.alz_pos)
        end = self.alz_pos

        return fname, self.mm[start:end]

    # -----------------------------------------------------------------
    # __GetFileName__(self, alz_pos)
    # 주어진 위치 이후로 Filename Header를 찾아 분석한다.
    # 리턴값 : Filename Header내의 파일명, 현재 위치
    # -----------------------------------------------------------------
    def __GetFileName__(self, alz_pos):
        try:
            mm = self.mm
            data_size = len(mm)
        except TypeError:
            return None, -1

        try:
            while alz_pos < data_size:
                magic = kavutil.get_uint32(mm, alz_pos)

                if magic == 0x015A4C42:  # Local File Header
                    _, _, size, fname = self.__Alz_LocalFileHeader__(mm[alz_pos:])
                    if size == -1:
                        raise ValueError
                    alz_pos += size
                    return fname, alz_pos
                else:
                    alz_pos = self.__DefaultMagicIDProc__(magic, alz_pos)
                    if alz_pos == -1:
                        raise ValueError
        except ValueError:
            pass

        return None, -1

    # -----------------------------------------------------------------
    # __Alz_LocalFileHeader__(self, data)
    # Local File Header를 분석한다
    # 리턴값 : 압축된 data 스트림, 압축 방식, Local File Header 크기, 파일 이름
    # -----------------------------------------------------------------
    def __Alz_LocalFileHeader__(self, data):
        try:
            fname_size = kavutil.get_uint16(data, 4)
            file_desc = ord(data[11])
            compress__method__m = ord(data[13])

            size = 19
            if file_desc & 0x10:
                compress__size = ord(data[size])
                uncompress__size = ord(data[size + 1])
                size += (1 * 2)  # 파일 크기가 2개 옴(압축전, 압축 후)
            elif file_desc & 0x20:
                compress__size = kavutil.get_uint16(data, size)
                uncompress__size = kavutil.get_uint16(data, size+2)
                size += (2 * 2)
            elif file_desc & 0x40:
                compress__size = kavutil.get_uint32(data, size)
                uncompress__size = kavutil.get_uint32(data, size+4)
                size += (4 * 2)
            elif file_desc & 0x80:
                compress__size = kavutil.get_uint64(data, size)
                uncompress__size = kavutil.get_uint64(data, size+8)
                size += (8 * 2)
            else:
                raise SystemError

            fname = data[size:size + fname_size]
            size += fname_size  # 파일 이름

            if file_desc & 1:
                size += 12  # Encrypt Block

            compressed__data = data[size:size + compress__size]

            return compressed__data, compress__method__m, size+compress__size, fname
        except IndexError:
            pass

        return None, -1

    # -----------------------------------------------------------------
    # __DefaultMagicIDProc__(self, Magic, alz_pos)
    # 주어진 위치의 Magic을 분석하고 파싱한다.
    # 리턴값 : 다음 Magic의 위치
    # -----------------------------------------------------------------
    def __DefaultMagicIDProc__(self, magic, alz_pos):
        try:
            if magic == 0x015A4C41:  # ALZ Header
                alz_pos += 8
            elif magic == 0x015A4C43:  # Central Directory Structure
                alz_pos += 12
            elif magic == 0x025A4C43:  # EOF Central Directory Record
                alz_pos += 4
            else:
                # print 'Not Support Header :', hex(alz_pos)
                raise ValueError
        except ValueError:
            return -1

        return alz_pos

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
        info['title'] = 'Alz Archive Engine'  # 엔진 설명
        info['kmd_name'] = 'alz'  # 엔진 파일 이름
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
            zfile = AlzFile(filename)  # alz 파일 열기
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
        if mm[0:4] == 'ALZ\x01':  # 헤더 체크
            fileformat['size'] = len(mm)  # 포맷 주요 정보 저장

            ret = {'ff_alz': fileformat}
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

        # 미리 분석된 파일 포맷중에 ALZ 포맷이 있는가?
        if 'ff_alz' in fileformat:
            zfile = self.__get_handle(filename)

            for name in zfile.namelist():
                file_scan_list.append(['arc_alz', name])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_alz':
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
