# -*- coding:utf-8 -*-

"""
Copyright (C) 2013 Nurilab.

Author: Kei Choi(hanul93@gmail.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
"""

__revision__ = '$LastChangedRevision: 1 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'

import struct
import mmap
import zlib
import bz2
import kernel

#---------------------------------------------------------------------
# EggFile 클래스
#---------------------------------------------------------------------
SIZE_EGG_HEADER = 14

COMPRESS_METHOD_STORE   = 0
COMPRESS_METHOD_DEFLATE = 1
COMPRESS_METHOD_BZIP2   = 2
COMPRESS_METHOD_AZO     = 3
COMPRESS_METHOD_LZMA    = 4

class EggFile :
    #-----------------------------------------------------------------
    # __init__(self, filename)
    # 압축을 해제할 Egg 파일을 지정한다.
    #-----------------------------------------------------------------
    def __init__(self, filename) :
        self.fp = None
        self.mm = None

        try :
            self.fp = open(filename, 'rb') 
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        except :
            pass

    #-----------------------------------------------------------------
    # def close(self)
    # EGG 파일을 닫는다.
    #-----------------------------------------------------------------
    def close(self) :
        if self.mm != None : self.mm.close()
        if self.fp != None : self.fp.close()

    #-----------------------------------------------------------------
    # read(self, filename)
    # EGG 파일 내부의 파일을 압축 해제한다.
    # 리턴값 : 압축 해제된 data 스트림
    #-----------------------------------------------------------------
    def read(self, filename) :
        ret_data = None

        try :
            fname = self.__FindFirstFileName__()
            while fname != None :
                if fname == filename :
                    # print fname, '{OK]'

                    data, method, self.egg_pos = self.__ReadBlockData__()
                    if   method == COMPRESS_METHOD_STORE :
                        ret_data = data
                        break
                    elif method == COMPRESS_METHOD_DEFLATE :
                        ret_data = zlib.decompress(data, -15)
                        break
                    elif method == COMPRESS_METHOD_BZIP2 :
                        ret_data = bz2.decompress(data)
                        break
                    else :
                        # print method
                        pass

                fname = self.__FindNextFileName__()
        except :
            pass

        return ret_data

    #-----------------------------------------------------------------
    # namelist(self)
    # EGG 파일 내부의 파일명을 리턴한다.
    # 리턴값 : EGG 파일 내부의 압축 파일명을 담은 리스트
    #-----------------------------------------------------------------
    def namelist(self) :
        name_list = []
        ret_data = None

        try :
            fname = self.__FindFirstFileName__()
            while fname != None :
                name_list.append(fname)
                fname = self.__FindNextFileName__()
        except :
            pass

        return name_list

    #-----------------------------------------------------------------
    # EggFile 클래스의 내부 멤버 함수들
    #-----------------------------------------------------------------

    #-----------------------------------------------------------------
    # __FindFirstFileName__(self)
    # Egg 파일 내부에 압축된 파일명의 첫번째 이름을 얻어온다.
    # 리턴값 : 압축된 첫번째 파일명
    #-----------------------------------------------------------------
    def __FindFirstFileName__(self) :
        self.egg_pos = 0

        fname, self.egg_pos = self.__GetFileName__(self.egg_pos)

        return fname

    #-----------------------------------------------------------------
    # __FindNextFileName__(self)
    # Egg 파일 내부에 압축된 파일명의 다음 이름을 얻어온다.
    # 리턴값 : 압축된 다음 파일명
    #-----------------------------------------------------------------
    def __FindNextFileName__(self) :
        fname, self.egg_pos = self.__GetFileName__(self.egg_pos)

        return fname

    #-----------------------------------------------------------------
    # __GetFileName__(self, egg_pos)
    # 주어진 위치 이후로 Filename Header를 찾아 분석한다.
    # 리턴값 : Filename Header내의 파일명, 현재 위치
    #-----------------------------------------------------------------
    def __GetFileName__(self, egg_pos) :
        mm           = self.mm
        data_size    = len(mm)

        try :
            while egg_pos < data_size :
                Magic = struct.unpack('<L', mm[egg_pos:egg_pos+4])[0]

                if Magic == 0x0A8591AC : # Filename Header
                    # print 'Filename Header'
                    size, fname = self.__EGG_Filename_Header__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                    return fname, egg_pos
                else :
                    egg_pos = self.__DefaultMagicIDProc__(Magic, egg_pos)
                    if egg_pos == -1 :
                        raise SystemError
        except :
            pass

        return None, -1

    #-----------------------------------------------------------------
    # __ReadBlockData__(self)
    # 현재 위치에서부터 Block Header를 찾아 분석한다.
    # 리턴값 : 압축된 data 스트림, 압축 방식, 현재 위치
    #-----------------------------------------------------------------
    def __ReadBlockData__(self) :
        egg_pos      = self.egg_pos
        mm           = self.mm
        data_size    = len(mm)

        try :
            while egg_pos < data_size :
                Magic = struct.unpack('<L', mm[egg_pos:egg_pos+4])[0]

                if Magic == 0x02B50C13 : # Block Header
                    # print 'Block Header'
                    size = self.__EGG_Block_Header_Size__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    Compress_Method_M = ord(mm[egg_pos+4])
                    Compress_Method_H = ord(mm[egg_pos+5])
                    Uncompress_Size   = struct.unpack('<L', mm[egg_pos+6:egg_pos+10])[0]
                    Compress_Size     = struct.unpack('<L', mm[egg_pos+10:egg_pos+14])[0]
                    CRC               = struct.unpack('<L', mm[egg_pos+14:egg_pos+18])[0]
                    Compressed_Data   = mm[egg_pos+22:egg_pos+22+Compress_Size]
                    egg_pos += size
                    return Compressed_Data, Compress_Method_M, egg_pos
                else :
                    egg_pos = self.__DefaultMagicIDProc__(Magic, egg_pos)
                    if egg_pos == -1 :
                        raise SystemError
        except :
            pass

        return None, -1, -1

    #-----------------------------------------------------------------
    # __DefaultMagicIDProc__(self, Magic, egg_pos)
    # 주어진 위치의 Magic을 분석하고 파싱한다.
    # 리턴값 : 다음 Magic의 위치
    #-----------------------------------------------------------------
    def __DefaultMagicIDProc__(self, Magic, egg_pos) :
        mm           = self.mm
        data_size    = len(mm)

        try :
            if egg_pos < data_size :
                if   Magic == 0x41474745 : # EGG Header
                    # print 'EGG Header'
                    if self.__EGG_Header__(mm) == -1 : raise SystemError # 헤더 체크
                    egg_pos += (SIZE_EGG_HEADER)
                elif Magic == 0x0A8590E3 : # File Header
                    # print 'File Header'
                    egg_pos += 16
                elif Magic == 0x02B50C13 : # Block Header
                    # print 'Block Header'
                    size = self.__EGG_Block_Header_Size__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                elif Magic == 0x08D1470F : # Encrypt Header
                    # print 'Encrypt Header'
                    size = self.__EGG_Encrypt_Header_Size__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                elif Magic == 0x2C86950B : # Windows File Information
                    # print 'Windows File Information'
                    egg_pos += 16
                elif Magic == 0x1EE922E5 : # Posix File Information
                    # print 'Posix File Information'
                    egg_pos += 27
                elif Magic == 0x07463307 : # Dummy Header
                    size = self.__EGG_Dummy_Header_Size__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                elif Magic == 0x0A8591AC : # Filename Header
                    # print 'Filename Header'
                    size, fname = self.__EGG_Filename_Header__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                elif Magic == 0x04C63672 : # Comment Header
                    # print 'Comment Header'
                    raise SystemError # 현 버전에서 지원 안됨
                elif Magic == 0x24F5A262 : # Split Compression
                    # print 'Split Compression'
                    egg_pos += 15
                elif Magic == 0x24E5A060 : # Solid Compression
                    # print 'Solid Compression'
                    egg_pos += 7
                elif Magic == 0x08E28222 : # End of File Header
                    # print 'End of File Header'
                    egg_pos += 4
                else :
                    # print 'Not Support Header :', hex(egg_pos)
                    raise SystemError
        except :
            return -1

        return egg_pos

    #-----------------------------------------------------------------
    # __EGG_Header__(self, data)
    # Egg 파일의 헤더를 분석한다.
    # 리턴값 : 0 (성공), -1(실패)
    #-----------------------------------------------------------------
    def __EGG_Header__(self, data) :
        try :
            Magic = struct.unpack('<L', data[0:4])[0]
            if Magic != 0x41474745 : raise SystemError

            Version = struct.unpack('<H', data[4:6])[0]
            if Version != 0x0100 : raise SystemError

            HeaderID = struct.unpack('<L', data[6:10])[0]
            if HeaderID == 0 : raise SystemError

            Reserved = struct.unpack('<L', data[10:14])[0]
            if Reserved != 0 : raise SystemError

            return 0
        except :
            pass

        return -1

    #-----------------------------------------------------------------
    # __EGG_Encrypt_Header_Size__(self, data)
    # Egg 파일의 Encrypt Header를 분석하여 헤더 크기를 구한다.
    # 리턴값 : Encrypt Header 크기
    #-----------------------------------------------------------------
    def __EGG_Encrypt_Header_Size__(self, data) :
        try :
            Encrypt_Method = ord(data[7])
            if   Encrypt_Method == 0 :
                return (4 + 1 + 2 + 1 + 12 + 4)
            elif Encrypt_Method == 1 :
                return (4 + 1 + 2 + 1 + 10 + 10)
            elif Encrypt_Method == 2 :
                return (4 + 1 + 2 + 1 + 18 + 10)
            else :
                raise SystemError
        except :
            pass

        return -1

    #-----------------------------------------------------------------
    # __EGG_Dummy_Header_Size__(self, data)
    # Egg 파일의 Dummy Header를 분석하여 헤더 크기를 구한다.
    # 리턴값 : Dummy Header 크기
    #-----------------------------------------------------------------
    def __EGG_Dummy_Header_Size__(self, data) :
        try :
            Dummy_Size = struct.unpack('<H', data[5:7])[0]
            return (5 + 2 + Dummy_Size)
        except :
            pass

        return -1

    #-----------------------------------------------------------------
    # __EGG_Filename_Header__(self, data)
    # Egg 파일의 Filename Header를 분석하여 헤더 크기를 구한다.
    # 리턴값 : Filename Header 크기, 압축된 파일명
    #-----------------------------------------------------------------
    def __EGG_Filename_Header__(self, data) :
        size = -1
        fname = None

        try :
            fname_size = struct.unpack('<H', data[5:7])[0]
            fname = data[7:7+fname_size]
            size = 7 + fname_size
        except :
            pass

        return size, fname

    #-----------------------------------------------------------------
    # __EGG_Block_Header_Size__(self, data)
    # Egg 파일의 Block Header를 분석하여 헤더 크기를 구한다.
    # 리턴값 : Block Header 크기
    #-----------------------------------------------------------------
    def __EGG_Block_Header_Size__(self, data) :
        size = -1

        try :
            Block_Size = (18 + 4)
            Compress_Size = struct.unpack('<L', data[10:14])[0]
            size = Block_Size + Compress_Size
        except :
            pass

        return size

#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------
'''
if __name__ == '__main__' :
    egg = EggFile('winhex.egg')

    print egg.read('234/egg.py')
    for name in egg.namelist() :
        print name
    egg.close()    
'''

#---------------------------------------------------------------------
# KavMain 클래스
# 키콤백신 엔진 모듈임을 나타내는 클래스이다.
# 이 클래스가 없으면 백신 엔진 커널 모듈에서 로딩하지 않는다.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # init(self, plugins)
    # 백신 엔진 모듈의 초기화 작업을 수행한다.
    #-----------------------------------------------------------------
    def init(self, plugins) : # 백신 모듈 초기화
        return 0

    #-----------------------------------------------------------------
    # uninit(self)
    # 백신 엔진 모듈의 종료화 작업을 수행한다.
    #-----------------------------------------------------------------
    def uninit(self) : # 백신 모듈 종료화
        return 0
    
    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = __author__ # 제작자
        info['version'] = __version__     # 버전
        info['title'] = 'Egg Engine' # 엔진 설명
        info['kmd_name'] = 'egg' # 엔진 파일명
        info['engine_type'] = kernel.ARCHIVE_ENGINE # 엔진 타입
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # 포맷 정보를 담을 공간

            mm = mmhandle
            if mm[0:4] == 'EGGA' : # 헤더 체크
                fformat['size'] = len(mm) # 포맷 주요 정보 저장

                ret = {}
                ret['ff_egg'] = fformat

                return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # 압축 파일 내부의 압축된 파일명을 리스트로 리턴한다.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # 검사 대상 정보를 모두 가짐

        try :
            # 미리 분석된 파일 포맷중에 EGG 포맷이 있는가?
            fformat = format['ff_egg']
                
            eggfile = EggFile(filename)
            for name in eggfile.namelist() :
                file_scan_list.append(['arc_egg', name])
            eggfile.close()
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_egg' :
                raise SystemError

            eggfile = EggFile(arc_name)
            data = eggfile.read(arc_in_name)
            eggfile.close()

            return data
        except :
            pass

        return None
