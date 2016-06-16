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
# AlzFile 클래스
#---------------------------------------------------------------------
COMPRESS_METHOD_STORE   = 0
COMPRESS_METHOD_BZIP2   = 1
COMPRESS_METHOD_DEFLATE = 2

class AlzFile :
    #-----------------------------------------------------------------
    # __init__(self, filename)
    # 압축을 해제할 Alz 파일을 지정한다.
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
            fname, data = self.__FindFirstFileName__()
            while fname != None :
                if fname == filename :
                    # print fname, '{OK]'

                    data, method = self.__ReadFileData__(data)
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

                fname, data = self.__FindNextFileName__()
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
            fname, data = self.__FindFirstFileName__()
            while fname != None :
                name_list.append(fname)
                fname, data = self.__FindNextFileName__()
        except :
            pass

        return name_list

    #-----------------------------------------------------------------
    # AlzFile 클래스의 내부 멤버 함수들
    #-----------------------------------------------------------------

    #-----------------------------------------------------------------
    # __FindFirstFileName__(self)
    # Alz 파일 내부에 압축된 파일명의 첫번째 이름을 얻어온다.
    # 리턴값 : 압축된 첫번째 파일명, 압축 스트림
    #-----------------------------------------------------------------
    def __FindFirstFileName__(self) :
        self.alz_pos = 8
        start        = 8
        end          = 0

        fname, self.alz_pos = self.__GetFileName__(self.alz_pos)
        end = self.alz_pos

        return fname, self.mm[start:end]

    #-----------------------------------------------------------------
    # __FindNextFileName__(self)
    # Alz 파일 내부에 압축된 파일명의 다음 이름을 얻어온다.
    # 리턴값 : 압축된 다음 파일명, 압축 스트림
    #-----------------------------------------------------------------
    def __FindNextFileName__(self) :
        start = self.alz_pos
        fname, self.alz_pos = self.__GetFileName__(self.alz_pos)
        end   = self.alz_pos

        return fname, self.mm[start:end]

    #-----------------------------------------------------------------
    # __GetFileName__(self, alz_pos)
    # 주어진 위치 이후로 Filename Header를 찾아 분석한다.
    # 리턴값 : Filename Header내의 파일명, 현재 위치
    #-----------------------------------------------------------------
    def __GetFileName__(self, alz_pos) :
        mm           = self.mm
        data_size    = len(mm)

        try :
            while alz_pos < data_size :
                Magic = struct.unpack('<L', mm[alz_pos:alz_pos+4])[0]

                if Magic == 0x015A4C42 : # Local File Header
                    size, fname = self.__ALZ_LocalFile_Header__(mm[alz_pos:])
                    if size == -1 : raise SystemError
                    alz_pos += size
                    return fname, alz_pos
                else :
                    alz_pos = self.__DefaultMagicIDProc__(Magic, alz_pos)
                    if alz_pos == -1 :
                        raise SystemError
        except :
            pass

        return None, -1

    #-----------------------------------------------------------------
    # __ReadFileData__(self)
    # 현재 위치에서부터 Block Header를 찾아 분석한다.
    # 리턴값 : 압축된 data 스트림, 압축 방식
    #-----------------------------------------------------------------
    def __ReadFileData__(self, data) :
        alz_pos      = self.alz_pos
        mm           = self.mm
        data_size    = len(mm)

        try :
            Magic = struct.unpack('<L', data[0:4])[0]

            if Magic == 0x015A4C42 : # Local File Header
                fname_size        = struct.unpack('<H', data[4:6])[0]
                file_desc         = ord(data[11])
                Compress_Method_M = ord(data[13])

                size = 19
                if   file_desc & 0x10 : 
                    Compress_Size   = ord(data[size])
                    Uncompress_Size = ord(data[size+1])
                    size += (1 * 2) # 파일 크기가 2개 옴(압축전, 압축 후)
                elif file_desc & 0x20 : 
                    Compress_Size   = struct.unpack('<H', data[size  :size+2])[0]
                    Uncompress_Size = struct.unpack('<H', data[size+2:size+4])[0]
                    size += (2 * 2)
                elif file_desc & 0x40 : 
                    Compress_Size   = struct.unpack('<L', data[size  :size+4])[0]
                    Uncompress_Size = struct.unpack('<L', data[size+4:size+8])[0]
                    size += (4 * 2)
                elif file_desc & 0x80 : 
                    Compress_Size   = struct.unpack('<Q', data[size  :size+ 8])[0]
                    Uncompress_Size = struct.unpack('<Q', data[size+8:size+16])[0]
                    size += (8 * 2)
                else                  : raise SystemError

                size += fname_size # 파일 이름
                
                if file_desc & 1 :
                    size += 12 # Encrypt Block

                Compressed_Data = data[size:size+Compress_Size]

                return Compressed_Data, Compress_Method_M
        except :
            pass

        return None, -1

    #-----------------------------------------------------------------
    # __DefaultMagicIDProc__(self, Magic, alz_pos)
    # 주어진 위치의 Magic을 분석하고 파싱한다.
    # 리턴값 : 다음 Magic의 위치
    #-----------------------------------------------------------------
    def __DefaultMagicIDProc__(self, Magic, alz_pos) :
        mm           = self.mm
        data_size    = len(mm)

        try :
            if alz_pos < data_size :
                if   Magic == 0x015A4C41 : # ALZ Header
                    alz_pos += 8
                    #print 'ALZ Header', hex(alz_pos)
                elif Magic == 0x015A4C42 : # Local File Header
                    size = self.__ALZ_LocalFile_Header_Size__(mm[alz_pos:])
                    alz_pos += size
                    #print 'Local File Header', hex(alz_pos)
                elif Magic == 0x015A4C43 : # Central Directory Structure
                    alz_pos += 12
                    #print 'Central Directory Structure', hex(alz_pos)
                elif Magic == 0x025A4C43 : # EOF Central Directory Record
                    alz_pos += 4
                    #print 'EOF Central Directory Record', hex(alz_pos)
                else :
                    # print 'Not Support Header :', hex(alz_pos)
                    raise SystemError
        except :
            return -1

        return alz_pos

    #-----------------------------------------------------------------
    # __ALZ_LocalFile_Header_Size__(self, data)
    # 압축 파일의 LocalFile Header의 크기를 구한다.
    # 리턴값 : LocalFile Header의 크기
    #-----------------------------------------------------------------
    def __ALZ_LocalFile_Header_Size__(self, data) :
        size = 0

        try :
            size += 4 # 0X015A4C42 헤더

            fname_size = struct.unpack('<H', data[size:size+2])[0]
            size += 2 # 파일 이름 길이
            size += 1 # 파일 속성
            size += 4 # 파일 날짜/시간

            file_desc = ord(data[size])
            size += 1 # 파일 디스크립트 
                      # 1 비트 ON - 암호 0x10 : 파일크기 1Byte, 0x20 : 2Byte...
            size += 1 # unknown

            compress_method = ord(data[size])
            size += 1 # 압축 방식 (0:압축안함, 1:BZip2, 2:Deflate)
            size += 1 # unknown
            size += 4 # CRC

            if   file_desc & 0x10 : 
                Compress_Size   = ord(data[size])
                Uncompress_Size = ord(data[size+1])
                size += (1 * 2) # 파일 크기가 2개 옴(압축전, 압축 후)
            elif file_desc & 0x20 : 
                Compress_Size   = struct.unpack('<H', data[size  :size+2])[0]
                Uncompress_Size = struct.unpack('<H', data[size+2:size+4])[0]
                size += (2 * 2)
            elif file_desc & 0x40 : 
                Compress_Size   = struct.unpack('<L', data[size  :size+4])[0]
                Uncompress_Size = struct.unpack('<L', data[size+4:size+8])[0]
                size += (4 * 2)
            elif file_desc & 0x80 : 
                Compress_Size   = struct.unpack('<Q', data[size  :size+ 8])[0]
                Uncompress_Size = struct.unpack('<Q', data[size+8:size+16])[0]
                size += (8 * 2)
            else                  : raise SystemError

            # print data[size:size+fname_size], hex(Compress_Size), hex(Uncompress_Size), compress_method
            size += fname_size # 파일 이름
            
            if file_desc & 1 :
                size += 12 # Encrypt Block

            #code = data[size:size+Compress_Size]
            #print zlib.decompress(code, -15)
            size += Compress_Size
        except :
            return -1

        return size

    #-----------------------------------------------------------------
    # __ALZ_LocalFile_Header__(self, data)
    # 압축 파일의 LocalFile Header를 파싱한다.
    # 리턴값 : LocalFile Header의 크기, 압축 파일명
    #-----------------------------------------------------------------
    def __ALZ_LocalFile_Header__(self, data) :
        size = 0
        fname = None

        try :
            size += 4
            fname_size = struct.unpack('<H', data[size:size+2])[0]

            size += 7 
            file_desc = ord(data[size])

            size += 2
            compress_method = ord(data[size])

            size += 6

            if   file_desc & 0x10 : 
                Compress_Size   = ord(data[size])
                Uncompress_Size = ord(data[size+1])
                size += (1 * 2) # 파일 크기가 2개 옴(압축전, 압축 후)
            elif file_desc & 0x20 : 
                Compress_Size   = struct.unpack('<H', data[size  :size+2])[0]
                Uncompress_Size = struct.unpack('<H', data[size+2:size+4])[0]
                size += (2 * 2)
            elif file_desc & 0x40 : 
                Compress_Size   = struct.unpack('<L', data[size  :size+4])[0]
                Uncompress_Size = struct.unpack('<L', data[size+4:size+8])[0]
                size += (4 * 2)
            elif file_desc & 0x80 : 
                Compress_Size   = struct.unpack('<Q', data[size  :size+ 8])[0]
                Uncompress_Size = struct.unpack('<Q', data[size+8:size+16])[0]
                size += (8 * 2)
            else                  : raise SystemError

            fname = data[size:size+fname_size]
            size += fname_size # 파일 이름
            
            if file_desc & 1 :
                size += 12 # Encrypt Block

            size += Compress_Size
        except :
            return -1

        return size, fname

#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------
'''
if __name__ == '__main__' :
    alz = AlzFile('unalz.alz')

    print alz.read('readme.txt')

    for name in alz.namelist() :
        print name

    alz.close()    
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
        info['title'] = 'Alz Engine' # 엔진 설명
        info['kmd_name'] = 'alz' # 엔진 파일명
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
            if mm[0:4] == 'ALZ\x01' : # 헤더 체크
                fformat['size'] = len(mm) # 포맷 주요 정보 저장

                ret = {}
                ret['ff_alz'] = fformat

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
            # 미리 분석된 파일 포맷중에 ALZ 포맷이 있는가?
            fformat = format['ff_alz']
                
            alzfile = AlzFile(filename)
            for name in alzfile.namelist() :
                file_scan_list.append(['arc_alz', name])
            alzfile.close()
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_alz' :
                raise SystemError

            alzfile = AlzFile(arc_name)
            data = alzfile.read(arc_in_name)
            alzfile.close()

            return data
        except :
            pass

        return None
