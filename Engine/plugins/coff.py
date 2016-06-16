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


import os # 파일 삭제를 위해 import
import kernel
import pefile # PE 파일 포맷을 위해 import
import hashlib
import struct

TARGET_EP      = 0
TARGET_SECTION = 0x80

def int32(iv) :
    if iv & 0x80000000 :
        iv = -0x100000000 + iv
    return iv   

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
        self.pattern = [ \
        #['Notepad (not a virus)', [TARGET_EP, 0x80, 0x1A9393CF], [TARGET_SECTION+0, 0x000003A0, 0x80, 0xE6829D78]]
        ]
        return 0

    #-----------------------------------------------------------------
    # uninit(self)
    # 백신 엔진 모듈의 종료화 작업을 수행한다.
    #-----------------------------------------------------------------
    def uninit(self) : # 백신 모듈 종료화
        return 0

    #-----------------------------------------------------------------
    # scan(self, filehandle, filename)
    # 악성코드를 검사한다.
    # 인자값 : mmhandle         - 파일 mmap 핸들
    #        : scan_file_struct - 파일 구조체
    #        : format           - 미리 분석된 파일 포맷
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    #-----------------------------------------------------------------
    def scan(self, mmhandle, filename, deepname, format) :
        try : # 백신 엔진의 오류를 방지하기 위해 예외 처리를 선언 
            # 미리 분석된 파일 포맷중에 pe 포맷이 있는가?
            fformat = format['ff_pe']

            mm = mmhandle # 파일 mmap 핸들을 mm에 저장

            file_pattern_1st = {}

            # EP에서 패턴을 생성
            offset = fformat['pe']['EntryPointRaw']
            # print hex(offset)

            file_pattern_1st[TARGET_EP] = self.__MakePattern__(mm, offset)

            # 각 섹션에서 패턴을 생성
            sections = fformat['pe']['Sections']
             
            for i in range(fformat['pe']['SectionNumber']) :
                section = sections[i]
                offset  = section['PointerRawData']
                file_pattern_1st[TARGET_SECTION+i] = self.__MakePattern__(mm, offset)

            # print hex(file_pattern_1st[TARGET_EP][0x80])

            # 1차 패턴 비교
            for p in self.pattern :
                vname   = p[0]
                ptn_1st = p[1]
                ptn_2nd = p[2]

                target  = ptn_1st[0] # 1차 패턴 위치 
                size    = ptn_1st[1] # 1차 패턴 크기
                ptn_crc = ptn_1st[2] # 1차 패턴 크기

                # 1차 패턴 일치않으면 다음 패턴 비교
                if file_pattern_1st[target][size] != ptn_crc : 
                    continue

                #2차 패턴 비교
                target  = ptn_2nd[0] # 2차 패턴 위치 
                pos     = ptn_2nd[1] # 2차 패턴 위치 
                size    = ptn_2nd[2] # 2차 패턴 크기
                ptn_crc = ptn_2nd[3] # 2차 패턴 크기

                if target == TARGET_EP :
                    offset = fformat['pe']['EntryPointRaw']
                elif target >= TARGET_SECTION :
                    nSec = target - TARGET_SECTION
                    section = sections[nSec]
                    offset  = section['PointerRawData']
                else :
                    raise SystemError

                offset = int32(offset + pos)

                # 2차 패턴 일치한다면 
                crc32 = self.__k2crc32__(mm, offset, size)
                '''
                print hex(offset)
                print hex(size)
                print hex(crc32)
                print hex(ptn_crc)
                '''
                if self.__k2crc32__(mm, offset, size) == ptn_crc :
                    # 맞다면 검사 결과와 이름, ID를 리턴
                    return (True, vname, 0, kernel.INFECTED)
        except : # 모든 예외사항을 처리
            pass

        # 악성코드를 발견하지 못했음을 리턴한다.
        return (False, '', -1, kernel.NOT_FOUND)

    def __MakePattern__(self, mm, offset) :
        pos = [0x10, 0x20, 0x40, 0x80]
        pattern = {}

        # 초기화
        for i in pos : pattern[i] = 0

        try :
            # 패턴 생성
            for i in pos :
                pattern[i] = self.__k2crc32__(mm, offset, i)
        except :
            pass

        return pattern
        
    def __k2crc32__(self, data, offset, size) :
        try :
                data = data[offset:offset + size]
                '''
                for i in range(len(data)) :
                    s = '%02X' % ord(data[i])
                    print s,
                print
                '''
                md5 = hashlib.md5()
                md5.update(data)
                fmd5 = md5.digest()

                crc1 = struct.unpack('<L', fmd5[ 0: 4])[0]
                crc2 = struct.unpack('<L', fmd5[ 4: 8])[0]
                crc3 = struct.unpack('<L', fmd5[ 8:12])[0]
                crc4 = struct.unpack('<L', fmd5[12:16])[0]
        except :
            return 0

        return (crc1 ^ crc2 ^ crc3 ^ crc4)

    #-----------------------------------------------------------------
    # disinfect(self, filename, malwareID)
    # 악성코드를 치료한다.
    # 인자값 : filename   - 파일 이름
    #        : malwareID  - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    #-----------------------------------------------------------------
    def disinfect(self, filename, malwareID) : # 악성코드 치료
        return False # 치료 실패 리턴

    #-----------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 목록을 알려준다.
    #-----------------------------------------------------------------
    def listvirus(self) :
        vlist = [] # 리스트형 변수 선언

        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = __author__   # 제작자
        info['version'] = __version__ # 버전
        info['title'] = 'COFF Engine' # 엔진 설명
        info['kmd_name'] = 'coff'     # 엔진 파일명

        
        # 패턴 생성날짜와 시간은 없다면 빌드 시간으로 자동 설정
        info['date']    = 0   # 패턴 생성 날짜 
        info['time']    = 0   # 패턴 생성 시간 
        info['sig_num'] = len(self.pattern) # 패턴 수
        
        return info

