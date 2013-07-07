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

__revision__ = '$LastChangedRevision: 2 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'


import struct

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
    # format(self, mmhandle, filename)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # 포맷 정보를 담을 공간
            pe_format = {'PE_Position':0, 'EntryPoint':0, 'SectionNumber':0,
                'DirectoryNumber':0, 'Sections':None, 'EntryPointRaw':0}
            mm = mmhandle

            if mm[0:2] != 'MZ' : # MZ로 시작하나?
                raise SystemError

            pe_pos = struct.unpack('<L', mm[0x3C:0x3C+4])[0]

            # PE 인가?
            if mm[pe_pos:pe_pos+4] != 'PE\x00\x00' : 
                raise SystemError

            pe_format['PE_Position'] = pe_pos

            # Optional Header의 Magic ID?
            if mm[pe_pos+0x18:pe_pos+0x18+2] != '\x0B\x01' : 
                raise SystemError
            
            # Entry Point 구하기
            pe_ep = struct.unpack('<L', mm[pe_pos+0x28:pe_pos+0x28+4])[0]
            pe_format['EntryPoint'] = pe_ep

            # Section 개수 구하기
            section_num = struct.unpack('<H', mm[pe_pos+0x6:pe_pos+0x6+2])[0]
            pe_format['SectionNumber'] = section_num

            # Data Directory 개수 구하기
            directory_num = struct.unpack('<L', mm[pe_pos+0x74:pe_pos+0x74+4])[0]
            pe_format['DirectoryNumber'] = directory_num

            section_pos = pe_pos+0x78 + (directory_num * 8)

            # 모든 섹션 정보 추출
            sections = [] # 모든 섹션 정보 담을 리스트

            for i in range(section_num) :
                section = {}
                s = section_pos + (0x28 * i) 

                section['Name'] = ''
                for ch in mm[s:s+8] :
                    if ch == '\x00' : break
                    section['Name'] += ch
                section['VirtualSize']     = struct.unpack('<L', mm[s+ 8:s+12])[0]
                section['RVA']             = struct.unpack('<L', mm[s+12:s+16])[0]
                section['SizeRawData']     = struct.unpack('<L', mm[s+16:s+20])[0]
                section['PointerRawData']  = struct.unpack('<L', mm[s+20:s+24])[0]
                section['Characteristics'] = struct.unpack('<L', mm[s+36:s+40])[0]
                sections.append(section)

            pe_format['Sections'] = sections

            # EntryPoint의 파일에서의 위치 구하기
            for section in sections :
                size = section['VirtualSize']
                rva = section['RVA']
                if rva <= pe_ep and rva+size > pe_ep :
                    foff  = section['PointerRawData']
                    ep_raw = pe_ep - rva + foff
                    pe_format['EntryPointRaw'] = ep_raw
                    break


            fformat['pe'] = pe_format
               
            ret = {}
            ret['ff_pe'] = fformat

            return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = __author__    # 제작자
        info['version'] = __version__  # 버전
        info['title'] = 'PE Engine'    # 엔진 설명
        info['kmd_name'] = 'pefile'    # 엔진 파일명
        return info
