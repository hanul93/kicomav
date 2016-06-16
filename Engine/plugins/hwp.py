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


import os # 파일 삭제를 위해 import
import zlib
import struct, mmap
import kernel

class HWPTag :
    fnTagID = {0x43:'self.HWPTAG_PARA_TEXT'}

    def HWPTAG_PARA_TEXT(self, buf, lenbuf) :
        ret = 0
        pos = 0
        ctrl_ch = False
        str_txt = ''
        old_ch = 0
        ch_count = 0

        while pos < lenbuf:
            ch = self.GetWord(buf, pos)
            # print ch, pos

            if ch >= 1 and ch <= 9 : # 16바이트 제어문자
                ctrl_ch = True
                pos += 16
            elif ch == 11 or ch == 12 : # 16바이트 제어문자
                ctrl_ch = True
                pos += 16
            elif ch >= 14 and ch <= 23 : # 16바이트 제어문자
                ctrl_ch = True
                pos += 16
            elif ch <= 31 :  # 2바이트 제어문자
                ctrl_ch = True
                pos += 2

            # 문단에 포함된 문자
            if ctrl_ch == False :
                str_txt += unichr(ch)
                pos += 2
                # 해당 문자의 반복성을 체크해본다
                if old_ch == ch :
                    ch_count += 1
                else :
                    old_ch = ch
                    ch_count = 0
            else :
                ctrl_ch = False

            # 문자의 반복성이 심하면 Exploit 공격일 가능성이 크다
            if ch_count > 4096 :
                ret  = -1
                break

        # print str_txt.encode('utf-8')
        return ret


    def GetInfo(self, val) :
        b = 0b1111111111
        c = 0b111111111111
        Size  = (val >> 20) & c
        TagID = (val &b)
        Level = ((val >> 10) & b)

        return TagID, Level, Size


    def GetDword(self, buf, off) :
        return struct.unpack('<L', buf[off:off+4])[0]


    def GetWord(self, buf, off) :
        return struct.unpack('<H', buf[off:off+2])[0]


    def Check(self, buf, lenbuf, isCompressed) :
        ret = -1
        pos = 0

        if isCompressed == 1 :
            buf = zlib.decompress(buf, -15)
            lenbuf = len(buf)

        while pos < lenbuf :
            extra_size = 4
            val = self.GetDword(buf, pos)
            tagid, level, size = self.GetInfo(val)

            if size == 0xfff :
                extra_size = 8
                size = self.GetDword(buf, pos+4)

            try :
                '''
                print
                print 'tag : %02X' % tagid
                print 'pos : %X (%s)' % (pos, self.fnTagID[tagid])
                '''
                fn = 'ret_tag = %s(buf[pos+extra_size:pos+size+extra_size], size)' % self.fnTagID[tagid]
                exec(fn)

                if ret_tag == -1 :
                    return -1, tagid
            except :
                pass

            pos += (size + extra_size)

        if pos == lenbuf :
            ret = 0

        return ret, tagid

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
    # scan(self, filehandle, filename)
    # 악성코드를 검사한다.
    # 인자값 : mmhandle         - 파일 mmap 핸들
    #        : scan_file_struct - 파일 구조체
    #        : format           - 미리 분석된 파일 포맷
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    #-----------------------------------------------------------------
    def scan(self, mmhandle, filename, deepname, format) :
        ret = 0
        scan_state = kernel.NOT_FOUND

        try :
            # HWP Exploit은 주로 BodyText/SectionXX에 존재한다
            # 파일을 열어 악성코드 패턴만큼 파일에서 읽는다.
            section_name = deepname

            if section_name.find(r'BodyText/Section') != -1 :
                data = mmhandle[:] # 파일 전체 내용

                # HWP의 잘못된 태그를 체크한다.
                h = HWPTag()
                ret, tagid = h.Check(data, len(data), 1)
                if tagid == 0x5A or tagid == 0x42: # Tagid가 0x5A, 0x42인것은 악성코드 확실
                    scan_state = kernel.INFECTED # 감염
                else :
                    scan_state = kernel.SUSPECT  # 의심

                if ret != 0 : # 악성코드 발견
                    s = 'Exploit.HWP.Generic.%2X' % tagid
            elif section_name.find(r'BodyText/') != -1 : # BodyText 폴더인데.. SectionXXX은 아니라는 의미
                ret = 1 # 악성코드 발견
                s = 'Exploit.HWP.Generic.EX'
                scan_state = kernel.SUSPECT

            if ret != 0 :
                # 악성코드 패턴이 갖다면 결과 값을 리턴한다.
                return (True, s, 0, scan_state)           
        except :
            pass

        # 악성코드를 발견하지 못했음을 리턴한다.
        return (False, '', -1, kernel.NOT_FOUND)

    #-----------------------------------------------------------------
    # disinfect(self, filename, malwareID)
    # 악성코드를 치료한다.
    # 인자값 : filename   - 파일 이름
    #        : malwareID  - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    #-----------------------------------------------------------------
    def disinfect(self, filename, malwareID) : # 악성코드 치료
        try :
            '''
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if malwareID == 0 : 
                os.remove(filename) # 파일 삭제
                return True # 치료 완료 리턴
            '''
        except :
            pass

        return False # 치료 실패 리턴

    #-----------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 목록을 알려준다.
    #-----------------------------------------------------------------
    def listvirus(self) : # 진단 가능한 악성코드 목록
        vlist = [] # 리스트형 변수 선언
        vlist.append('Exploit.HWP.Generic.42') 
        vlist.append('Exploit.HWP.Generic.43') 
        vlist.append('Exploit.HWP.Generic.5A')
        vlist.append('Exploit.HWP.Generic.EX')
        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = __author__          # 제작자
        info['version'] = __version__        # 버전
        info['title'] = 'HWP Exploit Engine' # 엔진 설명
        info['kmd_name'] = 'hwp'             # 엔진 파일명

        # 패턴 생성날짜와 시간은 없다면 빌드 시간으로 자동 설정
        info['date']    = 0   # 패턴 생성 날짜 
        info['time']    = 0   # 패턴 생성 시간 
        info['sig_num'] = 4 # 패턴 수
        return info

