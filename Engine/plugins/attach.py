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

import mmap
import os
import struct
import kernel


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
        info['title'] = 'Attach Engine' # 엔진 설명
        info['kmd_name'] = 'attach' # 엔진 파일명
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # 포맷 분석기이다.
    # 한글의 BinData중 OLE 파일을 추출하기 위한 용도..
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            ret = {}
            fformat = {} # 포맷 정보를 담을 공간
            mm = mmhandle
                
            # 한글 파일의 BinData/BIN0001.OLE 등의 파일을 진단하기 위한 조치
            # 첫 4바이트는 전체 크기
            # 나머지는 OLE 파일
            rsize = struct.unpack('<L', mm[0:4])[0]
            fsize = os.path.getsize(filename)
            
            if rsize +4 != fsize :
                return None

            if mm[4:4+8] == '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' :
                fformat = {} # 포맷 정보를 담을 공간
                fformat['Attached_Pos'] = 4
                ret['ff_attach'] = fformat
                
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
            # 미리 분석된 파일 포맷중에 추가 포맷이 있는가?
            fformat = format['ff_attach']

            pos = fformat['Attached_Pos']
            if pos <= 0 : 
                raise SystemError

            name = 'Attached'
            arc_name = 'arc_attach!%s' % pos

            file_scan_list.append([arc_name, name])
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        fp = None
        mm = None

        try :
            arc_id = arc_engine_id
            if arc_id[0:10] != 'arc_attach' :
                raise SystemError

            pos = int(arc_id[11:]) # 첨부된 파일의 위치 얻기
            if pos <= 0 : 
                raise SystemError

            # 첨부 파일을 가진 파일 열기
            fp = open(arc_name, 'rb') 
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            data = mm[pos:]

            mm.close()
            fp.close()

            mm = None
            fp = None

            return data
        except :
            pass

        if mm != None : mm.close()
        if fp != None : fp.close()

        return None
