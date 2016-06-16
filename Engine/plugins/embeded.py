# -*- coding:utf-8 -*-

"""
Copyright (C) 2013-2014 Nurilab.

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


import kernel
import struct
import zlib

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
        info['author'] = 'Kei Choi' # 제작자
        info['version'] = '1.0'     # 버전
        info['title'] = 'HWP OLE Embeded Engine' # 엔진 설명
        info['kmd_name'] = 'ole10native' # 엔진 파일명
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # 포맷 정보를 담을 공간

            mm = mmhandle
            mm = zlib.decompress(mm, -15)

            size = struct.unpack('<L', mm[0:4])[0]
            
            if len(mm) == size + 4 :
                fformat['size'] = len(mm) # 포맷 주요 정보 저장

                ret = {}
                ret['ff_embeded'] = fformat

                return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # 검사 대상 정보를 모두 가짐

        try :
            # 미리 분석된 파일 포맷중에 ff_embeded 포맷이 있는가?
            fformat = format['ff_embeded']
                
            arc_name = 'arc_embeded'
            file_scan_list.append([arc_name, 'Embeded'])

        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_embeded' :
                raise SystemError

            fp = open(arc_name, 'rb')
            data = fp.read()
            data = zlib.decompress(data, -15)
            fp.close()

            return data[4:]
        except :
            pass

        return None
