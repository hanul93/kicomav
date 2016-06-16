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
import zlib
import struct
import marshal
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
        info['author'] = 'Kei Choi' # 제작자
        info['version'] = '1.0'     # 버전
        info['title'] = 'PYZ Engine' # 엔진 설명
        info['kmd_name'] = 'pyz' # 엔진 파일명
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
            if mm[0:4] == 'PYZ\x00' : # 헤더 체크
                off = struct.unpack('>L', mm[8:0xC])[0] # PKZ 파일에서 TOC 위치
                fformat['TOC_off'] = off 

                ret = {}
                ret['ff_pyz'] = fformat

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
            # 미리 분석된 파일 포맷중에 ZIP 포맷이 있는가?
            fformat = format['ff_pyz']
            toc_off = fformat['TOC_off']

            fp = open(filename, 'rb')
            fp.seek(toc_off)
            toc = fp.read()
            tocs = marshal.loads(toc)
            fp.close()

            for name in tocs.keys() :
                file_scan_list.append(['arc_pyz', name])
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_pyz' :
                raise SystemError

            fp = open(arc_name, 'rb')
            buf = fp.read(0x10)
            toc_off = struct.unpack('>L', buf[8:0xC])[0]
            fp.seek(toc_off)
            toc_buf = fp.read()
            tocs = marshal.loads(toc_buf)

            toc = tocs[arc_in_name]
            start = toc[1]
            size  = toc[2]

            fp.seek(start)
            buf = fp.read(size)

            data = zlib.decompress(buf)

            fp.close()

            return data
        except :
            pass

        return None
