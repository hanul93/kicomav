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


import os # 파일 삭제를 위해 import
import kernel
import struct

def GetString(buf, off) :
    ret_str = ''

    try :
        pos = off
        while 1 :
            c = buf[pos]
            if c == '\x00' : break
            ret_str += c
            pos += 1
    except :
        pass

    return ret_str


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
        info['title'] = 'Ole10Native Engine' # 엔진 설명
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
            size = struct.unpack('<L', mm[0:4])[0]
            
            if mm[4:6] == '\x02\x00' :
                if len(mm) == size + 4 : 
                    fformat['size'] = len(mm) # 포맷 주요 정보 저장

                    label = GetString(mm, 6)
                    fformat['label'] = label

                    off = 6+len(label)+1
                    fname = GetString(mm, off)

                    off += len(fname) + 1
                    off += 2 # flag
                    
                    unknown_size = ord(mm[off])
                    off += 1 + unknown_size + 2

                    command = GetString(mm, off)
                    off += len(command) + 1

                    data_size = struct.unpack('<L', mm[off:off+4])[0]

                    fformat['data_off'] = off + 4
                    fformat['data_size'] = data_size

                    if len(mm) < off + data_size : # 오류
                        raise SystemError

                    ret = {}
                    ret['ff_ole10native'] = fformat

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
            # 미리 분석된 파일 포맷중에 ff_ole10native 포맷이 있는가?
            fformat = format['ff_ole10native']
                
            name = fformat['label'] # OLE 내부에 숨겨진 파일 명

            off       = fformat['data_off']
            data_size = fformat['data_size']

            arc_name = 'arc_ole10native!%s!%s' % (off, data_size)
            file_scan_list.append([arc_name, name])

        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            fformat = arc_engine_id.split('!')

            if fformat[0] != 'arc_ole10native' :
                raise SystemError

            off       = int(fformat[1])
            data_size = int(fformat[2])

            fp = open(arc_name, 'rb')
            fp.seek(off)
            data = fp.read(data_size)
            fp.close()

            return data
        except :
            pass

        return None
