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

UPX_NRV2B = '\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc'
UPX_NRV2D = '\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb'
UPX_NRV2E = '\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a'
UPX_LZMA1 = '\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90'
UPX_LZMA2 = '\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90'

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
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = __author__    # 제작자
        info['version'] = __version__  # 버전
        info['title'] = 'UPX Unpacker' # 엔진 설명
        info['kmd_name'] = 'upx'       # 엔진 파일명
        return info

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def arclist(self, scan_file_struct, format) :
        fp = None
        mm = None
        file_scan_list = [] # 검사 대상 정보를 모두 가짐
        deep_name = ''

        try :
            # 미리 분석된 파일 포맷중에 PE 포맷이 있는가?
            fformat   = format['ff_pe']
            pe_format = fformat['pe']
            ep_foff   = pe_format['EntryPointRaw']

            filename = scan_file_struct['real_filename']
            deep_name = scan_file_struct['deep_filename']

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            if   mm[ep_foff+0x69:ep_foff+0x69+13] == UPX_NRV2B : arc_name = 'arc_upx!nrv2b'
            elif mm[ep_foff+0x71:ep_foff+0x71+13] == UPX_NRV2B : arc_name = 'arc_upx!nrv2b'
            elif mm[ep_foff+0x69:ep_foff+0x69+13] == UPX_NRV2D : arc_name = 'arc_upx!nrv2d'
            elif mm[ep_foff+0x71:ep_foff+0x71+13] == UPX_NRV2D : arc_name = 'arc_upx!nrv2d'
            elif mm[ep_foff+0x69:ep_foff+0x69+13] == UPX_NRV2E : arc_name = 'arc_upx!nrv2e'
            elif mm[ep_foff+0x71:ep_foff+0x71+13] == UPX_NRV2E : arc_name = 'arc_upx!nrv2e'
            else :
                raise SystemError

            name = 'UPX'

            file_info = {}  # 파일 한개의 정보

            if len(deep_name) != 0 :
                dname = '%s/%s' % (deep_name, name)
            else :
                dname = '%s' % (name)

            file_info['is_arc'] = True # 압축 여부
            file_info['arc_engine_name'] = arc_name # 압축 해제 가능 엔진 ID
            file_info['arc_filename'] = filename # 실제 압축 파일
            file_info['arc_in_name'] = name #압축해제 대상 파일
            file_info['real_filename'] = '' # 검사 대상 파일
            file_info['deep_filename'] = dname  # 압축 파일의 내부를 표현하기 위한 파일명
            file_info['display_filename'] = scan_file_struct['display_filename'] # 출력용

            file_scan_list.append(file_info)
        except :
            pass

        if mm != None : mm.close()
        if fp != None : fp.close()

        return file_scan_list