# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

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

            mm = mmhandle

            if mm[0:2] != 'MZ' : # MZ로 시작하나?
                raise SystemError

            pe_pos = struct.unpack('<L', mm[0x3C:0x3C+4])[0]

            if mm[pe_pos:pe_pos+4] != 'PE\x00\x00' : # PE 인가?
                raise SystemError

            fformat['pe'] = pe_pos
               
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
        info['author'] = 'Kei Choi' # 제작자
        info['version'] = '1.0'     # 버전
        info['title'] = 'PE Engine' # 엔진 설명
        info['kmd_name'] = 'pefile' # 엔진 파일명
        return info
