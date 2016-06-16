# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # 파일 삭제를 위해 import
import hashlib # MD5 해시를 위해 import
import mmap
import kernel

#---------------------------------------------------------------------
# KavMain 클래스
# 키콤백신 엔진 모듈임을 나타내는 클래스이다.
# 이 클래스가 없으면 백신 엔진 커널 모듈에서 로딩하지 않는다.
#---------------------------------------------------------------------
class KavMain :
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
            mm = mmhandle # 파일 mmap 핸들을 mm에 저장

            buf = mm[0:2] # 파일 처음부터 68 Byte를 읽음

            if buf == 'va' : # buf에 68 Byte가 읽혔나?
                v_pattern = mm[0x14:0x14+11]

                if v_pattern == 'fnc = \'ev\';' :
                    # 맞다면 검사 결과와 이름, ID를 리턴
                    return (True, 'VIRUS-TEST', 0, kernel.INFECTED)
        except : # 모든 예외사항을 처리
            pass
        
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
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if malwareID == 0 : 
                os.remove(filename) # 파일 삭제
                return True # 치료 완료 리턴
        except :
            pass

        return False # 치료 실패 리턴

    #-----------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 목록을 알려준다.
    #-----------------------------------------------------------------
    def listvirus(self) :
        vlist = [] # 리스트형 변수 선언
        # vlist.append('VIRUS-TEST') # 진단하는 악성코드 이름 등록
        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = 'Kei Choi' # 제작자
        info['version'] = '1.0'     # 버전
        info['title'] = 'VIRUS-TEST Engine' # 엔진 설명
        info['kmd_name'] = 'script' # 엔진 파일명

        # 패턴 생성날짜와 시간은 없다면 빌드 시간으로 자동 설정
        info['date']    = 0   # 패턴 생성 날짜 
        info['time']    = 0   # 패턴 생성 시간 
        info['sig_num'] = 1 # 패턴 수
        return info