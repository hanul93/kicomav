# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # 파일 삭제를 위해 import
import kernel

#---------------------------------------------------------------------
# KavMain 클래스
# 키콤백신 엔진 모듈임을 나타내는 클래스이다.
# 이 클래스가 없으면 백신 엔진 커널 모듈에서 로딩하지 않는다.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # init(self)
    # 백신 엔진 모듈의 초기화 작업을 수행한다.
    #-----------------------------------------------------------------
    def init(self) : # 백신 모듈 초기화
        self.virus_name = 'Dummy-Test-File (not a virus)' # 진단하는 악성코드 이름
        # 악성코드 패턴 등록
        self.dummy_pattern = 'Dummy Engine test file - KICOM Anti-Virus Project, 2012, Kei Choi'
        return 0

    #-----------------------------------------------------------------
    # uninit(self)
    # 백신 엔진 모듈의 종료화 작업을 수행한다.
    #-----------------------------------------------------------------
    def uninit(self) : # 백신 모듈 종료화
        del self.virus_name
        del self.dummy_pattern
        return 0
    
    #-----------------------------------------------------------------
    # scan(self, filehandle, filename)
    # 악성코드를 검사한다.
    # 인자값 : mmhandle         - 파일 mmap 핸들
    #        : scan_file_struct - 파일 구조체
    #        : format           - 미리 분석된 파일 포맷
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    #-----------------------------------------------------------------
    def scan(self, mmhandle, scan_file_struct, format) :
        ret_value = {}
        ret_value['result']     = False # 바이러스 발견 여부
        ret_value['virus_name'] = ''    # 바이러스 이름
        ret_value['scan_state'] = kernel.NOT_FOUND     # 0:없음, 1:감염, 2:의심, 3:경고
        ret_value['virus_id']   = -1    # 바이러스 ID

        try :
            # 미리 분석된 파일 포맷중에 Dummy 포맷이 있는가?
            fformat = format['ff_dummy']

            # 미리 분석된 파일 포맷에 크기가 65Byte?
            if fformat['size'] != len(self.dummy_pattern) :
                raise SystemError

            # 파일을 열어 악성코드 패턴만큼 파일에서 읽는다.
            filename = scan_file_struct['real_filename']
            fp = open(filename)
            buf = fp.read(len(self.dummy_pattern)) # 패턴은 65 Byte 크기
            fp.close()

            # 악성코드 패턴을 비교한다.
            if buf == self.dummy_pattern :
                # 악성코드 패턴이 갖다면 결과 값을 리턴한다.
                ret_value['result']     = True            # 바이러스 발견 여부
                ret_value['virus_name'] = self.virus_name # 바이러스 이름
                ret_value['scan_state'] = kernel.INFECTED# 0:없음, 1:감염, 2:의심, 3:경고
                ret_value['virus_id']   = 0               # 바이러스 ID
                return ret_value
        except :
            pass

        # 악성코드를 발견하지 못했음을 리턴한다.
        return ret_value

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
    def listvirus(self) : # 진단 가능한 악성코드 목록
        vlist = [] # 리스트형 변수 선언
        vlist.append(self.virus_name) # 진단하는 악성코드 이름 등록
        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = 'Kei Choi' # 제작자
        info['version'] = '1.0'     # 버전
        info['title'] = 'Dummy Scan Engine' # 엔진 설명
        info['kmd_name'] = 'dummy' # 엔진 파일명
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # Dummy 전용 포맷 분석기이다.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # 포맷 정보를 담을 공간

            mm = mmhandle
            if mm[0:5] == 'Dummy' : # 헤더 체크
                fformat['size'] = len(mm) # 포맷 주요 정보 저장

                ret = {}
                ret['ff_dummy'] = fformat
                return ret
        except :
            pass

        return None