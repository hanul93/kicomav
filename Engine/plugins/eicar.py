# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # 파일 삭제를 위해 import
import hashlib # MD5 해시를 위해 import
import mmap
import kavutil

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
    def scan(self, mmhandle, scan_file_struct, format) :
        ret_value = {}
        ret_value['result']     = False # 바이러스 발견 여부
        ret_value['virus_name'] = ''    # 바이러스 이름
        ret_value['scan_state'] = kavutil.NOT_FOUND # 0:없음, 1:감염, 2:의심, 3:경고
        ret_value['virus_id']   = -1    # 바이러스 ID

        try : # 백신 엔진의 오류를 방지하기 위해 예외 처리를 선언 
            mm = mmhandle # 파일 mmap 핸들을 mm에 저장

            buf = mm[0:68] # 파일 처음부터 68 Byte를 읽음

            if len(buf) == 68 : # buf에 68 Byte가 읽혔나?
                md5 = hashlib.md5() # MD5 해시를 구함
                md5.update(buf)
                f_md5 = md5.hexdigest()

                eicar_pattern = '44d88612fea8a8f36de82e1278abb02f'

                if f_md5 == eicar_pattern :  # 패턴이 같은지를 비교
                    # 맞다면 검사 결과와 이름, ID를 리턴
                    ret_value['result']     = True             # 바이러스 발견 여부
                    ret_value['virus_name'] = 'EICAR-Test-File (not a virus)' # 바이러스 이름
                    ret_value['scan_state'] = kavutil.INFECTED # 0:없음, 1:감염, 2:의심, 3:경고
                    ret_value['virus_id']   = 0                # 바이러스 ID
                    return ret_value
        except : # 모든 예외사항을 처리
            pass
        
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
    def listvirus(self) :
        vlist = [] # 리스트형 변수 선언
        vlist.append('EICAR Test') # 진단하는 악성코드 이름 등록
        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = 'Kei Choi' # 제작자
        info['version'] = '1.0'     # 버전
        info['title'] = 'EICAR Test Engine' # 엔진 설명
        return info