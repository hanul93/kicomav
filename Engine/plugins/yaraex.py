# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import kernel
import yara


# -------------------------------------------------------------------------
# KavMain 클래스
# -------------------------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    #         verbose      - 디버그 모드 (True or False)
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):  # 플러그인 엔진 초기화
        self.verbose = verbose
        try:
            self.rules = yara.compile(plugins_path + os.sep + 'yaraex.yar')
        except:
            if self.verbose:
                print '[*] ERROR : YARA Rule compile'
            return -1

        return 0  # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.0'  # 버전
        info['title'] = 'Yara Engine'  # 엔진 설명
        info['kmd_name'] = 'yaraex'  # 엔진 파일 이름

        return info

    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat)
    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    #         fileformat  - 파일 포맷
    #         filename_ex - 파일 이름 (압축 내부 파일 이름)
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex):  # 악성코드 검사
        ret = self.rules.match(filename)
        if len(ret):
            vname = ret[0].meta.get('KicomAV', ret[0].rule)  # KicomAV meta 정보 확인
            return True, vname, 0, kernel.INFECTED

        # 악성코드를 발견하지 못했음을 리턴한다.
        return False, '', -1, kernel.NOT_FOUND

    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id)
    # 악성코드를 치료한다.
    # 입력값 : filename    - 파일 이름
    #        : malware_id - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    # ---------------------------------------------------------------------
    def disinfect(self, filename, malware_id):  # 악성코드 치료
        try:
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if malware_id == 0:
                os.remove(filename)  # 파일 삭제
                return True  # 치료 완료 리턴
        except IOError:
            pass

        return False  # 치료 실패 리턴

