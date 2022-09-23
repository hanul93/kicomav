# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import kernel
import kavutil


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
        self.p_http = re.compile(rb'https?://')
        return 0  # 플러그인 엔진 초기화 성공
        
    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공
        
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
        try:
            mm = filehandle

            if mm[0:8] != '\x4c\x00\x00\x00\x01\x14\x02\x00':  # LNK 헤더 체크
                raise ValueError
                
            flag = kavutil.get_uint32(mm, 0x14)
            
            off = 0x4c
            if flag & 0x0001 == 0x0001:  # HasLinkTargetIDList
                clid_mycom = '14001F50E04FD020EA3A6910A2D808002B30309D'.decode('hex')
                if mm[off+2:off+2+0x14] != clid_mycom:  # MyComputer
                    raise ValueError
                
                off += 2
                while True:
                    size = kavutil.get_uint16(mm, off)
                    if size == 0:
                        off += 2
                        break
                    if ord(mm[off+2]) == 0x32:
                        if mm[off+0xe:off+0xe+7].lower() != 'cmd.exe':
                            raise ValueError

                    off += size

            if flag & 0x0002 == 0x0002:  # HasLinkInfo
                off += kavutil.get_uint16(mm, off)
            
            if flag & 0x0004 == 0x0004:  # HasName
                size = kavutil.get_uint16(mm, off)
                off += (2 + (size * 2))
                
            if flag & 0x0008 == 0x0008:  # HasRelativePath
                size = kavutil.get_uint16(mm, off)
                cmd_path = mm[off+2:off+2+(size * 2):2].lower()

                # print cmd_path

                if cmd_path.find('cmd.exe') == -1:
                    raise ValueError
                off += (2 + (size * 2))
                
            if flag & 0x0010 == 0x0010:  # HasWorkingDir
                size = kavutil.get_uint16(mm, off)
                off += ( 2 + (size * 2))
                
            if flag & 0x0020 == 0x0020:  # HasArguments
                size = kavutil.get_uint16(mm, off)
                cmd_arg = mm[off+2:off+2+(size * 2):2].lower()
                cmd_arg = cmd_arg.replace('^', '')
                
                # print cmd_arg

                # 악성코드 패턴을 비교한다.
                if self.p_http.search(cmd_arg):
                    return True, 'Trojan.LNK.Agent.gen', 0, kernel.INFECTED
        except (IOError, ValueError):
            pass

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
        
    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = list()  # 리스트형 변수 선언

        vlist.append('Trojan.LNK.Agent.gen')  # 진단/치료하는 악성코드 이름 등록

        return vlist         

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.0'      # 버전
        info['title'] = 'LNK Scan Engine'  # 엔진 설명
        info['kmd_name'] = 'lnk'   # 엔진 파일 이름
        info['sig_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info
