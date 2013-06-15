# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # 파일 삭제를 위해 import
import zipfile
import tempfile

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
        info['title'] = 'Zip Engine' # 엔진 설명
        info['kmd_name'] = 'zip' # 엔진 파일명
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # 포맷 정보를 담을 공간

            mm = mmhandle
            if mm[0:2] == 'PK' : # 헤더 체크
                fformat['size'] = len(mm) # 포맷 주요 정보 저장

                ret = {}
                ret['ff_zip'] = fformat

                return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def arclist(self, scan_file_struct, format) :
        file_scan_list = [] # 검사 대상 정보를 모두 가짐
        deep_name = ''

        try :
            # 미리 분석된 파일 포맷중에 ZIP 포맷이 있는가?
            fformat = format['ff_zip']

            filename = scan_file_struct['real_filename']
            deep_name = scan_file_struct['deep_filename']
                
            zfile = zipfile.ZipFile(filename)
            for name in zfile.namelist() :
                file_info = {}  # 파일 한개의 정보

                if len(deep_name) != 0 :
                    dname = '%s/%s' % (deep_name, name)
                else :
                    dname = '%s' % (name)

                file_info['is_arc'] = True # 압축 여부
                file_info['arc_engine_name'] = 'arc_zip' # 압축 해제 가능 엔진 ID
                file_info['arc_filename'] = filename # 실제 압축 파일
                file_info['arc_in_name'] = name #압축해제 대상 파일
                file_info['real_filename'] = '' # 검사 대상 파일
                file_info['deep_filename'] = dname  # 압축 파일의 내부를 표현하기 위한 파일명
                file_info['display_filename'] = scan_file_struct['display_filename'] # 출력용

                file_scan_list.append(file_info)
            zfile.close()
        except :
            pass

        return file_scan_list

    def unarc(self, scan_file_struct) :
        try :
            if scan_file_struct['is_arc'] != True : 
                raise SystemError

            if scan_file_struct['arc_engine_name'] != 'arc_zip' :
                raise SystemError

            arc_name = scan_file_struct['arc_filename']
            filename = scan_file_struct['arc_in_name']

            zfile = zipfile.ZipFile(arc_name)
            data = zfile.read(filename)
            zfile.close()

            # 압축을 해제하여 임시 파일을 생성
            rname = tempfile.mktemp(prefix='ktmp')
            fp = open(rname, 'wb')
            fp.write(data)
            fp.close()

            scan_file_struct['real_filename'] = rname

            return scan_file_struct
        except :
            pass

        return None
