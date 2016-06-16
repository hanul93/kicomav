# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # 파일 삭제를 위해 import
import zipfile
import tempfile
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
        info['title'] = 'APK Engine' # 엔진 설명
        info['kmd_name'] = 'apk' # 엔진 파일명
        info['engine_type'] = kernel.ARCHIVE_ENGINE # 엔진 타입

        # 패턴 생성날짜와 시간은 없다면 빌드 시간으로 자동 설정
        info['date']    = 0   # 패턴 생성 날짜 
        info['time']    = 0   # 패턴 생성 시간 
        info['sig_num'] = 1 # 패턴 수

        return info

    #-----------------------------------------------------------------
    # scan(self, filehandle, filename)
    # 악성코드를 검사한다.
    # 인자값 : mmhandle         - 파일 mmap 핸들
    #        : scan_file_struct - 파일 구조체
    #        : format           - 미리 분석된 파일 포맷
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    #-----------------------------------------------------------------
    def scan(self, mmhandle, filename, deepname, format) :
        try :
            # 미리 분석된 파일 포맷중에 Dummy 포맷이 있는가?
            fformat = format['ff_apk']

            zfile = zipfile.ZipFile(filename)

            count = 0
            infolist = zfile.infolist()
            for l in infolist :
                fname = l.filename.lower()
                if fname == 'classes.dex' :
                    count += 1
                else :
                    continue

            zfile.close()

            # classes.dex가 한개 이상이면 취약점이 존재한다.
            if count > 1 :
                # 악성코드 패턴이 갖다면 결과 값을 리턴한다.
                return (True, 'Exploit.Android.MasterKey.A', 0, kernel.INFECTED)
        except :
            pass

        # 악성코드를 발견하지 못했음을 리턴한다.
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
    def listvirus(self) : # 진단 가능한 악성코드 목록
        vlist = [] # 리스트형 변수 선언
        vlist.append('Exploit.Android.MasterKey.A') # 진단하는 악성코드 이름 등록
        return vlist

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # 포맷 정보를 담을 공간

            mm = mmhandle
            if mm[0:2] == 'PK' : # 헤더 체크
                if zipfile.is_zipfile(filename) == False :
                    raise SystemError

                zfile = zipfile.ZipFile(filename)
                zfile.getinfo('classes.dex') # classes.dex 가 존재하나?
                zfile.getinfo('AndroidManifest.xml') # AndroidManifest.xml 존재하나?
                zfile.close()

                fformat['size'] = len(mm) # 포맷 주요 정보 저장

                ret = {}
                ret['ff_apk'] = fformat

                return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # 압축 파일 내부의 압축된 파일명을 리스트로 리턴한다.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # 검사 대상 정보를 모두 가짐

        try :
            # 미리 분석된 파일 포맷중에 APK 포맷이 있는가?
            fformat = format['ff_apk']

            zfile = zipfile.ZipFile(filename)

            apk_list = []
            infolist = zfile.infolist()
            for l in infolist :
                fname = l.filename.lower()
                if fname == 'classes.dex' or fname == 'androidmanifest.xml' :
                    name = l.filename
                    arc_engine_name = 'arc_apk!%d' % infolist.index(l)
                else :
                    continue

                file_scan_list.append([arc_engine_name, name])
            zfile.close()
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            arc_id = arc_engine_id
            if arc_id[0:7] != 'arc_apk' :
                raise SystemError

            id = int(arc_id[8:]) # 파일이 존재하는 ZIP ID
            if id <= 0 : 
                raise SystemError

            # id로 temp 폴더에 압축 해제
            tempdir = tempfile.gettempdir()

            zfile = zipfile.ZipFile(arc_name)
            l = zfile.infolist()
            zfile.extract(l[id], tempdir)
            zfile.close()

            rname = tempdir + os.sep + arc_in_name
            fp = open(rname, 'rb')
            data = fp.read()
            fp.close()

            os.remove(rname)

            return data
        except :
            pass

        return None
