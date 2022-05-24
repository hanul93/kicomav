# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import gzip
import kernel


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
        info['title'] = 'GZ Archive Engine'  # 엔진 설명
        info['kmd_name'] = 'gz'  # 엔진 파일 이름
        info['engine_type'] = kernel.ARCHIVE_ENGINE  # 엔진 타입
        info['make_arc_type'] = kernel.MASTER_PACK  # 악성코드 치료 후 재압축 유무

        return info

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #          filename   - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        ret = {}

        mm = filehandle
        if mm[0:3] == b'\x1F\x8B\x08':  # 헤더 체크
            ret['ff_gz'] = 'gz'
            return ret

        return None

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 GZ 포맷이 있는가?
        if 'ff_gz' in fileformat:
            file_scan_list.append(['arc_gz', 'GZ'])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_gz':
            try:
                data = gzip.open(arc_name, 'rb').read()
                return data
            except IOError:  # Not a gzipped file
                pass

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        pass

    # ---------------------------------------------------------------------
    # mkarc(self, arc_engine_id, arc_name, file_infos)
    # 입력값 : arc_engine_id - 압축 가능 엔진 ID
    #         arc_name      - 최종적으로 압축될 압축 파일 이름
    #         file_infos    - 압축 대상 파일 정보 구조체
    # 리턴값 : 압축 성공 여부 (True or False)
    # ---------------------------------------------------------------------
    def mkarc(self, arc_engine_id, arc_name, file_infos):
        if arc_engine_id == 'arc_gz':
            try:
                zfile = gzip.open(arc_name, 'wb')
                file_info = file_infos[0]

                rname = file_info.get_filename()
                data = open(rname, 'rb').read()

                zfile.write(data)
                zfile.close()

                return True
            except:
                pass

        return False
