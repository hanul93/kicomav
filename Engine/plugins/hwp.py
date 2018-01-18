# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import zlib
import kernel
import kavutil
import ole


# -------------------------------------------------------------------------
# get_hwp_recoard(val)
# 입력된 4Byte 값을 HWP 레코드 구조에 맞게 변환하여 추출한다.
# 입력값 : val - DWORD
# 리턴값 : tag_id, level, size
# -------------------------------------------------------------------------
def get_hwp_recoard(val):
    b = 0b1111111111
    c = 0b111111111111

    tag_id = (val & b)
    level = ((val >> 10) & b)
    size = (val >> 20) & c

    return tag_id, level, size


# -------------------------------------------------------------------------
# scan_hwp_recoard(buf, lenbuf)
# 주어진 버퍼를 HWP 레코드 구조로 해석한다.
# 입력값 : buf - 버퍼
#         lenbuf - 버퍼 크기
# 리턴값 : True or False (HWP 레코드 추적 성공 여부) 및 문제의 tagid
# -------------------------------------------------------------------------
def scan_hwp_recoard(buf, lenbuf):
    pos = 0
    tagid = 0

    while pos < lenbuf:
        extra_size = 4
        val = kavutil.get_uint32(buf, pos)
        tagid, level, size = get_hwp_recoard(val)

        if size == 0xfff:
            extra_size = 8
            size = kavutil.get_uint32(buf, pos + 4)

        if tagid == 0x43 and size > 4000:  # PARA_TEXT
            t_buf = buf[pos:pos+size+extra_size]
            d_buf = zlib.compress(t_buf)
            if len(d_buf) / float(len(t_buf)) < 0.02:
                return False, 0x43

        pos += (size + extra_size)

    if pos == lenbuf:
        return True, -1

    return False, tagid


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
        self.handle = {}
        self.hwp_ole = re.compile('bindata/bin\d+\.ole$', re.IGNORECASE)

        s = r'n\x00e\x00w\x00(\x20\x00)+A\x00c\x00t\x00i\x00v\x00e\x00X\x00O\x00b\x00j\x00e\x00c\x00t\x00'
        self.hwp_js = re.compile(s, re.IGNORECASE)
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
        info['version'] = '1.1'  # 버전
        info['title'] = 'HWP Engine'  # 엔진 설명
        info['kmd_name'] = 'hwp'  # 엔진 파일 이름
        info['make_arc_type'] = kernel.MASTER_DELETE  # 악성코드 치료는 삭제로...
        info['sig_num'] = len(self.listvirus())  # 진단/치료 가능한 악성코드 수

        return info

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = list()  # 리스트형 변수 선언

        vlist.append('Exploit.HWP.Generic')  # 진단/치료하는 악성코드 이름 등록
        vlist.append('Exploit.JS.Agent.gen')  # 진단/치료하는 악성코드 이름 등록

        vlist.sort()

        return vlist

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
        mm = filehandle

        if filename_ex.lower().find('bodytext/section') >= 0 or filename_ex.lower().find('docinfo') >= 0:
            val = kavutil.get_uint32(mm, 0)
            tagid, level, size = get_hwp_recoard(val)

            # 문서의 첫번째 tag가 문서 헤더(0x42), 문서 속성(0x10) 일때만 추적 진행
            if tagid == 0x42 or tagid == 0x10:
                ret, tagid = scan_hwp_recoard(mm, len(mm))
                if ret is False:  # 레코드 추적 실패
                    return True, 'Exploit.HWP.Generic.%02X' % tagid, 0, kernel.INFECTED
        elif filename_ex.lower().find('scripts/defaultjscript') >= 0:
            if self.hwp_js.search(mm):
                return True, 'Exploit.JS.Agent.gen', 0, kernel.INFECTED

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
