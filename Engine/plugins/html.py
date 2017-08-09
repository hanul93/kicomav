# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import re
import os
import kavutil


HTML_KEY_COUNT = 3  # 3개 이상 HTML Keyword가 존재하는가?

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
        # pat = r'<\s*html\b|\bdoctype\b|<\s*head\b|<\s*title\b|<\s*meta\b|\bhref\b|<\s*link\b|<\s*body\b|<\s*script\b|<\s*iframe\b|<\?(php\b)?'
        pat = r'<\s*html\b|\bdoctype\b|<\s*head\b|<\s*title\b|<\s*meta\b|\bhref\b|<\s*link\b|<\s*body\b|<\s*script\b|<\s*iframe\b'
        self.p_html = re.compile(pat, re.IGNORECASE)

        # script, iframe, php 키워드
        pat = r'<script.*?>[\d\D]*?</script>|<iframe.*?>[\d\D]*?</iframe>|<\?(php\b)?[\d\D]*?\?>'
        self.p_script = re.compile(pat, re.IGNORECASE)

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
        info['title'] = 'HTML Engine'  # 엔진 설명
        info['kmd_name'] = 'html'  # 엔진 파일 이름

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
        fileformat = {}  # 포맷 정보를 담을 공간

        if filename_ex:
            try:
                if filename_ex.split('/')[-2] == 'HTML':
                    return None
            except IndexError:
                pass

        mm = filehandle

        buf = mm[:4096]
        if kavutil.is_textfile(buf):  # Text 파일인가?
            # HTML 문서
            ret = self.p_html.findall(buf)
            if len(set(ret)) >= HTML_KEY_COUNT:
                fileformat['keyword'] = list(set(ret))  # 존재하는 HTML Keyword 보관
                ret = {'ff_html': fileformat}

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

        # 미리 분석된 파일 포맷중에 HTML 포맷이 있는가?
        if 'ff_html' in fileformat:
            buf = ''

            try:
                with open(filename, 'rb') as fp:
                    buf = fp.read()
            except IOError:
                return []

            s_count = 1  # Script 개수
            i_count = 1  # iframe 개수
            p_count = 1  # PHP 개수

            for obj in self.p_script.finditer(buf):
                t = obj.group()
                p = t.lower()

                if p.find('<script') != -1:
                    file_scan_list.append(['arc_html', 'HTML/Script #%d' % s_count])
                    s_count += 1
                elif p.find('<iframe') != -1:
                    file_scan_list.append(['arc_html', 'HTML/IFrame #%d' % i_count])
                    i_count += 1
                elif p.find('<?') != -1:
                    file_scan_list.append(['arc_html', 'HTML/PHP #%d' % p_count])
                    p_count += 1

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_html':
            buf = ''

            try:
                with open(arc_name, 'rb') as fp:
                    buf = fp.read()
            except IOError:
                return None

            s_count = 1  # Script 개수
            i_count = 1  # iframe 개수
            p_count = 1  # PHP 개수

            for obj in self.p_script.finditer(buf):
                t = obj.group()
                pos = obj.span()
                p = t.lower()

                if p.find('<script') != -1:
                    k = 'HTML/Script #%d' % s_count
                    s_count += 1
                elif p.find('<iframe') != -1:
                    k = 'HTML/IFrame #%d' % i_count
                    i_count += 1
                elif p.find('<?') != -1:
                    k = 'HTML/PHP #%d' % p_count
                    p_count += 1
                else:
                    k = ''

                if k == fname_in_arc:
                    data = buf[pos[0]:pos[1]]
                    return data

        return None

    # ---------------------------------------------------------------------
    # mkarc(self, arc_engine_id, arc_name, file_infos)
    # 입력값 : arc_engine_id - 압축 가능 엔진 ID
    #         arc_name      - 최종적으로 압축될 압축 파일 이름
    #         file_infos    - 압축 대상 파일 정보 구조체
    # 리턴값 : 압축 성공 여부 (True or False)
    # ---------------------------------------------------------------------
    def mkarc(self, arc_engine_id, arc_name, file_infos):
        if arc_engine_id == 'arc_html':
            # HTML 파일은 이미 기존 파일에서 각 스크립트의 위치 정보를 알아내야 한다.
            all_script_info = []
            buf = ''

            try:
                with open(arc_name, 'rb') as fp:
                    buf = fp.read()
            except IOError:
                return False

            for obj in self.p_script.finditer(buf):
                t = obj.group()
                pos = obj.span()
                p = t.lower()

                if p.find('<script') != -1:
                    all_script_info.append(['script', pos, t])
                elif p.find('<iframe') != -1:
                    all_script_info.append(['iframe', pos, t])
                elif p.find('<?') != -1:
                    all_script_info.append(['php', pos, t])
                else:
                    continue

            org_buf = buf

            # 순차적으로 수정된 파일 내용을 교체한다.
            for idx, file_info in enumerate(file_infos):
                rname = file_info.get_filename()
                try:
                    if os.path.exists(rname):  # 치료된 파일이 존재하나?
                        with open(rname, 'rb') as fp:
                            buf = fp.read()

                            if len(all_script_info[idx][2]) < len(buf):
                                return False

                            buf += ' ' * (len(all_script_info[idx][2]) - len(buf))
                            all_script_info[idx][2] = buf
                    else:  # 삭제된 파일이면 공백으로 처리
                        buf = ' ' * len(all_script_info[idx][2])
                        all_script_info[idx][2] = buf
                except IOError:
                    pass

            # 모든 내용 합치기
            fp = open(arc_name, 'wb')
            start_pos = 0
            for script_info in all_script_info:
                pos = script_info[1]
                buf = org_buf[start_pos:pos[0]]
                fp.write(buf)
                fp.write(script_info[2])
                start_pos = pos[1]
            else:
                fp.write(org_buf[start_pos:])

            fp.close()
            # print '[-] close()\n'
            return True

        return False
