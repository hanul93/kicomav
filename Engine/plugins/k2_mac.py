# -*- coding: utf-8 -*-

"""
Copyright (C) 2013 Nurilab.

Author: Kei Choi(hanul93@gmail.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
"""

import os
import sys
from optparse import OptionParser

s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(sys.argv[0])
    )
) + os.sep + 'kavcore'

sys.path.append(s)

import k2engine

# ---------------------------------------------------------------------
# 주요 상수
# ---------------------------------------------------------------------
KAV_VERSION = '0.27'
KAV_BUILDDATE = 'Oct 30 2017'
KAV_LASTYEAR = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]

# ---------------------------------------------------------------------
# 콘솔에 색깔 출력을 위한 클래스 및 함수들
# ---------------------------------------------------------------------
FOREGROUND_BLACK = '\033[40m'
FOREGROUND_RED = '\033[41m'
FOREGROUND_GREEN = '\033[42m'
FOREGROUND_YELLOW = '\033[43m'
FOREGROUND_BLUE = '\033[44m'
FOREGROUND_MAGENTA = '\033[45m'
FOREGROUND_CYAN = '\033[46m'
FOREGROUND_WHITE = '\033[47m'
FOREGROUND_RESET = '\033[49m'


BACKGROUND_BLACK = '\033[30m'
BACKGROUND_RED = '\033[31m'
BACKGROUND_GREEN = '\033[32m'
BACKGROUND_YELLOW = '\033[33m'
BACKGROUND_BLUE = '\033[34m'
BACKGROUND_MAGENTA = '\033[35m'
BACKGROUND_CYAN = '\033[36m'
BACKGROUND_WHITE = '\033[37m'
BACKGROUND_RESET = '\033[39m'


BRIGHT = '\033[1m'
DIM = '\033[2m'
NORMAL = '\033[22m'

RESET_ALL = '\033[0m'


def cprint(msg, foreground=FOREGROUND_WHITE, background=BACKGROUND_BLACK, bright=NORMAL):
    sys.stdout.write('{}{}{}{}{}'.format(bright, foreground, background, msg, RESET_ALL))


def print_error(msg):
    cprint('Error: ' + msg, FOREGROUND_RED, BACKGROUND_MAGENTA)


# ---------------------------------------------------------------------
# print_k2logo()
# 백신 로고를 출력한다
# ---------------------------------------------------------------------
def print_k2logo():
    logo = '''KICOM Anti_virus II (for %s) er %s (%s)
Copyright (C) 1995-%s Kei Choi. All rights reserved.
'''

    print '---------------------------------------------------------------------'
    s = logo % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE, KAV_LASTYEAR)
    cprint(s, '', BACKGROUND_BLACK, BRIGHT)
    print '---------------------------------------------------------------------'


# ---------------------------------------------------------------------
# 파이썬의 옵션 파서를 새롭게 정의한다.
# 에러문을 세세하게 조정할 수 있다.
# ---------------------------------------------------------------------
class OptionParsingError(RuntimeError):
    def __init__(self, msg):
        self.msg = msg


class OptionParsingExit(Exception):
    def __init__(self, status, msg):
        self.msg = msg
        self.status = status


class ModifiedOptionParser(OptionParser):
    def error(self, msg):
        raise OptionParsingError(msg)

    def exit(self, status=0, msg=None):
        raise OptionParsingExit(status, msg)


# ---------------------------------------------------------------------
# define_options()
# 백신의 옵션을 정의한다
# ---------------------------------------------------------------------
def define_options():   # 옵션을 정의한다
    usage = "Usage: %prog path[s] [options]"
    parser = ModifiedOptionParser(add_help_option=False, usage=usage)

    parser.add_option("-f", "--files",
                      action="store_true", dest="opt_files",
                      default=True)

    parser.add_option("-I", "--list",
                      action="store_true", dest="opt_list",
                      default=False)

    parser.add_option("-V", "--vlist",
                      action="store_true", dest="opt_vlist",
                      default=False)

    parser.add_option("-?", "--help",
                      action="store_true", dest="opt_help",
                      default=False)

    return parser


# ---------------------------------------------------------------------
# parser_options()
# 백신의 옵션을 분석한다
# ---------------------------------------------------------------------
def parser_options():
    parser = define_options()   # 백신 옵션 정의

    if len(sys.argv) < 2:
        return 'NONE_OPTION', None
    else:
        try:

            (options, args) = parser.parse_args()   # 커맨드라인에서 입력된 옵션 분석

            if len(args) == 0:
                return options, None

        except OptionParsingError, e:    # 잘못된 옵션 사용일 경우
            return 'ILLEGAL_OPTION', e.msg  # 백신 프로그램 자체에서 일관된 형태로 처리

        except OptionParsingExit, e:
            return 'ILLEGAL_OPTION', e.msg

        return options, args


# ---------------------------------------------------------------------
# print_usage()
# 백신의 사용법을 출력한다
# ---------------------------------------------------------------------
def print_usage():
    print '\nUsage: k2_windows.py path[s] [options]'


# ---------------------------------------------------------------------
# print_options()
# 백신의 옵션을 출력한다
# ---------------------------------------------------------------------
def print_options():
    options_string = \
        '''Options:
                -f, --files                 scan files *
                -I, --list                  display all files
                -V, --vlist                 display virus list
                -?, --help                  * = default option'''

    print options_string


# ---------------------------------------------------------------------
# listvirus의 콜백 함수
# ---------------------------------------------------------------------
def listvirus_callback(plugin_name, vnames):
    for vname in vnames:
        print '%-50s [%s.kmd]' % (vname, plugin_name)


# ---------------------------------------------------------------------
# 악성코드 결과를 한줄에 출력하기 위한 함수
# ---------------------------------------------------------------------
def convert_display_filename(real_filename):
    # 출력용 이름
    fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
    display_filename = unicode(real_filename, fsencoding).encode(sys.stdout.encoding, 'replace')
    return display_filename


def display_line(filename, message, message_color):
    filename += ' '
    filename = convert_display_filename(filename)
    len_fname = len(filename)
    len_msg = len(message)

    if len_fname + 1 + len_msg < 79:
        fname = '%s' % filename
    else:
        able_size = 79 - len_msg
        able_size -= 5  # ...
        min_size = able_size / 2
        if able_size % 2 == 0:
            fname1 = filename[:min_size-1]
        else:
            fname1 = filename[:min_size]
        fname2 = filename[len_fname - min_size:]

        fname = '%s ... %s' % (fname1, fname2)

    cprint(fname + ' ', '', BACKGROUND_WHITE, BRIGHT)
    cprint(message + '\n', '', message_color, BRIGHT)


# ---------------------------------------------------------------------
# scan의 콜백 함수
# ---------------------------------------------------------------------
def scan_callback(ret_value):
    real_name = ret_value['filename']

    disp_name = '%s' % real_name

    if ret_value['result']:
        state = 'infected'

        vname = ret_value['virus_name']
        message = '%s : %s' % (state, vname)
        message_color = BACKGROUND_RED
    else:
        message = 'ok'
        message_color = BACKGROUND_WHITE

    display_line(disp_name, message, message_color)


# ---------------------------------------------------------------------
# print_result(result)
# 악성코드 검사 결과를 출력한다.
# 입력값 : result - 악성코드 검사 결과
# ---------------------------------------------------------------------
def print_result(result):
    print
    print

    cprint('Results:\n', '', BACKGROUND_WHITE, BRIGHT)
    cprint('Folders           : %d\n' % result['Folders'], '', BACKGROUND_WHITE, BRIGHT)
    cprint('Files             : %d\n' % result['Files'], '', BACKGROUND_WHITE, BRIGHT)
    cprint('Infected_files    : %d\n' % result['Infected_files'], '', BACKGROUND_WHITE, BRIGHT)
    cprint('Identified Viruses: %d\n' % result['Identified_viruses'], '', BACKGROUND_WHITE, BRIGHT)
    cprint('I/O errors        : %d\n' % result['IO_errors'], '', BACKGROUND_WHITE, BRIGHT)



# ---------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------
def main():
    # 옵션 분석
    options, args = parser_options()    # 커맨드라인의 옵션 분석

    # 로고 출력
    print_k2logo()

    # 잘못된 옵션인가?
    if options == 'NONE_OPTION':  # 옵션이 없는 경우
        print_usage()  # 옵션 사용방법
        print_options()  # 옵션 목록
        return 0
    elif options == 'ILLEGAL_OPTION':  # 정의되지 않은 옵션을 사용한 경우
        print_usage()
        print 'Error: %s' % args  # 에러 메시지가 담겨 있음
        return 0

    # Help 옵션을 사용한 경우
    if options.opt_help:
        print_usage()
        print_options()
        return 0

    # 백신 엔진 구동
    k2 = k2engine.Engine()  # 엔진 클래스
    if not k2.set_plugins('plugins'):  # 플러그인 엔진 설정
        print
        print_error('KICOM Anti-Virus Engine set_plugins')
        return 0

    kav = k2.create_instance()  # 백신 엔진 인스턴스 생성
    if not kav:
        print
        print_error('KICOM Anti-Virus Engine create-instance')
        return 0

    if not kav.init():  # 전체 플러그인 엔진 초기화
        print
        print_error('KICOM Anti-Virus Engine init')
        return 0

    # 엔진 버전을 출력
    c = kav.get_version()   # 플러그인 엔진의 최신 빌드 버전을 얻는다
    msg = '\rLast updated %s UTC\n\n' % c.ctime()
    cprint(msg, '', BACKGROUND_WHITE, BRIGHT)

    # 진단/치료 가능한 악성코드 수 출력
    msg = 'Signature number: %d\n\n' % kav.get_signum()
    cprint(msg, '', BACKGROUND_WHITE, BRIGHT)

    kav.set_options(options)    # 옵션을 설정

    if options.opt_vlist is True:   # 악성코드 리스트 출력 ?
        kav.listvirus(listvirus_callback)
    else:
        if args:
            kav.set_result()    # 악성코드 검사 결과를 초기화
            # 검사용 Path(다중 경로 지원)
            for scan_path in args:  # 옵션을 제외한 첫번째가 검사 대상
                scan_path = os.path.abspath(scan_path)  # '.', '..' 붙은 경로를 절대경로로 변경

                if os.path.exists(scan_path):   # 폴더 혹은 파일이 존재하는가 ?
                    kav.scan(scan_path, scan_callback)  # scan 함수를 콜백 함수와 연결해서 호출
                else:
                    print_error('Invalid path: \'%s\'' % scan_path)

            # 악성코드 검사 결과 출력
            ret = kav.get_result()
            print_result(ret)

    kav.uninit()    # 전체 플러그인 엔진의 인스턴스를 종



class KavMain:

    # -------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인자값 : plugins_path - 플러그인 엔진의 위치
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # -------------------------------------------------------------------
    def init(self, plugins_path):  # 플러그인 엔진을 초기화 한다.
        return 0  # 플러그인 엔진 종료 성공

    # -------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # -------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진을 종료한다.
        return 0  # 플러그인 엔진 종료 성공

    # -------------------------------------------------------------------
    # getinfo(self, plugins_path)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # -------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'chanlee'  # 제작자
        info['version'] = '1.0'       # 버전
        info['title'] = 'console mac version'  # 엔진 설명
        info['kmd_name'] = 'k2 mac'  # 엔진 파일 이름

        return info  # 플러그인 엔진 주요 정보 리턴