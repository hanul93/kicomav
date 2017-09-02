﻿# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


# -------------------------------------------------------------------------
# PyInstaller를 위한 임포트 모듈
# -------------------------------------------------------------------------
import cgi
import HTMLParser
import csv
import xml.etree.cElementTree as ET
import json
import email
import yara

# -------------------------------------------------------------------------
# 실제 임포트 모듈
# -------------------------------------------------------------------------
import os
import sys
import types
import hashlib
import urllib
import time
import struct
import datetime
from optparse import OptionParser
import kavcore.k2engine
import kavcore.k2const

try:
    import pylzma
except ImportError:
    pass

if os.name == 'nt':
    from ctypes import wintypes

# -------------------------------------------------------------------------
# 주요 상수
# -------------------------------------------------------------------------
KAV_VERSION = '0.27b'
KAV_BUILDDATE = 'May 22 2017'
KAV_LASTYEAR = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]

g_options = None  # 옵션
g_delta_time = None  # 검사 시간


# -------------------------------------------------------------------------
# 콘솔에 색깔 출력을 위한 클래스 및 함수들
# -------------------------------------------------------------------------
FOREGROUND_BLACK = 0x0000
FOREGROUND_BLUE = 0x0001
FOREGROUND_GREEN = 0x0002
FOREGROUND_CYAN = 0x0003
FOREGROUND_RED = 0x0004
FOREGROUND_MAGENTA = 0x0005
FOREGROUND_YELLOW = 0x0006
FOREGROUND_GREY = 0x0007
FOREGROUND_INTENSITY = 0x0008  # foreground color is intensified.

BACKGROUND_BLACK = 0x0000
BACKGROUND_BLUE = 0x0010
BACKGROUND_GREEN = 0x0020
BACKGROUND_CYAN = 0x0030
BACKGROUND_RED = 0x0040
BACKGROUND_MAGENTA = 0x0050
BACKGROUND_YELLOW = 0x0060
BACKGROUND_GREY = 0x0070
BACKGROUND_INTENSITY = 0x0080  # background color is intensified.

NOCOLOR = False  # 색깔 옵션값


if os.name == 'nt':
    from ctypes import windll, Structure, c_short, c_ushort, byref

    SHORT = c_short
    WORD = c_ushort


    class Coord(Structure):
      _fields_ = [
        ("X", SHORT),
        ("Y", SHORT)]


    class SmallRect(Structure):
        _fields_ = [
            ("Left", SHORT),
            ("Top", SHORT),
            ("Right", SHORT),
            ("Bottom", SHORT)]


    class ConsoleScreenBufferInfo(Structure):
        _fields_ = [
            ("dwSize", Coord),
            ("dwCursorPosition", Coord),
            ("wAttributes", WORD),
            ("srWindow", SmallRect),
            ("dwMaximumWindowSize", Coord)]

    # winbase.h
    STD_INPUT_HANDLE = -10
    STD_OUTPUT_HANDLE = -11
    STD_ERROR_HANDLE = -12

    stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
    GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo


    def get_text_attr():
        csbi = ConsoleScreenBufferInfo()
        GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
        return csbi.wAttributes


    def set_text_attr(color):
        SetConsoleTextAttribute(stdout_handle, color)


    def cprint(msg, color):
        if not NOCOLOR:  # 색깔 설정
            default_colors = get_text_attr()
            default_bg = default_colors & 0x00F0

            set_text_attr(color | default_bg)
            sys.stdout.write(msg)
            set_text_attr(default_colors)
        else:  # 색깔 설정 없음
            sys.stdout.write(msg)
            sys.stdout.flush()
else:
    def cprint(msg, color):
        sys.stdout.write(msg)
        sys.stdout.flush()


def print_error(msg):
    cprint('Error: ', FOREGROUND_RED | FOREGROUND_INTENSITY)
    print (msg)


# -------------------------------------------------------------------------
# getch()
# 한개의 글자를 입력 받는다. 운영체제별 처리 방법이 다르다.
# -------------------------------------------------------------------------
def getch():
    if os.name == 'nt':
        import msvcrt

        return msvcrt.getch()
    else:
        import tty
        import termios

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return ch


# ---------------------------------------------------------------------
# CreateFolder : 파일을 생성 (path명이 존재하지 않을시 path까지 생성)
# ---------------------------------------------------------------------
def create_folder(path):
    if os.path.exists(path) is False:
        t_dir = path

        # 폴더가 존재하는 곳까지 진행
        while 1:
            if os.path.exists(t_dir) is False:
                t_dir, tmp = os.path.split(t_dir)
            else:
                break

        # print dir # 실제 존재하는 폴더

        makedir = path.replace(t_dir, '')
        mkdir_list = makedir.split(os.sep)

        for m in mkdir_list:
            if len(m) != 0:
                t_dir += (os.sep + m)
                # print dir # 폴더 생성
                os.mkdir(t_dir)

        return True
    else:
        return False


# -------------------------------------------------------------------------
# log_print(msg)
# 주어진 메시지를 로그 파일에 출력한다.
# -------------------------------------------------------------------------
def log_print(msg, file_mode='at'):
    global g_options

    if g_options != 'NONE_OPTION':
        log_mode = False
        log_fname = 'k2.log'  # 기본 로그 파일 이름

        if g_options.log_filename:
            log_fname = g_options.log_filename
            log_mode = True

        if g_options.opt_log:
            log_mode = True

        if log_mode:
            with open(log_fname, file_mode) as fp:
                fp.write(msg)


# -------------------------------------------------------------------------
# print_k2logo()
# 백신 로고를 출력한다
# -------------------------------------------------------------------------
def print_k2logo():
    logo = '''KICOM Anti-Virus II (for %s) Ver %s (%s)
Copyright (C) 1995-%s Kei Choi. All rights reserved.
'''

    print '------------------------------------------------------------'
    s = logo % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE, KAV_LASTYEAR)
    cprint(s, FOREGROUND_CYAN | FOREGROUND_INTENSITY)
    print '------------------------------------------------------------'


# -------------------------------------------------------------------------
# 파이썬의 옵션 파서를 새롭게 정의한다.
# 에러문을 세세하게 조정할 수 있다.
# -------------------------------------------------------------------------
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


# -------------------------------------------------------------------------
# define_options()
# 백신의 옵션을 정의한다
# -------------------------------------------------------------------------
def define_options():
    usage = "Usage: %prog path[s] [options]"
    parser = ModifiedOptionParser(add_help_option=False, usage=usage)

    parser.add_option("-f", "--files",
                      action="store_true", dest="opt_files",
                      default=True)
    parser.add_option("-r", "--arc",
                      action="store_true", dest="opt_arc",
                      default=False)
    parser.add_option("-G",
                      action="store_true", dest="opt_log",
                      default=False)
    parser.add_option("", "--log",
                      metavar="FILE", dest="log_filename")
    parser.add_option("-I", "--list",
                      action="store_true", dest="opt_list",
                      default=False)
    parser.add_option("-e", "--app",
                      action="store_true", dest="opt_app",
                      default=False)
    parser.add_option("-F", "--infp",
                      metavar="PATH", dest="infp_path")
    parser.add_option("-R", "--nor",
                      action="store_true", dest="opt_nor",
                      default=False)
    parser.add_option("-V", "--vlist",
                      action="store_true", dest="opt_vlist",
                      default=False)
    parser.add_option("-p", "--prompt",
                      action="store_true", dest="opt_prompt",
                      default=False)
    parser.add_option("-d", "--dis",
                      action="store_true", dest="opt_dis",
                      default=False)
    parser.add_option("-l", "--del",
                      action="store_true", dest="opt_del",
                      default=False)
    parser.add_option("", "--no-color",
                      action="store_true", dest="opt_nocolor",
                      default=False)
    parser.add_option("", "--move",
                      action="store_true", dest="opt_move",
                      default=False)
    parser.add_option("", "--update",
                      action="store_true", dest="opt_update",
                      default=False)
    parser.add_option("", "--verbose",
                      action="store_true", dest="opt_verbose",
                      default=False)
    parser.add_option("", "--sigtool",
                      action="store_true", dest="opt_sigtool",
                      default=False)
    parser.add_option("", "--debug",
                      action="store_true", dest="opt_debug",
                      default=False)
    parser.add_option("-?", "--help",
                      action="store_true", dest="opt_help",
                      default=False)

    # 숨겨진 기능 (인공지능 AI을 위해 만든 옵션)

    parser.add_option("", "--feature",
                      type="int", dest="opt_feature",
                      default=0xffffffff)

    return parser


# -------------------------------------------------------------------------
# parser_options()
# 백신의 옵션을 분석한다
# -------------------------------------------------------------------------
def parser_options():
    parser = define_options()  # 백신 옵션 정의

    if len(sys.argv) < 2:
        return 'NONE_OPTION', None
    else:
        try:
            (options, args) = parser.parse_args()
            if len(args) == 0:
                return options, None
        except OptionParsingError, e:  # 잘못된 옵션 사용일 경우
            # print 'ERROR'
            return 'ILLEGAL_OPTION', e.msg
        except OptionParsingExit, e:
            return 'ILLEGAL_OPTION', e.msg

        return options, args


# -------------------------------------------------------------------------
# print_usage()
# 백신의 사용법을 출력한다
# -------------------------------------------------------------------------
def print_usage():
    print '\nUsage: k2.py path[s] [options]'


# -------------------------------------------------------------------------
# print_options()
# 백신의 옵션을 출력한다
# -------------------------------------------------------------------------
def print_options():
    options_string = '''Options:
        -f,  --files           scan files *
        -r,  --arc             scan archives
        -G,  --log=file        create log file
        -I,  --list            display all files
        -e,  --app             append to log file
        -F,  --infp=path       set infected quarantine folder
        -R,  --nor             do not recurse into folders
        -V,  --vlist           display virus list
        -p,  --prompt          prompt for action
        -d,  --dis             disinfect files
        -l,  --del             delete infected files
             --no-color        don't print with color
             --move            move infected files in quarantine folder
             --update          update
             --verbose         enabling verbose mode
             --sigtool         make files for malware signatures
        -?,  --help            this help
                               * = default option'''

    print options_string


# -------------------------------------------------------------------------
# update_kicomav()
# 키콤백신 최신 버전을 업데이트 한다
# -------------------------------------------------------------------------
def update_kicomav():
    print

    try:
        url = 'https://raw.githubusercontent.com/hanul93/kicomav-db/master/update/'  # 서버 주소를 나중에 바꿔야 한다.

        # 업데이트해야 할 파일 목록을 구한다.
        down_list = get_download_list(url)

        while len(down_list) != 0:
            filename = down_list.pop(0)
            # 파일 한개씩 업데이트 한다.
            download_file(url, filename, hook)

        # 업데이트 완료 메시지 출력
        cprint('\n[', FOREGROUND_GREY)
        cprint('Update complete', FOREGROUND_GREEN)
        cprint(']\n', FOREGROUND_GREY)

        # 업데이트 설정 파일 삭제
        os.remove('update.cfg')
    except KeyboardInterrupt:
        cprint('\n[', FOREGROUND_GREY)
        cprint('Update Stop', FOREGROUND_GREY | FOREGROUND_INTENSITY)
        cprint(']\n', FOREGROUND_GREY)


# 업데이트 진행율 표시
def hook(blocknumber, blocksize, totalsize):
    cprint('.', FOREGROUND_GREY)


# 한개의 파일을 다운로드 한다.
def download_file(url, filename, fnhook=None):
    rurl = url

    # 업데이트 설정 파일에 있는 목록을 URL 주소로 변환한다
    rurl += filename.replace('\\', '/')

    # 저장해야 할 파일의 전체 경로를 구한다
    pwd = os.path.abspath('') + os.sep + filename

    if fnhook is not None:
        cprint(filename + ' ', FOREGROUND_GREY)

    # 파일을 다운로드 한다
    urllib.urlretrieve(rurl, pwd, fnhook)

    if fnhook is not None:
        cprint(' update\n', FOREGROUND_GREEN)


# 업데이트 해야 할 파일의 목록을 구한다
def get_download_list(url):
    down_list = []

    pwd = os.path.abspath('')

    # 업데이트 설정 파일을 다운로드 한다
    download_file(url, 'update.cfg')

    fp = open('update.cfg', 'r')

    while True:
        line = fp.readline().strip()
        if not line:
            break
        t = line.split(' ')  # 업데이트 목록 한개를 구한다

        # 업데이트 설정 파일의 해시와 로컬의 해시를 비교한다
        if chek_need_update(pwd + os.sep + t[1], t[0]) == 1:
            # 다르면 업데이트 목록에 추가
            down_list.append(t[1])

    fp.close()

    return down_list


# 업데이트 설정 파일의 해시와 로컬의 해시를 비교한다
def chek_need_update(file, hash):
    try:
        # 로컬 파일의 해시를 구한다
        fp = open(file, 'rb')
        data = fp.read()
        fp.close()

        # 해시를 비교한다
        s = hashlib.sha1()
        s.update(data)
        if s.hexdigest() == hash:
            return 0  # 업데이트 대상 아님
    except IOError:
        pass

    return 1  # 업데이트 대상


# -------------------------------------------------------------------------
# listvirus의 콜백 함수
# -------------------------------------------------------------------------
def listvirus_callback(plugin_name, vnames):
    for vname in vnames:
        print '%-50s [%s.kmd]' % (vname, plugin_name)


# -------------------------------------------------------------------------
# 악성코드 결과를 한줄에 출력하기 위한 함수
# -------------------------------------------------------------------------
def get_terminal_sizex():
    default_sizex = 80

    # 출처 : https://gist.github.com/jtriley/1108174
    if os.name == 'nt':
        try:
            from ctypes import windll, create_string_buffer
            h = windll.kernel32.GetStdHandle(-12)
            csbi = create_string_buffer(22)
            res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
            if res:
                (bufx, bufy, curx, cury, wattr,
                 left, top, right, bottom,
                 maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
                sizex = right - left + 1
                # sizey = bottom - top + 1
                return sizex
        except:
            pass
    else:
        def ioctl_GWINSZ(fd):
            try:
                import fcntl
                import termios
                cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
                return cr
            except:
                pass

        cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
        if not cr:
            try:
                fd = os.open(os.ctermid(), os.O_RDONLY)
                cr = ioctl_GWINSZ(fd)
                os.close(fd)
            except:
                pass
        if not cr:
            try:
                cr = (os.environ['LINES'], os.environ['COLUMNS'])
            except:
                return default_sizex
        return int(cr[1])  # , int(cr[0])

    return default_sizex  # default


def convert_display_filename(real_filename):
    # 출력용 이름
    fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
    if isinstance(real_filename, types.UnicodeType):
        display_filename = real_filename.encode(sys.stdout.encoding, 'replace')
    else:
        display_filename = unicode(real_filename, fsencoding).encode(sys.stdout.encoding, 'replace')
    return display_filename


def display_line(filename, message, message_color):
    max_sizex = get_terminal_sizex() - 1
    filename += ' '
    filename = convert_display_filename(filename)
    len_fname = len(filename)
    len_msg = len(message)

    if len_fname + 1 + len_msg < max_sizex:
        fname = '%s' % filename
    else:
        able_size = max_sizex - len_msg
        able_size -= 5  # ...
        min_size = able_size / 2
        if able_size % 2 == 0:
            fname1 = filename[:min_size-1]
        else:
            fname1 = filename[:min_size]
        fname2 = filename[len_fname - min_size:]

        fname = '%s ... %s' % (fname1, fname2)

    cprint(fname + ' ', FOREGROUND_GREY)
    cprint(message + '\n', message_color)


# -------------------------------------------------------------------------
# scan의 콜백 함수
# -------------------------------------------------------------------------
def scan_callback(ret_value):
    global g_options

    import kernel

    fs = ret_value['file_struct']

    if len(fs.get_additional_filename()) != 0:
        disp_name = '%s (%s)' % (fs.get_master_filename(), fs.get_additional_filename())
    else:
        disp_name = '%s' % (fs.get_master_filename())

    if ret_value['result']:
        if ret_value['scan_state'] == kernel.INFECTED:
            state = 'infected'
        elif ret_value['scan_state'] == kernel.SUSPECT:
            state = 'suspect'
        elif ret_value['scan_state'] == kernel.WARNING:
            state = 'warning'
        else:
            state = 'unknown'

        vname = ret_value['virus_name']
        message = '%s : %s' % (state, vname)
        message_color = FOREGROUND_RED | FOREGROUND_INTENSITY
    else:
        if ret_value['scan_state'] == kernel.ERROR:
            message = ret_value['virus_name']
            message_color = FOREGROUND_CYAN | FOREGROUND_INTENSITY
        else:
            message = 'ok'
            message_color = FOREGROUND_GREY | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color)
    log_print('%s\t%s\n' % (disp_name, message))

    if g_options.opt_move is False and g_options.opt_prompt:  # 프롬프트 옵션이 설정되었나?
        while True and ret_value['result']:
            if ret_value['scan_state'] == kernel.INFECTED:
                msg = 'Disinfect/Delete/Ignore/Quit? (d/l/i/q) : '
            else:
                msg = 'Delete/Ignore/Quit? (l/i/q) : '

            cprint(msg, FOREGROUND_CYAN | FOREGROUND_INTENSITY)
            log_print(msg)

            ch = getch().lower()
            print ch
            log_print(ch + '\n')

            if ret_value['scan_state'] == kernel.INFECTED and ch == 'd':
                return kavcore.k2const.K2_ACTION_DISINFECT
            elif ch == 'l':
                return kavcore.k2const.K2_ACTION_DELETE
            elif ch == 'i':
                return kavcore.k2const.K2_ACTION_IGNORE
            elif ch == 'q':
                return kavcore.k2const.K2_ACTION_QUIT
    elif g_options.opt_dis:  # 치료 옵션
        return kavcore.k2const.K2_ACTION_DISINFECT
    elif g_options.opt_del:  # 삭제 옵션
        return kavcore.k2const.K2_ACTION_DELETE

    return kavcore.k2const.K2_ACTION_IGNORE


# -------------------------------------------------------------------------
# disinfect의 콜백 함수
# -------------------------------------------------------------------------
def disinfect_callback(ret_value, action_type):
    fs = ret_value['file_struct']
    message = ''

    if len(fs.get_additional_filename()) != 0:
        disp_name = '%s (%s)' % (fs.get_master_filename(), fs.get_additional_filename())
    else:
        disp_name = '%s' % (fs.get_master_filename())

    if fs.is_modify():  # 수정 성공?
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = 'disinfected'
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = 'deleted'

        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
    else:
        if action_type == kavcore.k2const.K2_ACTION_DISINFECT:
            message = 'disinfection failed'
        elif action_type == kavcore.k2const.K2_ACTION_DELETE:
            message = 'deletion failed'

        message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color)
    log_print('%s\t%s\n' % (disp_name, message))


# -------------------------------------------------------------------------
# update의 콜백 함수
# -------------------------------------------------------------------------
def update_callback(ret_file_info):
    if ret_file_info.is_modify():  # 수정되었다면 결과 출력
        disp_name = ret_file_info.get_filename()

        if os.path.exists(disp_name):
            message = 'updated'
        else:
            message = 'deleted'

        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY

        display_line(disp_name, message, message_color)
        log_print('%s\t%s\n' % (disp_name, message))

'''
def update_callback1(ret_file_info):
    global g_infp_path

    if g_options.opt_move:  # 격리 옵션이 설정되었나?
        # 마스터 파일만 격리 조치하면 됨
        if ret_file_info.is_modify():  # 격리를 위해 가짜로 수정된것 처럼 처리
            disp_name = ret_file_info.get_master_filename()
            try:
                shutil.move(disp_name, g_infp_path)
                message = 'quarantined'
                message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
            except shutil.Error:
                message = 'quarantine failed'
                message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

            display_line(disp_name, message, message_color)
            log_print('%s\t%s\n' % (disp_name, message))
    else:
        if ret_file_info.is_modify():  # 수정되었다면 결과 출력
            disp_name = ret_file_info.get_filename()

            message = 'updated'
            message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY

            display_line(disp_name, message, message_color)
            log_print('%s\t%s\n' % (disp_name, message))
'''


# -------------------------------------------------------------------------
# quarantine 콜백 함수
# -------------------------------------------------------------------------
def quarantine_callback(filename, is_success):
    disp_name = filename

    if is_success:
        message = 'quarantined'
        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
    else:
        message = 'quarantine failed'
        message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color)
    log_print('%s\t%s\n' % (disp_name, message))


# -------------------------------------------------------------------------
# print_result(result)
# 악성코드 검사 결과를 출력한다.
# 입력값 : result - 악성코드 검사 결과
# -------------------------------------------------------------------------
def print_result(result):
    global g_options
    global g_delta_time

    print
    print

    cprint('Results:\n', FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Folders           :%d\n' % result['Folders'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Files             :%d\n' % result['Files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Packed            :%d\n' % result['Packed'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Infected files    :%d\n' % result['Infected_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Suspect files     :%d\n' % result['Suspect_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Warnings          :%d\n' % result['Warnings'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Identified viruses:%d\n' % result['Identified_viruses'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    if result['Disinfected_files']:
        cprint('Disinfected files :%d\n' % result['Disinfected_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    elif result['Deleted_files']:
        cprint('Deleted files     :%d\n' % result['Deleted_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('I/O errors        :%d\n' % result['IO_errors'], FOREGROUND_GREY | FOREGROUND_INTENSITY)

    # 검사 시간 출력
    if g_delta_time.seconds > 10:  # 10초 이상 걸린 경우에만 시간 출력
        t = str(g_delta_time).split(':')
        t_h = int(float(t[0]))
        t_m = int(float(t[1]))
        t_s = int(float(t[2]))
        cprint('Scan time         :%02d:%02d:%02d\n' % (t_h, t_m, t_s), FOREGROUND_GREY | FOREGROUND_INTENSITY)

    print


# -------------------------------------------------------------------------
# main()
# -------------------------------------------------------------------------
def main():
    global NOCOLOR
    global g_options

    # 옵션 분석
    options, args = parser_options()
    g_options = options  # 글로벌 options 셋팅

    if os.name == 'nt' and not isinstance(options, types.StringType):
        if options.opt_nocolor:
            NOCOLOR = True

    # 로고 출력
    print_k2logo()

    # 잘못된 옵션인가?
    if options == 'NONE_OPTION':  # 옵션이 없는 경우
        print_usage()
        print_options()
        return 0
    elif options == 'ILLEGAL_OPTION':  # 정의되지 않은 옵션을 사용한 경우
        print_usage()
        print 'Error: %s' % args  # 에러 메시지가 담겨 있음
        return 0

    # Help 옵션을 사용한 경우 또는 인자 값이 없는 경우
    if options.opt_help or not args:
        # 인자 값이 없는 업데이트 상황?
        if options.opt_update:
            update_kicomav()
            return 0

        if not options.opt_vlist:  # 악성코드 리스트 출력이면 인자 값이 없어도 Help 안보여줌
            print_usage()
            print_options()
            return 0

    # 로그 파일 생성
    if g_options.opt_app is False:
        log_print('#\n# KicomAV scan report\n#\n', 'wt')  # 추가 모드가 아니면 새로 생성
    else:
        log_print('\n#\n# KicomAV scan report\n#\n')

    log_print('# Time: %s\n' % time.ctime())

    log_print('# Command line: ')
    for argv in sys.argv[1:]:
        log_print(argv + ' ')
    log_print('\n')

    logo = 'KICOM Anti-Virus II (for %s) Ver %s (%s)' % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE)
    log_print('# %s\n' % logo)

    # 업데이트 상황이후 백신 검사 진행
    if options.opt_update:
        update_kicomav()

    # 격리소 설정하기
    if options.infp_path:
        path = os.path.abspath(options.infp_path)
        path = os.path.normcase(path)
        create_folder(path)
        options.infp_path = path

    # 백신 엔진 구동
    k2 = kavcore.k2engine.Engine()  # 엔진 클래스

    plugins_path = os.path.split(os.path.abspath(sys.argv[0]))[0] + os.sep + 'plugins'
    if not k2.set_plugins(plugins_path):  # 플러그인 엔진 설정
        print
        print_error('KICOM Anti-Virus Engine set_plugins')
        return 0

    kav = k2.create_instance()  # 백신 엔진 인스턴스 생성
    if not kav:
        print
        print_error('KICOM Anti-Virus Engine create_instance')
        return 0

    kav.set_options(options)  # 옵션을 설정

    if not kav.init():  # 전체 플러그인 엔진 초기화
        print
        print_error('KICOM Anti-Virus Engine init')
        return 0

    # 엔진 버전을 출력
    c = kav.get_version()
    msg = '\rLast updated %s UTC\n' % c.ctime()
    cprint(msg, FOREGROUND_GREY)

    # 진단/치료 가능한 악성코드 수 출력
    num_sig = kav.get_signum()
    msg = 'Signature number: %d\n\n' % num_sig
    cprint(msg, FOREGROUND_GREY)

    log_print('# Signature number: %d\n' % num_sig)
    log_print('#\n\n')  # 로그 파일 헤더 끝...

    if options.opt_vlist is True:  # 악성코드 리스트 출력?
        kav.listvirus(listvirus_callback)
    else:
        if args:
            kav.set_result()   # 악성코드 검사 결과를 초기화

            # 검사 시작 시간 체크
            start_time = datetime.datetime.now()

            # 검사용 Path (다중 경로 지원)
            for scan_path in args:  # 옵션을 제외한 첫번째가 검사 대상
                scan_path = os.path.abspath(scan_path)

                if os.path.exists(scan_path):  # 폴더 혹은 파일가 존재하는가?
                    kav.scan(scan_path, scan_callback, disinfect_callback, update_callback, quarantine_callback)
                else:
                    print_error('Invalid path: \'%s\'' % scan_path)

            # 검사 종료 시간 체크
            end_time = datetime.datetime.now()

            global g_delta_time
            g_delta_time = end_time - start_time

            # 악성코드 검사 결과 출력
            ret = kav.get_result()
            print_result(ret)

    kav.uninit()


if __name__ == '__main__':
    main()
