# -*- coding:utf-8 -*-

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

'''
+-----------------------------------------------------------------------------+
|                                              KICOM Anti-Virus (Disinfector) |
|                                              Copyright (C) 95-2013, Hanul93 |
|                                              Version 0.20, Made by Kei Choi |
+-----------------------------------------------------------------------------+
'''
import sys
import os
import string
import kavcore.k2main as kavcore
import hashlib
import urllib
import thread
import time
from optparse import OptionParser

KAV_VERSION   = '0.26'
KAV_BUILDDATE = 'Jun 16 2016'
KAV_LASTYEAR  = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]

g_EngineInit = 0

#---------------------------------------------------------------------
# 콘솔에 색깔 출력을 위한 클래스 및 함수들
#---------------------------------------------------------------------
FOREGROUND_BLACK     = 0x0000
FOREGROUND_BLUE      = 0x0001
FOREGROUND_GREEN     = 0x0002
FOREGROUND_CYAN      = 0x0003
FOREGROUND_RED       = 0x0004
FOREGROUND_MAGENTA   = 0x0005
FOREGROUND_YELLOW    = 0x0006
FOREGROUND_GREY      = 0x0007
FOREGROUND_INTENSITY = 0x0008 # foreground color is intensified.

BACKGROUND_BLACK     = 0x0000
BACKGROUND_BLUE      = 0x0010
BACKGROUND_GREEN     = 0x0020
BACKGROUND_CYAN      = 0x0030
BACKGROUND_RED       = 0x0040
BACKGROUND_MAGENTA   = 0x0050
BACKGROUND_YELLOW    = 0x0060
BACKGROUND_GREY      = 0x0070
BACKGROUND_INTENSITY = 0x0080 # background color is intensified.

if os.name == 'nt' :
    from ctypes import windll, Structure, c_short, c_ushort, byref

    NOCOLOR = False

    SHORT = c_short
    WORD = c_ushort

    class COORD(Structure):
      """struct in wincon.h."""
      _fields_ = [
        ("X", SHORT),
        ("Y", SHORT)]

    class SMALL_RECT(Structure):
        _fields_ = [
            ("Left", SHORT),
            ("Top", SHORT),
            ("Right", SHORT),
            ("Bottom", SHORT)]

    class CONSOLE_SCREEN_BUFFER_INFO(Structure):
        _fields_ = [
            ("dwSize", COORD),
            ("dwCursorPosition", COORD),
            ("wAttributes", WORD),
            ("srWindow", SMALL_RECT),
            ("dwMaximumWindowSize", COORD)]

    # winbase.h
    STD_INPUT_HANDLE = -10
    STD_OUTPUT_HANDLE = -11
    STD_ERROR_HANDLE = -12

    stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
    GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo

    def get_text_attr():
        csbi = CONSOLE_SCREEN_BUFFER_INFO()
        GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
        return csbi.wAttributes

    def set_text_attr(color):
        SetConsoleTextAttribute(stdout_handle, color)

    def cprint(msg, color) :
        if NOCOLOR == False :
            default_colors = get_text_attr()
            default_bg = default_colors & 0x00F0

            set_text_attr(color | default_bg)
            sys.stdout.write(msg)
            set_text_attr(default_colors)
        else :
            sys.stdout.write(msg)
        sys.stdout.flush()
else :
    def cprint(msg, color) :
        sys.stdout.write(msg)
        sys.stdout.flush()

def PrintError(msg) :
    cprint('Error: ', FOREGROUND_RED | FOREGROUND_INTENSITY)
    print (msg)

#---------------------------------------------------------------------
# PrintLogo()
# 키콤백신의 로고를 출력한다
#---------------------------------------------------------------------
def PrintLogo() :
    logo = 'KICOM Anti-Virus II (for %s) Ver %s (%s)\nCopyright (C) 1995-%s Kei Choi. All rights reserved.\n'

    print '------------------------------------------------------------'
    s = logo % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE, KAV_LASTYEAR)
    cprint(s, FOREGROUND_CYAN | FOREGROUND_INTENSITY)
    print '------------------------------------------------------------'

#---------------------------------------------------------------------
# Update()
# 키콤백신 최신 버전을 업데이트 한다
#---------------------------------------------------------------------
def Update() :
    print

    try :
        url = 'https://dl.dropboxusercontent.com/u/5806441/k2/'

        # 업데이트해야 할 파일 목록을 구한다.
        down_list = GetDownloadList(url)

        while len(down_list) != 0 :
            filename = down_list.pop(0)
            # 파일 한개씩 업데이트 한다.
            Download_file(url, filename, hook)

        # 업데이트 완료 메시지 출력
        cprint('\n[', FOREGROUND_GREY)
        cprint('Update complete', FOREGROUND_GREEN)
        cprint(']\n', FOREGROUND_GREY)

        # 업데이트 설정 파일 삭제
        os.remove('update.cfg')
    except :
        cprint('\n[', FOREGROUND_GREY)
        cprint('Update Stop', FOREGROUND_GREY | FOREGROUND_INTENSITY)
        cprint(']\n', FOREGROUND_GREY)

# 업데이트 진행율 표시
def hook(blocknumber, blocksize, totalsize) :
    cprint('.', FOREGROUND_GREY)

# 한개의 파일을 다운로드 한다.
def Download_file(url, file, fnhook=None) :
    rurl = url

    # 업데이트 설정 파일에 있는 목록을 URL 주소로 변환한다
    rurl += file.replace('\\', '/')

    # 저장해야 할 파일의 전체 경로를 구한다
    pwd = os.path.abspath('') + os.sep + file

    if fnhook != None :
        cprint(file + ' ', FOREGROUND_GREY)

    # 파일을 다운로드 한다
    urllib.urlretrieve(rurl, pwd, fnhook)

    if fnhook != None :
        cprint(' update\n', FOREGROUND_GREEN)

# 업데이트 해야 할 파일의 목록을 구한다
def GetDownloadList(url) :
    down_list = []

    pwd = os.path.abspath('')

    # 업데이트 설정 파일을 다운로드 한다
    Download_file(url, 'update.cfg')

    fp = open('update.cfg', 'r')

    while 1 :
        line = fp.readline().strip()
        if not line :
            break
        t = line.split(' ') # 업데이트 목록 한개를 구한다

        # 업데이트 설정 파일의 해시와 로컬의 해시를 비교한다
        if ChekNeedUpdate(pwd + os.sep + t[1], t[0]) == 1:
            # 다르면 업데이트 목록에 추가
            down_list.append(t[1])

    fp.close()

    return down_list

# 업데이트 설정 파일의 해시와 로컬의 해시를 비교한다
def ChekNeedUpdate(file, hash) :
    try :
        # 로컬 파일의 해시를 구한다
        fp = open(file, 'rb')
        data = fp.read()
        fp.close()

        # 해시를 비교한다
        s = hashlib.sha1()
        s.update(data)
        if s.hexdigest() == hash :
            return 0 # 업데이트 대상 아님
    except :
        pass

    return 1 # 업데이트 대상

#---------------------------------------------------------------------
# PrintUsage()
# 키콤백신의 사용법을 출력한다
#---------------------------------------------------------------------
def PrintUsage() :
    print '\nUsage: k2.py path[s] [options]'

#---------------------------------------------------------------------
# PrintOptions()
# 키콤백신의 옵션을 출력한다
#---------------------------------------------------------------------
def PrintOptions() :
    options_string = \
'''Options:
        -f,  --files           scan files *
        -r,  --arc             scan archives
        -I,  --list            display all files
        -V,  --vlist           display virus list
             --update          update
             --sigtool         create a malware signature
             --no-color        not print color
        -?,  --help            this help
                               * = default option'''

    print options_string

#---------------------------------------------------------------------
# DefineOptions()
# 키콤백신의 옵션을 정의한다
#---------------------------------------------------------------------
def DefineOptions() :
    try :
        # fmt = IndentedHelpFormatter(indent_increment=8, max_help_position=40, width=77, short_first=1)
        # usage = "usage: %prog path[s] [options]"
        # parser = OptionParser(add_help_option=False, usage=usage, formatter=fmt)

        usage = "Usage: %prog path[s] [options]"
        parser = OptionParser(add_help_option=False, usage=usage)

        parser.add_option("-f", "--files",
                      action="store_true", dest="opt_files",
                      default=True)
        parser.add_option("-b", "--boot",
                      action="store_true", dest="opt_boot",
                      default=False)
        parser.add_option("-r", "--arc",
                      action="store_true", dest="opt_arc",
                      default=False)
        parser.add_option("-i", "--mail",
                      action="store_true", dest="opt_mail",
                      default=False)
        parser.add_option("-k", "--nopack",
                      action="store_true", dest="opt_nopack",
                      default=False)
        parser.add_option("-h", "--nohed",
                      action="store_true", dest="opt_nohed",
                      default=False)
        parser.add_option("-X", "--xcl=ext1;ext2",
                      action="store_true", dest="opt_xcl",
                      default=False)
        parser.add_option("-G", "--log[=file]",
                      action="store_true", dest="opt_log",
                      default=False)
        parser.add_option("-S", "--cd",
                      action="store_true", dest="opt_cd",
                      default=False)
        parser.add_option("-N", "--fixed",
                      action="store_true", dest="opt_fixed",
                      default=False)
        parser.add_option("-M", "--floppy",
                      action="store_true", dest="opt_floppy",
                      default=False)
        parser.add_option("-I", "--list",
                      action="store_true", dest="opt_list",
                      default=False)
        parser.add_option("-g", "--prog",
                      action="store_true", dest="opt_prog",
                      default=False)
        parser.add_option("-e", "--app",
                      action="store_true", dest="opt_app",
                      default=False)
        parser.add_option("-F", "--infp=path",
                      action="store_true", dest="opt_infp",
                      default=False)
        parser.add_option("-U", "--susp=path",
                      action="store_true", dest="opt_susp",
                      default=False)
        parser.add_option("-R", "--nor",
                      action="store_true", dest="opt_nor",
                      default=False)
        parser.add_option("-p", "--prompt",
                      action="store_true", dest="opt_prompt",
                      default=False)
        parser.add_option("-O", "--info",
                      action="store_true", dest="opt_info",
                      default=False)
        parser.add_option("-W", "--nowarn",
                      action="store_true", dest="opt_nowarn",
                      default=False)
        parser.add_option("-V", "--vlist",
                      action="store_true", dest="opt_vlist",
                      default=False)
        parser.add_option("-d", "--dis",
                      action="store_true", dest="opt_dis",
                      default=False)
        parser.add_option("-o", "--copy",
                      action="store_true", dest="opt_copy",
                      default=False)
        parser.add_option("-y", "--copys",
                      action="store_true", dest="opt_copys",
                      default=False)
        parser.add_option("-l", "--del",
                      action="store_true", dest="opt_del",
                      default=False)

        parser.add_option("", "--sigtool",
                      action="store_true", dest="opt_sigtool",
                      default=False)
        parser.add_option("", "--no-color",
                      action="store_true", dest="opt_nocolor",
                      default=False)
        parser.add_option("", "--noclean",
                      action="store_true", dest="opt_noclean",
                      default=False)
        parser.add_option("", "--move",
                      action="store_true", dest="opt_move",
                      default=False)
        parser.add_option("", "--moves",
                      action="store_true", dest="opt_moves",
                      default=False)
        parser.add_option("", "--ren",
                      action="store_true", dest="opt_ren",
                      default=False)
        parser.add_option("", "--infext=ext",
                      action="store_true", dest="opt_infext",
                      default=False)
        parser.add_option("", "--alev[=n]",
                      action="store_true", dest="opt_alev",
                      default=False)
        parser.add_option("", "--flev[=n]",
                      action="store_true", dest="opt_flev",
                      default=False)
        parser.add_option("", "--update",
                      action="store_true", dest="opt_update",
                      default=False)

        parser.add_option("-?", "--help",
                      action="store_true", dest="opt_help",
                      default=False)

        return parser
    except :
        pass

    return None

#---------------------------------------------------------------------
# ParserOptions()
# 키콤백신의 옵션을 분석한다
#---------------------------------------------------------------------
def ParserOptions() :
    parser = DefineOptions()

    if parser == None or len( sys.argv ) < 2 :
        return None, None
    else :
        try :
            (options, args) = parser.parse_args()
        except :
            return None, None

        return options, args

def print_result(result) :
    print
    print

    cprint ('Results:\n', FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint ('Folders           :%d\n' % result['Folders'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint ('Files             :%d\n' % result['Files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint ('Packed            :%d\n' % result['Packed'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint ('Infected files    :%d\n' % result['Infected_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint ('Suspect files     :%d\n' % result['Suspect_files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint ('Warnings          :%d\n' % result['Warnings'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint ('Identified viruses:%d\n' % result['Identified_viruses'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint ('I/O errors        :%d\n' % result['IO_errors'], FOREGROUND_GREY | FOREGROUND_INTENSITY)

    print

#---------------------------------------------------------------------
# 악성코드 결과를 한줄에 출력하기 위한 함수
#---------------------------------------------------------------------
def convert_display_filename(real_filename) :
    # 출력용 이름
    fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
    display_filename = unicode(real_filename, fsencoding).encode(sys.stdout.encoding, 'replace')
    return display_filename


def display_line(filename, message, filename_color=None, message_color=None) :
    filename += ' '
    filename = convert_display_filename(filename)
    len_fname = len(filename)
    len_msg   = len(message)

    if len_fname + 1 + len_msg < 79 :
        fname = '%s' % filename
        msg   = '%s' % message
    else :
        able_size = 79 - len_msg
        able_size -= 5 # ...
        min_size = able_size / 2
        if able_size % 2 == 0 :
            fname1 = filename[0:min_size-1]
        else :
            fname1 = filename[0:min_size]
        fname2 = filename[len_fname - min_size:]

        fname = '%s ... %s' % (fname1, fname2)
        msg   = '%s' % message

    cprint (fname + ' ', FOREGROUND_GREY)
    cprint (message + '\n', message_color)

def listvirus_callback(ret_virus, ret_getinfo) :
    for name in ret_virus :
        print '%-50s [%s.kmd]' % (name, ret_getinfo['kmd_name'])

#---------------------------------------------------------------------
# scan 콜백 함수
#---------------------------------------------------------------------
def scan_callback(ret_value) :
    real_name = ret_value['real_filename']
    scan_info = ret_value['scan_info']

    if len(scan_info.GetDeepFilename()) != 0 :
        disp_name = '%s (%s)' % (scan_info.GetMasterFilename(), scan_info.GetDeepFilename())
    else :
        disp_name = '%s' % (scan_info.GetMasterFilename())

    message_color = None

    import kernel
    if ret_value['result'] == True :
        if ret_value['scan_state'] == kernel.INFECTED :
            s = 'infected'
        elif ret_value['scan_state'] == kernel.SUSPECT :
            s = 'Suspect'
        elif ret_value['scan_state'] == kernel.WARNING :
            s = 'Warning'
        else :
            s = 'Unknown'

        vname = ret_value['virus_name']
        message = '%s : %s' % (s, vname)
        message_color = FOREGROUND_RED | FOREGROUND_INTENSITY
    else :
        message = 'ok'
        message_color = FOREGROUND_GREY | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color = message_color)


def Start_Thread() :
    global g_EngineInit
    g_EngineInit = 0

def End_Thread() :
    global g_EngineInit

    g_EngineInit = 1
    time.sleep(0.1)

def PringLoding(id, msg) :
    global g_EngineInit

    progress = ['\\', '|', '/', '-']

    i = 0
    cprint(msg, FOREGROUND_GREY)

    while g_EngineInit == 0 :
        cprint(progress[i] + '\b', FOREGROUND_GREY)
        i += 1
        i %= 4
        time.sleep(0.1)
    cprint('\r', FOREGROUND_GREY)

#---------------------------------------------------------------------
# MAIN
#---------------------------------------------------------------------
def main() :
    global NOCOLOR
    global SIGTOOL
    global g_EngineInit

    kav1 = None

    try :
        # 옵션 분석
        options, args = ParserOptions()

        # 출력 색깔 없애기
        if options != None :
            if os.name == 'nt' and options.opt_nocolor == True :
                NOCOLOR = True

        # 로고 출력
        PrintLogo()

        # 잘못된 옵션?
        if options == None :
            PrintUsage()
            PrintOptions()
            return 0

        # Help 옵션 셋팅?
        if options.opt_help == True :
            PrintUsage()
            PrintOptions()
            return 0

        # 업데이트?
        if options.opt_update == True :
            Update()
            return 0

        # 키콤백신 엔진 구동
        kav = kavcore.Engine() # 엔진 클래스
        kav.SetPlugins('plugins') # 플러그인 폴더 설정

        # 엔진 인스턴스 생성1
        kav1 = kav.CreateInstance()
        if kav1 == None :
            print
            PrintError('KICOM Anti-Virus Engine CreateInstance')
            # print 'Error : KICOM Anti-Virus Engine CreateInstance'
            return 0

        # 쓰레드 생성
        Start_Thread()
        thread.start_new_thread(PringLoding, (0, 'Loading Engine... '))

        # 엔진 초기화
        if kav1.init() == False :
            print
            PrintError('KICOM Anti-Virus Engine Init')
            # print 'Error : KICOM Anti-Virus Engine Init'
            raise SystemError

        End_Thread()

        # 엔진 버전을 출력
        c = kav1.getversion()
        msg = '\rLast updated %s UTC\n' % c.ctime()
        cprint(msg, FOREGROUND_GREY)

        # 로딩된 시그너쳐 개수 출력
        msg = 'Signature number: %d' % kav1.getsignum()
        print msg
        print

        # 옵션을 설정한다
        if kav1.set_options(options) == False :
            PrintError('KICOM Anti-Virus Engine Options')
            # print 'Error : KICOM Anti-Virus Engine Options'
            raise SystemError

        '''
        # 로딩된 엔진 출력
        s = kav1.getinfo()
        for i in s :
            print 'Loaded Engine : %s' % i['title']
        print
        '''


        if options.opt_vlist == True : # 악성코드 리스트 출력?
            kav1.listvirus(listvirus_callback)
        else :                         # 악성코드 검사
            kav1.set_result()

            # 검사용 Path (다중 경로 지원)
            for scan_path in args : # 옵션을 제외한 첫번째가 검사 대상
                scan_path = os.path.abspath(scan_path)

                if os.path.exists(scan_path) : # 폴더 혹은 파일가 존재하는가?
                    if kav1.scan(scan_path, scan_callback) != 0 : # 키보드로 종료
                        raise KeyboardInterrupt
                else :
                    PrintError('Invalid path: \'%s\'' % scan_path)
                    # print 'Error: Invalid path: \'%s\'' % scan_path

            # 결과 출력
            ret = kav1.get_result()
            print_result(ret)

        kav1.uninit()
    except KeyboardInterrupt :
        cprint('\n[', FOREGROUND_GREY)
        cprint('Scan Stop', FOREGROUND_GREY | FOREGROUND_INTENSITY)
        cprint(']\n', FOREGROUND_GREY)
    #except :
    #    pass
    finally:
        #import traceback
        #print traceback.format_exc()

        if kav1 != None :
            kav1.uninit()
        pass

if __name__ == '__main__' :
    main()
