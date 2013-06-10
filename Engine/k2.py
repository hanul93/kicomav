# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)
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
import kavcore
from optparse import OptionParser
import traceback

KAV_VERSION   = '0.21'
KAV_BUILDDATE = 'June 11 2013'
KAV_LASTYEAR  = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]

#---------------------------------------------------------------------
# 콘솔에 색깔 출력을 위한 클래스 및 함수들
#---------------------------------------------------------------------
if os.name == 'nt' :
    from ctypes import windll, Structure, c_short, c_ushort, byref

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

    # wincon.h
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

    stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
    SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
    GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo

    def get_text_attr():
        csbi = CONSOLE_SCREEN_BUFFER_INFO()
        GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
        return csbi.wAttributes

    def set_text_attr(color):
        SetConsoleTextAttribute(stdout_handle, color)

#---------------------------------------------------------------------
# PrintLogo()
# 키콤백신의 로고를 출력한다
#---------------------------------------------------------------------
def PrintLogo() :
    logo = 'KICOM Anti-Virus II (for %s) Ver %s (%s)\nCopyright (C) 1995-%s Kei Choi. All rights reserved.' 

    print '------------------------------------------------------------'
    print logo % (sys.platform.upper(), KAV_VERSION, KAV_BUILDDATE, KAV_LASTYEAR)
    print '------------------------------------------------------------'
    print

#---------------------------------------------------------------------
# PrintUsage()
# 키콤백신의 사용법을 출력한다
#---------------------------------------------------------------------
def PrintUsage() :
    print 'Usage: k2.py path[s] [options]'

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
        # parser.print_help()
        PrintUsage()
        PrintOptions()
        return None
    else :
        try :
            (options, args) = parser.parse_args()
        except :
            print
            PrintOptions()
            return None

        return options                

def print_result(result) :
    print
    print

    if os.name == 'nt' :
        default_colors = get_text_attr()
        default_bg = default_colors & 0x0070
        set_text_attr(FOREGROUND_GREY | default_bg | FOREGROUND_INTENSITY)

    print 'Results:'
    print 'Folders           :%d' % result['Folders']            
    print 'Files             :%d' % result['Files']              
    print 'Packed            :%d' % result['Packed']             
    print 'Infected files    :%d' % result['Infected_files']     
    print 'Suspect files     :%d' % result['Suspect_files']      
    print 'Warnings          :%d' % result['Warnings']           
    print 'Identified viruses:%d' % result['Identified_viruses'] 
    print 'I/O errors        :%d' % result['IO_errors']          

    if os.name == 'nt' :
        set_text_attr(default_colors)
    
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

    if os.name == 'nt' :
        default_colors = get_text_attr()
        default_bg = default_colors & 0x0070
        set_text_attr(FOREGROUND_GREY | default_bg)

    print fname,

    if os.name == 'nt' :
        set_text_attr(message_color | default_bg)

    print message

    if os.name == 'nt' :
        set_text_attr(default_colors)


#---------------------------------------------------------------------
# scan 콜백 함수
#---------------------------------------------------------------------
def scan_callback(ret_value) :
    real_name = ret_value['real_filename']
    scan_info = ret_value['scan_info']

    if len(scan_info['deep_filename']) != 0 :
        disp_name = '%s (%s)' % (scan_info['display_filename'], scan_info['deep_filename'])
    else :
        disp_name = '%s' % (scan_info['display_filename'])

    message_color = None

    if ret_value['result'] == True :
        vname = ret_value['virus_name']
        message = 'infected : %s' % vname
        if os.name == 'nt' :
            message_color = FOREGROUND_RED | FOREGROUND_INTENSITY
    else :
        message = 'ok'
        if os.name == 'nt' :
            message_color = FOREGROUND_GREY | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color = message_color)

def scan_callback1(ret_value) :
    real_name = ret_value['real_filename']
    disp_name = ret_value['display_filename']

    message_color = None

    if ret_value['result'] == True :
        vname = ret_value['virus_name']
        message = 'infected : %s' % vname
        if os.name == 'nt' :
            message_color = FOREGROUND_RED | FOREGROUND_INTENSITY
    else :
        message = 'ok'
        if os.name == 'nt' :
            message_color = FOREGROUND_GREY | FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color = message_color)

#---------------------------------------------------------------------
# MAIN
#---------------------------------------------------------------------
def main() :
    try :
        # 로고 출력
        PrintLogo()

        # 옵션 분석
        options = ParserOptions()
        if options == None :
            return 0

        # Help 옵션 셋팅?
        if options.opt_help == True :
            PrintUsage()
            PrintOptions()
            return 0

        # 키콤백신 엔진 구동
        kav = kavcore.Engine() # 엔진 클래스
        kav.SetPlugings('plugins') # 플러그인 폴더 설정

        # 엔진 인스턴스 생성1
        kav1 = kav.CreateInstance()
        if kav1 == None :
            print 'Error : KICOM Anti-Virus Engine CreateInstance'
            return 0

        # 엔진 초기화
        if kav1.init() == False :
            print 'Error : KICOM Anti-Virus Engine Init'
            raise SystemError

        # 옵션을 설정한다
        if kav1.set_options(options) == False :
            print 'Error : KICOM Anti-Virus Engine Options'
            raise SystemError

        # 로딩된 엔진 출력
        s = kav1.getinfo()
        for i in s :
            print 'Loaded Engine : %s' % i['title']
        print

        kav1.set_result()

        # 검사용 Path
        scan_path = sys.argv[1]
        scan_path = os.path.abspath(scan_path)

        kav1.scan(scan_path, scan_callback)

        # 결과 출력
        ret = kav1.get_result()
        print_result(ret)
        
        kav1.uninit()
    except :
        print traceback.format_exc()
        if kav1 != None :
            kav1.uninit()
        pass

    

if __name__ == '__main__' :
    main()