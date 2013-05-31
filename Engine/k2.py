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

KAV_VERSION   = '0.20a'
KAV_BUILDDATE = 'May 27 2013'
KAV_LASTYEAR  = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]


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
        -b,  --boot            scan boot sector and mbr
        -r,  --arc             scan archives
        -i,  --mail            scan mail databases
        -k,  --nopack          don't scan packed programs
        -h,  --nohed           no heuristics
        -X,  --xcl=ext1;ext2;  exclude from scan this extensions
        -G,  --log[=file]      create log file
        -S,  --cd              scan cd-rom
        -N,  --fixed           scan all fixed drives
        -M,  --floppy          scan floppy
        -I,  --list            display all files
        -g,  --prog            scan only program files
        -e,  --app             append to log file
        -F,  --infp=path       set infected quarantine folder
        -U,  --susp=path       set suspected quarantine folder
        -R,  --nor             do not recurse into folders
        -p,  --prompt          prompt for action
        -O,  --info            information
        -W,  --nowarn          no warnings
        -V,  --vlist           display virus list
        -d,  --dis             disinfect files
        -o,  --copy            copy infected files in quarantine folder
        -y,  --copys           copy suspect files in quarantine folder
        -l,  --del             delete infected files
             --noclean         don't display clean files
             --move            move infected files in quarantine folder
             --moves           move suspect files in quarantine folder
             --ren             rename infected files
             --infext=ext      set rename extension
             --alev[=n]        set maximum archive depth level
             --flev[=n]        set maximum folder depth level
             --update          update
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

#---------------------------------------------------------------------
# 악성코드 결과를 한줄에 출력하기 위한 함수
#---------------------------------------------------------------------
def display_line(filename, message, filename_color=None, message_color=None) :
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
        default_colors = cons.get_text_attr()
        default_bg = default_colors & 0x0070
        cons.set_text_attr(cons.FOREGROUND_GREY | default_bg)

    print fname,

    if os.name == 'nt' :
        cons.set_text_attr(message_color | default_bg)

    print message

    if os.name == 'nt' :
        cons.set_text_attr(default_colors)


#---------------------------------------------------------------------
# scan 콜백 함수
#---------------------------------------------------------------------
def scan_callback(ret_value) :
    real_name = ret_value['real_filename']
    disp_name = ret_value['display_filename']

    message_color = None

    if ret_value['result'] == True :
        vname = ret_value['virus_name']
        message = 'infected : %s' % vname
        if os.name == 'nt' :
            message_color = cons.FOREGROUND_RED | cons.FOREGROUND_INTENSITY
    else :
        message = 'ok'
        if os.name == 'nt' :
            message_color = cons.FOREGROUND_GREY | cons.FOREGROUND_INTENSITY

    display_line(disp_name, message, message_color = message_color)

#---------------------------------------------------------------------
# MAIN
#---------------------------------------------------------------------
def main() :
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
        return 0

    # 로딩된 엔진 출력
    s = kav1.getinfo()
    for i in s :
        print i['title']
    print

    # 검사용 Path
    scan_path = sys.argv[1]
    scan_path = os.path.abspath(scan_path)

    kav1.scan(scan_path, scan_callback)

    
    kav1.uninit()

if __name__ == '__main__' :
    if os.name == 'nt' :
        import color_console as cons

    main()