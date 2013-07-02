# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import zlib
import zipfile
import hashlib
import StringIO
import marshal
import imp
import sys
import os
import types
import mmap
import glob
import datetime
import time
import struct

#---------------------------------------------------------------------
# Engine 클래스
#---------------------------------------------------------------------
class Engine :
    def __init__(self) :
        self.kmd_list = []
        self.mod_list = []
        self.plugins  = None # 플러그인 폴더 위치

    # plugins 폴더에 kmd 모듈을 로딩한다.
    def SetPlugins(self, plugins) :
        ret = False

        self.plugins = plugins
        self.ckmd = KMD()

        try :
            if len(self.kmd_list) == 0 : # 우선순위 list 내용이 없다면
                # kmd 로딩 우선순위 리스트를 가진 kmd 파일에서 리스트 확보
                self.kmd_list = self.ckmd.GetList(plugins) # kicom.kmd 파일 로딩
                if len(self.kmd_list) == 0 :      # 결과 값이 없으면 종료
                    raise SystemError

            # kmd 로딩 우선순위 리스트 순으로 동적 로딩
            if len(self.mod_list) == 0 :
                self.mod_list = self.ckmd.Import(plugins, self.kmd_list)

            ret = True
        except :
            pass

        return ret

    def CreateInstance(self) :
        try :
            sys.modules['kernel'] # kernel.kmd는 무조건 있어야 함
            ei = EngineInstance(self.plugins)
            ret = ei.SetModuleList(self.ckmd, self.mod_list)

            if ret == 0 :
                return ei
        except :
            pass

        return None

#---------------------------------------------------------------------
# EngineInstance 클래스
#---------------------------------------------------------------------
class EngineInstance :
    def __init__(self, plugins) :
        self.modules        = []
        self.KMD_AntiVirus  = []
        self.KMD_Decompress = []
        self.KMD_FileFormat = []
        self.plugins        = plugins
        self.last_update    = None

    def SetModuleList(self, ckmd, mod_list) :
        try :
            for m in mod_list :
                # 동적 로딩 되었으면 모듈 관리 리스트에 추가
                mod = ckmd.ExecKavMain(m)
                if mod != None :
                    self.modules.append(mod)

            # 로딩된 모듈이 하나도 없으면 종료
            if len(self.modules) == 0 :
                raise SystemError

            # 엔진 최신 빌드 날짜와 시간을 알아옴
            self.last_update = ckmd.GetLastUpdate() 
        except :
            return 1

        return 0

    #-----------------------------------------------------------------
    # init(self)
    # 키콤백신 엔진을 초기화 한다.
    # 리턴값 : 성공 여부 (True, False)
    #-----------------------------------------------------------------
    def init(self) :
        try :
            # 모든 백신 엔진 모듈의 init 멤버 함수 호출
            for mod in self.modules :
                if dir(mod).count('init') != 0 : # API 존재
                    ret_init = mod.init(self.plugins) # 호출
                    if ret_init != 0 :
                        raise SystemError
        except :
            return False

        self.options = {}
        self.set_options() # 옵션 초기화

        self.set_result() # 결과 초기화
        return True

    #-----------------------------------------------------------------
    # uninit(self)
    # 키콤백신 엔진을 종료화 한다.
    #-----------------------------------------------------------------
    def uninit(self) :
        # 백신 엔진 모듈의 uninit 멤버 함수 호출
        for mod in self.modules :
            if dir(mod).count('uninit') != 0 : # API 존재
                ret_uninit = mod.uninit()

    #-----------------------------------------------------------------
    # set_result(self)
    # 키콤백신 엔진의 검사 결과를 초기화 한다.
    #-----------------------------------------------------------------
    def set_result(self) :
        self.result = {}
        self.identified_virus = [] # 유니크한 악성코드 개수를 구하기 위해 사용

        self.result['Folders']            = 0
        self.result['Files']              = 0
        self.result['Packed']             = 0
        self.result['Infected_files']     = 0
        self.result['Suspect_files']      = 0
        self.result['Warnings']           = 0
        self.result['Identified_viruses'] = 0
        self.result['IO_errors']          = 0

        return True

    #-----------------------------------------------------------------
    # get_result(self)
    # 키콤백신 엔진의 검사 결과를 얻는다.
    #-----------------------------------------------------------------
    def get_result(self) :
        return self.result

    #-----------------------------------------------------------------
    # set_options(self, options)
    # 키콤백신 엔진의 옵션을 설정한다.
    #-----------------------------------------------------------------
    def set_options(self, options = None) :
        if options == None :
            self.options['opt_files']   = True
            self.options['opt_boot']    = False
            self.options['opt_arc']     = False
            self.options['opt_mail']    = False
            self.options['opt_nopack']  = False
            self.options['opt_nohed']   = False
            self.options['opt_xcl']     = False
            self.options['opt_log']     = False
            self.options['opt_cd']      = False
            self.options['opt_fixed']   = False
            self.options['opt_floppy']  = False
            self.options['opt_list']    = False
            self.options['opt_prog']    = False
            self.options['opt_app']     = False
            self.options['opt_infp']    = False
            self.options['opt_susp']    = False
            self.options['opt_nor']     = False
            self.options['opt_prompt']  = False
            self.options['opt_info']    = False
            self.options['opt_nowarn']  = False
            self.options['opt_vlist']   = False
            self.options['opt_dis']     = False
            self.options['opt_copy']    = False
            self.options['opt_copys']   = False
            self.options['opt_del']     = False
            self.options['opt_noclean'] = False
            self.options['opt_move']    = False
            self.options['opt_moves']   = False
            self.options['opt_ren']     = False
            self.options['opt_infext']  = False
            self.options['opt_alev']    = False
            self.options['opt_flev']    = False
            self.options['opt_update']  = False
            self.options['opt_sigtool'] = False
            # self.options['opt_help']  = False
        else :
            self.options['opt_files']   = options.opt_files
            self.options['opt_boot']    = options.opt_boot
            self.options['opt_arc']     = options.opt_arc
            self.options['opt_mail']    = options.opt_mail
            self.options['opt_nopack']  = options.opt_nopack
            self.options['opt_nohed']   = options.opt_nohed
            self.options['opt_xcl']     = options.opt_xcl
            self.options['opt_log']     = options.opt_log
            self.options['opt_cd']      = options.opt_cd
            self.options['opt_fixed']   = options.opt_fixed
            self.options['opt_floppy']  = options.opt_floppy
            self.options['opt_list']    = options.opt_list
            self.options['opt_prog']    = options.opt_prog
            self.options['opt_app']     = options.opt_app
            self.options['opt_infp']    = options.opt_infp
            self.options['opt_susp']    = options.opt_susp
            self.options['opt_nor']     = options.opt_nor
            self.options['opt_prompt']  = options.opt_prompt
            self.options['opt_info']    = options.opt_info
            self.options['opt_nowarn']  = options.opt_nowarn
            self.options['opt_vlist']   = options.opt_vlist
            self.options['opt_dis']     = options.opt_dis
            self.options['opt_copy']    = options.opt_copy
            self.options['opt_copys']   = options.opt_copys
            self.options['opt_del']     = options.opt_del
            self.options['opt_noclean'] = options.opt_noclean
            self.options['opt_move']    = options.opt_move
            self.options['opt_moves']   = options.opt_moves
            self.options['opt_ren']     = options.opt_ren
            self.options['opt_infext']  = options.opt_infext
            self.options['opt_alev']    = options.opt_alev
            self.options['opt_flev']    = options.opt_flev
            self.options['opt_update']  = options.opt_update
            self.options['opt_sigtool'] = options.opt_sigtool
            # self.options['opt_help']  = # options.opt_help
        return True

    #-----------------------------------------------------------------
    # get_options(self)
    # 키콤백신 엔진의 옵션을 설정한다.
    #-----------------------------------------------------------------
    def get_options(self) :
        return self.options

    #-----------------------------------------------------------------
    # scan(self, filename)
    # 키콤백신 엔진이 악성코드를 진단한다.
    #-----------------------------------------------------------------
    def scan(self, filename, *callback) :
        del_master_file = ''
        del_temp_list = [] # 검사를 위해 임시로 생성된 파일들
        ret_value = {
            'result':False, 'engine_id':-1, 'virus_name':'',
            'virus_id':-1, 'scan_state':None, 'scan_info':None
        }

        # 가변인자 확인
        argc = len(callback)

        if argc == 0 : # 인자가 없으면
            cb = None
        elif argc == 1 : # callback 함수가 존재하는지 체크
            cb = callback[0]
        else : # 인자가 너무 많으면 에러
            return -1

        # 1. 검사 대상 리스트에 파일을 등록
        file_scan_list = [] # 검사 대상 정보를 모두 가짐
        file_info = {}  # 파일 한개의 정보

        # 검사 대상 리스트에는 검사 대상 파일 이름과 출력용 이름을 동시에 저장
        file_info['is_arc'] = False # 압축 여부
        file_info['arc_engine_name'] = -1 # 압축 해제 가능 엔진 ID
        file_info['arc_filename'] = '' # 실제 압축 파일
        file_info['arc_in_name'] = '' #압축해제 대상 파일
        file_info['real_filename'] = filename # 검사 대상 파일
        file_info['deep_filename'] = ''  # 압축 파일의 내부를 표현하기 위한 파일명
        file_info['display_filename'] = filename # 출력용
        file_info['signature'] = self.options['opt_sigtool'] # 시그너쳐 생성을 요청 여부
        file_scan_list.append(file_info)

        # 검사 대상 리스트에 파일이 있으면...
        while len(file_scan_list) != 0 :
            # 1. 검사 대상 리스트에서 파일 하나 빼오기
            scan_file = file_scan_list.pop(0)

            # 임시 파일 정리
            if del_master_file != scan_file['display_filename'] :
                if len(del_temp_list) != 0 :
                    self.__del_temp_file__(del_temp_list)
                    del_temp_list = []
                    del_master_file = scan_file['display_filename']

            real_name = scan_file['real_filename']

            ret_value['real_filename'] = real_name    # 실제 파일 이름

            # 폴더면 내부 파일리스트만 검사 대상 리스트에 등록
            if os.path.isdir(real_name) == True :
                self.result['Folders'] += 1 # 폴더 수 증가
                ret_value['result'] = False # 폴더이므로 바이러스 없음
                ret_value['scan_info']  = scan_file

                if self.options['opt_list'] == True : # 모든 리스트 출력인가?
                    if cb != None :
                        cb(ret_value)

                # 폴더 등을 처리할 때를 위해 뒤에 붇는 os.sep는 우선 제거
                if real_name[len(real_name)-1] == os.sep :
                    real_name = real_name[:len(real_name)-1]

                # 폴더 안의 파일들을 검사대상 리스트에 추가
                flist = glob.glob(real_name + os.sep + '*')
                for rfname in flist :
                    tmp_info = {}

                    tmp_info['is_arc'] = False # 압축 여부
                    tmp_info['arc_engine_name'] = -1 # 압축 해제 가능 엔진 ID
                    tmp_info['arc_filename'] = '' # 실제 압축 파일
                    tmp_info['arc_in_name'] = '' #압축해제 대상 파일
                    tmp_info['real_filename'] = rfname # 검사 대상 파일
                    tmp_info['deep_filename'] = ''  # 압축 파일의 내부를 표현하기 위한 파일명
                    tmp_info['display_filename'] = rfname # 출력용
                    tmp_info['signature'] = self.options['opt_sigtool'] # 시그너쳐 생성을 요청 여부
                    file_scan_list.append(tmp_info)

            else : # 파일이면 검사
                self.result['Files'] += 1 # 파일 수 증가

                # 압축된 파일이면 해제하기
                ret = self.__unarc_file__(scan_file)
                if ret != None :
                    ret['signature'] = self.options['opt_sigtool']
                    if ret['is_arc'] == True : # 압축이 풀렸을때에만 삭제 대상 등록
                        del_master_file = ret['display_filename']
                        del_temp_list.append(ret['real_filename'])
                    scan_file = ret

                # 2. 포맷 분석
                ff = self.__get_fileformat__(scan_file)

                '''
                print '-' * 79
                for k in scan_file.keys() :
                    print '%-16s : %s' % (k, scan_file[k])
                print '-' * 79
                '''

                # 3. 파일로 악성코드 검사
                ret = self.__scan_file__(scan_file, ff)

                #    악성코드 발견이면 콜백 호출 또는 검사 리턴값 누적 생성
                ret_value['result']     = ret['result'    ] # 바이러스 발견 여부
                ret_value['engine_id']  = ret['engine_id' ] # 엔진 ID
                ret_value['virus_name'] = ret['virus_name'] # 바이러스 이름
                ret_value['scan_state'] = ret['scan_state'] # 바이러스 검사 상태
                ret_value['virus_id']   = ret['virus_id'  ] # 바이러스 ID
                ret_value['scan_info']  = scan_file

                if self.options['opt_list'] == True : # 모든 리스트 출력인가?
                    if cb != None :
                        cb(ret_value)
                else : # 아니라면 바이러스인 것만 출력
                    if ret_value['result'] == True :
                        if cb != None :
                            cb(ret_value)

                # 이미 해당 파일이 바이러스라고 판명되었다면
                # 그 파일을 압축해제해서 내부를 볼 필요는 없다.
                if ret_value['result'] == False : # 따라서 바이러스가 아닌경우만 검사
                    # 4. 압축 파일이면 검사대상 리스트에 추가
                    try :
                        scan_file['real_filename'] = scan_file['temp_filename']
                    except :
                        pass
                    arc_file_list = self.__get_list_arc__(scan_file, ff)
                    if len(arc_file_list) != 0 :
                        file_scan_list = arc_file_list + file_scan_list

        # 검사 마무리 작업(임시 파일 정리)
        if len(del_temp_list) != 0 :
            self.__del_temp_file__(del_temp_list)

        return 0 # 정상적으로 검사 종료


    def __get_list_arc__(self, scan_file_struct, format) :
        import kernel

        file_scan_list = [] # 검사 대상 정보를 모두 가짐

        # 압축 엔진 모듈의 arclist 멤버 함수 호출
        for mod in self.modules :
            if dir(mod).count('arclist') != 0 : # API 존재
                if self.options['opt_arc'] == True : # 압축 검사 옵션이 있으면 모두 호출
                    file_scan_list = mod.arclist(scan_file_struct, format) 
                else : # 압축 검사 옵션이 없다면 선별적 호출
                    if dir(mod).count('getinfo') != 0 : # API 존재
                        ret_getinfo = mod.getinfo()
                        try :
                            if ret_getinfo['engine_type'] != kernel.ARCHIVE_ENGINE : 
                                # 압축 엔진이 아니어도 호출
                                file_scan_list = mod.arclist(scan_file_struct, format)
                        except :
                            # entine_type이 없어도 호출
                            file_scan_list = mod.arclist(scan_file_struct, format)

                if len(file_scan_list) != 0 : # 압축이 풀렸으면 종료
                    self.result['Packed'] += 1
                    break

        return file_scan_list


    def __unarc_file__(self, scan_file_struct) :
        try :
            if scan_file_struct['is_arc'] == True :
                # 압축 엔진 모듈의 arclist 멤버 함수 호출
                for mod in self.modules :
                    if dir(mod).count('unarc') != 0 : # API 존재
                        rname_struct = mod.unarc(scan_file_struct)
                        if rname_struct != None : # 압축이 풀렸으면 종료
                            break

                return rname_struct
        except :
            pass

        return scan_file_struct


    def __del_temp_file__(self, dellist) :
        for file in dellist :
            os.remove(file)


    def __scan_file__(self, scan_file_struct, format) :
        ret_value = {
            'result':False, 'engine_id':-1, 'virus_name':'',
            'virus_id':-1, 'scan_state':None, 'scan_info':None
        }

        filename = scan_file_struct['real_filename']

        try :
            fsize = os.path.getsize(filename)
            if fsize == 0 : # 파일 크기가 0인 경우 검사 제외
                raise SystemError

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            # 백신 엔진 모듈의 scan 멤버 함수 호출
            for mod in self.modules :
                if dir(mod).count('scan') != 0 : # API 존재
                    ret_value = mod.scan(mm, scan_file_struct, format)
                    ret   = ret_value['result']     # 바이러스 발견 여부
                    vname = ret_value['virus_name'] # 바이러스 이름

                    if ret == True : # 악성코드 발견이면 검사 중단
                        break

            mm.close()
            fp.close()

            if ret == True :
                import kernel
                if ret_value['scan_state'] == kernel.INFECTED :
                    self.result['Infected_files'] += 1 # 악성코드 발견 수 증가
                elif ret_value['scan_state'] == kernel.SUSPECT :
                    self.result['Suspect_files'] += 1 # 악성코드 발견 수 증가
                elif ret_value['scan_state'] == kernel.WARNING :
                    self.result['Warnings'] += 1 # 악성코드 발견 수 증가

                # 동일한 악성코드 발견 유무 체크
                if self.identified_virus.count(vname) == 0 :
                    self.identified_virus.append(vname)
                    self.result['Identified_viruses'] += 1

                ret_value['engine_id'] = self.modules.index(mod) # 발견된 엔진 ID
                return ret_value
        except :
            self.result['IO_errors'] += 1 # 오류 발생 수 증가
            pass

        ret_value['engine_id'] = -1
        return ret_value


    def __get_fileformat__(self, scan_file_struct) :
        ret = {}
        filename = scan_file_struct['real_filename']

        try :
            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            # 백신 엔진 모듈의 scan 멤버 함수 호출
            for mod in self.modules :
                if dir(mod).count('format') != 0 : # API 존재
                    ff = mod.format(mm, filename)
                    if ff != None :
                        ret.update(ff)

            mm.close()
            fp.close()
        except :
            pass

        return ret

    #-----------------------------------------------------------------
    # disinfect(self, filename, modID, virusID)
    # 키콤백신 엔진이 악성코드를 치료한다.
    #-----------------------------------------------------------------
    def disinfect(self, filename, modID, virusID) :
        ret_disinfect = False

        try :
            mod = self.modules[modID]
            if dir(mod).count('disinfect') != 0 : # API 존재
                ret_disinfect = mod.disinfect(filename, virusID)

        except :
            pass

        return ret_disinfect

    #-----------------------------------------------------------------
    # getinfo(self)
    # 키콤백신 엔진의 각 엔진 모듈의 정보를 리턴한다.
    #-----------------------------------------------------------------
    def getinfo(self) :
        ret = []

        # 백신 엔진 모듈의 getinfo 멤버 함수 호출
        for mod in self.modules :
            if dir(mod).count('getinfo') != 0 : # API 존재
                ret_getinfo = mod.getinfo()
                ret.append(ret_getinfo)

        return ret

    #-----------------------------------------------------------------
    # listvirus(self, *callback)
    # 키콤백신 엔진이 진단하는 악성코드 이름을 리턴한다.
    #-----------------------------------------------------------------
    def listvirus(self, *callback) :
        # 가변인자 확인
        argc = len(callback)

        if argc == 0 : # 인자가 없으면
            cb = None
        elif argc == 1 : # callback 함수가 존재하는지 체크
            cb = callback[0]
        else : # 인자가 너무 많으면 에러
            return []

        # 백신 엔진 모듈의 listvirus 멤버 함수 호출
        ret = []

        for mod in self.modules :
            if dir(mod).count('listvirus') != 0 : # API 존재
                ret_listvirus = mod.listvirus()

                # callback 함수가 있다면
                # callback 함수 호출
                if type(cb) is types.FunctionType :
                    # 해당 kmd의 정보도 함께 제공
                    ret_getinfo = None
                    if dir(mod).count('getinfo') != 0 :
                        ret_getinfo = mod.getinfo()
                    cb(ret_listvirus, ret_getinfo)
                # callback 함수가 없다면
                # 악성코드 이름을 리스트에 누적
                else :
                    ret += ret_listvirus

        # callback 함수 없으면 누적된 악성코드 리스트를 리턴
        if argc == 0 :
            return ret

    def getversion(self) :
        t = CTIME()

        # self.last_update에는 엔진 빌드 날짜와 시간 정보만 존재
        update_date = self.last_update 

        # 각 백신 엔진 모듈이 가진 패턴의 날짜와 시간 정보를 비교해서
        # 최신 엔진의 날짜와 시간정보를 출력해야 함

        # 백신 엔진 모듈의 getinfo 멤버 함수 호출
        for mod in self.modules :
            if dir(mod).count('getinfo') != 0 : # API 존재
                ret_getinfo = mod.getinfo()

                try :
                    pattern_date = ret_getinfo['date']
                    pattern_time = ret_getinfo['time']

                    d_y, d_m, d_d = t.GetDate(pattern_date)
                    t_h, t_m, t_s = t.GetTime(pattern_time)

                    t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

                    # 최신 날짜를 구함

                    if update_date < t_datetime :
                        update_date = t_datetime
                except :
                    pass

        return update_date

    def getsignum(self) :
        sig_num = 0

        # 백신 엔진 모듈의 getinfo 멤버 함수 호출
        for mod in self.modules :
            if dir(mod).count('getinfo') != 0 : # API 존재
                ret_getinfo = mod.getinfo()

                try :
                    pattern_signum = ret_getinfo['sig_num']
                    sig_num += pattern_signum
                except :
                    pass

        return sig_num

class CTIME :
    def GetDate(self, t) :
        t_y = 0xFE00
        t_m = 0x01E0
        t_d = 0x001F

        y = (t & t_y) >> 9
        y += 1980
        m = (t & t_m) >> 5
        d = (t & t_d)

        # return '%04d-%02d-%02d' % (y, m, d)
        return (y, m, d)

    def GetTime(self, t) :
        t_h = 0xF800
        t_m = 0x07E0
        t_s = 0x001F

        h = (t & t_h) >> 11
        m = (t & t_m) >> 5
        s = (t & t_s) * 2

        # return '%02d:%02d:%02d' % (h, m, s)
        return (h, m, s)

#---------------------------------------------------------------------
# KMD 클래스
#---------------------------------------------------------------------
class KMD :
    def __init__(self) :
        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)

    def GetLastUpdate(self) :
        return self.max_datetime

    def GetList(self, plugins) :
        kmd_list = []

        try :
            # kicom.kmd 파일을 복호화
            ret, buf = self.Decrypt(plugins + os.sep + 'kicom.kmd')

            if ret == True : # 성공
                msg = StringIO.StringIO(buf) # 버퍼 IO 준비

                while 1 :
                    # 버퍼 한 줄을 읽어 엔터키 제거
                    line = msg.readline().strip()
                    if line.find('.kmd') != -1 : # kmd 확장자가 존재한다면
                        kmd_list.append(line) # kmd 순서 리스트에 추가
                    else :
                        break
        except :
            pass

        return kmd_list # kmd 순서 리스트 리턴

    def Decrypt(self, fname) :
        t = CTIME()
        header_length = 8
        hash_length = 0x40

        try : # 예외가 발생할 가능성에 대해 처리
            fp = open(fname, 'rb') # kmd 파일 읽기
            buf = fp.read()
            fp.close()

            f_hash = buf[len(buf)-hash_length:] # 파일 뒤쪽에서 MD5 해시 값 분리

            hash = hashlib.sha256()

            val_5hash = buf[0:len(buf)-hash_length] # 파일 뒤쪽 hash_lengthByte를 제외한 나머지 영역
            for i in range(3): # MD5 해시 값을 3번 연속으로 구하기
                hash.update(val_5hash)
                val_5hash = hash.hexdigest()

            if f_hash != val_5hash:
                return False, '' # 에러

            buf2 = buf[header_length:len(buf)-hash_length] # KAVM 헤더 제거

            buf3 =""
            for i in range(len(buf2)):  # buf2 크기만큼...
                c = ord(buf2[i]) ^ 0xFF #　0xFF로 XOR 암호화 한다
                buf3 += chr(c)

            buf4 = zlib.decompress(buf3) # 압축 해제

            # 최근 날짜 구하기
            kmd_date = buf[4:6]
            kmd_time = buf[6:8]

            d_y, d_m, d_d = t.GetDate(struct.unpack('<H', kmd_date)[0])
            t_h, t_m, t_s = t.GetTime(struct.unpack('<H', kmd_time)[0])
            t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

            if self.max_datetime < t_datetime :
                self.max_datetime = t_datetime

            return True, buf4 # kmd 복호화 성공 그리고 복호화된 내용 리턴
        except : # 예외 발생
            return False, '' # 에러

    def Import(self, plugins, kmd_list) :
        mod_list = []

        for kmd in kmd_list :
            ret_kmd, buf = self.Decrypt(plugins + os.sep + kmd)

            if ret_kmd == True :
                ret_imp, mod = self.LoadModule(kmd.split('.')[0], buf)
                if ret_imp == True :
                    mod_list.append(mod)

        return mod_list

    def LoadModule(self, kmd_name, buf) :
        try :
            code = marshal.loads(buf[8:]) # 버퍼를 컴파일 가능한 직렬화 된 문자열로 변환
            module = imp.new_module(kmd_name) # 새로운 모듈 생성
            exec(code, module.__dict__) # 직렬화 된 문자열을 컴파일하여 모듈과 연결
            sys.modules[kmd_name] = module # 전역에서 사용가능하게 등록
            return True, module
        except :
            return False, None

    def ExecKavMain(self, module) :
        obj = None

        # 로딩된 모듈에서 KavMain이 있는지 검사
        # KavMain이 발견되었으면 클래스의 인스턴스 생성
        if dir(module).count('KavMain') != 0 :
            obj = module.KavMain()

        # 생성된 인스턴스가 없다면 지금 로딩한 모듈은 취소
        if obj == None :
            # 로딩 취소
            del sys.modules[kmd_name]
            del module

        return obj # 생성된 인스턴스 리턴

#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------
'''
def cb(list_vir) :
    for vir in list_vir :
        print vir

# 엔진 클래스
kav = Engine()
kav.SetPlugins('plugins') # 플러그인 폴더 설정

print '----------------------------'
# 엔진 인스턴스 생성1
kav1 = kav.CreateInstance()
if kav1 == None :
    print 'Error : KICOM Anti-Virus Engine CreateInstance1'
else :
    print kav1

# 엔진 인스턴스 생성2
kav2 = kav.CreateInstance()
if kav2 == None :
    print 'Error : KICOM Anti-Virus Engine CreateInstance2'
else :
    print kav2

print '----------------------------'
print kav1.init()
print kav2.init()
print '----------------------------'
s = kav1.getinfo()
for i in s :
    print i['title']
print '----------------------------'
kav1.listvirus(cb)
print '----------------------------'
print kav1.scan('dummy.txt')
print kav1.scan('eicar.txt')
print kav1.scan('kavcore.py')
print '----------------------------'
kav1.uninit()
kav2.uninit()
'''