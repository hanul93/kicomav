# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import glob
import mmap
import os
import sys
import tempfile
import datetime
import types
from k2fs        import K2FileStruct
from k2kmd       import K2KMD
from k2ctime     import K2CTIME

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
        self.ckmd = K2KMD()

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
            import traceback
            print traceback.format_exc()

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
            import traceback
            print traceback.format_exc()

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
            'result'     : False, 
            'engine_id'  : -1, 
            'virus_name' : '',
            'virus_id'   : -1, 
            'scan_state' : None, 
            'scan_info'  : None
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

        # 검사 대상 리스트에는 검사 대상 파일 이름과 출력용 이름을 동시에 저장
        file_info = K2FileStruct()
        file_info.Set(filename)
        # file_info['signature'] = self.options['opt_sigtool'] # 시그너쳐 생성을 요청 여부
        file_scan_list.append(file_info)

        try :
            # 검사 대상 리스트에 파일이 있으면...
            while len(file_scan_list) != 0 :
                # 1. 검사 대상 리스트에서 파일 하나 빼오기
                scan_file = file_scan_list.pop(0)

                # 임시 파일 정리
                if del_master_file != scan_file.GetMasterFilename() :
                    if len(del_temp_list) != 0 :
                        self.__del_temp_file__(del_temp_list)
                        del_temp_list = []
                        del_master_file = scan_file.GetMasterFilename()

                real_name = scan_file.GetFilename()

                ret_value['real_filename'] = real_name    # 실제 파일 이름

                # 폴더면 내부 파일리스트만 검사 대상 리스트에 등록
                if os.path.isdir(real_name) == True :
                    self.result['Folders'] += 1 # 폴더 수 증가
                    ret_value['result'] = False # 폴더이므로 악성코드 없음
                    ret_value['scan_info']  = scan_file

                    if self.options['opt_list'] == True : # 모든 리스트 출력인가?
                        if cb != None :
                            cb(ret_value)

                    # 폴더 등을 처리할 때를 위해 뒤에 붇는 os.sep는 우선 제거
                    if real_name[len(real_name)-1] == os.sep :
                        real_name = real_name[:len(real_name)-1]

                    # 폴더 안의 파일들을 검사대상 리스트에 추가
                    flist = glob.glob(real_name + os.sep + '*')
                    tmp_flist = []

                    for rfname in flist :
                        tmp_info = K2FileStruct()
                        tmp_info.Set(rfname)
                        # tmp_info['signature'] = self.options['opt_sigtool'] # 시그너쳐 생성을 요청 여부
                        tmp_flist.append(tmp_info)

                    file_scan_list = tmp_flist + file_scan_list
                else : # 파일이면 검사
                    self.result['Files'] += 1 # 파일 수 증가

                    # 압축된 파일이면 해제하기
                    ret = self.__unarc_file__(scan_file)
                    if ret != None :
                        # ret['signature'] = self.options['opt_sigtool']
                        if ret.IsArchive() == True : # 압축이 풀렸을때에만 삭제 대상 등록
                            del_master_file = ret.GetMasterFilename()
                            del_temp_list.append(ret.GetFilename())
                        scan_file = ret

                    # 2. 포맷 분석
                    ff = self.__get_fileformat__(scan_file)

                    # 3. 파일로 악성코드 검사
                    ret, vname, v_id, scan_state, engine_id = self.__scan_file__(scan_file, ff)

                    #    악성코드 발견이면 콜백 호출 또는 검사 리턴값 누적 생성
                    ret_value['result']     = ret        # 악성코드 발견 여부
                    ret_value['engine_id']  = engine_id  # 엔진 ID
                    ret_value['virus_name'] = vname      # 악성코드 이름
                    ret_value['virus_id']   = v_id       # 악성코드 ID
                    ret_value['scan_state'] = scan_state # 악성코드 검사 상태
                    ret_value['scan_info']  = scan_file

                    if self.options['opt_list'] == True : # 모든 리스트 출력인가?
                        if cb != None :
                            cb(ret_value)
                    else : # 아니라면 악성코드인 것만 출력
                        if ret_value['result'] == True :
                            if cb != None :
                                cb(ret_value)

                    # 이미 해당 파일이 악성코드라고 판명되었다면
                    # 그 파일을 압축해제해서 내부를 볼 필요는 없다.
                    if ret_value['result'] == False : # 따라서 악성코드가 아닌경우만 검사
                        # 4. 압축 파일이면 검사대상 리스트에 추가
                        arc_file_list = self.__get_list_arc__(scan_file, ff)
                        if len(arc_file_list) != 0 :
                            file_scan_list = arc_file_list + file_scan_list
        
            # 검사 마무리 작업(임시 파일 정리)
            if len(del_temp_list) != 0 :
                self.__del_temp_file__(del_temp_list)
        except KeyboardInterrupt :
            return 1 # 키보드 종료

        return 0 # 정상적으로 검사 종료


    def __get_list_arc__(self, scan_file_struct, format) :
        import kernel

        arc_list = [] # 압축 파일 리스트
        file_scan_list = [] # 검사 대상 정보를 모두 가짐 (K2FileStruct)

        rname     = scan_file_struct.GetFilename()
        deep_name = scan_file_struct.GetDeepFilename()
        mname     = scan_file_struct.GetMasterFilename()

        # 압축 엔진 모듈의 arclist 멤버 함수 호출
        for mod in self.modules :
            if dir(mod).count('arclist') != 0 : # API 존재
                if self.options['opt_arc'] == True : # 압축 검사 옵션이 있으면 모두 호출
                    arc_list = mod.arclist(rname, format) 
                else : # 압축 검사 옵션이 없다면 선별적 호출
                    if dir(mod).count('getinfo') != 0 : # API 존재
                        ret_getinfo = mod.getinfo()
                        try :
                            if ret_getinfo['engine_type'] != kernel.ARCHIVE_ENGINE : 
                                # 압축 엔진이 아니어도 호출
                                arc_list = mod.arclist(rname, format)
                        except :
                            # entine_type이 없어도 호출
                            arc_list = mod.arclist(rname, format)

                if len(arc_list) != 0 : # 압축 리스트가 존재한다면 추가하고 종료
                    for alist in arc_list :
                        arc_id = alist[0]
                        name   = alist[1]

                        if len(deep_name) != 0 : # 압축 파일 내부 표시용
                            dname = '%s/%s' % (deep_name, name)
                        else :
                            dname = '%s' % (name)

                        fs = K2FileStruct()
                        fs.SetArchive(arc_id, rname, name, dname, mname)
                        file_scan_list.append(fs)

                    self.result['Packed'] += 1
                    break

        return file_scan_list


    def __unarc_file__(self, scan_file_struct) :
        rname_struct = None

        try :
            if scan_file_struct.IsArchive() == True : # 압축인가?
                arc_engine_id = scan_file_struct.GetArchiveEngine() # 엔진 ID
                arc_name      = scan_file_struct.GetArchiveFilename()
                arc_in_name   = scan_file_struct.GetArchiveInFilename()

                # 압축 엔진 모듈의 arclist 멤버 함수 호출
                for mod in self.modules :
                    if dir(mod).count('unarc') != 0 : # API 존재
                        unpack_data = mod.unarc(arc_engine_id, arc_name, arc_in_name)

                        if unpack_data != None :
                            # 압축을 해제하여 임시 파일을 생성
                            rname = tempfile.mktemp(prefix='ktmp')
                            fp = open(rname, 'wb')
                            fp.write(unpack_data)
                            fp.close()

                            rname_struct = scan_file_struct
                            rname_struct.SetFilename(rname)
                            break # 압축이 풀렸으면 종료

                return rname_struct
        except :
            pass

        return None


    def __del_temp_file__(self, dellist) :
        for file in dellist :
            os.remove(file)


    def __scan_file__(self, scan_file_struct, format) :
        import kernel

        filename = scan_file_struct.GetFilename()
        deepname = scan_file_struct.GetDeepFilename()

        try :
            fsize = os.path.getsize(filename)
            if fsize == 0 : # 파일 크기가 0인 경우 검사 제외
                return (False, '', -1, kernel.NOT_FOUND, -1)

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            ret        = False # 악성코드 감염 유무
            vname      = ''
            v_id       = -1
            scan_state = kernel.NOT_FOUND

            # 백신 엔진 모듈의 scan 멤버 함수 호출
            for mod in self.modules :
                if dir(mod).count('scan') != 0 : # API 존재
                    ret, vname, v_id, scan_state = mod.scan(mm, filename, deepname, format)
                    if ret == True : # 악성코드 발견이면 검사 중단
                        break

            mm.close()
            fp.close()

            if ret == True :
                if scan_state == kernel.INFECTED :
                    self.result['Infected_files'] += 1 # 악성코드 발견 수 증가
                elif scan_state == kernel.SUSPECT :
                    self.result['Suspect_files'] += 1 # 악성코드 발견 수 증가
                elif scan_state == kernel.WARNING :
                    self.result['Warnings'] += 1 # 악성코드 발견 수 증가

                # 동일한 악성코드 발견 유무 체크
                if self.identified_virus.count(vname) == 0 :
                    self.identified_virus.append(vname)
                    self.result['Identified_viruses'] += 1

                engine_id = self.modules.index(mod) # 발견된 엔진 ID
                
                return (ret, vname, v_id, scan_state, engine_id)
        except :
            self.result['IO_errors'] += 1 # 오류 발생 수 증가
            pass

        return (False, '', -1, kernel.NOT_FOUND, -1)


    def __get_fileformat__(self, scan_file_struct) :
        ret = {}
        filename = scan_file_struct.GetFilename()

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
        t = K2CTIME()

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