# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import StringIO
import datetime
import types
import mmap
import glob
import tempfile
import shutil
import struct

import k2timelib
import k2kmdfile
import k2rsa
import k2file
import k2const


# ---------------------------------------------------------------------
# 엔진 오류 메시지를 정의
# ---------------------------------------------------------------------
class EngineKnownError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# -------------------------------------------------------------------------
# Engine 클래스
# -------------------------------------------------------------------------
class Engine:
    # ---------------------------------------------------------------------
    # __init__(self, debug=False)
    # 클래스를 초기화 한다.
    # 인자값 : debug - 디버그 여부
    # ---------------------------------------------------------------------
    def __init__(self, debug=False):
        self.debug = debug  # 디버깅 여부

        self.plugins_path = None  # 플러그인 경로
        self.kmdfiles = []  # 우선순위가 기록된 kmd 리스트
        self.kmd_modules = []  # 메모리에 로딩된 모듈

        # 플러그 엔진의 가장 최신 시간 값을 가진다.
        # 초기값으로는 1980-01-01을 지정한다.
        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)
        
        # 키콤백신이 만든 임시 파일 모두 제거
        self.__remove_kav_tempfile()  

    # ---------------------------------------------------------------------
    # __remove_kav_tempfile(self)
    # 임시 폴더에 존재하는 임시 파일 제거
    # ---------------------------------------------------------------------
    def __remove_kav_tempfile(self):
        tpath = tempfile.gettempdir()
        fl = glob.glob(tpath + os.sep + 'ktmp*')
        for name in fl:
            if os.path.isfile(name):
                try:
                    os.remove(name)
                except IOError:
                    pass

    # ---------------------------------------------------------------------
    # set_plugins(self, plugins_path)
    # 주어진 경로에서 플러그인 엔진을 로딩 준비한다.
    # 인자값 : plugins_path - 플러그인 엔진 경로
    # 리턴값 : 성공 여부
    # ---------------------------------------------------------------------
    def set_plugins(self, plugins_path):
        # 플러그인 경로를 저장한다.
        self.plugins_path = plugins_path

        # 공개키를 로딩한다.
        pu = k2rsa.read_key(plugins_path + os.sep + 'key.pkr')
        if not pu:
            return False

        # 우선순위를 알아낸다.
        ret = self.__get_kmd_list(plugins_path + os.sep + 'kicom.kmd', pu)
        if not ret:  # 로딩할 KMD 파일이 없다.
            return False

        if self.debug:
            print '[*] kicom.kmd :'
            print '   ', self.kmdfiles

        # 우선순위대로 KMD 파일을 로딩한다.
        for kmd_name in self.kmdfiles:
            kmd_path = plugins_path + os.sep + kmd_name
            try:
                k = k2kmdfile.KMD(kmd_path, pu)  # 모든 KMD 파일을 복호화한다.
                module = k2kmdfile.load(kmd_name.split('.')[0], k.body)
                if module:  # 메모리 로딩 성공
                    self.kmd_modules.append(module)
                    # 메모리 로딩에 성공한 KMD에서 플러그 엔진의 시간 값 읽기
                    # 최신 업데이트 날짜가 된다.
                    self.__get_last_kmd_build_time(k)
            except IOError:
                pass
            except k2kmdfile.KMDFormatError:  # 다른키로 암호호화 한 엔진은 무시
                pass

        # 악성코드 패턴에서 최신 시간 값을 얻는다.
        fl = glob.glob(plugins_path + os.sep + '*.n??')
        for fname in fl:
            try:
                buf = open(fname, 'rb').read(12)
                if buf[0:4] == 'KAVS':
                    sdate = k2timelib.convert_date(struct.unpack('<H', buf[8:10])[0])
                    stime = k2timelib.convert_time(struct.unpack('<H', buf[10:12])[0])

                    t_datetime = datetime.datetime(sdate[0], sdate[1], sdate[2], stime[0], stime[1], stime[2])

                    if self.max_datetime < t_datetime:
                        self.max_datetime = t_datetime
            except IOError:
                pass

        if self.debug:
            print '[*] kmd_modules :'
            print '   ', self.kmd_modules
            print '[*] Last updated %s UTC' % self.max_datetime.ctime()

        return True

    # ---------------------------------------------------------------------
    # create_instance(self)
    # 백신 엔진의 인스턴스를 생성한다.
    # ---------------------------------------------------------------------
    def create_instance(self):
        ei = EngineInstance(self.plugins_path, self.max_datetime, self.debug)
        if ei.create(self.kmd_modules):
            return ei
        else:
            return None

    # ---------------------------------------------------------------------
    # __get_last_kmd_build_time(self, kmd_info)
    # 복호화 된 플러그인 엔진의 빌드 시간 값 중 최신 값을 보관한다.
    # 입력값 : kmd_info - 복호화 된 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def __get_last_kmd_build_time(self, kmd_info):
        d_y, d_m, d_d = kmd_info.date
        t_h, t_m, t_s = kmd_info.time
        t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

        if self.max_datetime < t_datetime:
            self.max_datetime = t_datetime

    # ---------------------------------------------------------------------
    # __get_kmd_list(self, kicom_kmd_file, pu)
    # 플러그인 엔진의 로딩 우선순위를 알아낸다.
    # 인자값 : kicom_kmd_file - kicom.kmd 파일의 전체 경로
    #         pu             - 공개키
    # 리턴값 : 성공 여부
    # ---------------------------------------------------------------------
    def __get_kmd_list(self, kicom_kmd_file, pu):
        kmdfiles = []  # 우선순위 목록

        k = k2kmdfile.KMD(kicom_kmd_file, pu)  # kicom.kmd 파일을 복호화한다.

        if k.body:  # kicom.kmd 읽혔는가?
            msg = StringIO.StringIO(k.body)

            while True:
                # 버퍼 한 줄을 읽어 엔터키 제거
                line = msg.readline().strip()

                if not line:  # 읽혀진 내용이 없으면 종료
                    break
                elif line.find('.kmd') != -1:  # KMD 확장자가 존재한다면
                    kmdfiles.append(line)  # KMD 우선순위 목록에 추가
                else:  # 확장자가 KMD가 아니면 다음 파일로...
                    continue

        if len(kmdfiles):  # 우선순위 목록에 하나라도 있다면 성공
            self.kmdfiles = kmdfiles
            return True
        else:  # 우선순위 목록에 아무것도 없으면 실패
            return False


# -------------------------------------------------------------------------
# EngineInstance 클래스
# -------------------------------------------------------------------------
class EngineInstance:
    # ---------------------------------------------------------------------
    # __init__(self, plugins_path, max_datetime, debug=False)
    # 클래스를 초기화 한다.
    # 인자값 : plugins_path - 플러그인 엔진 경로
    #         max_datetime - 플러그인 엔진의 최신 시간 값
    #         debug        - 디버그 여부
    # ---------------------------------------------------------------------
    def __init__(self, plugins_path, max_datetime, debug=False):
        self.debug = debug  # 디버깅 여부

        self.plugins_path = plugins_path  # 플러그인 경로
        self.max_datetime = max_datetime  # 플러그 엔진의 가장 최신 시간 값

        self.options = {}  # 옵션
        self.set_options()  # 기본 옵션을 설정한다.

        self.kavmain_inst = []  # 모든 플러그인의 KavMain 인스턴스

        self.update_info = []  # 압축 파일 최종 치료를 위한 압축 리스트

        self.result = {}
        self.identified_virus = set()  # 유니크한 악성코드 개수를 구하기 위해 사용
        self.set_result()  # 악성코드 검사 결과를 초기화한다.

        self.disinfect_callback_fn = None  # 악성코드 치료 콜백 함수
        self.update_callback_fn = None  # 악성코드 압축 최종 치료 콜백 함수
        self.quarantine_callback_fn = None  # 악성코드 격리 콜백 함수

    # ---------------------------------------------------------------------
    # create(self, kmd_modules)
    # 백신 엔진의 인스턴스를 생성한다.
    # 인자값 : kmd_modules - 메모리에 로딩된 KMD 모듈 리스트
    # 리턴값 : 성공 여부
    # ---------------------------------------------------------------------
    def create(self, kmd_modules):  # 백신 엔진 인스턴스를 생성
        for mod in kmd_modules:
            try:
                t = mod.KavMain()  # 각 플러그인 KavMain 인스턴스 생성
                self.kavmain_inst.append(t)
            except AttributeError:  # KavMain 클래스 존재하지 않음
                continue

        if len(self.kavmain_inst):  # KavMain 인스턴스가 하나라도 있으면 성공
            if self.debug:
                print '[*] Count of KavMain : %d' % (len(self.kavmain_inst))
            return True
        else:
            return False

    # ---------------------------------------------------------------------
    # init(self)
    # 플러그인 엔진 전체를 초기화한다.
    # 리턴값 : 성공 여부
    # ---------------------------------------------------------------------
    def init(self):
        # self.kavmain_inst는 최종 인스턴스가 아니다.
        # init 초기화 명령어를 실행해서 정상인 플러그인만 최종 등록해야 한다.
        t_kavmain_inst = []  # 최종 인스턴스 리스트

        if self.debug:
            print '[*] KavMain.init() :'

        for inst in self.kavmain_inst:
            try:
                # 플러그인 엔진의 init 함수 호출
                ret = inst.init(self.plugins_path, self.options['opt_verbose'])
                if not ret:  # 성공
                    t_kavmain_inst.append(inst)

                    if self.debug:
                        print '    [-] %s.init() : %d' % (inst.__module__, ret)
            except AttributeError:
                continue

        self.kavmain_inst = t_kavmain_inst  # 최종 KavMain 인스턴스 등록

        if len(self.kavmain_inst):  # KavMain 인스턴스가 하나라도 있으면 성공
            if self.debug:
                print '[*] Count of KavMain.init() : %d' % (len(self.kavmain_inst))
            return True
        else:
            return False

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진 전체를 종료한다.
    # ---------------------------------------------------------------------
    def uninit(self):
        if self.debug:
            print '[*] KavMain.uninit() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.uninit()
                if self.debug:
                    print '    [-] %s.uninit() : %d' % (inst.__module__, ret)
            except AttributeError:
                continue

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진 정보를 얻는다.
    # 리턴값 : 플러그인 엔진 정보 리스트
    # ---------------------------------------------------------------------
    def getinfo(self):
        ginfo = []  # 플러그인 엔진 정보를 담는다.

        if self.debug:
            print '[*] KavMain.getinfo() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()
                ginfo.append(ret)

                if self.debug:
                    print '    [-] %s.getinfo() :' % inst.__module__
                    for key in ret.keys():
                        print '        - %-10s : %s' % (key, ret[key])
            except AttributeError:
                continue

        return ginfo

    # ---------------------------------------------------------------------
    # listvirus(self, *callback)
    # 플러그인 엔진이 진단/치료 할 수 있는 악성코드 목록을 얻는다.
    # 입력값 : callback - 콜백함수 (생략 가능)
    # 리턴값 : 악성코드 목록 (콜백함수 사용시 아무런 값도 없음)
    # ---------------------------------------------------------------------
    def listvirus(self, *callback):
        vlist = []  # 진단/치료 가능한 악성코드 목록

        argc = len(callback)  # 가변인자 확인

        if argc == 0:  # 인자가 없으면
            cb_fn = None
        elif argc == 1:  # callback 함수가 존재하는지 체크
            cb_fn = callback[0]
        else:  # 인자가 너무 많으면 에러
            return []

        if self.debug:
            print '[*] KavMain.listvirus() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.listvirus()

                # callback 함수가 있다면 callback 함수 호출
                if isinstance(cb_fn, types.FunctionType):
                    cb_fn(inst.__module__, ret)
                else:  # callback 함수가 없으면 악성코드 목록을 누적하여 리턴
                    vlist += ret

                if self.debug:
                    print '    [-] %s.listvirus() :' % inst.__module__
                    for vname in ret:
                        print '        - %s' % vname
            except AttributeError:
                continue

        return vlist

    # ---------------------------------------------------------------------
    # scan(self, filename, *callback)
    # 플러그인 엔진에게 악성코드 검사를 요청한다.
    # 입력값 : filename - 악성코드 검사 대상 파일 또는 폴더 이름
    #          callback - 검사 시 출력 화면 관련 콜백 함수
    # 리턴값 : 0 - 성공
    #          1 - Ctrl+C를 이용해서 악성코드 검사 강제 종료
    #         -1 - 콜백 함수가 너무 많음
    # ---------------------------------------------------------------------
    def scan(self, filename, *callback):
        scan_callback_fn = None  # 악성코드 검사 콜백 함수

        move_master_file = False  # 마스터 파일 격리 필요 여부
        t_master_file = ''  # 마스터 파일

        # 악성코드 검사 결과
        ret_value = {
            'filename': '',  # 파일 이름
            'result': False,  # 악성코드 발견 여부
            'virus_name': '',  # 발견된 악성코드 이름
            'virus_id': -1,  # 악성코드 ID
            'engine_id': -1  # 악성코드를 발견한 플러그인 엔진 ID
        }

        try:  # 콜백 함수 저장
            scan_callback_fn = callback[0]
            self.disinfect_callback_fn = callback[1]
            self.update_callback_fn = callback[2]
            self.quarantine_callback_fn = callback[3]
        except IndexError:
            pass

        # 1. 검사 대상 리스트에 파일을 등록
        file_info = k2file.FileStruct(filename)
        file_scan_list = [file_info]

        # 최초 한번만 하위 폴더 검색
        is_sub_dir_scan = True

        while len(file_scan_list):
            try:
                t_file_info = file_scan_list.pop(0)  # 검사 대상 파일 하나를 가짐
                real_name = t_file_info.get_filename()

                # 폴더면 내부 파일리스트만 검사 대상 리스트에 등록
                if os.path.isdir(real_name):
                    # 폴더 등을 처리할 때를 위해 뒤에 붇는 os.sep는 우선 제거
                    if real_name[-1] == os.sep:
                        real_name = real_name[:-1]

                    # 콜백 호출 또는 검사 리턴값 생성
                    ret_value['result'] = False  # 폴더이므로 악성코드 없음
                    ret_value['filename'] = real_name  # 검사 파일 이름
                    ret_value['file_struct'] = t_file_info  # 검사 파일 이름

                    self.result['Folders'] += 1  # 폴더 개수 카운트

                    if self.options['opt_list']:  # 옵션 내용 중 모든 리스트 출력인가?
                        if isinstance(scan_callback_fn, types.FunctionType):  # 콜백 함수가 존재하는가?
                            scan_callback_fn(ret_value)  # 콜백 함수 호출

                    if is_sub_dir_scan:
                        # 폴더 안의 파일들을 검사대상 리스트에 추가
                        flist = glob.glob(real_name + os.sep + '*')
                        tmp_flist = []

                        for rfname in flist:
                            tmp_info = k2file.FileStruct(rfname)
                            tmp_flist.append(tmp_info)

                        file_scan_list = tmp_flist + file_scan_list

                    if self.options['opt_nor']:  # 하위 폴더 검색 옵션이 체크
                        is_sub_dir_scan = False  # 하위 폴더 검색 하지 않음
                elif os.path.isfile(real_name) or t_file_info.is_archive():  # 검사 대상이 파일인가? 압축 해제 대상인가?
                    self.result['Files'] += 1  # 파일 개수 카운트

                    # 압축된 파일이면 해제하기
                    if real_name == '':  # 이미 실제 파일명이 존재하지 않으면 압축 파일임
                        ret = self.unarc(t_file_info)
                        if ret:
                            t_file_info = ret  # 압축 결과물이 존재하면 파일 정보 교체

                    # 2. 포맷 분석
                    ff = self.format(t_file_info)

                    # 파일로 악성코드 검사
                    ret, vname, mid, scan_state, eid = self.__scan_file(t_file_info, ff)
                    if self.options['opt_feature'] != 0xffffffff:  # 인공지능 AI를 위한 Feature 추출
                        self.__feature_file(t_file_info, ff, self.options['opt_feature'])

                    if ret:  # 악성코드 진단 개수 카운트
                        import kernel

                        if scan_state == kernel.INFECTED:
                            self.result['Infected_files'] += 1
                        elif scan_state == kernel.SUSPECT:
                            self.result['Suspect_files'] += 1
                        elif scan_state == kernel.WARNING:
                            self.result['Warnings'] += 1

                        self.identified_virus.update([vname])

                    # 콜백 호출 또는 검사 리턴값 생성
                    ret_value['result'] = ret  # 악성코드 발견 여부
                    ret_value['engine_id'] = eid  # 엔진 ID
                    ret_value['virus_name'] = vname  # 악성코드 이름
                    ret_value['virus_id'] = mid  # 악성코드 ID
                    ret_value['scan_state'] = scan_state  # 악성코드 검사 상태
                    ret_value['file_struct'] = t_file_info  # 검사 파일 이름

                    # 격리 시점 체크하기?
                    if move_master_file:
                        if t_master_file != t_file_info.get_master_filename():
                            # print 'move 2 :', t_master_file
                            self.__quarantine_file(t_master_file)
                            move_master_file = False

                    if ret_value['result']:  # 악성코드 발견인가?
                        if isinstance(scan_callback_fn, types.FunctionType):
                            action_type = scan_callback_fn(ret_value)

                            if self.options['opt_move']:
                                if t_file_info.get_additional_filename() == '':
                                    # print 'move 1 :', t_file_info.get_master_filename()
                                    self.__quarantine_file(t_file_info.get_master_filename())
                                    move_master_file = False
                                else:
                                    move_master_file = True
                                    t_master_file = t_file_info.get_master_filename()
                            else:  # 격리 옵션이 치료 옵션보다 우선 적용
                                if action_type == k2const.K2_ACTION_QUIT:  # 종료인가?
                                    return 0

                                self.__disinfect_process(ret_value, action_type)

                                # 악성코드 치료 후 해당 파일이 삭제되지 않고 존재한다면 다시 검사 필요
                                if self.options['opt_dis']:  # 치료 옵션이 존재할때에만... 실행
                                    if os.path.exists(t_file_info.get_filename()):
                                        t_file_info.set_modify(True)
                                        file_scan_list = [t_file_info] + file_scan_list
                                    else:
                                        # 압축 파일 최종 치료 처리
                                        self.__update_process(t_file_info)
                    else:
                        if self.options['opt_list']:  # 모든 리스트 출력인가?
                            if isinstance(scan_callback_fn, types.FunctionType):
                                scan_callback_fn(ret_value)

                        # 압축 파일 최종 치료 처리
                        self.__update_process(t_file_info)

                        # 이미 해당 파일이 악성코드라고 판명되었다면
                        # 그 파일을 압축해제해서 내부를 볼 필요는 없다.
                        # 압축 파일이면 검사대상 리스트에 추가
                        arc_file_list = self.arclist(t_file_info, ff)
                        if len(arc_file_list):
                            file_scan_list = arc_file_list + file_scan_list
            except KeyboardInterrupt:
                return 1  # 키보드 종료

        self.__update_process(None, True)  # 최종 파일 정리

        # 격리 시점 체크하기?
        if move_master_file:
            # print 'move 3 :', t_master_file
            self.__quarantine_file(t_master_file)
            move_master_file = False

        return 0  # 정상적으로 검사 종료

    # ---------------------------------------------------------------------
    # __quarantine_file(self, filename)
    # 악성코드 파일을 격리소로 이동한다
    # 입력값 : filename - 격리 대상 파일 이름
    # ---------------------------------------------------------------------
    def __quarantine_file(self, filename):
        try:
            if self.options['infp_path']:
                t_filename = os.path.split(filename)[-1]
                # 격리소에 동일한 파일 이름이 존재하는지 체크
                fname = self.options['infp_path'] + os.sep + t_filename
                t_quarantine_fname = fname
                count = 1
                while True:
                    if os.path.exists(t_quarantine_fname):
                        t_quarantine_fname = '%s (%d)' % (fname, count)  # 유니크한 파일 이름 생성
                        count += 1
                    else:
                        break

                shutil.move(filename, t_quarantine_fname)  # 격리소로 이동
                if isinstance(self.quarantine_callback_fn, types.FunctionType):
                    self.quarantine_callback_fn(filename, True)
        except shutil.Error:
            if isinstance(self.quarantine_callback_fn, types.FunctionType):
                self.quarantine_callback_fn(filename, False)

    # ---------------------------------------------------------------------
    # __update_process(self, file_struct, immediately_flag=False)
    # update_info를 갱신한다.
    # 입력값 : file_struct        - 파일 정보 구조체
    #          immediately_flag   - update_info 모든 정보 갱신 여부
    # ---------------------------------------------------------------------
    def __update_process(self, file_struct, immediately_flag=False):
        # 압축 파일 정보의 재압축을 즉시하지 않고 내부 구성을 확인하여 처리한다.
        if immediately_flag is False:
            if len(self.update_info) == 0:  # 아무런 파일이 없으면 추가
                self.update_info.append(file_struct)
            else:
                n_file_info = file_struct  # 현재 작업 파일 정보
                p_file_info = self.update_info[-1]  # 직전 파일 정보

                # 마스터 파일이 같은가? (압축 엔진이 있을때만 유효)
                if p_file_info.get_master_filename() == n_file_info.get_master_filename() and \
                        n_file_info.get_archive_engine_name() is not None:
                    if p_file_info.get_level() <= n_file_info.get_level():
                        # 마스터 파일이 같고 계속 압축 깊이가 깊어지면 계속 누적
                        self.update_info.append(n_file_info)
                    else:
                        ret_file_info = p_file_info
                        while ret_file_info.get_level() != n_file_info.get_level():
                            # 마스터 파일이 같고 압축 깊이가 달라지면 내부 파일 업데이트 시점
                            ret_file_info = self.__update_arc_file_struct(ret_file_info)
                            self.update_info.append(ret_file_info)  # 결과 파일 추가
                        self.update_info.append(n_file_info)  # 다음 파일 추가
                else:
                    # 새로운 파일이 시작되므로 self.update_info 내부 모두 정리
                    if len(self.update_info) == 1:  # 정리 시점이나 정리 대상이 없다면 다음 파일로
                        self.update_info = [file_struct]
                    else:
                        immediately_flag = True

        # 압축 파일 정보를 이용해 즉시 압축하여 최종 마스터 파일로 재조립한다.
        if immediately_flag and len(self.update_info) > 1:
                ret_file_info = None

                while len(self.update_info):
                    p_file_info = self.update_info[-1]  # 직전 파일 정보
                    ret_file_info = self.__update_arc_file_struct(p_file_info)

                    if len(self.update_info):  # 최상위 파일이 아니면 하위 결과 추가
                        self.update_info.append(ret_file_info)

                if isinstance(self.update_callback_fn, types.FunctionType) and ret_file_info:
                    self.update_callback_fn(ret_file_info)

                self.update_info = [file_struct]

    # ---------------------------------------------------------------------
    # __update_arc_file_struct(self, p_file_info)
    # update_info 내부의 압축을 처리한다.
    # 입력값 : p_file_info - update_info의 마지막 파일 정보 구조체
    # 리턴값 : 갱신된 파일 정보 구조체
    # ---------------------------------------------------------------------
    def __update_arc_file_struct(self, p_file_info):
        import kernel

        # 실제 압축 파일 이름이 같은 파일을 모두 추출한다.
        t = []

        arc_level = p_file_info.get_level()

        while len(self.update_info):
            if self.update_info[-1].get_level() == arc_level:
                t.append(self.update_info.pop())
            else:
                break

        t.reverse()  # 순위를 바꾼다.

        # 리턴값이 될 파일 정보 (압축 파일의 최상위 파일)
        ret_file_info = self.update_info.pop()

        # 업데이트 대상 파일들이 수정 여부를 체크한다
        b_update = False

        for finfo in t:
            if finfo.is_modify():
                b_update = True
                break

        if b_update:  # 수정된 파일이 존재한다면 재압축 진행
            arc_name = t[0].get_archive_filename()
            arc_engine_id = t[0].get_archive_engine_name()
            can_arc = t[-1].get_can_archive()

            # 재압축 진행
            # 파일 압축 (t) -> arc_name

            if can_arc == kernel.MASTER_PACK:  # 재압축
                for inst in self.kavmain_inst:
                    try:
                        ret = inst.mkarc(arc_engine_id, arc_name, t)
                        if ret:  # 최종 압축 성공
                            break
                    except AttributeError:
                        continue
            elif can_arc == kernel.MASTER_DELETE:  # 삭제
                os.remove(arc_name)

            ret_file_info.set_modify(True)  # 수정 여부 표시

        # 압축된 파일들 모두 삭제
        for tmp in t:
            t_fname = tmp.get_filename()
            # 플러그인 엔진에 의해 파일이 치료(삭제) 되었을 수 있음
            if os.path.exists(t_fname):
                os.remove(t_fname)
                # print '[*] Remove :', t_fname

        return ret_file_info

    # ---------------------------------------------------------------------
    # __disinfect_process(self, ret_value, action_type)
    # 악성코드를 치료한다.
    # 입력값 : ret_value            - 악성코드 검사 결과
    #          action_type            - 악성코드 치료 or 삭제 처리 여부
    # 리턴값 : 치료 성공 여부 (True or False)
    # ---------------------------------------------------------------------
    def __disinfect_process(self, ret_value, action_type):
        if action_type == k2const.K2_ACTION_IGNORE:  # 치료에 대해 무시
            return

        t_file_info = ret_value['file_struct']  # 검사 파일 정보
        mid = ret_value['virus_id']
        eid = ret_value['engine_id']

        d_fname = t_file_info.get_filename()
        d_ret = False

        if action_type == k2const.K2_ACTION_DISINFECT:  # 치료 옵션이 설정되었나?
            d_ret = self.disinfect(d_fname, mid, eid)
            if d_ret:
                self.result['Disinfected_files'] += 1  # 치료 파일 수
        elif action_type == k2const.K2_ACTION_DELETE:  # 삭제 옵션이 설정되었나?
            try:
                os.remove(d_fname)
                d_ret = True
                self.result['Deleted_files'] += 1  # 삭제 파일 수
            except IOError:
                d_ret = False

        t_file_info.set_modify(d_ret)  # 치료(수정/삭제) 여부 표시

        if isinstance(self.disinfect_callback_fn, types.FunctionType):
            self.disinfect_callback_fn(ret_value, action_type)

    # ---------------------------------------------------------------------
    # __scan_file(self, file_struct, fileformat)
    # 플러그인 엔진에게 악성코드 검사를 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    #         format      - 미리 분석한 파일 포맷 분석 정보
    # 리턴값 : (악성코드 발견 유무, 악성코드 이름, 악성코드 ID, 악성코드 검사 상태, 플러그인 엔진 ID)
    # ---------------------------------------------------------------------
    def __scan_file(self, file_struct, fileformat):
        import kernel

        if self.debug:
            print '[*] KavMain.__scan_file() :'

        fp = None
        mm = None

        try:
            ret = False
            vname = ''
            mid = -1
            scan_state = kernel.NOT_FOUND
            eid = -1

            filename = file_struct.get_filename()  # 검사 대상 파일 이름 추출
            filename_ex = file_struct.get_additional_filename()  # 압축 내부 파일명

            # 파일 크기가 0이면 악성코드 검사를 할 필요가 없다.
            if os.path.getsize(filename) == 0:
                raise EngineKnownError('File Size is Zero!')

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for i, inst in enumerate(self.kavmain_inst):
                try:
                    ret, vname, mid, scan_state = inst.scan(mm, filename, fileformat, filename_ex)
                    if ret:  # 악성코드 발견하면 추가 악성코드 검사를 중단한다.
                        eid = i  # 악성코드를 발견한 플러그인 엔진 ID

                        if self.debug:
                            print '    [-] %s.__scan_file() : %s' % (inst.__module__, vname)

                        break
                except AttributeError:
                    continue

            if mm:
                mm.close()

            if fp:
                fp.close()

            return ret, vname, mid, scan_state, eid
        except EngineKnownError:
            pass
        except ValueError:
            pass
        except KeyboardInterrupt:
            pass
        except:
            self.result['IO_errors'] += 1  # 파일 I/O 오류 발생 수

        if mm:
            mm.close()

        if fp:
            fp.close()

        return False, '', -1, kernel.NOT_FOUND, -1

    # ---------------------------------------------------------------------
    # __feature_file(self, file_struct, fileformat)
    # 플러그인 엔진에게 악성코드 feature 추출을 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    #         format      - 미리 분석한 파일 포맷 분석 정보
    #         malware_id  - Feature 헤더에 저장될 malware_id
    # 리턴값 : Feature 성공 여부 (True or False)
    # ---------------------------------------------------------------------
    def __feature_file(self, file_struct, fileformat, malware_id):
        if self.debug:
            print '[*] KavMain.__feature_file() :'

        try:
            ret = False

            filename = file_struct.get_filename()  # 검사 대상 파일 이름 추출
            filename_ex = file_struct.get_additional_filename()  # 압축 내부 파일명

            # 파일 크기가 0이면 Feature 추출을 할 필요가 없다.
            if os.path.getsize(filename) == 0:
                raise EngineKnownError('File Size is Zero!')

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for i, inst in enumerate(self.kavmain_inst):
                try:
                    ret = inst.feature(mm, filename, fileformat, filename_ex, malware_id)
                    if ret:  # Feature 추출 완료
                        break
                except AttributeError:
                    continue

            if mm:
                mm.close()
            if fp:
                fp.close()

            return ret
        except IOError:
            pass
        except EngineKnownError:
            pass
        except WindowsError:
            pass

        return False

    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id, engine_id)
    # 플러그인 엔진에게 악성코드 치료를 요청한다.
    # 입력값 : filename   - 악성코드 치료 대상 파일 이름
    #          malware_id - 감염된 악성코드 ID
    #          engine_id  - 악성코드를 발견한 플러그인 엔진 ID
    # 리턴값 : 악성코드 치료 성공 여부
    # ---------------------------------------------------------------------
    def disinfect(self, filename, malware_id, engine_id):
        ret = False

        if self.debug:
            print '[*] KavMain.disinfect() :'

        try:
            # 악성코드를 진단한 플러그인 엔진에게만 치료를 요청한다.
            inst = self.kavmain_inst[engine_id]
            ret = inst.disinfect(filename, malware_id)

            if self.debug:
                print '    [-] %s.disinfect() : %s' % (inst.__module__, ret)
        except AttributeError:
            pass

        return ret

    # ---------------------------------------------------------------------
    # unarc(self, file_struct)
    # 플러그인 엔진에게 압축 해제를 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    # 리턴값 : 압축 해제된 파일 정보 or None
    # ---------------------------------------------------------------------
    def unarc(self, file_struct):
        import kernel

        rname_struct = None

        try:
            if file_struct.is_archive():  # 압축인가?
                arc_engine_id = file_struct.get_archive_engine_name()  # 엔진 ID
                arc_name = file_struct.get_archive_filename()
                name_in_arc = file_struct.get_filename_in_archive()

                # 압축 엔진 모듈의 unarc 멤버 함수 호출
                for inst in self.kavmain_inst:
                    try:
                        unpack_data = inst.unarc(arc_engine_id, arc_name, name_in_arc)

                        if unpack_data:
                            # 압축을 해제하여 임시 파일을 생성
                            rname = tempfile.mktemp(prefix='ktmp')
                            fp = open(rname, 'wb')
                            fp.write(unpack_data)
                            fp.close()
                            # print '[*] Make   :', rname

                            # 압축 엔진의 마스터 파일 처리 방법은 getinfo에서 확인 가능함
                            try:
                                can_arc = inst.getinfo()['make_arc_type']
                            except KeyError:
                                can_arc = kernel.MASTER_IGNORE
                            except AttributeError:
                                can_arc = kernel.MASTER_IGNORE

                            rname_struct = file_struct
                            rname_struct.set_filename(rname)
                            rname_struct.set_can_archive(can_arc)

                            # 악성코드 패턴 생성을 위한 모드인가?
                            if self.options['opt_sigtool']:
                                # 임시 파일을 현재 폴더에 복사
                                sig_fname = os.path.split(rname)[1]
                                shutil.copy(rname, sig_fname)

                                # sigtool.log 파일을 생성한다.
                                msg = '%s : %s\n' % (sig_fname, rname_struct.get_additional_filename())
                                fp = open('sigtool.log', 'at')
                                fp.write(msg)
                                fp.close()

                            break  # 압축이 풀렸으면 종료
                    except AttributeError:
                        continue
                    except struct.error:
                        continue
                else:  # end for
                    # 어떤 엔진도 압축 해제를 하지 못한 경우
                    # 임시 파일만 생성한 뒤 종료
                    rname = tempfile.mktemp(prefix='ktmp')
                    fp = open(rname, 'wb')
                    fp.close()
                    # print '[*] Make   :', rname

                    rname_struct = file_struct
                    rname_struct.set_filename(rname)
                    rname_struct.set_can_archive(kernel.MASTER_IGNORE)
                return rname_struct
        except IOError:
            pass

        return None

    # ---------------------------------------------------------------------
    # arclist(self, file_struct, fileformat)
    # 플러그인 엔진에게 압축 파일의 내부 리스트를 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    #         format      - 미리 분석한 파일 포맷 분석 정보
    # 리턴값 : [압축 파일 내부 리스트] or []
    # ---------------------------------------------------------------------
    def arclist(self, file_struct, fileformat):
        import kernel

        file_scan_list = []  # 검사 대상 정보를 모두 가짐 (k2file.FileStruct)

        rname = file_struct.get_filename()
        deep_name = file_struct.get_additional_filename()
        mname = file_struct.get_master_filename()
        level = file_struct.get_level()

        # 압축 엔진 모듈의 arclist 멤버 함수 호출
        for inst in self.kavmain_inst:
            is_archive_engine = False
            can_arc = kernel.MASTER_IGNORE

            try:
                ret_getinfo = inst.getinfo()
                if 'engine_type' in ret_getinfo:
                    if ret_getinfo['engine_type'] == kernel.ARCHIVE_ENGINE:  # 압축 엔진 Type
                        is_archive_engine = True

                if 'make_arc_type' in ret_getinfo:
                    can_arc = ret_getinfo['make_arc_type']
            except AttributeError:
                pass

            try:
                arc_list = []  # 압축 파일 리스트

                if self.options['opt_arc']:
                    # 압축 검사 옵션이 있으면 모두 호출
                    arc_list = inst.arclist(rname, fileformat)

                    # 단, 카운트는 압축 엔진일때만 처리
                    if len(arc_list) and is_archive_engine:
                        self.result['Packed'] += 1
                else:
                    # 압축 엔진 Type이 아니면 일반 엔진 호출
                    if not is_archive_engine:
                        arc_list = inst.arclist(rname, fileformat)
            except AttributeError:
                pass

            if len(arc_list):  # 압축 리스트가 존재한다면 추가하고 종료
                for alist in arc_list:
                    arc_id = alist[0]  # 항상 압축 엔진 ID가 들어옴
                    name = alist[1]  # 압축 파일의 내부 파일 이름

                    if len(deep_name):  # 압축 파일 내부 표시용
                        dname = '%s/%s' % (deep_name, name)
                    else:
                        dname = '%s' % name

                    fs = k2file.FileStruct()
                    fs.set_archive(arc_id, rname, name, dname, mname, False, can_arc, level+1)
                    file_scan_list.append(fs)

                # break

        return file_scan_list

    # ---------------------------------------------------------------------
    # format(self, file_struct)
    # 플러그인 엔진에게 파일 포맷 분석을 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    # 리턴값 : {파일 포맷 분석 정보} or {}
    # ---------------------------------------------------------------------
    def format(self, file_struct):
        ret = {}
        filename = file_struct.get_filename()
        filename_ex = file_struct.get_additional_filename()  # 압축 내부 파일명

        fp = None
        mm = None

        try:
            # 파일 크기가 0이면 포맷 검사를 할 필요가 없다.
            if os.path.getsize(filename) == 0:
                raise EngineKnownError('File Size is Zero!')

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            # 엔진 모듈의 format 멤버 함수 호출
            for inst in self.kavmain_inst:
                try:
                    ff = inst.format(mm, filename, filename_ex)
                    if ff:
                        ret.update(ff)
                except AttributeError:
                    pass
        except IOError:
            pass
        except EngineKnownError:
            pass
        except ValueError:
            pass
        except WindowsError:
            pass

        if mm:
            mm.close()

        if fp:
            fp.close()

        return ret

    # ---------------------------------------------------------------------
    # getversion(self)
    # 전체 플러그인 엔진의 최신 버전 정보를 전달한다.
    # 리턴값 : 최신 버전 정보
    # ---------------------------------------------------------------------
    def get_version(self):
        return self.max_datetime

    # ---------------------------------------------------------------------
    # set_options(self, options)
    # 옵션을 설정한다.
    # ---------------------------------------------------------------------
    def set_options(self, options=None):
        if options:
            self.options['opt_arc'] = options.opt_arc
            self.options['opt_nor'] = options.opt_nor
            self.options['opt_list'] = options.opt_list
            self.options['opt_move'] = options.opt_move
            self.options['opt_dis'] = options.opt_dis
            self.options['infp_path'] = options.infp_path
            self.options['opt_verbose'] = options.opt_verbose
            self.options['opt_sigtool'] = options.opt_sigtool
            self.options['opt_feature'] = options.opt_feature
        else:  # 기본값 설정
            self.options['opt_arc'] = False
            self.options['opt_nor'] = False
            self.options['opt_list'] = False
            self.options['opt_move'] = False
            self.options['opt_dis'] = False
            self.options['infp_path'] = None
            self.options['opt_verbose'] = False
            self.options['opt_sigtool'] = False
            self.options['opt_feature'] = 0xffffffff
        return True

    # -----------------------------------------------------------------
    # set_result(self)
    # 백신 엔진의 악성코드 검사 결과를 초기화 한다.
    # -----------------------------------------------------------------
    def set_result(self):
        self.result['Folders'] = 0  # 폴더 수
        self.result['Files'] = 0  # 파일 수
        self.result['Packed'] = 0  # 압축 파일 수
        self.result['Infected_files'] = 0  # 발견된 전체 악성코드 수 (감염)
        self.result['Suspect_files'] = 0  # 발견된 전체 악성코드 수 (추정)
        self.result['Warnings'] = 0  # 발견된 전체 악성코드 수 (경고)
        self.result['Identified_viruses'] = 0  # 발견된 유니크한 악성코드 수
        self.result['Disinfected_files'] = 0  # 치료한 파일 수
        self.result['Deleted_files'] = 0  # 삭제한 파일 수
        self.result['IO_errors'] = 0  # 파일 I/O 에러 발생 수

    # -----------------------------------------------------------------
    # get_result(self)
    # 백신 엔진의 악성코드 검사 결과를 얻는다.
    # 리턴값 : 악성코드 검사 결과
    # -----------------------------------------------------------------
    def get_result(self):
        # 지금까지 발견한 유티크한 악성코드의 수를 카운트한다.
        self.result['Identified_viruses'] = len(self.identified_virus)
        return self.result

    # -----------------------------------------------------------------
    # get_signum(self)
    # 백신 엔진이 진단/치료 가능한 악성코드 수를 얻는다.
    # 리턴값 : 진단/치료 가능한 악성코드 수
    # -----------------------------------------------------------------
    def get_signum(self):
        signum = 0  # 진단/치료 가능한 악성코드 수

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()

                # 플러그인 엔진 정보에 진단/치료 가능 악성코드 수 누적
                if 'sig_num' in ret:
                    signum += ret['sig_num']
            except AttributeError:
                continue

        return signum
