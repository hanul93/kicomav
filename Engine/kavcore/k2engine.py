# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import imp
import StringIO
import datetime
import types
import mmap
import glob
import re
import shutil
import struct
import zipfile
import hashlib

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
    # __init__(self, verbose=False)
    # 클래스를 초기화 한다.
    # 인자값 : verbose - 디버그 여부
    # ---------------------------------------------------------------------
    def __init__(self, verbose=False):
        self.verbose = verbose  # 디버깅 여부

        self.plugins_path = None  # 플러그인 경로
        self.temp_path = None  # 임시 폴더 클래스
        self.kmdfiles = []  # 우선순위가 기록된 kmd 리스트
        self.kmd_modules = []  # 메모리에 로딩된 모듈

        # 플러그 엔진의 가장 최신 시간 값을 가진다.
        # 초기값으로는 1980-01-01을 지정한다.
        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)

        # 키콤백신이 만든 임시 파일 모두 제거 (운영체제의 임시 폴더를 초기화)
        k2file.K2Tempfile().removetempdir()

        self.__set_temppath()  # 임시 폴더 초기화

    # ---------------------------------------------------------------------
    # __del__(self)
    # 클래스를 종료 한다.
    # ---------------------------------------------------------------------
    def __del__(self):
        # 키콤백신이 만든 임시 파일 모두 제거
        self.temp_path.removetempdir()

        try:  # 해당 pid 폴더도 삭제한다.
            shutil.rmtree(self.temp_path.temp_path)
        except OSError:
            pass

    # ---------------------------------------------------------------------
    # set_plugins(self, plugins_path)
    # 주어진 경로에서 플러그인 엔진을 로딩 준비한다.
    # 인자값 : plugins_path - 플러그인 엔진 경로
    # 리턴값 : 성공 여부
    # ---------------------------------------------------------------------
    def set_plugins(self, plugins_path, callback_fn=None):
        # 플러그인 경로를 저장한다.
        self.plugins_path = plugins_path

        # 우선순위를 알아낸다.
        if k2const.K2DEBUG:
            pu = None
            ret = self.__get_kmd_list(os.path.join(plugins_path, 'kicom.lst'), pu)
        else:
            # 공개키를 로딩한다.
            pu = k2rsa.read_key(os.path.join(plugins_path, 'key.pkr'))
            if not pu:
                return False

            ret = self.__get_kmd_list(os.path.join(plugins_path, 'kicom.kmd'), pu)

        if not ret:  # 로딩할 KMD 파일이 없다.
            return False

        if self.verbose:
            print '[*] kicom.%s :' % ('lst' if k2const.K2DEBUG else 'kmd')
            print '   ', self.kmdfiles

        # 우선순위대로 KMD 파일을 로딩한다.
        for kmd_name in self.kmdfiles:
            kmd_path = os.path.join(plugins_path, kmd_name)
            try:
                name = kmd_name.split('.')[0]
                if k2const.K2DEBUG:
                    k = None
                    module = imp.load_source(name, os.path.splitext(kmd_path)[0] + '.py')
                    try:
                        os.remove(os.path.splitext(kmd_path)[0] + '.pyc')
                    except OSError:
                        pass
                else:
                    k = k2kmdfile.KMD(kmd_path, pu)  # 모든 KMD 파일을 복호화한다.
                    data = k.body
                    module = k2kmdfile.load(name, data)

                if module:  # 메모리 로딩 성공
                    self.kmd_modules.append(module)
                    # 메모리 로딩에 성공한 KMD에서 플러그 엔진의 시간 값 읽기
                    # 최신 업데이트 날짜가 된다.
                    self.__get_last_kmd_build_time(k)
                else:  # 메모리 로딩 실패
                    if isinstance(callback_fn, types.FunctionType):
                        callback_fn(name)
            except IOError:
                pass
            except k2kmdfile.KMDFormatError:  # 다른키로 암호호화 한 엔진은 무시
                pass

        # 악성코드 패턴에서 최신 시간 값을 얻는다.
        fl = glob.glob(os.path.join(plugins_path, '*.n??'))
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

        if self.verbose:
            print '[*] kmd_modules :'
            print '   ', self.kmd_modules
            print '[*] Last updated %s UTC' % self.max_datetime.ctime()

        return True

    # ---------------------------------------------------------------------
    # __set_temppath(self)
    # 주어진 임시 폴더를 설정한다.
    # ---------------------------------------------------------------------
    def __set_temppath(self):
        # 임시 폴더를 지정한다.
        self.temp_path = k2file.K2Tempfile()

    # ---------------------------------------------------------------------
    # create_instance(self)
    # 백신 엔진의 인스턴스를 생성한다.
    # ---------------------------------------------------------------------
    def create_instance(self):
        ei = EngineInstance(self.plugins_path, self.temp_path, self.max_datetime, self.verbose)
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
        if k2const.K2DEBUG:
            t_datetime = datetime.datetime.utcnow()
        else:
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

        if k2const.K2DEBUG:  # 디버깅에서는 복호화 없이 파일을 읽는다.
            lst_data = open(kicom_kmd_file, 'rb').read()
        else:
            k = k2kmdfile.KMD(kicom_kmd_file, pu)  # kicom.kmd 파일을 복호화한다.
            lst_data = k.body

        if lst_data:  # kicom.kmd 읽혔는가?
            msg = StringIO.StringIO(lst_data)

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
    # __init__(self, plugins_path, temp_path, max_datetime, verbose=False)
    # 클래스를 초기화 한다.
    # 인자값 : plugins_path - 플러그인 엔진 경로
    #         temp_path    - 임시 폴더 클래스
    #         max_datetime - 플러그인 엔진의 최신 시간 값
    #         verbose      - 디버그 여부
    # ---------------------------------------------------------------------
    def __init__(self, plugins_path, temp_path, max_datetime, verbose=False):
        self.verbose = verbose  # 디버깅 여부

        self.plugins_path = plugins_path  # 플러그인 경로
        self.temp_path = temp_path  # 임시 폴더 클래스
        self.max_datetime = max_datetime  # 플러그 엔진의 가장 최신 시간 값

        self.options = {}  # 옵션
        self.set_options()  # 기본 옵션을 설정한다.

        self.kavmain_inst = []  # 모든 플러그인의 KavMain 인스턴스

        self.update_info = []  # 압축 파일 최종 치료를 위한 압축 리스트

        self.result = {}
        self.identified_virus = set()  # 유니크한 악성코드 개수를 구하기 위해 사용
        self.set_result()  # 악성코드 검사 결과를 초기화한다.

        self.quarantine_name = {}  # 격리소로 파일 이동시 악성코드 이름 폴더로 이동시 사용

        self.disinfect_callback_fn = None  # 악성코드 치료 콜백 함수
        self.update_callback_fn = None  # 악성코드 압축 최종 치료 콜백 함수
        self.quarantine_callback_fn = None  # 악성코드 격리 콜백 함수

        self.disable_path = re.compile(r'/<\w+>')

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
            if self.verbose:
                print '[*] Count of KavMain : %d' % (len(self.kavmain_inst))
            return True
        else:
            return False

    # ---------------------------------------------------------------------
    # init(self, callback_fn)
    # 플러그인 엔진 전체를 초기화한다.
    # 입력값 : callback_fn - 콜백함수 (생략 가능)
    # 리턴값 : 성공 여부
    # ---------------------------------------------------------------------
    def init(self, callback_fn=None):
        # self.kavmain_inst는 최종 인스턴스가 아니다.
        # init 초기화 명령어를 실행해서 정상인 플러그인만 최종 등록해야 한다.
        t_kavmain_inst = []  # 최종 인스턴스 리스트

        if self.verbose:
            print '[*] KavMain.init() :'

        for inst in self.kavmain_inst:
            try:
                # 플러그인 엔진의 init 함수 호출
                if k2const.K2DEBUG:  # 디버그 모드일때만 verbose 옵션 동작
                    ret = inst.init(self.plugins_path, self.options['opt_verbose'])
                else:
                    ret = inst.init(self.plugins_path, False)

                if not ret:  # 성공
                    t_kavmain_inst.append(inst)

                    if self.verbose:
                        print '    [-] %s.init() : %d' % (inst.__module__, ret)
                else:  # 실패
                    if isinstance(callback_fn, types.FunctionType):
                        callback_fn(inst.__module__)
            except AttributeError:
                continue

        self.kavmain_inst = t_kavmain_inst  # 최종 KavMain 인스턴스 등록

        if len(self.kavmain_inst):  # KavMain 인스턴스가 하나라도 있으면 성공
            if self.verbose:
                print '[*] Count of KavMain.init() : %d' % (len(self.kavmain_inst))
            return True
        else:
            return False

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진 전체를 종료한다.
    # ---------------------------------------------------------------------
    def uninit(self):
        if self.verbose:
            print '[*] KavMain.uninit() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.uninit()
                if self.verbose:
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

        if self.verbose:
            print '[*] KavMain.getinfo() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.getinfo()
                ginfo.append(ret)

                if self.verbose:
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

        if self.verbose:
            print '[*] KavMain.listvirus() :'

        for inst in self.kavmain_inst:
            try:
                ret = inst.listvirus()

                # callback 함수가 있다면 callback 함수 호출
                if isinstance(cb_fn, types.FunctionType):
                    cb_fn(inst.__module__, ret)
                else:  # callback 함수가 없으면 악성코드 목록을 누적하여 리턴
                    vlist += ret

                if self.verbose:
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
        import kernel

        # 파일을 한 개씩 검사 요청할 경우 압축으로 인해 self.update_info 정보가 누적 된 경우
        self.update_info = []
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
                    real_name = os.path.abspath(real_name)

                    # 콜백 호출 또는 검사 리턴값 생성
                    ret_value['result'] = False  # 폴더이므로 악성코드 없음
                    ret_value['filename'] = real_name  # 검사 파일 이름
                    ret_value['file_struct'] = t_file_info  # 검사 파일 이름
                    ret_value['scan_state'] = kernel.NOT_FOUND  # 악성코드 없음

                    self.result['Folders'] += 1  # 폴더 개수 카운트

                    if self.options['opt_list']:  # 옵션 내용 중 모든 리스트 출력인가?
                        self.call_scan_callback_fn(scan_callback_fn, ret_value)

                    if is_sub_dir_scan:
                        # 폴더 안의 파일들을 검사대상 리스트에 추가
                        flist = glob.glob(os.path.join(real_name, '*'))
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
                        ret, ret_fi = self.unarc(t_file_info)
                        if ret:
                            t_file_info = ret_fi  # 압축 결과물이 존재하면 파일 정보 교체
                        else:  # 압축 해제 오류 발생
                            if ret_fi:  # 오류 메시지가 존재하는가?
                                # 콜백 호출 또는 검사 리턴값 생성
                                ret_value['result'] = ret  # 악성코드 발견 여부
                                ret_value['engine_id'] = -1  # 엔진 ID
                                ret_value['virus_name'] = ret_fi  # 에러 메시지로 대체
                                ret_value['virus_id'] = -1  # 악성코드 ID
                                ret_value['scan_state'] = kernel.ERROR  # 악성코드 검사 상태
                                ret_value['file_struct'] = t_file_info  # 검사 파일 이름

                                if self.options['opt_list']:  # 모든 리스트 출력인가?
                                    self.call_scan_callback_fn(scan_callback_fn, ret_value)

                                continue

                    # 비정상 종료의 파일을 찾기 위해 추가된 모드
                    if self.options['opt_debug']:  # 디버깅 모드인가?
                        ret_value['result'] = False  # 악성코드 발견 여부
                        ret_value['engine_id'] = -1  # 엔진 ID
                        ret_value['virus_name'] = 'debug'  # 에러 메시지로 대체
                        ret_value['virus_id'] = -1  # 악성코드 ID
                        ret_value['scan_state'] = kernel.ERROR  # 악성코드 검사 상태
                        ret_value['file_struct'] = t_file_info  # 검사 파일 이름

                        self.call_scan_callback_fn(scan_callback_fn, ret_value)

                    # 2. 포맷 분석
                    ff = self.format(t_file_info)

                    # 파일로 악성코드 검사
                    ret, vname, mid, scan_state, eid = self.__scan_file(t_file_info, ff)
                    if self.options['opt_feature'] != 0xffffffff:  # 인공지능 AI를 위한 Feature 추출
                        self.__feature_file(t_file_info, ff, self.options['opt_feature'])

                    if ret:  # 악성코드 진단 개수 카운트
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
                            self.__arcclose()
                            self.__quarantine_file(t_master_file)
                            move_master_file = False

                    if ret_value['result']:  # 악성코드 발견인가?
                        t_master_file = t_file_info.get_master_filename()

                        # 격리소에 생성시 악성코드 이름 부여할 경우 사용할 목적임
                        if not self.quarantine_name.get(t_master_file, None):
                            self.quarantine_name[t_master_file] = ret_value['virus_name']

                        action_type = self.call_scan_callback_fn(scan_callback_fn, ret_value)

                        if self.options['opt_move'] or self.options['opt_copy']:
                            if t_file_info.get_additional_filename() == '':
                                # print 'move 1 :', t_master_file
                                self.__arcclose()
                                self.__quarantine_file(t_master_file)
                                move_master_file = False
                            else:
                                move_master_file = True
                        else:  # 격리 옵션이 치료 옵션보다 우선 적용
                            if action_type == k2const.K2_ACTION_QUIT:  # 종료인가?
                                return 0

                            d_ret = self.__disinfect_process(ret_value, action_type)

                            if d_ret:  # 치료 성공?
                                # 악성코드 치료 후 해당 파일이 삭제되지 않고 존재한다면 다시 검사 필요
                                if self.options['opt_dis'] or \
                                   (action_type == k2const.K2_ACTION_DISINFECT or action_type == k2const.K2_ACTION_DELETE):
                                    # 치료 옵션이 존재할때에만... 실행
                                    if os.path.exists(t_file_info.get_filename()):
                                        t_file_info.set_modify(True)
                                        file_scan_list = [t_file_info] + file_scan_list
                                    else:
                                        # 압축 파일 최종 치료 처리
                                        self.__update_process(t_file_info)
                    else:
                        # 압축 파일 최종 치료 처리
                        self.__update_process(t_file_info)

                        # 이미 해당 파일이 악성코드라고 판명되었다면
                        # 그 파일을 압축해제해서 내부를 볼 필요는 없다.
                        # 압축 파일이면 검사대상 리스트에 추가
                        try:
                            arc_file_list = self.arclist(t_file_info, ff)
                            if len(arc_file_list):
                                file_scan_list = arc_file_list + file_scan_list

                            '''
                            # 한 개의 정보가 추가되는 것 중에 /<...> 형태로 입력되는 파일이면 파일 카운트를 하지 않는다.
                            if len(arc_file_list) == 1 and \
                               self.disable_path.search(arc_file_list[0].get_additional_filename()):
                                self.result['Files'] -= 1  # 파일 개수 카운트
                            '''
                        except zipfile.BadZipfile:  # zip 헤더 오류
                            pass

                        # 검사 결과 출력하기
                        if self.options['opt_list']:  # 모든 리스트 출력인가?
                            self.call_scan_callback_fn(scan_callback_fn, ret_value)
            except KeyboardInterrupt:
                return 1  # 키보드 종료
            except:
                if k2const.K2DEBUG:
                    import traceback
                    print traceback.format_exc()
                pass

        self.__update_process(None, True)  # 최종 파일 정리

        # 격리 시점 체크하기?
        if move_master_file:
            # print 'move 3 :', t_master_file
            self.__arcclose()
            self.__quarantine_file(t_master_file)
            move_master_file = False

        return 0  # 정상적으로 검사 종료

    # ---------------------------------------------------------------------
    # call_scan_callback_fn(self, a_scan_callback_fn, ret_value)
    # 악성코드 검사 결과 출력 시 /<...> 표시는 제외하고 출력한다.
    # 입력값 : a_scan_callback_fn - 콜백 함수
    #         ret_value : 출력 대상
    # 리턴값 : scan 콜백 함수의 리턴값
    # ---------------------------------------------------------------------
    def call_scan_callback_fn(self, a_scan_callback_fn, ret_value):
        if isinstance(a_scan_callback_fn, types.FunctionType):
            fs = ret_value['file_struct']  # 출력할 파일 정보
            rep_path = self.disable_path.sub('', fs.get_additional_filename())
            fs.set_additional_filename(rep_path)
            ret_value['file_struct'] = fs

            return a_scan_callback_fn(ret_value)

    # ---------------------------------------------------------------------
    # __quarantine_file(self, filename)
    # 악성코드 파일을 격리소로 이동한다
    # 입력값 : filename - 격리 대상 파일 이름
    # ---------------------------------------------------------------------
    def __quarantine_file(self, filename):
        if self.options['infp_path'] and (self.options['opt_move'] or self.options['opt_copy']):
            is_success = False

            try:
                if self.options['opt_qname']:
                    x = self.quarantine_name.get(filename, None)
                    if x:
                        q_path = os.path.join(self.options['infp_path'], x)
                        self.quarantine_name.pop(filename)
                    else:
                        q_path = self.options['infp_path']
                else:
                    q_path = self.options['infp_path']

                if not os.path.exists(q_path):
                    os.makedirs(q_path)  # 다중 폴더 생성

                if self.options['opt_qhash']:  # 해시로 격리
                    t_filename = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
                else:
                    t_filename = os.path.split(filename)[-1]

                # 격리소에 동일한 파일 이름이 존재하는지 체크
                fname = os.path.join(q_path, t_filename)
                t_quarantine_fname = fname
                count = 1
                while True:
                    if os.path.exists(t_quarantine_fname):
                        t_quarantine_fname = '%s (%d)' % (fname, count)  # 유니크한 파일 이름 생성
                        count += 1
                    else:
                        break

                if self.options['opt_move']:
                    shutil.move(filename, t_quarantine_fname)  # 격리소로 이동
                elif self.options['opt_copy']:
                    shutil.copy(filename, t_quarantine_fname)  # 격리소로 복사
                    q_type = k2const.K2_QUARANTINE_COPY

                is_success = True
            except (shutil.Error, OSError) as e:
                pass

            if isinstance(self.quarantine_callback_fn, types.FunctionType):
                if self.options['opt_copy']:
                    q_type = k2const.K2_QUARANTINE_COPY
                else:
                    q_type = k2const.K2_QUARANTINE_MOVE

                self.quarantine_callback_fn(filename, is_success, q_type)

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
                        self.__arcclose()
                        self.update_info = [file_struct]
                    else:
                        immediately_flag = True

        # 압축 파일 정보를 이용해 즉시 압축하여 최종 마스터 파일로 재조립한다.
        if immediately_flag:
            # 재조립해야 할 압축 파일의 핸들을 모두 닫는다.
            self.__arcclose()

            if len(self.update_info) > 1:  # 최종 재조립시 1개 이상이면 압축 파일이라는 의미
                ret_file_info = None

                while len(self.update_info):
                    p_file_info = self.update_info[-1]  # 직전 파일 정보
                    ret_file_info = self.__update_arc_file_struct(p_file_info)

                    if len(self.update_info):  # 최상위 파일이 아니면 하위 결과 추가
                        self.update_info.append(ret_file_info)

                # if isinstance(self.update_callback_fn, types.FunctionType) and ret_file_info:
                #    self.update_callback_fn(ret_file_info, True)

                self.update_info = [file_struct]

            # if len(self.update_info) == 1:  # 최종 재조립시 1개면 일반 파일
            #    self.update_info = [file_struct]

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
        arc_engine = p_file_info.get_archive_engine_name()
        if arc_engine:
            arc_engine = arc_engine.split(':')[0]

        while len(self.update_info):
            ename = self.update_info[-1].get_archive_engine_name()
            if ename:
                ename = ename.split(':')[0]

            if self.update_info[-1].get_level() == arc_level and ename == arc_engine:
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

            ret = False
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
                ret = True

            if ret:
                ret_file_info.set_modify(True)  # 수정 여부 성공 표시
                if isinstance(self.update_callback_fn, types.FunctionType) and ret_file_info:
                    self.update_callback_fn(ret_file_info, True)
            else:
                ret_file_info.set_modify(False)  # 수정 여부 실패 표시
                if isinstance(self.update_callback_fn, types.FunctionType) and ret_file_info:
                    self.update_callback_fn(ret_file_info, False)

        # 압축된 파일들 모두 삭제
        for tmp in t:
            t_fname = tmp.get_filename()
            # 플러그인 엔진에 의해 파일이 치료(삭제) 되었을 수 있음
            if os.path.exists(t_fname):
                try:
                    os.remove(t_fname)
                    # print '[*] Remove :', t_fname
                except OSError:
                    pass
        return ret_file_info

    # ---------------------------------------------------------------------
    # __arcclose(self)
    # 열려진 모든 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def __arcclose(self):
        for i, inst in enumerate(self.kavmain_inst):
            try:
                inst.arcclose()
            except AttributeError:
                pass

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
            except (IOError, OSError) as e:
                d_ret = False

        t_file_info.set_modify(d_ret)  # 치료(수정/삭제) 여부 표시

        if isinstance(self.disinfect_callback_fn, types.FunctionType):
            self.disinfect_callback_fn(ret_value, action_type)

        return d_ret

    # ---------------------------------------------------------------------
    # __scan_file(self, file_struct, fileformat)
    # 플러그인 엔진에게 악성코드 검사를 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    #         format      - 미리 분석한 파일 포맷 분석 정보
    # 리턴값 : (악성코드 발견 유무, 악성코드 이름, 악성코드 ID, 악성코드 검사 상태, 플러그인 엔진 ID)
    # ---------------------------------------------------------------------
    def __scan_file(self, file_struct, fileformat):
        import kernel

        if self.verbose:
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

            # 파일이 아니거나 크기가 0이면 악성코드 검사를 할 필요가 없다.
            if os.path.isfile(filename) is False:
                raise EngineKnownError('File is not found!')

            if os.path.getsize(filename) == 0:
                raise EngineKnownError('File Size is Zero!')

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for i, inst in enumerate(self.kavmain_inst):
                try:
                    ret, vname, mid, scan_state = inst.scan(mm, filename, fileformat, filename_ex)
                    if ret:  # 악성코드 발견하면 추가 악성코드 검사를 중단한다.
                        eid = i  # 악성코드를 발견한 플러그인 엔진 ID

                        if self.verbose:
                            print '    [-] %s.__scan_file() : %s' % (inst.__module__, vname)

                        break
                except AttributeError:
                    continue

            if mm:
                mm.close()

            if fp:
                fp.close()

            return ret, vname, mid, scan_state, eid
        except (EngineKnownError, ValueError) as e:
            pass
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            if k2const.K2DEBUG:
                import traceback
                print traceback.format_exc()
                # raw_input('>>')
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
        if self.verbose:
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
        except (IOError, EngineKnownError, OSError) as e:
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

        if self.verbose:
            print '[*] KavMain.disinfect() :'

        try:
            # 악성코드를 진단한 플러그인 엔진에게만 치료를 요청한다.
            inst = self.kavmain_inst[engine_id]
            ret = inst.disinfect(filename, malware_id)

            if self.verbose:
                print '    [-] %s.disinfect() : %s' % (inst.__module__, ret)
        except AttributeError:
            pass

        return ret

    # ---------------------------------------------------------------------
    # unarc(self, file_struct)
    # 플러그인 엔진에게 압축 해제를 요청한다.
    # 입력값 : file_struct - 압축 해제 대상 파일 정보
    # 리턴값 : (True, 압축 해제된 파일 정보) or (False, 오류 원인 메시지)
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
                            rname = self.temp_path.mktemp()
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
                                t = rname_struct.get_additional_filename()
                                if t[0] == '/' or t[0] == '\\':
                                    t = t[1:]
                                msg = '%s : %s\n' % (sig_fname, t)
                                fp = open('sigtool.log', 'at')
                                fp.write(msg)
                                fp.close()

                            break  # 압축이 풀렸으면 종료
                    except (AttributeError, struct.error) as e:
                        continue
                    except RuntimeError:  # 암호가 설정된 zip 파일
                        return False, 'password protected'
                    except MemoryError:
                        return False, None
                else:  # end for
                    # 어떤 엔진도 압축 해제를 하지 못한 경우
                    # 임시 파일만 생성한 뒤 종료
                    rname = self.temp_path.mktemp()
                    fp = open(rname, 'wb')
                    fp.close()
                    # print '[*] Make   :', rname

                    rname_struct = file_struct
                    rname_struct.set_filename(rname)
                    rname_struct.set_can_archive(kernel.MASTER_IGNORE)
                return True, rname_struct
        except IOError:
            pass

        return False, None

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
                        try:
                            deep_name1 = deep_name
                            name1 = name

                            if type(deep_name) != type(name):
                                if isinstance(deep_name, unicode):
                                    name1 = name.decode('utf-8', 'ignore')
                                elif isinstance(name, unicode):
                                    deep_name1 = deep_name.decode('utf-8', 'ignore')

                            dname = '%s/%s' % (deep_name1, name1)
                        except UnicodeDecodeError:
                            continue
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
        except (IOError, EngineKnownError, ValueError, OSError) as e:
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
            self.options['opt_copy'] = options.opt_copy
            self.options['opt_dis'] = options.opt_dis
            self.options['infp_path'] = options.infp_path
            self.options['opt_verbose'] = options.opt_verbose
            self.options['opt_sigtool'] = options.opt_sigtool
            self.options['opt_debug'] = options.opt_debug
            self.options['opt_feature'] = options.opt_feature
            self.options['opt_qname'] = options.opt_qname
            self.options['opt_qhash'] = options.opt_qhash
        else:  # 기본값 설정
            self.options['opt_arc'] = False
            self.options['opt_nor'] = False
            self.options['opt_list'] = False
            self.options['opt_move'] = False
            self.options['opt_copy'] = False
            self.options['opt_dis'] = False
            self.options['infp_path'] = None
            self.options['opt_verbose'] = False
            self.options['opt_sigtool'] = False
            self.options['opt_debug'] = False
            self.options['opt_feature'] = 0xffffffff
            self.options['opt_qname'] = False
            self.options['opt_qhash'] = False
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
