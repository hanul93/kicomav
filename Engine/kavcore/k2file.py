# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import glob
import shutil
import tempfile
# import psutil


# ---------------------------------------------------------------------
# K2Tempfile 클래스
# ---------------------------------------------------------------------
class K2Tempfile:
    def __init__(self):
        self.re_pid = re.compile(r'ktmp([0-9a-f]{5})$', re.IGNORECASE)

        self.temp_path = os.path.join(tempfile.gettempdir(), 'ktmp%05x' % os.getpid())

        if not os.path.exists(self.temp_path):
            try:
                os.mkdir(self.temp_path)
            except (IOError, OSError) as e:
                self.temp_path = tempfile.gettempdir()

    def gettempdir(self):
        return self.temp_path

    def mktemp(self):
        return tempfile.mktemp(prefix='ktmp', dir=self.temp_path)

    def removetempdir(self):
        # 자기 폴더만 지우는 걸로...
        try:
            if os.path.exists(self.temp_path):
                shutil.rmtree(self.temp_path)
        except OSError:
            pass

        '''
        fl = glob.glob(os.path.join(tempfile.gettempdir(), 'ktmp*'))
        if len(fl):
            for tname in fl:
                if os.path.isdir(tname):
                    tpath = self.re_pid.search(tname)
                    if tpath:  # 정상적으로 임시 폴더가 생겼음
                        if psutil.pid_exists(int(tpath.groups()[0], 16)) is False:
                            try:
                                shutil.rmtree(tname)
                            except OSError:
                                pass
                elif os.path.isfile(tname):
                    try:
                        os.remove(tname)
                    except OSError:
                        pass
        '''

# -------------------------------------------------------------------------
# FileStruct 클래스
# -------------------------------------------------------------------------
class FileStruct:
    # ---------------------------------------------------------------------
    # __init__(self, filename=None)
    # 클래스를 초기화 한다.
    # 인자값 : filename - 파일 이름
    # ---------------------------------------------------------------------
    def __init__(self, filename=None, level=0):
        self.__fs = {}

        if filename:
            self.set_default(filename, level)

    # ---------------------------------------------------------------------
    # set_default(self, filename)
    # 파일에 대한 하나의 FileStruct 생성한다.
    # 인자값 : filename - 파일 이름
    # ---------------------------------------------------------------------
    def set_default(self, filename, level):
        import kernel

        self.__fs['is_arc'] = False  # 압축 여부
        self.__fs['arc_engine_name'] = None  # 압축 해제 가능 엔진 ID
        self.__fs['arc_filename'] = ''  # 실제 압축 파일
        self.__fs['filename_in_arc'] = ''  # 압축해제 대상 파일
        self.__fs['real_filename'] = filename  # 검사 대상 파일
        self.__fs['additional_filename'] = ''   # 압축 파일의 내부를 표현하기 위한 파일명
        self.__fs['master_filename'] = filename  # 출력용
        self.__fs['is_modify'] = False  # 수정 여부
        self.__fs['can_arc'] = kernel.MASTER_IGNORE  # 재압축 가능 여부
        self.__fs['level'] = level  # 압축 깊이

    # ---------------------------------------------------------------------
    # is_archive(self)
    # 파일에 대한 압축 여부를 확인한다.
    # 리턴값 : True or False
    # ---------------------------------------------------------------------
    def is_archive(self):  # 압축 여부
        return self.__fs['is_arc']

    # ---------------------------------------------------------------------
    # get_archive_engine_name(self)
    # 압축 해제 가능한 엔진을 확인한다.
    # 리턴값 : 압축 해제 가능한 엔진 (ex, arc_zip)
    # ---------------------------------------------------------------------
    def get_archive_engine_name(self):  # 압축 엔진 ID
        return self.__fs['arc_engine_name']

    # ---------------------------------------------------------------------
    # get_archive_filename(self)
    # 실제 압축 파일 이름을 확인한다.
    # 리턴값 : 실제 압축 파일 이름
    # ---------------------------------------------------------------------
    def get_archive_filename(self):  # 실제 압축 파일
        return self.__fs['arc_filename']

    # ---------------------------------------------------------------------
    # get_filename_in_archive(self)
    # 압축 해제 대상 파일명을 확인한다.
    # 리턴값 : 압축해제 대상 파일
    # ---------------------------------------------------------------------
    def get_filename_in_archive(self):  # 압축해제 대상 파일
        return self.__fs['filename_in_arc']

    # ---------------------------------------------------------------------
    # get_filename(self)
    # 실제 작업 대상 파일 이름을 확인한다.
    # 리턴값 : 실제 작업 대상 파일
    # ---------------------------------------------------------------------
    def get_filename(self):  # 실제 작업 파일 이름
        return self.__fs['real_filename']

    # ---------------------------------------------------------------------
    # set_filename(self)
    # 실제 작업 대상 파일 이름을 저장한다.
    # 입력값 : 실제 작업 대상 파일
    # ---------------------------------------------------------------------
    def set_filename(self, fname):  # 실제 작업 파일명을 저장
        self.__fs['real_filename'] = fname

    # ---------------------------------------------------------------------
    # get_master_filename(self)
    # 최상위 파일 이름을 확인한다.
    # 리턴값 : 압축일 경우 압축 파일명
    # ---------------------------------------------------------------------
    def get_master_filename(self):  # 압축일 경우 최상위 파일
        return self.__fs['master_filename']  # 출력용

    # ---------------------------------------------------------------------
    # get_additional_filename(self)
    # 압축 파일 내부를 표현하기 위한 파일 이름을 확인한다.
    # 리턴값 : 압축 파일 내부 표현 파일 이름
    # ---------------------------------------------------------------------
    def get_additional_filename(self):
        return self.__fs['additional_filename']

    # ---------------------------------------------------------------------
    # set_additional_filename(self, filename)
    # 압축 파일 내부를 표현하기 위한 파일 이름을 셋팅한다.
    # ---------------------------------------------------------------------
    def set_additional_filename(self, filename):
        self.__fs['additional_filename'] = filename

    # ---------------------------------------------------------------------
    # is_modify(self)
    # 악성코드 치료로 인해 파일이 수정됨 여부를 확인한다.
    # 리턴값 : True or False
    # ---------------------------------------------------------------------
    def is_modify(self):  # 수정 여부
        return self.__fs['is_modify']

    # ---------------------------------------------------------------------
    # set_modify(self, modify)
    # 악성코드 치료로 파일이 수정 여부를 저장함
    # 입력값 : 수정 여부 (True or False)
    # ---------------------------------------------------------------------
    def set_modify(self, modify):  # 수정 여부
        self.__fs['is_modify'] = modify

    # ---------------------------------------------------------------------
    # get_can_archive(self)
    # 악성코드로 치료 후 파일을 재압축 할 수 있는지 여부를 확인한다.
    # 리턴값 : kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    # ---------------------------------------------------------------------
    def get_can_archive(self):  # 재압축 가능 여부
        return self.__fs['can_arc']

    # ---------------------------------------------------------------------
    # set_can_archive(self, mode)
    # 악성코드로 치료 후 파일을 재압축 할 수 있는지 여부를 설정한다.
    # 입력값 : mode - kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    # ---------------------------------------------------------------------
    def set_can_archive(self, mode):  # 재압축 가능 여부
        self.__fs['can_arc'] = mode

    # ---------------------------------------------------------------------
    # get_level(self)
    # 압축의 깊이를 알아낸다.
    # 리턴값 : 0, 1, 2 ...
    # ---------------------------------------------------------------------
    def get_level(self):  # 압축 깊이
        return self.__fs['level']

    # ---------------------------------------------------------------------
    # set_level(self, level)
    # 압축의 깊이를 설정한다.
    # 입력값 : level - 압축 깊이
    # ---------------------------------------------------------------------
    def set_level(self, level):  # 압축 깊이
        self.__fs['level'] = level

    # ---------------------------------------------------------------------
    # set_archive(self, engine_id, rname, fname, dname, mname, modify, can_arc)
    # 주어진 정보로 파일 정보를 저장한다.
    # 입력값 : engine_id - 압축 해제 가능 엔진 ID
    #          rname     - 압축 파일
    #          fname     - 압축해제 대상 파일
    #          dname     - 압축 파일의 내부를 표현하기 위한 파일 이름
    #          mname     - 마스터 파일 (최상위 파일 이름)
    #          modify    - 수정 여부
    #          can_arc   - 재압축 가능 여부
    #          level     - 압축 깊이
    # ---------------------------------------------------------------------
    def set_archive(self, engine_id, rname, fname, dname, mname, modify, can_arc, level):
        self.__fs['is_arc'] = True  # 압축 여부
        self.__fs['arc_engine_name'] = engine_id  # 압축 해제 가능 엔진 ID
        self.__fs['arc_filename'] = rname  # 실제 압축 파일
        self.__fs['filename_in_arc'] = fname  # 압축해제 대상 파일
        self.__fs['real_filename'] = ''  # 검사 대상 파일
        self.__fs['additional_filename'] = dname  # 압축 파일의 내부를 표현하기 위한 파일명
        self.__fs['master_filename'] = mname  # 마스터 파일 (최상위 파일 이름)
        self.__fs['is_modify'] = modify  # 수정 여부
        self.__fs['can_arc'] = can_arc  # 재압축 가능 여부
        self.__fs['level'] = level  # 재압축 깊이
