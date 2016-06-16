# -*- coding:utf-8 -*-

#---------------------------------------------------------------------
# K2FileStruct 클래스
#---------------------------------------------------------------------
class K2FileStruct :
    def __init__(self) :
        self.fs = {}

    def Set(self, filename) : # 파일에 대한 하나의 K2FileStruct를 생성한다.
        self.fs['is_arc'] = False # 압축 여부
        self.fs['arc_engine_name'] = -1 # 압축 해제 가능 엔진 ID
        self.fs['arc_filename'] = '' # 실제 압축 파일
        self.fs['arc_in_name'] = '' #압축해제 대상 파일
        self.fs['real_filename'] = filename # 검사 대상 파일
        self.fs['deep_filename'] = ''  # 압축 파일의 내부를 표현하기 위한 파일명
        self.fs['display_filename'] = filename # 출력용

    def IsArchive(self) : # 압축 여부
        return self.fs['is_arc']

    def GetArchiveEngine(self) : # 압축 엔진 ID
        return self.fs['arc_engine_name']

    def GetArchiveFilename(self) : # 실제 압축 파일
        return self.fs['arc_filename']

    def GetArchiveInFilename(self) : # 압축해제 대상 파일
        return self.fs['arc_in_name']

    def GetFilename(self) : # 실제 작업 파일명을 리턴
        return self.fs['real_filename']

    def SetFilename(self, fname) : # 실제 작업 파일명을 저장
        self.fs['real_filename'] = fname

    def GetMasterFilename(self) : # 압축일 경우 최상위 파일
        return self.fs['display_filename'] # 출력용

    def GetDeepFilename(self) : # 압축 파일의 내부를 표현하기 위한 파일명
        return self.fs['deep_filename']

    def SetArchive(self, engine_id, rname, fname, dname, mname) :
        self.fs['is_arc'] = True # 압축 여부
        self.fs['arc_engine_name'] = engine_id # 압축 해제 가능 엔진 ID
        self.fs['arc_filename'] = rname # 실제 압축 파일
        self.fs['arc_in_name'] = fname #압축해제 대상 파일
        self.fs['real_filename'] = '' # 검사 대상 파일
        self.fs['deep_filename'] = dname  # 압축 파일의 내부를 표현하기 위한 파일명
        self.fs['display_filename'] = mname
