# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import struct
import zlib
import os
import py7zlib

import zipfile
import kernel


# 참소 : https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html

# ---------------------------------------------------------------------
# 엔진 오류 메시지를 정의
# ---------------------------------------------------------------------
class BadZipTagError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class NeedPasswordError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# ---------------------------------------------------------------------
# New ZipFile을 위한 구조체 정의
# ---------------------------------------------------------------------
struct_zipfilerecord = '<5H3L2H'  # PK\x03\x04
size_struct_zipfilerecord = struct.calcsize(struct_zipfilerecord)

struct_zipdirentry = '<6H3L5H2L'  # PK\x01\x02
size_struct_zipdirentry = struct.calcsize(struct_zipdirentry)

struct_zipdigitalsig = '<H'  # PK\x05\x05
size_struct_zipdigitalsig = struct.calcsize(struct_zipdigitalsig)

struct_zipdatadescr = '<3H'  # PK\x07\x08
size_struct_zipdatadescr = struct.calcsize(struct_zipdatadescr)

struct_zipendlocator = '<4H2LH'  # PK\x05\x06
size_struct_zipendlocator = struct.calcsize(struct_zipendlocator)


# ---------------------------------------------------------------------
# COMP_TYPE 정의
# ---------------------------------------------------------------------
COMP_STORED = 0
COMP_SHRUNK = 1
COMP_REDUCED1 = 2
COMP_REDUCED2 = 3
COMP_REDUCED3 = 4
COMP_REDUCED4 = 5
COMP_IMPLODED = 6
COMP_TOKEN = 7
COMP_DEFLATE = 8
COMP_DEFLATE64 = 9


# ---------------------------------------------------------------------
# New ZipFile 클래스
# ---------------------------------------------------------------------
class NZipFile:
    def __init__(self, fname):
        self.fname = fname
        self.fp = None
        self.fsize = 0
        self.zipsize = 0

        self.zipfilerecord = []
        self.zipdirentry = []
        self.zipdigitalsig = []
        self.zipdatadescr = []
        self.zipendlocator = []

    def __del__(self):
        if self.fp:
            self.close()

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def get_zipsize(self):
        return self.zipsize

    def namelist(self):
        flist = []

        for fr in self.zipfilerecord:
            flist.append(fr[10])

        return flist

    def read(self, fname):
        for fr in self.zipfilerecord:
            if fr[10] == fname:
                if fr[1] & 1 == 1:  # falgs - Password 필요
                    raise NeedPasswordError('%s' % fname)
                else:
                    if fr[2] == COMP_STORED:  # COMTypes
                        return fr[12]
                    elif fr[2] == COMP_DEFLATE:
                        return zlib.decompress(fr[12], -15)

        return None

    def parse(self):
        try:
            self.fp = open(self.fname, 'rb')
            self.fsize = os.fstat(self.fp.fileno()).st_size

            cur_pos = 0

            while self.fsize != cur_pos:  # EOF?
                sig = self.fp.read(4)
                if sig == 'PK\x03\x04':
                    zfr = self.__read_zipfilerecord()
                    self.zipfilerecord.append(zfr)
                elif sig == 'PK\x01\x02':
                    zde = self.__read_zipdirentry()
                    self.zipdirentry.append(zde)
                elif sig == 'PK\x05\x05':
                    zds = self.__read_zipdigitalsig()
                    self.zipdigitalsig.append(zds)
                elif sig == 'PK\x07\x08':
                    zdd = self.__read_zipdatadescr()
                    self.zipdatadescr.append(zdd)
                elif sig == 'PK\x05\x06':
                    zel = self.__read_zipendlocator()
                    self.zipendlocator.append(zel)
                    break
                else:
                    raise BadZipTagError('Tag is \'%s\'' % repr(sig))

                cur_pos = self.fp.tell()

            if self.fsize != self.fp.tell():
                self.zipsize = self.fp.tell()  # 최종 ZipFile Size

            return True
        except (IOError, OSError) as e:
            pass

        return False

    def __read_zipfilerecord(self):  # PK\x03\x04
        data = self.fp.read(size_struct_zipfilerecord)
        fr = struct.unpack(struct_zipfilerecord, data)
        comp_len = fr[6]
        fname_len = fr[8]
        extra_len = fr[9]

        fr = list(fr)
        if fname_len > 0:
            fname = self.fp.read(fname_len)
            fr.append(fname)
        else:
            fr.append('')

        if extra_len > 0:
            fr.append(self.fp.read(extra_len))
        else:
            fr.append('')

        if comp_len > 0:
            fr.append(self.fp.read(comp_len))
        else:
            fr.append('')

        return fr

    def __read_zipdirentry(self):  # PK\x01\x02
        data = self.fp.read(size_struct_zipdirentry)
        de = struct.unpack(struct_zipdirentry, data)
        fname_len = de[9]
        extra_len = de[10]
        comment_len = de[11]

        de = list(de)
        if fname_len > 0:
            fname = self.fp.read(fname_len)
            de.append(fname)
        else:
            de.append('')

        if extra_len > 0:
            de.append(self.fp.read(extra_len))
        else:
            de.append('')

        if comment_len > 0:
            de.append(self.fp.read(comment_len))
        else:
            de.append('')

        return de

    def __read_zipdigitalsig(self):  # PK\x05\x05
        data = self.fp.read(size_struct_zipdigitalsig)
        ds = struct.unpack(struct_zipdigitalsig, data)
        data_len = ds[0]

        ds = list(ds)
        if data_len > 0:
            ds.append(self.fp.read(data_len))
        else:
            ds.append('')

        return ds

    def __read_zipdatadescr(self):  # PK\x07\x08
        data = self.fp.read(size_struct_zipdatadescr)
        dd = struct.unpack(struct_zipdatadescr, data)

        return list(dd)

    def __read_zipendlocator(self):  # PK\x05\x06
        data = self.fp.read(size_struct_zipendlocator)
        el = struct.unpack(struct_zipendlocator, data)

        return list(el)

'''
if __name__ == '__main__':
    z = NZipFile('zip_attatch_data.bin')
    z.parse()
    for name in z.namelist():
        print name

    print z.read('docProps/app.xml')

    z.close()
'''

# -------------------------------------------------------------------------
# KavMain 클래스
# -------------------------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    #         verbose      - 디버그 모드 (True or False)
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):  # 플러그인 엔진 초기화
        self.handle = {}  # 압축 파일 핸들
        return 0  # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.1'  # 버전
        info['title'] = 'Zip Archive Engine'  # 엔진 설명
        info['kmd_name'] = 'zip'  # 엔진 파일 이름
        info['engine_type'] = kernel.ARCHIVE_ENGINE  # 엔진 타입
        info['make_arc_type'] = kernel.MASTER_PACK  # 악성코드 치료 후 재압축 유무

        return info

    # ---------------------------------------------------------------------
    # __get_handle(self, filename)
    # 압축 파일의 핸들을 얻는다.
    # 입력값 : filename   - 파일 이름
    # 리턴값 : 압축 파일 핸들
    # ---------------------------------------------------------------------
    def __get_handle(self, filename):
        if filename in self.handle:  # 이전에 열린 핸들이 존재하는가?
            zfile = self.handle.get(filename, None)
        else:
            zfile = zipfile.ZipFile(filename)  # zip 파일 열기
            self.handle[filename] = zfile

        return zfile

    def __get_handle_7z(self, filename):
        if filename in self.handle:  # 이전에 열린 핸들이 존재하는가?
            zfile = self.handle.get(filename, None)
        else:
            zfile = py7zlib.Archive7z(open(filename, 'rb'))  # 7z 파일 열기
            self.handle[filename] = zfile

        return zfile

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #          filename   - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        ret = {}

        mm = filehandle
        if mm[0:4] == 'PK\x03\x04':  # 헤더 체크
            try:
                zfile = zipfile.ZipFile(filename)  # zip 파일 열기
                names = zfile.namelist()
                zfile.close()

                # 파일 포맷은 ZIP이지만 특수 포맷인지를 한번 더 체크한다.
                if names is not None:
                    for name in names:
                        n = name.lower()
                        if n == 'classes.dex':
                            ret['ff_apk'] = 'apk'
                        elif n == 'xl/workbook.xml':
                            ret['ff_ooxml'] = 'xlsx'
                        elif n == 'word/document.xml':
                            ret['ff_ooxml'] = 'docx'
                        elif n == 'ppt/presentation.xml':
                            ret['ff_ooxml'] = 'pptx'

                    if len(ret) == 0:
                        ret['ff_zip'] = 'zip'
            except zipfile.BadZipfile:
                zfile = NZipFile(filename)
                try:
                    if zfile.parse():
                        zsize = zfile.get_zipsize()
                        fsize = os.path.getsize(filename)
                        zfile.close()

                        if zsize < fsize and zsize != 0:
                            # 파이썬 ZipFile로 해제되지 않는 파일 처리
                            # zip 파일 뒤에 attach 된 데이터가 있으면 오류 발생
                            ret['ff_attach_zip'] = (zsize, fsize - zsize)
                except BadZipTagError:
                    pass

            return ret
        elif mm[0:4] == '7z\xbc\xaf':
            ret['ff_7z'] = '7z'
            return ret

        return None

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 ZIP 포맷이 있는가?
        if 'ff_zip' in fileformat:
            zfile = self.__get_handle(filename)

            for name in zfile.namelist():
                file_scan_list.append(['arc_zip', name])
            # zfile.close()
        elif 'ff_attach_zip' in fileformat:
            off, zsize = fileformat['ff_attach_zip']
            file_scan_list.append(['arc_attach_zip:0:%d' % off, '#1'])
            file_scan_list.append(['arc_attach_zip:%d:%d' % (off, zsize), '#2'])
        elif 'ff_7z' in fileformat:
            zfile = self.__get_handle_7z(filename)
            for name in zfile.filenames:
                file_scan_list.append(['arc_7z', name])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_zip':
            zfile = self.__get_handle(arc_name)
            try:
                data = zfile.read(fname_in_arc)
                return data
            except zipfile.BadZipfile:
                pass
        elif arc_engine_id.find('arc_attach_zip') != -1:
            t = arc_engine_id.split(':')
            off = int(t[1])
            size = int(t[2])

            with open(arc_name, 'rb') as fp:
                fp.seek(off)
                data = fp.read(size)
                return data
        elif arc_engine_id == 'arc_7z':
            zfile = self.__get_handle_7z(arc_name)
            cf = zfile.getmember(fname_in_arc)
            try:
                data = cf.read()
                return data
            except (ValueError, py7zlib.UnsupportedCompressionMethodError) as e:
                # BCJ LZMA, BCJ2 LZMA를 py7zlib가 아직 지원하지 못함 (ver 0.4.9)
                # LZMA 지원 체크 완료
                pass

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        for fname in self.handle.keys():
            zfile = self.handle[fname]
            zfile.close()
            self.handle.pop(fname)

    # ---------------------------------------------------------------------
    # mkarc(self, arc_engine_id, arc_name, file_infos)
    # 입력값 : arc_engine_id - 압축 가능 엔진 ID
    #         arc_name      - 최종적으로 압축될 압축 파일 이름
    #         file_infos    - 압축 대상 파일 정보 구조체
    # 리턴값 : 압축 성공 여부 (True or False)
    # ---------------------------------------------------------------------
    def mkarc(self, arc_engine_id, arc_name, file_infos):
        if arc_engine_id == 'arc_zip':
            zfile = zipfile.ZipFile(arc_name, 'w')
            # print '[-] zip :', arc_name

            for file_info in file_infos:
                rname = file_info.get_filename()
                try:
                    with open(rname, 'rb') as fp:
                        buf = fp.read()
                        # print '[-] filename :', rname, len(buf)
                        # print '[-] rname :',
                        a_name = file_info.get_filename_in_archive()
                        zfile.writestr(a_name, buf)
                except IOError:
                    # print file_info.get_filename_in_archive()
                    pass

            zfile.close()
            # print '[-] close()\n'
            return True

        return False
