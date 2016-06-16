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

__revision__ = '$LastChangedRevision: 1 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'


import os # 파일 삭제를 위해 import
import mmap
import re
import zlib
import kernel

class PDF :
    def __init__(self, fname) :
        self.SPACE = (' ' * 4) # 출력 공백
        self.ObjInfo = []
        self.Root = {}
        self.fp = None
        self.mm = None

        self.fp = open(fname, 'rb')
        self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

        self.re_version   = re.compile('[\d]+.[\d]+')
        self.re_obj       = re.compile('[\d]+ [0] obj[ \r\n]*')
        self.re_endobj    = re.compile('endobj[ \r\n]*')
        self.re_objid     = re.compile('([\d]+) [0] obj[ \r\n]*')
        self.re_stream    = re.compile('stream[\r\n]*')
        self.re_endstream = re.compile('[\r\n]*endstream[\r\n]*')
        self.re_shapchar  = re.compile('#([0-9A-Fa-f]{2})')
        self.re_refer     = re.compile('([\d]+) [0] [R]')
        self.re_trailer   = re.compile('trailer[ \r\n]*<<')
        self.re_root      = re.compile('/Root ([\d]+) [0] [R]')
        self.re_filter    = re.compile('/[Ff]ilter.+?([/A-Za-z0-9]+)')

        self.parse()

    def close(self) :
        if self.mm : self.mm.close()
        if self.fp : self.fp.close()

    def parse(self) :
        # if self.__isPDF__() != 0 :
        #     raise ValueError

        # self.version = self.__getPDFVersion__() # 버전 체크
        # if self.version == None :
        #     raise ValueError

        self.ObjNum = self.__getPDFObjectNum__() # Object 개수 체크
        if self.ObjNum == 0 :
            raise ValueError

        # self.__getPDFRoot__()

    def getstream(self, objid) :
        if len(self.ObjInfo) == 0 :
            return

        for obj in self.ObjInfo :
            if obj['Object ID'] == objid :
                s_start, s_end = obj['Object Stream']
                data = self.mm[s_start:s_start+s_end]

                '''
                print hex(s_start), (s_end)
                fp = open(objid, 'wb')
                fp.write(data)
                fp.close()
                '''

                b_start = obj['Object Start']
                b_end   = b_start + obj['Object Size']
                body = self.mm[b_start:b_end]
                if body.find('FlateDecode') != -1 :
                    data = zlib.decompress(data)

                return data

        return ''

    def getinfo(self, objid) :
        ret = None

        if len(self.ObjInfo) == 0 :
            return

        for obj in self.ObjInfo :
            if obj['Object ID'] == objid :
                start = obj['Object Start']
                size  = obj['Object Size']
                ret = self.summuryinfo(self.mm[start:start+size])

        return ret

    # 주어진 오브젝트 정보에서 오브젝트 ID 구하기
    def __parseObjID__(self, data) :
        id = self.re_objid.search(data)
        if id :
            return id.groups()[0]
        else :
            return -1

    def __parseObjSteam__(self, data) :
        stream_data = None
        start = 0
        size  = 0

        try :
            stream_s = self.re_stream.search(data)
            if stream_s == None :
                raise SystemError

            stream_e = self.re_endstream.search(data)
            if stream_e == None :
                raise SystemError

            start = stream_s.end()
            end   = stream_e.start()

            size  = end - start

            stream_data = data[start:end]
        except :
            pass

        return stream_data, start, size

    def __getPDFObjectNum__(self) :
        num = 0

        pos = 0
        while 1 :
            obj = self.re_obj.search(self.mm[pos:])
            if obj : # obj 가 있고
                endobj = self.re_endobj.search(self.mm[pos:])
                if endobj : #endobj가 존재할때 정상적인 obj 존재
                    objid = {}

                    obj_start_pos = pos + obj.start()
                    obj_size      = endobj.end() - obj.start()

                    objid['Object Start'] = obj_start_pos
                    objid['Object Size']  = obj_size

                    # Obj의 내용을 담음
                    # body = self.summuryinfo(self.mm[obj_start_pos:obj_start_pos+obj_size])
                    # objid['Object Body'] = body

                    # Obj의 내부 참조 오브젝트를 담음
                    # objid['Object Reference'] = self.re_refer.findall(body)


                    # 오브젝트 정보 추출하기
                    id = self.__parseObjID__(self.mm[obj_start_pos:obj_start_pos+obj_size])
                    if id != -1:
                        objid['Object ID'] = id
                        num += 1

                        # Stream 추출하기
                        stream, stream_start, stream_size = self.__parseObjSteam__(self.mm[obj_start_pos:obj_start_pos+obj_size])
                        if stream != None :
                            objid['Object Stream'] = (obj_start_pos + stream_start, stream_size)
                        else :
                            objid['Object Stream'] = (0, 0)

                        # 이전에 동일한 Object ID가 있는지 조사한다.
                        # PDF는 증분 업데이트 기능을 지원하기 때문이다.
                        for o in self.ObjInfo :
                            if o['Object ID'] == id :
                                i = self.ObjInfo.index(o)
                                self.ObjInfo.pop(i) # 이전 정보는 삭제

                        self.ObjInfo.append(objid) # 최종 정보 축적

                    pos = obj_start_pos + obj_size
                else :
                    break
            else :
                break

        return num

#---------------------------------------------------------------------
# KavMain 클래스
# 키콤백신 엔진 모듈임을 나타내는 클래스이다.
# 이 클래스가 없으면 백신 엔진 커널 모듈에서 로딩하지 않는다.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # init(self, plugins)
    # 백신 엔진 모듈의 초기화 작업을 수행한다.
    #-----------------------------------------------------------------
    def init(self, plugins) : # 백신 모듈 초기화
        return 0

    #-----------------------------------------------------------------
    # uninit(self)
    # 백신 엔진 모듈의 종료화 작업을 수행한다.
    #-----------------------------------------------------------------
    def uninit(self) : # 백신 모듈 종료화
        return 0
    
    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = 'Kei Choi' # 제작자
        info['version'] = '1.0'     # 버전
        info['title'] = 'PDF Engine' # 엔진 설명
        info['kmd_name'] = 'pdf' # 엔진 파일명
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # 포맷 정보를 담을 공간

            mm = mmhandle

            if mm[0:7] == '%PDF-1.' : # 헤더 체크
                fformat['size'] = len(mm) # 포맷 주요 정보 저장

                ret = {}
                ret['ff_pdf'] = fformat

                return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # 검사 대상 정보를 모두 가짐

        try :
            # 미리 분석된 파일 포맷중에 ZIP 포맷이 있는가?
            fformat = format['ff_pdf']

            pdf = PDF(filename)

            for obj in pdf.ObjInfo :
                if obj['Object Stream'][0] != 0 :
                    name = 'Object#' + obj['Object ID']
                    file_scan_list.append(['arc_pdf', name])
                    # print obj['Object ID']
            # print pdf.ObjInfo
            pdf.close()
            
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_pdf' :
                raise SystemError

            pdf = PDF(arc_name)
            data = pdf.getstream(arc_in_name[7:])
            pdf.close()
            
            return data
        except :
            pass

        return None
