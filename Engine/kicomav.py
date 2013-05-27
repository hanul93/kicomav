# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import hashlib  # MD5 해시를 사용하기 위해 import
import zlib     # 압축 및 해제를 위해 import
import StringIO # 버퍼 IO를 위해 import
import marshal  # 직렬화 된 문자열을 위해 import
import imp      # 동적모듈 로딩을 위해 import
import sys      # 모듈 등록을 위해 import
import types    # 타입 채킹을 위해 import
import os

#---------------------------------------------------------------------
# load_kmd(fname)
# 암호화 된 백신 엔진 모듈인 kmd 파일을 복호화 하는 함수
#---------------------------------------------------------------------
def load_kmd(fname) :
    try : # 예외가 발생할 가능성에 대해 처리
        fp = open(fname, 'rb') # kmd 파일 읽기
        buf = fp.read()
        fp.close()

        f_md5hash = buf[len(buf)-32:] # 파일 뒤쪽에서 MD5 해시 값 분리

        md5 = hashlib.md5()

        md5hash = buf[0:len(buf)-32] # 파일 뒤쪽 32Byte를 제외한 나머지 영역
        for i in range(3): # MD5 해시 값을 3번 연속으로 구하기
            md5.update(md5hash)
            md5hash = md5.hexdigest()

        if f_md5hash != md5hash:
            return False, '' # 에러

        buf2 = buf[4:len(buf)-32] # KAVM 헤더 제거

        buf3 =""
        for i in range(len(buf2)):  # buf2 크기만큼...
            c = ord(buf2[i]) ^ 0xFF #　0xFF로 XOR 암호화 한다
            buf3 += chr(c)

        buf4 = zlib.decompress(buf3) # 압축 해제
        
        return True, buf4 # kmd 복호화 성공 그리고 복호화된 내용 리턴
    except : # 예외 발생
        return False, '' # 에러

#---------------------------------------------------------------------
# load_set(plugins)
# kmd 모듈의 로딩 순서 리스트를 넘겨주는 함수
#---------------------------------------------------------------------
def load_set(plugins) :
    kmd_list = []

    try :
        # kicom.kmd 파일을 복호화
        pathname = plugins + '\\kicom.kmd'
        pathname = os.path.normcase(pathname)
        ret, buf = load_kmd(pathname)

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

#-----------------------------------------------------------------
# import_kmd(kmd_name)
# 암호화 된 백신 엔진 모듈인 kmd 파일을 import 하는 함수
#-----------------------------------------------------------------
def import_kmd(kmd_name, buf) :
    code = marshal.loads(buf[8:]) # 버퍼를 컴파일 가능한 직렬화 된 문자열로 변환
    module = imp.new_module(kmd_name) # 새로운 모듈 생성
    exec(code, module.__dict__) # 직렬화 된 문자열을 컴파일하여 모듈과 연결
    sys.modules[kmd_name] = module # 전역에서 사용가능하게 등록

    obj = None

    for clsName in dir(module): # 로딩된 모듈에서 KavMain이 있는지 검사
        if clsName.find('KavMain') == 0 : # KavMain이 발견되었으면 클래스의 인스턴스 생성
            obj = module.KavMain()

    # 생성된 인스턴스가 없다면 지금 로딩한 모듈은 취소
    if obj == None :
        # 로딩 취소
        del sys.modules[kmd_name] 
        del module

    return obj # 생성된 인스턴스 리턴

#---------------------------------------------------------------------
# Engine 클래스
# 키콤백신 엔진의 인터페이스 클래스
#---------------------------------------------------------------------
class Engine :
    modules = []
    #-----------------------------------------------------------------
    # init(self, plugins)
    # 키콤백신 엔진을 초기화 한다.
    # 인자값 : plugins - 백신 엔진 모듈이 존재하는 폴더
    # 리턴값 : 성공 여부 (True, False)
    #-----------------------------------------------------------------
    def init(self, plugins) :
        ret = False

        try :
            # kmd 로딩 우선순위 리스트를 가진 kmd 파일에서 리스트 확보
            kmd_list = load_set(plugins) # kicom.kmd 파일 로딩
            if len(kmd_list) == 0 :      # 결과 값이 없으면 종료
                raise SystemError 

            # kmd 로딩 우선순위 리스트 순으로 동적 로딩
            for kmd in kmd_list :
                pathname = plugins + '\\' + kmd
                pathname = os.path.normcase(pathname)
                ret_kmd, buf = load_kmd(pathname)
                if ret_kmd == True :
                    mod = import_kmd(kmd.split('.')[0], buf)
                    # 동적 로딩 되었으면 모듈 관리 리스트에 추가
                    if mod != None :
                        self.modules.append(mod)

            # 로딩된 모듈이 하나도 없으면 종료
            if len(self.modules) == 0 : 
                raise SystemError 

            # 모든 백신 엔진 모듈의 init 멤버 함수 호출
            for i in range(len(self.modules)) :
                mod = self.modules[i]
                for api in dir(mod) :
                    if api == 'init' : # init 멤버 함수가 있으면
                        ret_init = mod.init() # 호출
                        break

            ret = True
        except :
            pass

        return ret

    #-----------------------------------------------------------------
    # uninit(self)
    # 키콤백신 엔진을 종료화 한다.
    #-----------------------------------------------------------------
    def uninit(self) :
        # 백신 엔진 모듈의 uninit 멤버 함수 호출
        for i in range(len(self.modules)) :
            mod = self.modules[i]
            for api in dir(mod) :
                if api == 'uninit' :
                    ret_uninit = mod.uninit()
                    break

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

        for i in range(len(self.modules)) :
            mod = self.modules[i]
            for api in dir(mod) :
                if api == 'listvirus' :
                    ret_listvirus = mod.listvirus()

                    # callback 함수가 있다면 
                    # callback 함수 호출
                    if type(cb) is types.FunctionType :
                        cb(ret_listvirus)
                    # callback 함수가 없다면 
                    # 악성코드 이름을 리스트에 누적
                    else :
                        ret += ret_listvirus

                    break

        # callback 함수 없으면 누적된 악성코드 리스트를 리턴
        if argc == 0 :
            return ret

    #-----------------------------------------------------------------
    # getinfo(self)
    # 키콤백신 엔진이 진단하는 악성코드 이름을 리턴한다.
    #-----------------------------------------------------------------
    def getinfo(self) :
        ret = []

        # 백신 엔진 모듈의 getinfo 멤버 함수 호출
        for i in range(len(self.modules)) :
            mod = self.modules[i]
            for api in dir(mod) :
                if api == 'getinfo' :
                    ret_getinfo = mod.getinfo()
                    ret.append(ret_getinfo)
                    break

        return ret

    #-----------------------------------------------------------------
    # scan(self, filename)
    # 키콤백신 엔진이 악성코드를 진단한다.
    #-----------------------------------------------------------------
    def scan(self, filename) :
        ret = False

        try :
            fp = open(filename, 'rb')
            
            # 백신 엔진 모듈의 scan 멤버 함수 호출
            for i in range(len(self.modules)) :
                mod = self.modules[i]
                for api in dir(mod) :
                    if api == 'scan' :
                        ret, vname, id = mod.scan(fp, filename)
                        if ret == True : # 악성코드 발견이면 검사 중단
                            break
                if ret == True :
                    break

            fp.close()

            return ret, i, vname, id
        except :
            pass

        return False, -1, '', -1

    #-----------------------------------------------------------------
    # disinfect(self, filename, modID, virusID)
    # 키콤백신 엔진이 악성코드를 치료한다.
    #-----------------------------------------------------------------
    def disinfect(self, filename, modID, virusID) :
        ret_disinfect = False

        try :
            mod = self.modules[modID]
            for api in dir(mod) :
                if api == 'disinfect' :
                    ret_disinfect = mod.disinfect(filename, virusID)
                elif api == 'getinfo' :
                    print mod.getinfo()['title']


        except :
            pass

        return ret_disinfect

#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------
kav = Engine()
ret = kav.init('plugins')
if ret == False :
    print 'Error : KICOM Anti-Virus Engine init'
    exit()

kav.listvirus()
kav.getinfo()

ret, modID, vname, id =  kav.scan(sys.argv[1])
if ret == True :
    print vname
    print kav.disinfect(sys.argv[1], modID, id)


kav.uninit()