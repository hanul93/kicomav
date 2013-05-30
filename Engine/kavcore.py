# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import zlib
import hashlib
import StringIO
import marshal
import imp
import sys
import os
import types
import mmap
import traceback

#---------------------------------------------------------------------
# Engine 클래스
#---------------------------------------------------------------------
class Engine :
    def __init__(self) :
        self.kmd_list = []
        self.mod_list = []
    
    # plugins 폴더에 kmd 모듈을 로딩한다.
    def SetPlugings(self, plugins) :
        ret = False
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
            print traceback.format_exc()
            pass

        return ret

    def CreateInstance(self) :
        ei = EngineInstance()
        ret = ei.SetModuleList(self.ckmd, self.mod_list)

        if ret == 0 :
            return ei
        else :
            return None
        
#---------------------------------------------------------------------
# EngineInstance 클래스
#---------------------------------------------------------------------
class EngineInstance :
    def __init__(self) :
        self.modules        = []
        self.KMD_AntiVirus  = []
        self.KMD_Decompress = []
        self.KMD_FileFormat = []

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
                    ret_init = mod.init() # 호출
                    if ret_init != 0 :
                        raise SystemError
        except :
            return False
            
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
    # scan(self, filename)
    # 키콤백신 엔진이 악성코드를 진단한다.
    #-----------------------------------------------------------------
    def scan(self, filename) :
        ret = False

        try :
            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            
            # 백신 엔진 모듈의 scan 멤버 함수 호출
            for mod in self.modules :
                if dir(mod).count('scan') != 0 : # API 존재
                    ret, vname, id = mod.scan(mm, filename)
                    if ret == True : # 악성코드 발견이면 검사 중단
                        break

            mm.close()
            fp.close()

            if ret == True :
                return ret, self.modules.index(mod), vname, id
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
            if dir(mod).count('disinfect') != 0 : # API 존재
                ret_disinfect = mod.disinfect(filename, virusID)

        except :
            pass

        return ret_disinfect

    #-----------------------------------------------------------------
    # getinfo(self)
    # 키콤백신 엔진이 진단하는 악성코드 이름을 리턴한다.
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
                    cb(ret_listvirus)
                # callback 함수가 없다면 
                # 악성코드 이름을 리스트에 누적
                else :
                    ret += ret_listvirus

        # callback 함수 없으면 누적된 악성코드 리스트를 리턴
        if argc == 0 :
            return ret


#---------------------------------------------------------------------
# KMD 클래스
#---------------------------------------------------------------------
class KMD :     
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
            print traceback.format_exc()
            pass
        
        return kmd_list # kmd 순서 리스트 리턴  

    def Decrypt(self, fname) :
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
            print traceback.format_exc()
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
def cb(list_vir) :
    for vir in list_vir :
        print vir

# 엔진 클래스
kav = Engine() 
kav.SetPlugings('plugins') # 플러그인 폴더 설정

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
