# -*- coding:utf-8 -*-

import os
import sys
import imp
import hashlib
import zlib
import struct
import StringIO
import datetime
import marshal
import base64
from k2rc4    import K2RC4
from k2ctime  import K2CTIME

#---------------------------------------------------------------------
# KMD 클래스
#---------------------------------------------------------------------
class K2KMD :
    def __init__(self) :
        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)

    def GetLastUpdate(self) :
        return self.max_datetime

    def GetList(self, plugins) :
        kmd_list = []

        try :
            # RSA 공개키 로딩
            fp = open(plugins + os.sep + 'kicomav.pkr', 'rt') # 공개키
            b = fp.read()
            fp.close()
            s = base64.b64decode(b)
            self.PU = marshal.loads(s)

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

    def RSACrypt(self, buf, PR) :
        plantext_ord = 0
        for i in range(len(buf)) :
            plantext_ord |= ord(buf[i]) << (i*8)

        val = pow(plantext_ord, PR[0], PR[1]) # 개인키로 암호화

        ret = ''
        for i in range(32) :
            b = val & 0xff
            val >>= 8
            ret += chr(b)

            if val == 0 :
                break

        return ret

    def Decrypt(self, fname) :
        t = K2CTIME()
        header_length = 8
        hash_length = 0x40

        try : # 예외가 발생할 가능성에 대해 처리
            # kmd 파일 읽기
            fp = open(fname, 'rb') 
            buf = fp.read()
            fp.close()

            # 파일에서 각 부분 분리
            e_md5         = buf[len(buf)-32:]
            buf           = buf[:len(buf)-32]
            header        = buf[:4]
            reserved_area = buf[4:4+32]
            rc4_key       = buf[36:36+32]
            enc_data      = buf[36+32:]

            # 헤더 체크
            if header != 'KAVM' :
                raise ValueError

            # 파일 뒤 md5 정보로 무결성 체크
            e_md5hash = self.RSACrypt(e_md5, self.PU)

            md5 = hashlib.md5()
            md5hash = buf
            for i in range(3): 
                md5.update(md5hash)
                md5hash = md5.hexdigest()   

            if e_md5hash != md5hash.decode('hex') :
                raise ValueError

            # RC4 Key 복호화
            key = self.RSACrypt(rc4_key, self.PU)
            
            # RC4 복호화
            e_rc4 = K2RC4()  # 암호화
            e_rc4.SetKey(key)
            data = e_rc4.Crypt(enc_data)

            # 압축 해제
            data = zlib.decompress(data)

            # 최근 날짜 구하기
            kmd_date = reserved_area[0:2]
            kmd_time = reserved_area[2:4]

            d_y, d_m, d_d = t.GetDate(struct.unpack('<H', kmd_date)[0])
            t_h, t_m, t_s = t.GetTime(struct.unpack('<H', kmd_time)[0])
            t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

            if self.max_datetime < t_datetime :
                self.max_datetime = t_datetime

            return True, data # kmd 복호화 성공 그리고 복호화된 내용 리턴
        except : # 예외 발생
            import traceback
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
            import traceback
            print traceback.format_exc()

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

