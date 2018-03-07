# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import struct
import hashlib
import zlib
import marshal
import imp
import sys
import os
import py_compile
import random
import shutil
import k2rc4
import k2rsa
import k2timelib


# ---------------------------------------------------------------------
# make(src_fname)
# rsa 개인키를 이용해서 주어진 파일을 암호화하여 KMD 파일을 생성한다.
# 입력값 : src_fname - 암호화 대상 파일
# 리턴값 : kmd 파일 생성 성공 여부
# ---------------------------------------------------------------------
def make(src_fname, debug=False):
    # -----------------------------------------------------------------
    # 암호화 대상 파일을 컴파일 또는 복사해서 준비한다.
    # -----------------------------------------------------------------
    fname = src_fname  # 암호화 대상 파일

    if fname.split('.')[1] == 'py':  # 파이썬 파일을 컴파일 한다.
        py_compile.compile(fname)    # 컴파일
        pyc_name = fname+'c'         # 컴파일 이후 파일명
    else:  # 파이썬 파일이 아닐 경우 확장자를 pyc로 하여 복사한다.
        pyc_name = fname.split('.')[0]+'.pyc'
        shutil.copy(fname, pyc_name)

    # -----------------------------------------------------------------
    # Simple RSA를 사용하기 위해 공개키와 개인키를 로딩한다.
    # -----------------------------------------------------------------
    # 공개키를 로딩한다.
    rsa_pu = k2rsa.read_key('key.pkr')
    # print 'pkr : ', rsa_pu

    # 개인키를 로딩한다.
    rsa_pr = k2rsa.read_key('key.skr')
    # print 'skr : ', rsa_pr

    if not (rsa_pr and rsa_pu):  # 키 파일을 찾을 수 없다
        if debug:
            print 'ERROR : Canot find the Key files!'
        return False

    # -----------------------------------------------------------------
    # KMD 파일을 생성한다.
    # -----------------------------------------------------------------
    # 헤더 : 시그너처(KAVM)+예약영역 : [[KAVM][[날짜][시간]...]
    # -----------------------------------------------------------------
    # 시그너처(KAVM)을 추가한다.
    kmd_data = 'KAVM'

    # 현재 날짜와 시간을 구한다.
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    # 날짜와 시간 값을 2Byte로 변경한다.
    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    reserved_buf = val_date + val_time + (chr(0) * 28)  # 예약 영역

    # 날짜/시간 값이 포함된 예약 영역을 만들어 추가한다.
    kmd_data += reserved_buf

    # -----------------------------------------------------------------
    # 본문 : [[개인키로 암호화한 RC4 키][RC4로 암호화한 파일]]
    # -----------------------------------------------------------------
    random.seed()

    while 1:
        tmp_kmd_data = ''  # 임시 본문 데이터

        # RC4 알고리즘에 사용할 128bit 랜덤키 생성
        key = ''
        for i in range(16):
            key += chr(random.randint(0, 0xff))

        # 생성된 RC4 키를 암호화한다.
        e_key = k2rsa.crypt(key, rsa_pr)  # 개인키로 암호화
        if len(e_key) != 32:  # 암호화에 오류가 존재하면 다시 생성
            continue

        # 암호화된 RC4 키를 복호화한다.
        d_key = k2rsa.crypt(e_key, rsa_pu)  # 공개키로 복호화

        # 생성된 RC4 키에 문제 없음을 확인한다.
        if key == d_key and len(key) == len(d_key):
            # 개인키로 암호화 된 RC4 키를 임시 버퍼에 추가한다.
            tmp_kmd_data += e_key

            # 생성된 pyc 파일 압축하기
            buf1 = open(pyc_name, 'rb').read()
            buf2 = zlib.compress(buf1)

            e_rc4 = k2rc4.RC4()  # RC4 알고리즘 사용
            e_rc4.set_key(key)  # RC4 알고리즘에 key를 적용한다.

            # 압축된 pyc 파일 이미지를 RC4로 암호화한다.
            buf3 = e_rc4.crypt(buf2)

            e_rc4 = k2rc4.RC4()  # RC4 알고리즘 사용
            e_rc4.set_key(key)  # RC4 알고리즘에 key를 적용한다.

            # 암호화한 압축된 pyc 파일 이미지 복호화하여 결과가 같은지를 확인한다.
            if e_rc4.crypt(buf3) != buf2:
                continue

            # 개인키로 암호화 한 압축 된 파일 이미지를 임시 버퍼에 추가한다.
            tmp_kmd_data += buf3

            # ---------------------------------------------------------
            # 꼬리 : [개인키로 암호화한 MD5x3]
            # ---------------------------------------------------------
            # 헤더와 본문에 대해 MD5를 3번 연속 구한다.
            md5 = hashlib.md5()
            md5hash = kmd_data + tmp_kmd_data  # 헤더와 본문을 합쳐서 MD5 계산
            for i in range(3):
                md5.update(md5hash)
                md5hash = md5.hexdigest()

            m = md5hash.decode('hex')

            e_md5 = k2rsa.crypt(m, rsa_pr)  # MD5 결과를 개인키로 암호화
            if len(e_md5) != 32:  # 암호화에 오류가 존재하면 다시 생성
                continue

            d_md5 = k2rsa.crypt(e_md5, rsa_pu)  # 암호화횓 MD5를 공개키로 복호화

            if m == d_md5:  # 원문과 복호화 결과가 같은가?
                # 헤더, 본문, 꼬리를 모두 합친다.
                kmd_data += tmp_kmd_data + e_md5
                break  # 무한 루프를 종료한다.

    # -----------------------------------------------------------------
    # KMD 파일을 생성한다.
    # -----------------------------------------------------------------
    # KMD 파일 이름을 만든다.
    ext = fname.find('.')
    kmd_name = fname[0:ext] + '.kmd'

    try:
        if kmd_data:
            # KMD 파일을 생성한다.
            open(kmd_name, 'wb').write(kmd_data)

            # pyc 파일은 삭제한다.
            os.remove(pyc_name)

            if debug:
                print '    Success : %-13s ->  %s' % (fname, kmd_name)
            return True
        else:
            raise IOError
    except IOError:
        if debug:
            print '    Fail : %s' % fname
        return False


# ---------------------------------------------------------------------
# ntimes_md5(buf, ntimes)
# 주어진 버퍼에 대해 n회 반복해서 MD5 해시 결과를 리턴한다.
# 입력값 : buf    - 버퍼
#         ntimes - 반복 횟수
# 리턴값 : MD5 해시
# ---------------------------------------------------------------------
def ntimes_md5(buf, ntimes):
    md5 = hashlib.md5()
    md5hash = buf
    for i in range(ntimes):
        md5.update(md5hash)
        md5hash = md5.hexdigest()

    return md5hash


# ---------------------------------------------------------------------
# KMD 오류 메시지를 정의
# ---------------------------------------------------------------------
class KMDFormatError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# ---------------------------------------------------------------------
# KMD 관련 상수
# ---------------------------------------------------------------------
class KMDConstants:
    KMD_SIGNATURE = 'KAVM'  # 시그너처

    KMD_DATE_OFFSET = 4  # 날짜 위치
    KMD_DATE_LENGTH = 2  # 날짜 크기
    KMD_TIME_OFFSET = 6  # 시간 위치
    KMD_TIME_LENGTH = 2  # 시간 크기

    KMD_RESERVED_OFFSET = 8  # 예약 영역 위치
    KMD_RESERVED_LENGTH = 28  # 예약 영역 크기

    KMD_RC4_KEY_OFFSET = 36  # RC4 Key 위치
    KMD_RC4_KEY_LENGTH = 32  # RC4 Key 길이

    KMD_MD5_OFFSET = -32  # MD5 위치


# ---------------------------------------------------------------------
# KMD 클래스
# ---------------------------------------------------------------------
class KMD(KMDConstants):
    # ---------------------------------------------------------------------
    # __init__(self, fname, pu)
    # 클래스를 초기화 한다.
    # 인자값 : fname - KMD 파일 이름
    #         pu    - 복호화를 위한 공개키
    # ---------------------------------------------------------------------
    def __init__(self, fname, pu):
        self.filename = fname  # KMD 파일 이름
        self.date = None  # KMD 파일의 날짜
        self.time = None  # KMD 파일의 시간
        self.body = None  # 복호화 된 파일 내용

        self.__kmd_data = None  # KMD 암호화 된 파일 내용
        self.__rsa_pu = pu  # RSA 공개키
        self.__rc4_key = None  # RC4 키

        if self.filename:
            self.__decrypt(self.filename)  # 파일을 복호화한다.

    # ---------------------------------------------------------------------
    # __decrypt(self, fname)
    # kmd 파일을 복호화 한다.
    # 인자값 : fname - KMD 파일 이름
    # ---------------------------------------------------------------------
    def __decrypt(self, fname, debug=False):
        # KMD 파일을 열고 시그너처를 체크한다.
        with open(fname, 'rb') as fp:
            if fp.read(4) == self.KMD_SIGNATURE:  # KMD 파일이 맞는지 체크 함
                self.__kmd_data = self.KMD_SIGNATURE + fp.read()  # 파일을 읽어 들임
            else:
                raise KMDFormatError('KMD Header magic not found.')

        # KMD 파일 날짜 읽기
        tmp = self.__kmd_data[self.KMD_DATE_OFFSET:
                              self.KMD_DATE_OFFSET + self.KMD_DATE_LENGTH]
        self.date = k2timelib.convert_date(struct.unpack('<H', tmp)[0])
        # print self.date

        # KMD 파일 시간 읽기
        tmp = self.__kmd_data[self.KMD_TIME_OFFSET:
                              self.KMD_TIME_OFFSET + self.KMD_TIME_LENGTH]
        self.time = k2timelib.convert_time(struct.unpack('<H', tmp)[0])
        # print self.time

        # KMD 파일에서 MD5 읽기
        e_md5hash = self.__get_md5()

        # 무결성 체크
        md5hash = ntimes_md5(self.__kmd_data[:self.KMD_MD5_OFFSET], 3)
        if e_md5hash != md5hash.decode('hex'):
            raise KMDFormatError('Invalid KMD MD5 hash.')

        # KMD 파일에서 RC4 키 읽기
        self.__rc4_key = self.__get_rc4_key()

        # KMD 파일에서 본문 읽기
        e_kmd_data = self.__get_body()
        if debug:
            print len(e_kmd_data)

        # 압축 해제하기
        self.body = zlib.decompress(e_kmd_data)
        if debug:
            print len(self.body)

    # ---------------------------------------------------------------------
    # __get_rc4_key(self)
    # kmd 파일의 rc4 키를 얻는다.
    # 리턴값 : rc4 키
    # ---------------------------------------------------------------------
    def __get_rc4_key(self):
        e_key = self.__kmd_data[self.KMD_RC4_KEY_OFFSET:
                                self.KMD_RC4_KEY_OFFSET + self.KMD_RC4_KEY_LENGTH]
        return k2rsa.crypt(e_key, self.__rsa_pu)

    # ---------------------------------------------------------------------
    # __get_body(self)
    # kmd 파일의 body를 얻는다.
    # 리턴값 : body
    # ---------------------------------------------------------------------
    def __get_body(self):
        e_kmd_data = self.__kmd_data[self.KMD_RC4_KEY_OFFSET
                                     + self.KMD_RC4_KEY_LENGTH:self.KMD_MD5_OFFSET]
        r = k2rc4.RC4()
        r.set_key(self.__rc4_key)
        return r.crypt(e_kmd_data)

    # ---------------------------------------------------------------------
    # __get_md5(self)
    # kmd 파일의 md5를 얻는다.
    # 리턴값 : md5
    # ---------------------------------------------------------------------
    def __get_md5(self):
        e_md5 = self.__kmd_data[self.KMD_MD5_OFFSET:]
        return k2rsa.crypt(e_md5, self.__rsa_pu)


# ---------------------------------------------------------------------
# load(mod_name, buf)
# 주어진 모듈 이름으로 파이썬 코드를 메모리에 로딩한다.
# 입력값 : mod_name - 모듈 이름
#         buf      - 파이썬 코드 (pyc 시그너처 포함)
# 리턴값 : 로딩된 모듈 Object 
# ---------------------------------------------------------------------
def load(mod_name, buf):
    if buf[:4] == '03F30D0A'.decode('hex'):  # puc 시그너처가 존재하는가?
        try:
            code = marshal.loads(buf[8:])  # pyc에서 파이썬 코드를 로딩한다.
            module = imp.new_module(mod_name)  # 새로운 모듈 생성한다.
            exec (code, module.__dict__)  # pyc 파이썬 코드와 모듈을 연결한다.
            sys.modules[mod_name] = module  # 전역에서 사용가능하게 등록한다.

            return module
        except:
            return None
    else:
        return None
