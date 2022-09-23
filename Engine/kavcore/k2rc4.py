# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


# ---------------------------------------------------------------------
# RC4 클래스
# rc4.set_key : 암호 문자열 정의
# rc4.crypt   : 주어진 버퍼 암/복호화
# ---------------------------------------------------------------------
class RC4:
    # -----------------------------------------------------------------
    # __init__(self)
    # 멤버 변수를 초기화한다.
    # -----------------------------------------------------------------
    def __init__(self):
        self.__S = []
        self.__T = []
        self.__Key = []
        self.__K_i = 0
        self.__K_j = 0

    # -----------------------------------------------------------------
    # set_key(self, password)
    # 암호를 설정한다.
    # 인자값 : password - rc4의 암호문
    # -----------------------------------------------------------------
    def set_key(self, password):
        for i in range(len(password)):
            self.__Key.append(ord(password[i]))
        self.__init_rc4()

    # -----------------------------------------------------------------
    # crypt(self, data):
    # 주어진 데이터를 암/복호화한다.
    # 인자값 : data - 암/복호화할 데이터
    # 리턴값 : 암/복호화 결과 데이터
    # -----------------------------------------------------------------
    def crypt(self, data):
        t_str = []

        for i in range(len(data)):
            # surfree
#            t_str.append(ord(data[i]))
            t_str.append(data[i])

        for i in range(len(t_str)):
            t_str[i] ^= self.__gen_k()

        ret_s = bytearray(b'')
        for i in range(len(t_str)):
#            ret_s += chr(t_str[i])
            ret_s.append(t_str[i])

        return bytes(ret_s)

    # -----------------------------------------------------------------
    # __init_rc4(self)
    # rc4의 테이블을 초기화한다.
    # -----------------------------------------------------------------
    def __init_rc4(self):
        # S 초기화
        for i in range(256):
            self.__S.append(i)
            self.__T.append(self.__Key[i % len(self.__Key)])

        # S의 초기 순열 (치환)
        j = 0
        for i in range(256):
            j = (j + self.__S[i] + self.__T[i]) % 256
            self.__swap(i, j)

    # -----------------------------------------------------------------
    # __swap(self, i, j):
    # 주어진 두 인덱스의 데이터를 교환한다.
    # -----------------------------------------------------------------
    def __swap(self, i, j):
        temp = self.__S[i]
        self.__S[i] = self.__S[j]
        self.__S[j] = temp

    # -----------------------------------------------------------------
    # __gen_k(self)
    # 암/복호화에 필요한 스트림을 생성한다.
    # -----------------------------------------------------------------
    def __gen_k(self):
        i = self.__K_i
        j = self.__K_j

        i = (i + 1) % 256
        j = (j + self.__S[i]) % 256
        self.__swap(i, j)
        t = (self.__S[i] + self.__S[j]) % 256

        self.__K_i = i
        self.__K_j = j

        return self.__S[t]
