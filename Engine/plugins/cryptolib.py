# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import hashlib
import zlib
from ctypes import c_ushort


# -------------------------------------------------------------------------
# md5(data)
# 주어진 데이터에 대해 MD5 해시를 구한다.
# 입력값 : data - 데이터
# 리턴값 : MD5 해시 문자열
# -------------------------------------------------------------------------
def md5(data):
    return hashlib.md5(data).hexdigest()


# -------------------------------------------------------------------------
# crc32(data)
# 주어진 데이터에 대해 CRC32 해시를 구한다.
# 입력값 : data - 데이터
# 리턴값 : CRC32 해시 문자열
# -------------------------------------------------------------------------
def crc32(data):
    return '%08x' % (zlib.crc32(data) & 0xffffffff)


# -------------------------------------------------------------------------
# sha256(data)
# 주어진 데이터에 대해 SHA256 해시를 구한다.
# 입력값 : data - 데이터
# 리턴값 : SHA256 해시 문자열
# -------------------------------------------------------------------------
def sha256(data):
    return hashlib.sha256(data).hexdigest()


# -------------------------------------------------------------------------
# CRC16
# 주어진 데이터에 대해 CRC16 해시를 구한다.
# -------------------------------------------------------------------------
class CRC16(object):
    crc16_tab = []

    # The CRC's are computed using polynomials. Here is the most used
    # coefficient for CRC16
    crc16_constant = 0xA001  # 40961

    def __init__(self, modbus_flag=False):
        # initialize the precalculated tables
        if not len(self.crc16_tab):
            self.init_crc16()
        self.mdflag = bool(modbus_flag)

    def calculate(self, input_data=None):
        try:
            is_string = isinstance(input_data, str)
            is_bytes = isinstance(input_data, (bytes, bytearray))

            if not is_string and not is_bytes:
                raise Exception("Please provide a string or a byte sequence "
                                "as argument for calculation.")

            crc_value = 0x0000 if not self.mdflag else 0xffff

            for c in input_data:
                d = ord(c) if is_string else c
                tmp = crc_value ^ d
                rotated = crc_value >> 8
                crc_value = rotated ^ self.crc16_tab[(tmp & 0x00ff)]

            return crc_value
        except Exception as e:
            print("EXCEPTION(calculate): {}".format(e))

    def init_crc16(self):
        """The algorithm uses tables with precalculated values"""
        for i in range(0, 256):
            crc = c_ushort(i).value
            for j in range(0, 8):
                if crc & 0x0001:
                    crc = c_ushort(crc >> 1).value ^ self.crc16_constant
                else:
                    crc = c_ushort(crc >> 1).value
            self.crc16_tab.append(crc)

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
        info['version'] = '1.0'  # 버전
        info['title'] = 'Crypto Library'  # 엔진 설명
        info['kmd_name'] = 'cryptolib'  # 엔진 파일 이름

        return info
