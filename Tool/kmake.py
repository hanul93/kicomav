# -*- coding:utf-8 -*-

"""
Copyright (C) 2013-2014 Nurilab.

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

import base64
import hashlib
import marshal
import os
import py_compile
import random
import shutil
import struct
import sys
import time
import zlib

#---------------------------------------------------------------------
# RC4 클래스
#---------------------------------------------------------------------
class RC4 :
    def __init__(self) :
        self.S   = []
        self.T   = []
        self.Key = []
        self.K_i = 0
        self.K_j = 0

    def SetKey(self, s_key) :
        for i in range(len(s_key)) :
            self.Key.append(ord(s_key[i]))
        self.__InitRc4__()

    def __InitRc4__(self) :
        # S 초기화
        for i in range(256) :
            self.S.append(i)
            self.T.append(self.Key[i%len(self.Key)])

        # S의 초기 순열 (치환)    
        j = 0
        for i in range(256) :
            j = (j + self.S[i] + self.T[i]) % 256
            self.__Swap__(i, j)

    def __Swap__(self, i, j) :
        temp      = self.S[i]
        self.S[i] = self.S[j]
        self.S[j] = temp

    def GenK(self) :
        # 스트림 생성
        i = self.K_i
        j = self.K_j
        
        i = (i + 1) % 256
        j = (j + self.S[i]) % 256
        self.__Swap__(i, j)
        t = (self.S[i] + self.S[j]) % 256

        self.K_i = i
        self.K_j = j

        return self.S[t]

    def Crypt(self, s_string) :
        Str = []

        for i in range(len(s_string)) :
            Str.append(ord(s_string[i]))
            
        for i in range(len(Str)) :
            Str[i] ^= self.GenK()

        ret_s = ''
        for i in range(len(Str)) :
            ret_s += chr(Str[i])

        return ret_s

def GetDateValue(now) :
    t_y = now.tm_year - 1980
    t_y = (t_y << 9) & 0xFE00
    t_m = (now.tm_mon << 5) & 0x01E0
    t_d = (now.tm_mday) & 0x001F

    return (t_y | t_m | t_d) & 0xFFFF


def GetTimeValue(now) :
    t_h = (now.tm_hour << 11) & 0xF800
    t_m = (now.tm_min << 5) & 0x07E0
    t_s = (now.tm_sec / 2) & 0x001F

    return (t_h | t_m | t_s) & 0xFFFF

def RSACrypt(buf, PR) :

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



# [HEADER          ][CODE Image][TAILER]
# [KAVM][DATE][TIME][Image     ][md5x3 ]

# Check arguments
if len(sys.argv) != 2 :
    print 'Usage : kmake.py [python source]'
    exit()

# RSA 키로딩
fp = open('key.skr', 'rt') # 개인키
b = fp.read()
fp.close()
s = base64.b64decode(b)
PR = marshal.loads(s)

# print 'skr : ', PR

fp = open('key.pkr', 'rt') # 공개키
b = fp.read()
fp.close()
s = base64.b64decode(b)
PU = marshal.loads(s)
# print 'pkr : ', PU

# Compile python source files
fname = sys.argv[1] 
if fname.split('.')[1] == 'py' :
    py_compile.compile(fname) # 컴파일
    pyc_name = fname+'c'      # 컴파일 이후 파일명
else :
    pyc_name = fname.split('.')[0]+'.pyc'
    shutil.copy (fname, pyc_name) # lst 파일을 pyc 파일로 복사

# Compress
buf1 = open(pyc_name, 'rb').read()
buf2 = zlib.compress(buf1)

# Add Date and Time
now = time.gmtime()
ret_date = GetDateValue(now)
ret_time = GetTimeValue(now)

d = struct.pack('<H', ret_date)
t = struct.pack('<H', ret_time)

# 128비트 랜덤키 생성 
random.seed()

while 1 :
    key = ''
    for i in range(16) :
        key += chr(random.randint(0, 0xff))

    # RC4 키 암호화
    # print key, len(key)
    e_key = RSACrypt(key, PR) # 개인키로 암호화
    if len(e_key) != 32 :
        continue 

    d_key = RSACrypt(e_key, PU) # 복호화
    
    # print d_key, len(d_key)

    if key == d_key and len(key) == len(d_key) :     
        # RC4 암호화
        e_rc4 = RC4()  # 암호화
        e_rc4.SetKey(key)
        buf3 = e_rc4.Crypt(buf2)

        # RC4 암호화
        e_rc4 = RC4()  # 암호화
        e_rc4.SetKey(key)
        if e_rc4.Crypt(buf3) != buf2 :
            print 'ERROR'


        # 파일 구성
        reserved_buf = d + t + (chr(0)*28) # 예약영역
        buf3 = 'KAVM' + reserved_buf + e_key + buf3

        md5 = hashlib.md5()

        # md5 hash value is calculated 3 times
        md5hash = buf3
        for i in range(3): 
            md5.update(md5hash)
            md5hash = md5.hexdigest()   

        m = md5hash.decode('hex')

        # print m
        # print md5hash

        e_md5 = RSACrypt(m, PR) # 개인키로 암호화
        if len(e_md5) != 32 :
            continue 

        d_md5 = RSACrypt(e_md5, PU) # 복호화

        if m == d_md5 :
            buf3 += e_md5 # Add md5x3 to tail
            break

# Change the name of the extension to KMD
ext = fname.find('.')
kmd_name = fname[0:ext] + '.kmd'

# Write kmd file
fp = open(kmd_name, 'wb')
fp.write(buf3)
fp.close()

# remove pyc file
os.remove(pyc_name)
print '    Success : %-13s ->  %s' % (fname, kmd_name)  
