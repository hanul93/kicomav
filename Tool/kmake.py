# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import py_compile
import sys
import zlib
import hashlib
import os
import shutil
import time
import struct

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

# [HEADER          ][CODE Image][TAILER  ]
# [KAVM][DATE][TIME][Image     ][Sha256x3]

# Check arguments
if len(sys.argv) != 2 :
    print 'Usage : kmake.py [python source]'
    exit()
    
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
buf2 = zlib.compress(buf1, 9)

# XOR Encryption
buf3 =""
for i in range(len(buf2)):
    c = ord(buf2[i]) ^ 0xFF
    buf3 += chr(c)

# Add Date and Time
now = time.gmtime()
ret_date = GetDateValue(now)
ret_time = GetTimeValue(now)

d = struct.pack('<H', ret_date)
t = struct.pack('<H', ret_time)

# Add MagicID('KAVM')
buf3 = 'KAVM' + d + t + buf3

sha256 = hashlib.sha256()

# sha256 hash value is calculated 3 times
sha256hash = buf3
for i in range(3): 
    sha256.update(sha256hash)
    sha256hash = sha256.hexdigest()   
    
buf3 += sha256hash # Add sha256x3 to tail

# Change the name of the extension to KMD
ext = fname.find('.')
kmd_name = fname[0:ext] + '.kmd'

# Write kmd file
fp = open(kmd_name, 'wb')
fp.write(buf3)
fp.close()

# remove pyc file
os.remove(pyc_name)
print 'Success : %s -> %s' % (fname, kmd_name)  