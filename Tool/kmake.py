# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import py_compile
import sys
import zlib
import hashlib
import os
import shutil

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

# Add MagicID('KAVM')
buf3 = 'KAVM' + buf3

md5 = hashlib.md5()

# MD5 hash value is calculated 3 times
md5hash = buf3
for i in range(3): 
    md5.update(md5hash)
    md5hash = md5.hexdigest()   
    
buf3 += md5hash # Add MD5x3 to tail

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