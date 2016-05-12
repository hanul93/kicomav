# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import sys
import marshal
import zlib
import shutil
import time
import struct
import hashlib

SIGDB_FILENAME = 'x95m.mdb'

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


def SigDB2PatBin(fname, sig_num) :
    shutil.copy (fname, fname+'.bak') # bak 파일로 복사

    # Compress
    fp = open(fname, 'rb')
    buf1 = fp.read()
    fp.close()

    buf2 = zlib.compress(buf1, 9)

    # Add Date and Time
    now = time.gmtime()
    ret_date = GetDateValue(now)
    ret_time = GetTimeValue(now)

    d = struct.pack('<H', ret_date)
    t = struct.pack('<H', ret_time)
    sig_num = struct.pack('<L', long(sig_num))

    # Add MagicID('KAVM')
    buf3 = 'KAVM' + d + t + sig_num + buf2

    sha256 = hashlib.sha256()

    # sha256 hash value is calculated 3 times
    if len(buf3) > 0x4000 :
        sha256hash = buf3[:0x4000]
    else :
        sha256hash = buf3

    for i in range(3): 
        sha256.update(sha256hash)
        sha256hash = sha256.hexdigest()   
        
    buf3 += sha256hash # Add sha256x3 to tail

    # Write file
    fp = open(fname, 'wb')
    fp.write(buf3)
    fp.close()

    print 'Success : %s' % (fname)  


def Func_Pack(filename, id) :
    global line_num

    try :
        Paser_SigMDB(filename, id)

        fname = '%s.c%02d' % (filename, id)
        SigDB2PatBin(fname, line_num)

        fname = '%s.i%02d' % (filename, id)
        SigDB2PatBin(fname, 0)
    except :
        import traceback
        print traceback.format_exc()
        pass

def Paser_SigMDB(file, num) :
    global SIGDB_FILENAME
    fp = open(SIGDB_FILENAME)

    while 1: 
        lines = fp.readlines(100000) #메모리가 허용하는 적당한 양 
        if not lines: 
            break 
        for line in lines: 
            convert(line, num)

    fp.close()

    fname = '%s.c%02d' % (file, num)
    output = open(fname, 'wb')
    #s = pickle.dumps(db_size_pattern, -1)
    s = marshal.dumps(db_size_pattern)
    output.write(s)
    output.close()

    fname = '%s.i%02d' % (file, num)
    output = open(fname, 'wb')
    # s = pickle.dumps(db_vname, -1)
    s = marshal.dumps(db_vname)
    output.write(s)
    output.close()

db_size_pattern = {}
db_vname = []
line_num = 0

def convert(line, num) :
    global db_size_pattern
    global db_vname
    global line_num

    line    = line.strip()
    pattern = line.split(':')

    fsize   = int(pattern[0])
    md5     = pattern[1].decode('hex')
    #macro_data_size = pattern[2]
    #virname = pattern[3]

    try :
        id_pattern = db_size_pattern[fsize]
    except :
        id_pattern = {}

    id_pattern[md5[0:6]] = [num, line_num] # 파일번호, 바이러스명 ID

    db_size_pattern[fsize] = id_pattern
    line_num += 1

    # t = [md5[6:], macro_data_size, virname]
    t = []
    t.append(md5[6:])
    for i in range(len(pattern)-2) :
        t.append(pattern[i+2])
    db_vname.append(t)


def main() :
    global SIGDB_FILENAME

    SIGDB_FILENAME = sys.argv[1]
    Func_Pack(sys.argv[2], int(sys.argv[3]))

if __name__ == '__main__' :
    main()