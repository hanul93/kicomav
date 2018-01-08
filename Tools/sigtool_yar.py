# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

import re
import sys
import os
import struct
import yara
import zlib
import cPickle


s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
) + os.sep + 'Engine' + os.sep + 'kavcore'

sys.path.append(s)

import k2timelib


# -------------------------------------------------------------------------
# virus.db 파일에서 Rule의 숫자를 얻는다.
# -------------------------------------------------------------------------
re_rule = r'rule\s+\w+'


# -------------------------------------------------------------------------
# 파일을 생성한다.
# -------------------------------------------------------------------------
def save_file(fname, data):
    fp = open(fname, 'wb')
    fp.write(data)
    fp.close()


# -------------------------------------------------------------------------
# 텍스트 형태의 악성코드 패턴 DB 파일을 분석해서 악성코드 패턴 파일들을 생성한다.
# -------------------------------------------------------------------------
def make_signature(fname):
    p_rule = re.compile(re_rule)

    buf = open(fname, 'rb').read()
    sig_num = len(p_rule.findall(buf))

    c = yara.compile(fname)
    c.save(fname + '.yc')

    buf = open(fname + '.yc', 'rb').read()
    os.remove(fname + '.yc')

    # 현재 날짜와 시간을 구한다.
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    # 날짜와 시간 값을 2Byte로 변경한다.
    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    # 크기 파일 저장 : ex) script.a01
    name = os.path.splitext(fname)[0]
    sname = '%s.y01' % name
    t = zlib.compress(buf)
    t = 'KAVS' + struct.pack('<L', sig_num) + val_date + val_time + t
    save_file(sname, t)


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage : sigtool_yar.py [sig text]'
        exit(0)

    sin_fname = sys.argv[1]

    make_signature(sin_fname)
