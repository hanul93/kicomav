# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

import re
import sys
import os
import struct
import marshal
import zlib
import cPickle
from acora import AcoraBuilder

s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
) + os.sep + 'Engine' + os.sep + 'kavcore'

sys.path.append(s)

import k2timelib


# -------------------------------------------------------------------------
# virus.db 파일에서 사용할 주석문 정규표현식
# -------------------------------------------------------------------------
re_comment = r'#.*'


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
    builder = AcoraBuilder()

    fp = open(fname, 'rb')

    while True:
        line = fp.readline()
        if not line:
            break

        # 주석문 및 화이트 스페이스 제거
        line = re.sub(re_comment, '', line)
        line = line.strip()

        if len(line) == 0:
            continue  # 아무것도 없다면 다음줄로...

        builder.add(line)
    fp.close()

    ac = builder.build()
    pickled = cPickle.dumps(ac)

    # 현재 날짜와 시간을 구한다.
    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    # 날짜와 시간 값을 2Byte로 변경한다.
    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    # 크기 파일 저장 : ex) script.a01
    name = os.path.splitext(fname)[0]
    sname = '%s.a01' % name
    t = zlib.compress(pickled)
    t = 'KAVS' + struct.pack('<L', len(pickled)) + val_date + val_time + t
    save_file(sname, t)


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage : sigtool_ach.py [sig text]'
        exit(0)

    sin_fname = sys.argv[1]

    make_signature(sin_fname)
