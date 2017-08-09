# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import sys

s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
) + os.sep + 'Engine' + os.sep + 'kavcore'

sys.path.append(s)

import k2kmdfile


if __name__ == '__main__':
    # -----------------------------------------------------------------
    # 인자값을 체크한다.
    # -----------------------------------------------------------------
    if len(sys.argv) != 2:
        print 'Usage : kmake.py [python source]'
        exit()

    k2kmdfile.make(sys.argv[1], True)
