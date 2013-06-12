# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import glob
import os
import hashlib

file_scan_list = []
file_scan_list.append('.')

while len(file_scan_list) != 0 :
    real_name = file_scan_list.pop(0)

    if os.path.isdir(real_name) == True :    
        flist = glob.glob(real_name + '/*')
        file_scan_list += flist
    else :
        fp = open(real_name, 'rb')
        data = fp.read()
        fp.close()

        s = hashlib.sha1()
        s.update(data)
        hash = s.hexdigest()

        print hash, real_name[2:]
