# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

# Open a file
fp = open('eicar.txt', 'rb')
fbuf = fp.read()
fp.close()

# Detection of malware
if fbuf[0:3] == 'X5O' :
    print 'Found Virus'
else :
    print 'Not Found'