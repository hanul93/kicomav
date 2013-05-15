# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os

#-----------------------------------------------------------------
# cure_eicar(fname)
#-----------------------------------------------------------------
def cure_eicar(fname) :
	os.remove(fname)
	return 0