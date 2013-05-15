# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import hashlib
import os
import sys

# Malware Patterns
VirusDB = [ \
	'EICAR Test:68:44d88612fea8a8f36de82e1278abb02f',  
	'EICAR Test2:68:44d88612fea8a8f36de82e1278abb02e'  # Test Pattern
]

# Check argument
if len(sys.argv) != 2 :
	print 'Usage : vaccine.py [filename]'
	exit()

fname = sys.argv[1]

fsize = os.path.getsize(fname) # Get file size
VirusFound = -1

for i in range(len(VirusDB)) :
	# Read a pattern of Malware
	vdb = VirusDB[i].split(':')
	VirusName = vdb[0] # Malware name
	VirusSize = vdb[1] # Malware file size
	VirusMD5  = vdb[2] # Malware MD5 hash
	
	# Check file size
	if fsize != int(VirusSize) :
		continue
	
	# Open a file
	fp = open(fname, 'rb')
	fbuf = fp.read()
	fp.close()

	# Create MD5 hash
	md5 = hashlib.md5()
	md5.update(fbuf)
	fmd5 = md5.hexdigest()

	# Detection of malware
	if fmd5 == VirusMD5 :
		VirusFound = i
		break

if VirusFound != -1 : # Found a Malware
	vdb = VirusDB[VirusFound].split(':')
	VirusName = vdb[0] # Malware name
	print '[%s] : Found %s Virus -> Repaired' % (fname, VirusName)
	os.remove(fname) # Remove malware
else :
	print 'Not Found'
