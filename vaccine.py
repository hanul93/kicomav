# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import hashlib
import os
import sys
import re
import imp

#-----------------------------------------------------------------
# CheckRule(rule, s)
#-----------------------------------------------------------------
def CheckRule(rule, s) :
	ret = re.match(rule, s)
	if  ret == None : return None
	if len(ret.group()) != len(s) : return None
	return True
		

rule_size = '[0-9]+'       # rule of file size
rule_md5 = '[0-9a-f]{32}'  # rule of MD5 hash
	
# Malware Patterns
VirusDB = []
fp = open('virus.db')
for c in fp.readlines() :
    line = c.strip()
    VirusDB.append(line)
fp.close()

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

	# Check file size & MD5 hash
	r1 = CheckRule(rule_size, vdb[1])
	r2 = CheckRule(rule_md5, vdb[2])

	if r1 == None or r2 == None:
		continue

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
	VirusName    = vdb[0] # Malware name
	VirusCureFn  = vdb[3] # name of Malware cure function 
	print '[%s] : Found %s Virus -> Repaired' % (fname, VirusName)
	
	# Remove malware
	m = 'curemod'                                   # pyc name
	f, filename, desc = imp.find_module(m, [''])
	module = imp.load_module(m, f, filename, desc)  # load module
	cmd = 'module.%s(fname)' % VirusCureFn
	exec cmd
else :
	print 'Not Found'
