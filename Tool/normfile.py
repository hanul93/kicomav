# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

# sigtool 옵션에 의해 생성된 파일을 악성코드 검사를 위한 버퍼 형태를 만든다.
# 사용방법 : normfile.py [sigtool.log]


import sys
import re
import hashlib


# 주석문 및 공백 제거를 위한 정규표현식
p_http = re.compile(r'https?://')
p_script_cmt1 = re.compile(r'//.*|/\*[\d\D]*?\*/')
p_script_cmt2 = re.compile(r'(#|\bREM\b).*', re.IGNORECASE)
p_space = re.compile(r'\s')

p_vba = re.compile(r'^\s*Attribute\s+VB_Name.+|^\s*Attribute\s+.+VB_Invoke_Func.+|\s+_\r?\n', re.IGNORECASE|re.MULTILINE)
p_vba_cmt = re.compile(r'(\'|\bREM\b).*', re.IGNORECASE)

# -------------------------------------------------------------------------
# sigtool.log의 로그 한 줄을 분석한 뒤 파일 내용을 정형화 하는 작업
# -------------------------------------------------------------------------
def normfile(fname, ftype):
    buf = open(fname, 'rb').read()  # 파일 읽기

    if ftype.find('HTML/Script') >= 0 or ftype.find('HTML/IFrame') >= 0:
        buf = p_http.sub('', buf)  # http:// 제거
        buf = p_script_cmt1.sub('', buf)  # 주석문 제거
        buf = p_script_cmt2.sub('', buf)  # 주석문 제거
        buf = p_space.sub('', buf)  # 공백 제거
        buf = buf.lower()  # 영어 소문자로 통일
    elif ftype.find('VBA/') >= 0 and buf.find('Attribute VB_Name') >= 0:
        buf = p_vba_cmt.sub('', buf)  # 주석문 제거
        buf = p_vba.sub('', buf)  # 불필요한 정보 제거
        buf = p_space.sub('', buf)  # 공백 제거
        buf = buf.lower()  # 영어 소문자로 통일
    elif ftype.find('Attached') >= 0:
        pass
    else:
        print 'NOT Support : %s' % ftype
        return

    # 정형화된 내용의 파일을 생성한다.
    new_fname = 'm_'+fname
    open(new_fname, 'wb').write(buf)

    # 악성코드 패턴 만들기
    fsize = len(buf)
    fmd5 = hashlib.md5(buf).hexdigest()

    msg = '%d:%s:Malware_Name  # %s, %s\n' % (fsize, fmd5, new_fname, ftype)
    open('sigtool_md5.log', 'at').write(msg)


# -------------------------------------------------------------------------
# sigtool.log의 로그 한 줄을
# -------------------------------------------------------------------------
def main(log_fname):
    fp = open(log_fname)
    while True:
        line = fp.readline()
        if not line:
            break
        line = line.strip()

        f = line.split(':')

        fname = f[0].strip()
        ftype = f[1].strip()
        print fname

        normfile(fname, ftype)  # 정형화 하기
    fp.close()


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage : normfile.py [sigtool.log]'
        exit(0)

    main(sys.argv[1])
