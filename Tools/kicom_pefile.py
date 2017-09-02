# -*- coding:utf-8 -*-
# Author: chanlee(pck886@gmail.com)

import glob
import pefile
import os
import logger

import time
import sys
from capstone import *
from shutil import copyfile

import vtscan

s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(sys.argv[0])
    )
) + os.sep + 'Engine' + os.sep + 'plugins'

sys.path.append(s)

import cryptolib


VIRUS_DB_NAME = 'virus.db'

logger = logger.Klog('Klog').logger


def disassemble(file_path):
    pe = pefile.PE(file_path)

    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(eop)

    code_dump = code_section.get_data()

    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    for i in md.disasm(code_dump, code_addr):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


def scan_section(file_name):
    pe = pefile.PE(file_name)

    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    code_section = pe.get_section_by_rva(eop)

    md5 = cryptolib.md5(code_section.get_data())

    return md5

def read_virus_db(debug=False):
    re_fp = open(VIRUS_DB_NAME, 'rb')

    fd = []

    while (True):
        line = re_fp.readline()

        if not line:
            break

        tmp_str = line.split(':')

        fd.append(tmp_str[1])

    re_fp.close()

    if debug:
        logger.info('=============VIRUS DB LIST=============')
        logger.info(fd)

    return fd


def compare_list_str(v_list, cmp_str):
    for v_str in v_list:
        if v_str == cmp_str:
            return True

    return False


def copy_unknown(file_path):
    # 각종 오류 파일 및 스캔 대상이 아닌 파일을 unknown 폴더로 복사
    logger.info('[EXCEPT_UNKNOWN] : %s' % file_path)

    copy_path = os.getcwd() + '/unknown'

    if not os.path.exists(copy_path):
        os.makedirs(copy_path)

    file_name = os.path.basename(file_path)

    copyfile(file_path, copy_path + os.sep + file_name)


def make_virus_db():
    scan_folder_result = False

    # Entry Point Section의 md5 추출
    md5 = scan_section(file_path)

    # 해당 파일의 사이즈
    f_size = os.path.getsize(file_path)

    # 해당 파일이 이미 DB에 입력되어 있는가?
    if not compare_list_str(virus_list, md5):

        # 해당 파일을 이어쓰기로 열기
        fp = open(VIRUS_DB_NAME, 'a')

        # Virustotal class 초기화
        vt = vtscan.Virustotal(file_path)

        logger.info('[SCAN_FILE_NAME] : %s' % vt.basename)

        # Virustotal에 해당파일 스캔
        result = vt.scan_virustotal()

        # Virustotal에서 응답이 정상적인가 ?
        if not result:
            vt.rescan_virustotal()  # 재스캔

        # Virustotal에 해당 파일의 정보 호출
        # 간혹 204 응답이 오므로 1분후 재후출
        while True:
            if vt.report_virustotal():
                break
            else:
                logger.info('[RESCAN_WAIT] 30 sec')
                time.sleep(30)

        # 해당 파일이 바이러스로 검출되었나 ?
        if not vt.scan_info['detected']:
            # 아닐 경우 unknown 폴더로 이동
            raise pefile.PEFormatError(IOError)

        # Virustotal에서 추출한 바이러스 이름의 가장 끝 명만 사용
        if vt.scan_name.find(':'):
            vt.scan_name = vt.scan_name.split(':')[-1]

        # 파일사이즈 : md5 : 바이러스 이름
        virus_db_data = f_size.__str__() + ':' + md5 + ':' + vt.scan_name

        logger.info('[WRITE_DB] : %s' % virus_db_data)

        # DB 파일에 해당 정보 입력
        fp.write(virus_db_data + '\n')

        # 중간에 멈추더라도 파일을 쓰기 위하여 파일닫기
        fp.close()
        scan_folder_result = True
    else:
        logger.info('[PASS] : %s' % file_path, level='DEBUG')

    return scan_folder_result


if __name__ == '__main__':

    if len(sys.argv) == 0:
        logger.info('Usage : kicom_pefile [file]')

    file_name = sys.argv[1]

    virus_list = read_virus_db(debug=True)

    # 폴더면 내부 파일리스트만 검사 대상 리스트에 등록
    if os.path.isdir(file_name):

        logger.info('=============START DIR SEARCH=============')

        # 폴더 등을 처리할 때를 위해 뒤에 붇는 os.sep는 우선 제거
        if file_name[-1] == os.sep:
            file_name = file_name[:-1]

        # 폴더 안의 파일들을 검사대상 리스트에 추가
        flist = glob.glob(file_name + os.sep + '*')

        # 파일을 분석하여 DB로 저장
        for file_path in flist:

            try:
                make_virus_db()
            except pefile.PEFormatError:
                copy_unknown(file_path)
                continue

    elif os.path.isfile(file_name):

        logger.info('=============START FILE SEARCH=============')

        try:
            make_virus_db()
        except pefile.PEFormatError:

            copy_unknown(file_name)
            pass
