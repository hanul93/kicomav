# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import sys
import struct
import types
import kernel
import kavutil


# -------------------------------------------------------------------------
# 메시지 출력 함수
# -------------------------------------------------------------------------
__version__ = '1.0'


# -------------------------------------------------------------------------
# 엔진 오류 메시지를 정의
# -------------------------------------------------------------------------
class Error(Exception):
    pass


# ---------------------------------------------------------------------
# MisiBase64 인코더 디코더
# ---------------------------------------------------------------------
def MsiBase64Encode(x):
    ct = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'
    if x > 63:
        return None

    return ord(ct[x])


def DecodeStreamName(name):
    wch = []
    och = []

    for i in range(len(name) / 2):
        wch.append(kavutil.get_uint16(name, i * 2))

    for ch in wch:
        if 0x3800 <= ch <= 0x4840:
            if ch >= 0x4800:  # 0x4800 - 0x483F
                # only one charecter can be decoded
                ch = MsiBase64Encode(ch - 0x4800)
                if not ch:
                    continue
            else:  # 0x3800 - 0x383F
                # the value contains two characters
                ch -= 0x3800
                och.append(MsiBase64Encode(ch & 0x3f))
                ch = MsiBase64Encode(((ch >> 6) & 0x3f))

        och.append(ch)

    ret_str = ''

    for ch in och:
        ret_str += struct.pack('<H', ch)

    # print ret_str.decode('UTF-16LE', 'replace')
    return ret_str


# ---------------------------------------------------------------------
# OLE 내부 링크 구하기
# ---------------------------------------------------------------------
def get_block_link(no, bbd_or_sbd_fat):
    ret = []

    fat = bbd_or_sbd_fat

    next_b = no

    if next_b != 0xfffffffe:
        ret.append(next_b)

        while True:
            try:
                next_b = fat[next_b]
                if next_b == 0xfffffffe:
                    break

                if len(ret) % 10000 == 0:
                    if next_b in ret:  # 이미 링크가 존재하면 종료
                        break

                ret.append(next_b)
            except KeyError:
                break

    return ret


# ---------------------------------------------------------------------
# OLE 블록 읽기
# ---------------------------------------------------------------------
def get_bblock(buf, no, bsize):
    off = (no+1) * bsize
    return buf[off:off+bsize]


# ---------------------------------------------------------------------
# OLE의 BBD 리스트를 얻는다.
# ---------------------------------------------------------------------
def get_bbd_list_array(buf, verbose=False):
    bbd_list_array = buf[0x4c:0x200]  # 전체 bbd_list
    num_of_bbd_blocks = kavutil.get_uint32(buf, 0x2c)

    xbbd_start_block = kavutil.get_uint32(buf, 0x44)
    num_of_xbbd_blocks = kavutil.get_uint32(buf, 0x48)

    bsize = 1 << kavutil.get_uint16(buf, 0x1e)

    if verbose:
        kavutil.vprint(None, 'Num of BBD Blocks', '%d' % num_of_bbd_blocks)
        kavutil.vprint(None, 'XBBD Start', '%08X' % xbbd_start_block)
        kavutil.vprint(None, 'Num of XBBD Blocks', '%d' % num_of_xbbd_blocks)

    if num_of_bbd_blocks > 109:  # bbd list 개수가 109보다 크면 xbbd를 가져와야 함
        next_b = xbbd_start_block

        for i in range(num_of_xbbd_blocks):
            t_data = get_bblock(buf, next_b, bsize)
            bbd_list_array += t_data[:-4]
            next_b = kavutil.get_uint32(t_data, bsize-4)

    return bbd_list_array[:num_of_bbd_blocks*4], num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block


# ---------------------------------------------------------------------
# OLE의 BBD list의 index를 Offset으로 리턴한다.
# ---------------------------------------------------------------------
def get_bbd_list_index_to_offset(buf, idx):
    num_of_bbd_blocks = kavutil.get_uint32(buf, 0x2c)

    xbbd_start_block = kavutil.get_uint32(buf, 0x44)
    # num_of_xbbd_blocks = kavutil.get_uint32(buf, 0x48)

    bsize = 1 << kavutil.get_uint16(buf, 0x1e)

    if idx >= num_of_bbd_blocks:  # 범위를 벗어나면 에러
        return -1

    if idx <= 109:
        return 0x4c + (idx * 4)
    else:
        t_idx = idx - 109
        seg = (t_idx / ((bsize / 4) - 1)) + (1 if (t_idx % ((bsize / 4) - 1)) else 0)
        off = (t_idx % ((bsize / 4) - 1))

        next_b = xbbd_start_block
        for i in range(seg):
            if next_b == 0xfffffffe:
                return -1

            t_buf = get_bblock(buf, next_b, bsize)
            next_b = kavutil.get_uint32(t_buf, bsize-4)

        return (next_b + 1) * bsize + (off * 4)


# ---------------------------------------------------------------------
# OLE 파일인지 확인한다.
# ---------------------------------------------------------------------
def is_olefile(filename):
    try:
        buf = open(filename, 'rb').read(8)

        if buf == 'D0CF11E0A1B11AE1'.decode('hex'):
            return True
    except IOError:
        pass

    return False


# ---------------------------------------------------------------------
# OleFile 클래스
# ---------------------------------------------------------------------
class OleFile:
    def __init__(self, input_data, write_mode=False, verbose=False):
        self.verbose = verbose  # 디버깅용
        self.isfile = False  # 파일로 접근 중인가?

        if isinstance(input_data, types.StringType):
            if os.path.exists(input_data):
                self.isfile = True
                self.fname = input_data
                self.fp = open(input_data, 'rb')
                buf = self.fp.read()
            else:
                buf = input_data
        else:
            raise Error('Input data is invalid.')

        # 수정 모드
        self.write_mode = write_mode

        # OLE 주요 데이터
        self.mm = None
        self.bsize = None
        self.ssize = None
        self.bbd_list_array = None
        self.bbd = None
        self.bbd_fat = {}
        self.sbd = None
        self.root = None
        self.pps = None
        self.small_block = None
        self.root_list_array = None
        self.exploit = []  # 취약점 존재 여부

        # 임시 변수
        self.__deep = None
        self.__full_list = None

        self.init(buf)

    def init(self, buf):
        # OLE 주요 데이터
        self.mm = buf
        self.bsize = 0
        self.ssize = 0

        # 임시 변수
        self.__deep = 0
        self.__full_list = []

        self.parse()  # OLE 파일을 분석

    def close(self):
        if self.isfile:
            self.fp.close()

            if self.write_mode:
                open(self.fname, 'wb').write(self.mm)

    # ---------------------------------------------------------------------
    # OLE 파싱하기
    # ---------------------------------------------------------------------
    def parse(self):
        buf = self.mm[:8]
        if buf != 'D0CF11E0A1B11AE1'.decode('hex'):
            raise Error('Not Ole signature')

        # big block, small bloc 크기 구하기
        self.bsize = 1 << kavutil.get_uint16(self.mm, 0x1e)
        self.ssize = 1 << kavutil.get_uint16(self.mm, 0x20)

        if self.verbose:
            kavutil.vprint('Header')
            kavutil.vprint(None, 'Big Block Size', '%d' % self.bsize)
            kavutil.vprint(None, 'Small Block Size', '%d' % self.ssize)
            print
            kavutil.HexDump().Buffer(self.mm, 0, 0x60)
            print

        if self.bsize % 0x200 != 0 or self.ssize != 0x40:  # 이상 파일 정보 처리
            return False

        # bbd 읽기
        self.bbd_list_array, num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block = \
            get_bbd_list_array(self.mm, self.verbose)

        '''
        # 상당히 많은 데이터가 출력되어 주석 처리
        if self.verbose:
            print
            if num_of_bbd_blocks < 109:
                kavutil.HexDump().Buffer(self.mm, 0x4c, num_of_bbd_blocks * 4)
            else:
                kavutil.HexDump().Buffer(self.mm, 0x4c, num_of_bbd_blocks * 109)

                next_b = xbbd_start_block
                for i in range(num_of_xbbd_blocks):
                    t_data = get_bblock(self.mm, next_b, self.bsize)
                    print
                    kavutil.HexDump().Buffer(self.mm, (next_b+1) * self.bsize)
                    next_b = kavutil.get_uint32(t_data, self.bsize-4)
        '''

        if len(self.bbd_list_array)/4 < num_of_bbd_blocks:
            return False

        self.bbd = ''
        for i in range(num_of_bbd_blocks):
            no = kavutil.get_uint32(self.bbd_list_array, i*4)
            self.bbd += get_bblock(self.mm, no, self.bsize)

        self.bbd_fat = {}
        for i in range(len(self.bbd) / 4):
            n = kavutil.get_uint32(self.bbd, i*4)
            self.bbd_fat[i] = n

        if self.verbose:
            open('bbd.dmp', 'wb').write(self.bbd)
            print
            kavutil.vprint('BBD')
            print
            kavutil.HexDump().Buffer(self.bbd, 0, 0x80)

        # Root 읽기
        root_startblock = kavutil.get_uint32(self.mm, 0x30)
        root_list_array = get_block_link(root_startblock, self.bbd_fat)
        self.root_list_array = root_list_array

        self.root = ''
        for no in root_list_array:
            self.root += get_bblock(self.mm, no, self.bsize)

        if self.verbose:
            open('root.dmp', 'wb').write(self.root)
            print
            kavutil.vprint('ROOT')
            kavutil.vprint(None, 'Start Blocks', '%d' % root_startblock)
            print
            kavutil.HexDump().Buffer(self.root, 0, 0x80)

        # sbd 읽기
        sbd_startblock = kavutil.get_uint32(self.mm, 0x3c)
        num_of_sbd_blocks = kavutil.get_uint32(self.mm, 0x40)
        sbd_list_array = get_block_link(sbd_startblock, self.bbd_fat)

        self.sbd = ''
        for no in sbd_list_array:
            self.sbd += get_bblock(self.mm, no, self.bsize)

        self.sbd_fat = {}
        for i in range(len(self.sbd) / 4):
            n = kavutil.get_uint32(self.sbd, i*4)
            self.sbd_fat[i] = n

        if self.verbose:
            open('sbd.dmp', 'wb').write(self.sbd)
            print
            kavutil.vprint('SBD')
            kavutil.vprint(None, 'Start Blocks', '%d' % sbd_startblock)
            kavutil.vprint(None, 'Num of SBD Blocks', '%d' % num_of_sbd_blocks)
            print
            kavutil.HexDump().Buffer(self.sbd, 0, 0x80)

        # PPS 읽기
        self.pps = []
        for i in range(len(self.root) / 0x80):
            p = {}
            pps = self.root[i*0x80:(i+1)*0x80]

            t_size = min(kavutil.get_uint16(pps, 0x40), 0x40)

            if t_size != 0:
                # 출력시 이름이 깨질 가능성이 큼
                if ord(pps[0]) & 0xF0 == 0x00 and ord(pps[1]) == 0x00:
                    name = '_\x00' + pps[2:t_size-2]
                else:
                    name = pps[0:t_size-2]
                p['Name'] = DecodeStreamName(name).decode('UTF-16LE', 'replace')
            else:
                p['Name'] = ''

            p['Type'] = ord(pps[0x42])
            p['Prev'] = kavutil.get_uint32(pps, 0x44)
            p['Next'] = kavutil.get_uint32(pps, 0x48)
            p['Dir'] = kavutil.get_uint32(pps, 0x4c)
            p['Start'] = kavutil.get_uint32(pps, 0x74)
            p['Size'] = kavutil.get_uint32(pps, 0x78)
            p['Valid'] = False

            # CVE-2012-0158 검사하기
            # pps에 ListView.2의 CLSID가 존재함
            # 참고 : https://securelist.com/the-curious-case-of-a-cve-2012-0158-exploit/37158/
            # 참고 : https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=25657
            cve_clsids = ['\x4B\xF0\xD1\xBD\x8B\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28',
                          '\xE0\xF5\x6B\x99\x44\x80\x50\x46\xAD\xEB\x0B\x01\x39\x14\xE9\x9C',
                          '\xE6\x3F\x83\x66\x83\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28',
                          '\x5F\xDC\x81\x91\x7D\xE0\x8A\x41\xAC\xA6\x8E\xEA\x1E\xCB\x8E\x9E',
                          '\xB6\x90\x41\xC7\x89\x85\xD1\x11\xB1\x6A\x00\xC0\xF0\x28\x36\x28'
                         ]
            if pps[0x50:0x60] in cve_clsids:
                self.exploit.append('Exploit.OLE.CVE-2012-0158')
                return False

            self.pps.append(p)

        # PPS Tree 검증
        if self.__valid_pps_tree() is False:
            return False

        if self.verbose:
            print
            kavutil.vprint('Property Storage')
            '''
            print '    %-2s %-20s %4s %-8s %-8s %-8s %-8s %-8s' % ('No', 'Name', 'Type', 'Prev', 'Next', 'Dir', 'SB',
                                                                   'Size')
            print '    ' + ('-' * 74)

            for p in self.pps:
                print '    ' + '%2d %-23s %d %8X %8X %8X %8X %8d' % (self.pps.index(p), p['Name'], p['Type'], p['Prev'],
                                                                     p['Next'], p['Dir'], p['Start'], p['Size'])
            '''

            print '    %-2s %-32s %4s %-4s %-4s %-4s %8s %8s' % ('No', 'Name', 'Type', 'Prev', 'Next', ' Dir', 'SB',
                                                                   'Size')
            print '    ' + ('-' * 74)

            for p in self.pps:
                if p['Valid'] is False:  # 유효한 Tree가 아니면 다음
                    continue

                t = ''
                t += '   - ' if p['Prev'] == 0xffffffff else '%4d ' % p['Prev']
                t += '   - ' if p['Next'] == 0xffffffff else '%4d ' % p['Next']
                t += '   - ' if p['Dir'] == 0xffffffff else '%4d ' % p['Dir']
                t += '       - ' if p['Start'] == 0xffffffff else '%8X ' % p['Start']

                tname = p['Name'].encode(sys.stdout.encoding, 'replace')
                print '    ' + '%2d %-35s %d %22s %8d' % (self.pps.index(p), tname, p['Type'], t, p['Size'])

        # PPS 전체 경로 구하기
        self.__deep = 0
        self.__full_list = []

        try:
            self.__get_pps_path()
        except IndexError:
            pass

        # small block link 얻기
        self.small_block = get_block_link(self.pps[0]['Start'], self.bbd_fat)
        if self.verbose:
            print
            kavutil.vprint('Small Blocks')
            print self.small_block

        return True

    # ---------------------------------------------------------------------
    # PPS Tree의 유효성을 체크한다. (내장)
    # ---------------------------------------------------------------------
    def __valid_pps_tree(self):
        scaned_pps_node = [0]  # 이미 분석한 노드의 경우 더이상 분석하지 않기 위해 처리
        f = []

        if len(self.pps) == 0:  # 분석된 PPS가 없으면 종료
            return False

        if self.pps[0]['Dir'] != 0xffffffff and self.pps[0]['Type'] == 5:
            f.append(self.pps[0]['Dir'])
            scaned_pps_node.append(self.pps[0]['Dir'])
            self.pps[0]['Valid'] = True

        if len(f) == 0:  # 정상적인 PPS가 없음
            return False

        while len(f):
            x = f.pop(0)

            try:
                if self.pps[x]['Type'] != 1 and self.pps[x]['Type'] != 2 and len(self.pps[x]['Name']) == 0:
                    continue
            except IndexError:
                if (x & 0x90900000) == 0x90900000:  # CVE-2003-0820 취약점
                    self.exploit.append('Exploit.OLE.CVE-2003-0820')
                    return False
                else:  # CVE-2003-0347 취약점
                    self.exploit.append('Exploit.OLE.CVE-2003-0347')
                    return False

            self.pps[x]['Valid'] = True

            if self.pps[x]['Prev'] != 0xffffffff:
                if self.pps[x]['Prev'] in scaned_pps_node:
                    self.pps[x]['Prev'] = 0xffffffff
                else:
                    f.append(self.pps[x]['Prev'])
                    scaned_pps_node.append(self.pps[x]['Prev'])

            if self.pps[x]['Next'] != 0xffffffff:
                if self.pps[x]['Next'] in scaned_pps_node:
                    self.pps[x]['Next'] = 0xffffffff
                else:
                    f.append(self.pps[x]['Next'])
                    scaned_pps_node.append(self.pps[x]['Next'])

            if self.pps[x]['Dir'] != 0xffffffff:
                if self.pps[x]['Dir'] in scaned_pps_node:
                    self.pps[x]['Dir'] = 0xffffffff
                else:
                    f.append(self.pps[x]['Dir'])
                    scaned_pps_node.append(self.pps[x]['Dir'])

        return True

    # ---------------------------------------------------------------------
    # PPS 전체 경로 구하기 (내장)
    # ---------------------------------------------------------------------
    def __get_pps_path(self, node=0, prefix=''):
        if node == 0:
            pps_name = ''
            name = prefix + pps_name
        else:
            if self.pps[node]['Valid'] is False:  # 유효한 PPS만 처리함
                return 0

            pps_name = self.pps[node]['Name'].encode('cp949', 'ignore')
            name = prefix + '/' + pps_name
            # print ("%02d : %d %s") % (node, self.deep, name)
            # if self.pps[node]['Type'] != 5:  # Stream만 저장
            p = {'Node': node, 'Name': name[1:], 'Type': self.pps[node]['Type']}
            self.__full_list.append(p)

        if self.pps[node]['Dir'] != 0xFFFFFFFFL:
            self.__deep += 1
            self.__get_pps_path(self.pps[node]['Dir'], name)
            self.__deep -= 1

        if self.pps[node]['Prev'] != 0xFFFFFFFFL:
            self.__get_pps_path(self.pps[node]['Prev'], prefix)

        if self.pps[node]['Next'] != 0xFFFFFFFFL:
            self.__get_pps_path(self.pps[node]['Next'], prefix)

        return 0

    # ---------------------------------------------------------------------
    # PPS 전체 경로 구하기 (스트림만 출력)
    # ---------------------------------------------------------------------
    def listdir(self, streams=True, storages=False):
        ret = []
        for p in self.__full_list:
            if p['Type'] == 2 and streams:
                ret.append(p['Name'])
            elif p['Type'] == 1 and storages:
                ret.append(p['Name'])
            else:
                pass
        return ret

    # ---------------------------------------------------------------------
    # 스트림이 존재하는가?
    # ---------------------------------------------------------------------
    def exists(self, name):
        for p in self.__full_list:
            if p['Name'] == name:
                return True
        else:
            return False

    # ---------------------------------------------------------------------
    # 스트림을 연다
    # ---------------------------------------------------------------------
    def openstream(self, name):
        # -----------------------------------------------------------------
        # 스트림 전용 클래스
        # -----------------------------------------------------------------
        class Stream:
            def __init__(self, parent, node):
                self.parent = parent
                self.node = node
                self.read_size = 0
                self.fat = None

                # print self.parent.verbose

            # 연속된 숫자 값을 리턴한다.
            # TODO : 임시로 작성한거라 최적화 필요함
            def get_liner_value(self, num_list):
                start = None
                end = None

                if not start:
                    start = num_list.pop(0)

                e = start
                loop = False

                for x in num_list:
                    if e + 1 == x:
                        e = x
                        loop = True
                        continue
                    else:
                        while loop:
                            if e == num_list.pop(0):
                                break
                        end = e
                        break
                else:
                    for i in range(len(num_list)):
                        num_list.pop(0)
                    end = e

                return start, end

            def read(self):
                pps = self.parent.pps[self.node]
                sb = pps['Start']
                size = pps['Size']

                if size >= 0x1000:
                    self.read_size = self.parent.bsize
                    self.fat = self.parent.bbd_fat
                else:
                    self.read_size = self.parent.ssize
                    self.fat = self.parent.sbd_fat

                list_array = get_block_link(sb, self.fat)

                data = ''
                if size >= 0x1000:
                    t_list = list(list_array)
                    while len(t_list):
                        s, e = self.get_liner_value(t_list)  # 연속된 링크를 모두 수집해서 한꺼번에 파일로 읽기
                        off = (s + 1) * self.read_size
                        data += self.parent.mm[off:off + self.read_size * (e - s + 1)]
                else:
                    for n in list_array:
                        div_n = self.parent.bsize / self.parent.ssize
                        off = (self.parent.small_block[n / div_n] + 1) * self.parent.bsize
                        off += (n % div_n) * self.parent.ssize
                        data += self.parent.mm[off:off + self.read_size]

                if self.parent.verbose:
                    print
                    kavutil.vprint(pps['Name'])
                    kavutil.HexDump().Buffer(data, 0, 80)

                return data[:size]

            def close(self):
                pass

        # -----------------------------------------------------------------
        for p in self.__full_list:
            if p['Name'] == name:
                no = p['Node']
                break
        else:
            no = -1

        if no == -1:
            raise Error('PPS name is invalid.')

        return Stream(self, no)

    # ---------------------------------------------------------------------
    # 스트림의 데이터를 덮어쓴다.
    # ---------------------------------------------------------------------
    def write_stream(self, name, data):
        for p in self.__full_list:
            if p['Name'] == name:
                no = p['Node']
                break
        else:
            no = -1

        if no == -1:
            raise Error('PPS name(%s) is invalid.' % name)

        # self.init(self.mm)
        # return

        ow = OleWriteStream(self.mm, self.pps, self.bsize, self.ssize,
                            self.bbd, self.bbd_fat,
                            self.sbd, self.sbd_fat,
                            self.root_list_array, self.small_block, self.verbose)
        t = ow.write(no, data)
        if t:
            self.init(t)  # 새롭게 OLE 재로딩

    # ---------------------------------------------------------------------
    # 스트림 또는 스토리지를 삭제한다.
    # ---------------------------------------------------------------------
    def delete(self, name, delete_storage=False, reset_stream=False):
        for p in self.__full_list:
            if p['Name'] == name:
                no = p['Node']
                break
        else:
            no = -1

        if no == -1:
            raise Error('PPS name is invalid.')

        # print no

        ow = OleWriteStream(self.mm, self.pps, self.bsize, self.ssize,
                            self.bbd, self.bbd_fat,
                            self.sbd, self.sbd_fat,
                            self.root_list_array, self.small_block, self.verbose)

        target_pps = self.pps[no]
        if target_pps['Valid'] and target_pps['Type'] == 2:  # 유효한 PPS에 대한 삭제인지 확인
            if  reset_stream:
                size = target_pps['Size']
                t = ow.write(no, '\x00' * size)  # 모든 데이터를 0으로 Wipe

            t = ow.delete(no)
            if t:
               self.init(t)  # 새롭게 OLE 재로딩
        elif target_pps['Valid'] and target_pps['Type'] == 1 and delete_storage:  # 유효한 스토리지?
            t = ow.delete(no)  # 링크 삭제
            if t:
                self.init(t)  # 새롭게 OLE 재로딩

# ---------------------------------------------------------------------
# OleWriteStream 클래스
# ---------------------------------------------------------------------
class OleWriteStream:
    def __init__(self, mm, pps, bsize, ssize, bbd, bbd_fat, sbd, sbd_fat, root_list_array, small_block, verbose):
        self.verbose = verbose

        self.mm = mm
        self.pps = pps
        self.bsize = bsize
        self.ssize = ssize
        self.bbd = bbd
        self.bbd_fat = bbd_fat
        self.sbd = sbd
        self.sbd_fat = sbd_fat
        self.root_list_array = root_list_array
        self.small_block = small_block

    def __get_root_node(self, node):  # 해당 정보를 가진 root를 찾기
        for i, pps in enumerate(self.pps):
            if pps['Prev'] == node or pps['Next'] == node or pps['Dir'] == node:
                return i

    def __get_max_node(self, node):  # 특정 노드의 Max 값을 가진 node를 찾기
        no = node

        while True:
            pps = self.pps[no]
            if pps['Next'] == 0xffffffff:  # 더이상 오른쪽이 없으면 탐색 종료
                break
            else:  # 항상 오른쪽 노드가 큰 값임
                no = pps['Next']

        return no

    def delete(self, del_no):
        del_pps = self.pps[del_no]
        prev_no = del_pps['Prev']
        next_no = del_pps['Next']
        dir_no = del_pps['Dir']

        # root를 찾기
        root_no = self.__get_root_node(del_no)

        # 양쪽 노드가 존재하는가?
        if prev_no != 0xffffffff and next_no != 0xffffffff:  # 양쪽 모두 노트가 존재함
            # 1. prev 노드 값을 root로 보낸다.
            t_no = prev_no

            # 2. prev 노드 하위에 next가 없는 node를 찾아서 del_pps의 next_no를 등록한다.
            blank_next_no = self.__get_max_node(prev_no)
            self.__set_pps_header(blank_next_no, pps_next=next_no)

        elif prev_no != 0xffffffff and next_no == 0xffffffff:  # Prev만 존재
            # 1. prev 노드 값을 root로 보낸다.
            t_no = prev_no

        elif prev_no == 0xffffffff and next_no != 0xffffffff:  # Next만 존재
            # 1. next 노드 값을 root로 보낸다.
            t_no = next_no

        else:  # prev_no == 0xffffffff and next_no == 0xffffffff:  # 단일 노드
            # 1. 0xffffffff 노드 값을 root로 보낸다.
            t_no = 0xffffffff

        # root 노드를 수정한다.
        pps = self.pps[root_no]
        if pps['Prev'] == del_no:
            self.__set_pps_header(root_no, pps_prev=t_no)
        elif pps['Next'] == del_no:
            self.__set_pps_header(root_no, pps_next=t_no)
        else:  # Dir
            self.__set_pps_header(root_no, pps_dir=t_no)

        # 삭제 노드 값은 모두 지우기
        self.__set_pps_header(del_no, size=0, start=0xffffffff, pps_prev=0xffffffff, pps_next=0xffffffff,
                              pps_dir=0xffffffff, del_info=True)

        return self.mm

    def write(self, no, data):
        # 기존 PPS 정보를 얻는다
        org_sb = self.pps[no]['Start']
        org_size = self.pps[no]['Size']

        '''
        if org_size >= 0x1000:
            # read_size = self.bsize
            fat = self.bbd
        else:
            # read_size = self.ssize
            fat = self.sbd

        # org_list_array = get_block_link(org_sb, fat)
        '''

        # 수정된 data를 쓰기 위해 준비한다
        if len(data) >= 0x1000:  # BBD를 사용한다.
            if org_size >= 0x1000:  # 기존에는 BBD 사용
                if org_size >= len(data):
                    # raise error('Not Support : BBD -> BBD (Dec)')  # 개발 완료

                    n = (len(data) / self.bsize) + (1 if (len(data) % self.bsize) else 0)
                    t_data = data + ('\x00' * ((n * self.bsize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                    t_link = get_block_link(org_sb, self.bbd_fat)  # 이전 링크 수집하기
                    t_link = self.__decrease_bbd_link(t_link, n)  # 필요한 개수로 링크 줄이기

                    # Big block 영역에 bsize 만큼씩 Overwrite
                    self.__write_data_to_big_block(t_data, t_link)

                    # PPS 크기 수정
                    self.__set_pps_header(no, size=len(data))
                else:
                    # raise error('Not Support : BBD -> BBD (Inc)')

                    n = (len(data) / self.bsize) + (1 if (len(data) % self.bsize) else 0)
                    t_data = data + ('\x00' * ((n * self.bsize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                    t_link = get_block_link(org_sb, self.bbd_fat)  # 이전 링크 수집하기

                    t_num = 0
                    if (len(t_link) * self.bsize) < len(t_data):  # 블록 추가해야 하나?
                        t_size = len(t_data) - (len(t_link) * self.bsize)
                        t_num = (t_size / self.bsize) + (1 if (t_size % self.bsize) else 0)

                        self.__add_big_block_num(t_num)  # 필요한 블록 수 추가하기

                    # 수집된 마지막 링크 이후에 존재하는 사용하지 않는 블록을 수집한다.
                    t_link = self.__modify_big_block_link(t_link, t_num)

                    # Big block 영역에 bsize 만큼씩 Overwrite
                    self.__write_data_to_big_block(t_data, t_link)

                    # PPS 크기 수정
                    self.__set_pps_header(no, size=len(data))

            else:  # 기존에는 SBD 사용
                # raise error('Not Support : SBD -> BBD')  # 섹터가 변화는 것은 Dec, Inc가 의미 없음

                n = (len(data) / self.bsize) + (1 if (len(data) % self.bsize) else 0)
                t_data = data + ('\x00' * ((n * self.bsize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                t_num = len(t_data) / self.bsize  # 몇개의 블록이 필요한가?

                self.__add_big_block_num(t_num)  # 필요한 블록 수 추가하기

                # BBD 링크를 처음 생성하므로 이전 링크가 없다.
                t_link = self.__modify_big_block_link(None, t_num)

                # Big block 영역에 bsize 만큼씩 Overwrite
                self.__write_data_to_big_block(t_data, t_link)

                # PPS 크기 수정, start 블록 수정
                self.__set_pps_header(no, size=len(data), start=t_link[0])

                # 이전 SBD의 링크는 모두 삭제한다.
                # t_link = get_block_link(org_sb, self.sbd)  # 이전 링크 수집하기
                t_link = get_block_link(org_sb, self.sbd_fat)  # 이전 링크 수집하기

                sbd = self.sbd
                for no in t_link:
                    sbd = sbd[:no*4] + '\xff\xff\xff\xff' + sbd[(no+1)*4:]

                self.__modify_sbd(sbd)

        else:  # SBD를 사용한다.
            if org_size >= 0x1000:  # 기존에는 BBD 사용
                # raise error('Not Support : BBD -> SBD')  # 섹터가 변화는 것은 Dec, Inc가 의미 없음

                n = (len(data) / self.ssize) + (1 if (len(data) % self.ssize) else 0)
                t_data = data + ('\x00' * ((n * self.ssize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                t_num = len(t_data) / self.ssize  # 몇개의 블록이 필요한가?

                self.__add_small_block_num(t_num)  # 필요한 블록 수 추가하기

                # SBD 링크를 처음 생성하므로 이전 링크가 없다.
                t_link = self.__modify_small_block_link(None, t_num)

                bbd_list_array, _, _, _ = get_bbd_list_array(self.mm)

                self.bbd = ''
                for i in range(len(bbd_list_array)/4):
                    n = kavutil.get_uint32(bbd_list_array, i*4)
                    self.bbd += get_bblock(self.mm, n, self.bsize)

                # 새로운 Small Block 링크가 필요하다
                self.small_block = get_block_link(self.pps[0]['Start'], self.bbd_fat)

                # Small block 영역에 ssize 만큼씩 Overwrite
                self.__write_data_to_small_bolck(t_data, t_link)

                # PPS 크기 수정, start 블록 수정
                self.__set_pps_header(no, size=len(data), start=t_link[0])

                # 이전 BBD의 링크는 모두 삭제한다.
                # t_link = get_block_link(org_sb, self.bbd)  # 이전 링크 수집하기
                t_link = get_block_link(org_sb, self.bbd_fat)  # 이전 링크 수집하기

                bbd = self.bbd
                for no in t_link:
                    bbd = bbd[:no*4] + '\xff\xff\xff\xff' + bbd[(no+1)*4:]

                self.__modify_bbd(bbd)

            else:  # 기존에는 SBD 사용
                if org_size >= len(data):
                    # raise error('Not Support : SBD -> SBD (Dec)')  # 지원 완료

                    n = (len(data) / self.ssize) + (1 if (len(data) % self.ssize) else 0)
                    t_data = data + ('\x00' * ((n*self.ssize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                    t_link = get_block_link(org_sb, self.sbd_fat)  # 이전 링크 수집하기
                    t_link = self.__decrease_sbd_link(t_link, n)  # 필요한 개수로 링크 줄이기

                    # Small block 영역에 ssize 만큼씩 Overwrite
                    self.__write_data_to_small_bolck(t_data, t_link)

                    # PPS 크기 수정
                    self.__set_pps_header(no, size=len(data))
                else:
                    # raise error('Not Support : SBD -> SBD (Inc)')  # 작업 완료

                    n = (len(data) / self.ssize) + (1 if (len(data) % self.ssize) else 0)
                    t_data = data + ('\x00' * ((n*self.ssize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                    # t_link = get_block_link(org_sb, self.sbd)  # 이전 링크 수집하기
                    t_link = get_block_link(org_sb, self.sbd_fat)  # 이전 링크 수집하기

                    t_num = 0
                    if (len(t_link) * self.ssize) < len(t_data):  # 블록 추가해야 하나?
                        t_size = len(t_data) - (len(t_link) * self.ssize)
                        t_num = (t_size / self.ssize) + (1 if (t_size % self.ssize) else 0)

                        self.__add_small_block_num(t_num)  # 필요한 블록 수 추가하기

                    # 수집된 마지막 링크 이후에 존재하는 사용하지 않는 블록을 수집한다.
                    t_link = self.__modify_small_block_link(t_link, t_num)

                    # Small block 갱신
                    self.bbd_fat = {}
                    for i in range(len(self.bbd) / 4):
                        n = kavutil.get_uint32(self.bbd, i * 4)
                        self.bbd_fat[i] = n

                    self.small_block = get_block_link(self.pps[0]['Start'], self.bbd_fat)
                    
                    # Small block 영역에 ssize 만큼씩 Overwrite
                    self.__write_data_to_small_bolck(t_data, t_link)

                    # PPS 크기 수정
                    self.__set_pps_header(no, size=len(data))

        return self.mm

    # ---------------------------------------------------------------------
    # 특정 데이터를 big block 링크를 따라 데이터 쓰기 (내장)
    # ---------------------------------------------------------------------
    def __write_data_to_big_block(self, t_data, t_link):
        for i, n in enumerate(t_link):
            off = (n + 1) * self.bsize
            self.mm = self.mm[:off] + t_data[i * self.bsize:(i + 1) * self.bsize] + self.mm[off + self.bsize:]

    # ---------------------------------------------------------------------
    # 특정 데이터를 small block 링크를 따라 데이터 쓰기 (내장)
    # ---------------------------------------------------------------------
    def __write_data_to_small_bolck(self, t_data, t_link):
        for i, n in enumerate(t_link):
            off = (self.small_block[n / 8] + 1) * self.bsize
            off += (n % 8) * self.ssize
            self.mm = self.mm[:off] + t_data[i * self.ssize:(i + 1) * self.ssize] + self.mm[off + self.ssize:]

    # ---------------------------------------------------------------------
    # OLE 영역의 특정 위치에 1개의 Big Block Overwrite하기 (내장)
    # ---------------------------------------------------------------------
    def __set_bblock(self, no, data):
        off = (no + 1) * self.bsize
        if len(data) == self.bsize:
            self.mm = self.mm[:off] + data + self.mm[off+self.bsize:]
            return True

        return False

    # ---------------------------------------------------------------------
    # PPS 헤더에 존재하는 특정 스트림의 크기를 조정한다. (내장)
    # node : PPS 인덱스
    # size : 설정 크기
    # start : 시작 링크
    # ---------------------------------------------------------------------
    def __set_pps_header(self, node, size=None, start=None, pps_prev=None, pps_next=None, pps_dir=None, del_info=False):
        n = self.root_list_array[node / 4]

        buf = get_bblock(self.mm, n, self.bsize)

        off = ((node % 4) * 0x80)

        if del_info and off == 0x180:
            buf = buf[:off] + '\x00' * 0x80
        elif del_info:
            buf = buf[:off] + '\x00' * 0x80 + buf[off+0x80:]

        if size is not None:
            t_off = off + 0x78
            buf = buf[:t_off] + struct.pack('<L', size) + buf[t_off + 4:]

        if start is not None:
            t_off = off + 0x74
            buf = buf[:t_off] + struct.pack('<L', start) + buf[t_off + 4:]

        if pps_prev is not None:
            t_off = off + 0x44
            buf = buf[:t_off] + struct.pack('<L', pps_prev) + buf[t_off + 4:]

        if pps_next is not None:
            t_off = off + 0x48
            buf = buf[:t_off] + struct.pack('<L', pps_next) + buf[t_off + 4:]

        if pps_dir is not None:
            t_off = off + 0x4C
            buf = buf[:t_off] + struct.pack('<L', pps_dir) + buf[t_off + 4:]

        self.__set_bblock(n, buf)

        if self.verbose:
            print
            buf = get_bblock(self.mm, n, self.bsize)
            kavutil.HexDump().Buffer(buf, 0, 0x200)

    # ---------------------------------------------------------------------
    # SBD 링크를 줄인다
    # org_link_list : 기존 Small block 링크
    # num_link : 필요로 하는 전체 링크 수
    # ---------------------------------------------------------------------
    def __decrease_sbd_link(self, org_link_list, num_link):
        if len(org_link_list) > num_link:
            # SBD를 배열로 바꾸기
            t_link = []

            for i in range(len(self.sbd) / 4):
                t_link.append(kavutil.get_uint32(self.sbd, i * 4))

            t = org_link_list[num_link:]
            org_link_list = org_link_list[:num_link]

            t_link[t[0]] = 0xfffffffe  # 링크 끝 설정하기

            # 남은 링크는 모두 0xffffffff로 설정하기
            for i in t[1:]:
                t_link[i] = 0xffffffff

            # SBD 배열을 SBD 버퍼로 바꾸기
            self.sbd = ''
            for i in t_link:
                self.sbd += struct.pack('<L', i)

            # self.mm에 SBD 적용하기
            sbd_startblock = kavutil.get_uint32(self.mm, 0x3c)
            sbd_list_array = get_block_link(sbd_startblock, self.bbd_fat)

            for i, n in enumerate(sbd_list_array):
                self.__set_bblock(n, self.sbd[i*self.bsize:(i+1)*self.bsize])

            return org_link_list
        elif len(org_link_list) == num_link:
            return org_link_list
        else:
            raise Error('Invalid call')

    # ---------------------------------------------------------------------
    # BBD 링크를 줄인다
    # org_link_list : 기존 Small block 링크
    # num_link : 필요로 하는 전체 링크 수
    # ---------------------------------------------------------------------
    def __decrease_bbd_link(self, org_link_list, num_link):
        if len(org_link_list) > num_link:
            # BBD를 배열로 바꾸기
            t_link = []

            for i in range(len(self.bbd) / 4):
                t_link.append(kavutil.get_uint32(self.bbd, i * 4))

            t = org_link_list[num_link:]
            org_link_list = org_link_list[:num_link]

            t_link[t[0]] = 0xfffffffe  # 링크 끝 설정하기

            # 남은 링크는 모두 0xffffffff로 설정하기
            for i in t[1:]:
                t_link[i] = 0xffffffff

            # BBD 배열을 BBD 버퍼로 바꾸기
            self.bbd = ''
            for i in t_link:
                self.bbd += struct.pack('<L', i)

            # self.mm에 BBD 적용하기
            t, num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block = \
                get_bbd_list_array(self.mm, self.verbose)

            bbd_list_array = []
            for i in range(len(t) / 4):
                bbd_list_array.append(kavutil.get_uint32(t, i * 4))

            for i, n in enumerate(bbd_list_array):
                self.__set_bblock(n, self.bbd[i*self.bsize:(i+1)*self.bsize])
            return org_link_list
        elif len(org_link_list) == num_link:
            return org_link_list
        else:
            raise Error('Invalid call')

    # ---------------------------------------------------------------------
    # Big Block을 주어진 개수만큼 추가한다.
    # num : 추가할 Big Block 개수
    # ---------------------------------------------------------------------
    def __add_big_block_num(self, num):
        size = (len(self.mm) / self.bsize) * self.bsize  # 파일 크기
        self.mm = self.mm[:size]  # 뒤쪽 쓸모 없는 부분은 제거
        attach_data = self.mm[size:]  # 파일 뒤에 붙어 있는 잔여 데이터

        # 전체 BBD 링크를 구한다
        bbd_list_array, num_of_bbd_blocks, _, _ = get_bbd_list_array(self.mm)

        # BBD를 모은다
        bbd = ''
        for i in range(num_of_bbd_blocks):
            no = kavutil.get_uint32(bbd_list_array, i*4)
            bbd += get_bblock(self.mm, no, self.bsize)

        bbd_link = []
        for i in range(len(bbd) / 4):
            bbd_link.append(kavutil.get_uint32(bbd, i*4))

        # 사용하지 않는 BBD 링크를 찾는다.
        free_link = [i for i, no in enumerate(bbd_link) if (no == 0xffffffff and i < size / self.bsize)]

        if len(free_link) >= num:  # 여유분이 충분히 존재함...
            return  # 추가할 필요 없음

        # 잔여 개수 체크하기
        last_no = (size / self.bsize) - 2  # 실제 마지막 Big Block 번호
        n = (len(self.bbd) / 4 - 1) - last_no

        if n >= num:
            # 잔여 개수가 추가하려는 개수보다 많거나 같으면 추가 블록 개수만 파일 뒤에 추가하기
            self.mm += '\x00' * self.bsize * num  # 실제 필요한 데이터 블록
            self.mm += attach_data
        else:
            special_no = []  # 특수 목적의 Big Block 번호. 해당 블록은 0xfffffffd로 처리해야 함

            x_data = ''
            # b_data = ''
            # add_data = ''

            add_num = num - n  # 추가해야 할 블록 수
            add_data = ('\x00' * self.bsize * add_num)

            # 추가해야 할 BBD list 개수는 한개의 BBD에는 bsize / 4 개수만큼 Big Block을 담을 수 있음
            b_num = (add_num / (self.bsize/4)) + (1 if (add_num % (self.bsize/4)) else 0)
            old_num_bbd = kavutil.get_uint32(self.mm, 0x2c)

            xbbd_start_block = kavutil.get_uint32(self.mm, 0x44)
            num_of_xbbd_blocks = kavutil.get_uint32(self.mm, 0x48)

            # 추가적인 Big Block을 계산한다. BBD List와 XBBD 블록도 추가될 수 있기 때문에...
            old_b_num = b_num
            while True:
                if old_num_bbd + b_num > 109:
                    t_num = (old_num_bbd + b_num - 109)
                    total_xbbd_num = (t_num / ((self.bsize - 4) / 4)) + (1 if (t_num % ((self.bsize - 4) / 4)) else 0)

                    x_num = total_xbbd_num - num_of_xbbd_blocks  # 추가해야 할 XBBD 개수
                    add_num += x_num
                    b_num = (add_num / (self.bsize / 4)) + (1 if (add_num % (self.bsize / 4)) else 0)

                if old_b_num == b_num:
                    break
                else:
                    old_b_num = b_num

            total_bbd_num = old_num_bbd + b_num  # 전체 BBD list 개수
            self.mm = self.mm[:0x2c] + struct.pack('<L', total_bbd_num) + self.mm[0x30:]

            last_no += 1

            # XBBD 처리하기
            if total_bbd_num > 109:
                t_num = (total_bbd_num - 109)
                total_xbbd_num = (t_num / ((self.bsize - 4) / 4)) + (1 if (t_num % ((self.bsize - 4) / 4)) else 0)

                x_num = total_xbbd_num - num_of_xbbd_blocks  # 추가해야 할 XBBD 개수

                # XBBD를 위한 헤더 수정
                if num_of_xbbd_blocks == 0:
                    data = struct.pack('<LL', last_no, total_xbbd_num)
                    self.mm = self.mm[:0x44] + data + self.mm[0x4C:]
                else:
                    data = struct.pack('<L', total_xbbd_num)
                    self.mm = self.mm[:0x48] + data + self.mm[0x4C:]

                # XBBD 블록 연결
                next_b = xbbd_start_block

                if num_of_xbbd_blocks == 1:
                    t_data = get_bblock(self.mm, next_b, self.bsize)
                else:
                    t_data = ''
                    for i in range(num_of_xbbd_blocks-1):
                        t_data = get_bblock(self.mm, next_b, self.bsize)
                        next_b = kavutil.get_uint32(t_data, self.bsize-4)

                # 기존 XBBD 마지막에 새로운 XBBD 링크 추가
                t_data = t_data[:-4] + struct.pack('<L', last_no)
                off = (next_b + 1) * self.bsize  # t_data의 위치
                self.mm = self.mm[:off] + t_data + self.mm[off + self.bsize:]

                # XBBD 생성하기
                for i in range(x_num):
                    x_data += '\xff\xff\xff\xff' * ((self.bsize/4) - 1)
                    if i != (x_num-1):
                        x_data += struct.pack('<L', last_no+1)  # 다음 블록을 가리켜야 함으로 1를 더함
                    else:
                        x_data += '\xfe\xff\xff\xff'  # 마지막 블록의 링크는 끝을 처리함
                    special_no.append(last_no)  # 특수 블록 등록
                    last_no += 1
            # END of XBBD

            # BBD 추가하기
            bbd_no = []
            b_data = '\xff' * self.bsize * b_num
            for i in range(b_num):
                bbd_no.append(last_no)
                last_no += 1

            # 최종 조합
            self.mm += x_data + b_data + add_data + attach_data

            # 특수 블록에 BBD list도 추가
            special_no += bbd_no

            # 특수 블록 처리 (bbd_list_array, num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block)
            bbd_list_array, num_of_bbd_blocks, _, _ = get_bbd_list_array(self.mm)

            bb_num = (self.bsize/4)  # 한개의 BBD list 블록에 들어갈 수 있는 Big Block 개수
            for no in special_no:
                seg = no / bb_num
                off = no % bb_num
                # print hex(no), hex(seg), hex(off), hex(kavutil.get_uint32(bbd_list_array, seg*4))

                t_no = kavutil.get_uint32(bbd_list_array, seg*4)
                t_off = ((t_no + 1) * self.bsize) + (off * 4)

                self.mm = self.mm[:t_off] + '\xfd\xff\xff\xff' + self.mm[t_off+4:]

                # print repr(self.mm[t_off:t_off+4])

                # t = get_bblock(self.mm, t_no, self.bsize)
                # print repr(t)
                # t = kavutil.get_uint32(t, off*4)
                # print hex(t)

            # BBD List에 BBD 등록하기
            for i, no in enumerate(bbd_no):
                off = get_bbd_list_index_to_offset(self.mm, old_num_bbd + i)
                # print hex(off)
                self.mm = (self.mm[:off] + struct.pack('<L', no) + self.mm[off+4:])

    # ---------------------------------------------------------------------
    # Small Block을 주어진 개수만큼 추가한다.
    # num : 추가할 Big Block 개수
    # ---------------------------------------------------------------------
    def __add_small_block_num(self, num):
        root = self.pps[0]
        r_size = root['Size']
        r_no = root['Start']

        # SBD 링크를 생성한다.
        sbd_link = []
        for i in range(len(self.sbd) / 4):
            sbd_link.append(kavutil.get_uint32(self.sbd, i*4))

        # 사용하지 않는 SBD 링크를 찾는다.
        free_link = [i for i, no in enumerate(sbd_link) if (no == 0xffffffff and i < r_size / self.ssize)]

        if len(free_link) >= num:  # 여유분이 충분히 존재함...
            return  # 추가할 필요 없음
        else:  # 여유분이 부족함. 따라서 Root를 늘려야 함
            size = num * self.ssize  # 추가해야 할 용량
            add_big_num = (size / self.bsize) + (1 if (size % self.bsize) else 0)  # 추가해야 할 Big Block 개수

            self.__add_big_block_num(add_big_num)  # Big Block 추가 요청

            # t_link = get_block_link(r_no, self.bbd)  # 이전 Small Block의 링크를 구함
            t_link = get_block_link(r_no, self.bbd_fat)  # 이전 Small Block의 링크를 구함
            self.__modify_big_block_link(t_link, add_big_num)  # 이전 링크에 필요한 블록 수 추가하여 링크를 새롭게 생성

            # Root 크기 수정
            self.__set_pps_header(0, size=r_size + add_big_num * self.bsize)

    # ---------------------------------------------------------------------
    # BBD link 추가 요청한다. (원본 이미지의 BBD link가 수정 됨)
    # old_link : 기존 BBD link
    # add_num : 추가 BBD link 개수
    # ---------------------------------------------------------------------
    def __modify_big_block_link(self, old_link, add_num):
        if add_num < 0:
            return []

        # 전체 BBD 링크를 구한다
        bbd_list_array, num_of_bbd_blocks, _, _ = get_bbd_list_array(self.mm)

        # BBD를 모은다
        bbd = ''
        for i in range(num_of_bbd_blocks):
            no = kavutil.get_uint32(bbd_list_array, i*4)
            bbd += get_bblock(self.mm, no, self.bsize)

        if self.verbose:
            open('bbd.dm2', 'wb').write(bbd)

        bbd_link = []
        for i in range(len(bbd) / 4):
            bbd_link.append(kavutil.get_uint32(bbd, i*4))

        # 사용하지 않는 BBD 링크를 찾는다.
        free_link = [i for i, no in enumerate(bbd_link) if (no == 0xffffffff)]

        if old_link:
            ret_link = old_link + free_link[:add_num]  # 최종 결과의 BBD 링크
            t_link = old_link[-1:] + free_link[:add_num]  # BBD에 링크 연결하기
        else:
            # 이전 링크가 없다면...
            ret_link = free_link[:add_num]  # 최종 결과의 BBD 링크
            t_link = free_link[:add_num]  # BBD에 링크 연결하기

        for i in range(len(t_link)-1):
            no = t_link[i+1]
            data = struct.pack('<L', no)

            no = t_link[i]
            bbd = bbd[:no*4] + data + bbd[(no+1)*4:]

        no = t_link[-1]
        bbd = bbd[:no * 4] + '\xfe\xff\xff\xff' + bbd[(no + 1) * 4:]

        if self.verbose:
            open('bbd.dm3', 'wb').write(bbd)

        # 원래 이미지에 BBD 덮어쓰기
        self.__modify_bbd(bbd)

        return ret_link  # 연결된 링크

    # ---------------------------------------------------------------------
    # SBD link 추가 요청한다. (원본 이미지의 SBD link가 수정 됨)
    # old_link : 기존 SBD link
    # add_num : 추가 SBD link 개수
    # ---------------------------------------------------------------------
    def __modify_small_block_link(self, old_link, add_num):
        if add_num < 0:
            return []

        sbd = self.sbd

        if self.verbose:
            open('sbd.dm2', 'wb').write(sbd)

        # SBD 링크를 생성한다.
        sbd_link = []
        for i in range(len(sbd) / 4):
            sbd_link.append(kavutil.get_uint32(sbd, i*4))

        # 사용하지 않는 SBD 링크를 찾는다.
        free_link = [i for i, no in enumerate(sbd_link) if (no == 0xffffffff)]

        if old_link:
            ret_link = old_link + free_link[:add_num]  # 최종 결과의 SBD 링크
            t_link = old_link[-1:] + free_link[:add_num]  # SBD에 링크 연결하기
        else:
            # 이전 링크가 없다면...
            ret_link = free_link[:add_num]  # 최종 결과의 BBD 링크
            t_link = free_link[:add_num]  # BBD에 링크 연결하기

        for i in range(len(t_link)-1):
            no = t_link[i+1]
            data = struct.pack('<L', no)

            no = t_link[i]
            sbd = sbd[:no*4] + data + sbd[(no+1)*4:]

        no = t_link[-1]
        sbd = sbd[:no * 4] + '\xfe\xff\xff\xff' + sbd[(no + 1) * 4:]

        # SBD가 나누어 bsize 단위가 아니면 맞춘다.
        n = len(sbd) % self.bsize
        if n:
            t = self.bsize - n
            sbd += '\xff' * t

        if self.verbose:
            open('sbd.dm3', 'wb').write(sbd)

        self.__modify_sbd(sbd)  # 수정된 SDB 적용하기

        return ret_link  # 연결된 링크

    # ---------------------------------------------------------------------
    # SBD를 수정한다.
    # sbd : 수정된 SBD 이미지
    # ---------------------------------------------------------------------
    def __modify_sbd(self, sbd):
        # 원래 이미지에 SBD 덮어쓰기
        sbd_no = kavutil.get_uint32(self.mm, 0x3c)
        # sbd_list_array = get_block_link(sbd_no, self.bbd)
        sbd_list_array = get_block_link(sbd_no, self.bbd_fat)
        # print sbd_list_array

        for i, no in enumerate(sbd_list_array):
            data = sbd[i*self.bsize:(i+1)*self.bsize]
            off = (no + 1) * self.bsize
            self.mm = self.mm[:off] + data + self.mm[off+self.bsize:]

    # ---------------------------------------------------------------------
    # BBD를 수정한다.
    # bbd : 수정된 BBD 이미지
    # ---------------------------------------------------------------------
    def __modify_bbd(self, bbd):
        self.bbd = bbd  # 체크 !!!
        bbd_list_array, _, _, _ = get_bbd_list_array(self.mm)

        for i in range(len(bbd_list_array) / 4):
            no = kavutil.get_uint32(bbd_list_array, i * 4)
            data = bbd[i * self.bsize:(i + 1) * self.bsize]
            off = (no + 1) * self.bsize
            self.mm = self.mm[:off] + data + self.mm[off + self.bsize:]


if __name__ == '__main__':
    # import zlib

    # o = OleFile('normal.hwp', write_mode=True, verbose=True)
    o = OleFile('a82d381c20cfdf47d603b4b2b840136ed32f71d2757c64c898dc209868bb57d6', write_mode=True, verbose=True)
    print o.listdir()
    o.delete('_VBA_PROJECT_CUR/VBA')  # Root 수정, Next 수정
    o.close()

    '''
    o = OleFile('normal.hwp', verbose=True)

    pics = o.openstream('PrvImage')
    print get_block_link(o.pps[6]['Start'], o.sbd)
    # d2 = pics.read()
    o.close()
    '''

    # XBBD 늘어나는 경우
    # o = OleFile('xbbd2.ppt', write_mode=True, verbose=True)
    # o.test()

    '''
    # 늘어나는건 경우의 수가 너무 많음
    o = OleFile('normal.hwp', write_mode=True, verbose=True)
    pics = o.openstream('FileHeader')

    d = pics.read()
    d = d + d

    o.write_stream('FileHeader', d)

    o.close()
    '''

    '''
    # case1
    o = OleFile('normal.hwp', write_mode=True, verbose=True)
    pics = o.openstream('Scripts/DefaultJScript')

    d = pics.read()
    d = zlib.decompress(d, -15)

    d = d.replace(b'v\x00a\x00r', b'f\x00o\x00o')  # var -> foo
    d = zlib.compress(d)[2:]

    o.write_stream('Scripts/DefaultJScript', d)
    o.close()
    '''

# -------------------------------------------------------------------------
# KavMain 클래스
# -------------------------------------------------------------------------
class KavMain:
    # ---------------------------------------------------------------------
    # init(self, plugins_path)
    # 플러그인 엔진을 초기화 한다.
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    #         verbose      - 디버그 모드 (True or False)
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def init(self, plugins_path, verbose=False):  # 플러그인 엔진 초기화
        self.handle = {}
        self.verbose = verbose
        return 0  # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.1'  # 버전
        info['title'] = 'OLE Library'  # 엔진 설명
        info['kmd_name'] = 'ole'  # 엔진 파일 이름
        info['make_arc_type'] = kernel.MASTER_PACK  # 악성코드 치료 후 재압축 유무
        info['sig_num'] = len(self.listvirus())  # 진단/치료 가능한 악성코드 수

        return info

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = list()  # 리스트형 변수 선언

        vlist.append('Exploit.OLE.CVE-2012-0158')  # 진단/치료하는 악성코드 이름 등록
        vlist.append('Exploit.OLE.CVE-2003-0820')
        vlist.append('Exploit.OLE.CVE-2003-0347')

        vlist.sort()

        return vlist

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #          filename   - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        ret = {}

        mm = filehandle

        # OLE 헤더와 동일
        if mm[:8] == '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            ret['ff_ole'] = 'OLE'

            # OLE 뒤에 첨부된 파일이 있는지를 조사한다.
            fsize = len(mm)

            bsize = 1 << kavutil.get_uint16(mm, 0x1e)
            rsize = (fsize / bsize) * bsize
            if fsize > rsize:
                fileformat = {  # 포맷 정보를 담을 공간
                    'Attached_Pos': rsize,
                    'Attached_Size': fsize - rsize
                }
                ret['ff_attach'] = fileformat

            # HWP 인가?
            o = OleFile(filename)
            try:
                pics = o.openstream('FileHeader')
                d = pics.read()

                if d[:0x11] == 'HWP Document File':
                    val = ord(d[0x24])
                    ret['ff_hwp'] = {'compress': (val & 0x1 == 0x1),
                                     'encrypt': (val & 0x2 == 0x2),
                                     'viewtext': (val & 0x4 == 0x4)}
            except Error:
                pass
            o.close()

        return ret

    # ---------------------------------------------------------------------
    # __get_handle(self, filename)
    # 압축 파일의 핸들을 얻는다.
    # 입력값 : filename   - 파일 이름
    # 리턴값 : 압축 파일 핸들
    # ---------------------------------------------------------------------
    def __get_handle(self, filename):
        if filename in self.handle:  # 이전에 열린 핸들이 존재하는가?
            zfile = self.handle.get(filename, None)
        else:
            zfile = OleFile(filename, verbose=self.verbose)  # ole 파일 열기
            self.handle[filename] = zfile

        return zfile

    # ---------------------------------------------------------------------
    # arclist(self, filename, fileformat)
    # 압축 파일 내부의 파일 목록을 얻는다.
    # 입력값 : filename   - 파일 이름
    #          fileformat - 파일 포맷 분석 정보
    # 리턴값 : [[압축 엔진 ID, 압축된 파일 이름]]
    # ---------------------------------------------------------------------
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 OLE 파일 포맷이 있는가?
        if 'ff_ole' in fileformat:
            try:
                # OLE Stream 목록 추출하기
                o = self.__get_handle(filename)
                for name in o.listdir():
                    file_scan_list.append(['arc_ole', name])

                return file_scan_list
            except:
                pass

        return []

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        data = None

        if arc_engine_id == 'arc_ole':
            o = self.__get_handle(arc_name)
            fp = o.openstream(fname_in_arc)
            try:
                data = fp.read()
            except:
                data = None

        return data

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        for fname in self.handle.keys():
            zfile = self.handle[fname]
            zfile.close()
            self.handle.pop(fname)

    # ---------------------------------------------------------------------
    # mkarc(self, arc_engine_id, arc_name, file_infos)
    # 입력값 : arc_engine_id - 압축 가능 엔진 ID
    #         arc_name      - 최종적으로 압축될 압축 파일 이름
    #         file_infos    - 압축 대상 파일 정보 구조체
    # 리턴값 : 압축 성공 여부 (True or False)
    # ---------------------------------------------------------------------
    def mkarc(self, arc_engine_id, arc_name, file_infos):
        if arc_engine_id == 'arc_ole':
            o = OleFile(arc_name, write_mode=True)  # , verbose=True)
            # zfile = zipfile.ZipFile(arc_name, 'w')

            for file_info in file_infos:
                rname = file_info.get_filename()
                a_name = file_info.get_filename_in_archive()
                try:
                    if os.path.exists(rname):
                        with open(rname, 'rb') as fp:
                            buf = fp.read()
                            # print '[-] filename :', rname, len(buf)
                            # print '[-] rname :',
                            o.write_stream(a_name, buf)
                            # zfile.writestr(a_name, buf)
                    else:
                        # 삭제 처리
                        o.delete(a_name)
                except IOError:
                    # print file_info.get_filename_in_archive()
                    pass

            o.close()
            # zfile.close()

            return True

        return False
