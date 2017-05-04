# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import struct
import types


# -------------------------------------------------------------------------
# 메시지 출력 함수
# -------------------------------------------------------------------------
__version__ = '1.0'


# -------------------------------------------------------------------------
# 메시지 출력 함수
# -------------------------------------------------------------------------
def vprint(header, section=None, msg=None):
    if header:
        print '[*] %s' % header

    if section:
        if len(msg) > 50:
            new_msg = msg[:22] + ' ... ' + msg[-22:]
        else:
            new_msg = msg
        print '    [-] %-20s: %s' % (section, new_msg)


# -------------------------------------------------------------------------
# 함수명 : HexDump
# 설  명 : 주어진 파일에서 지정된 영역에 대해 Hex 덤프를 보여준다.
# 인자값 : fname : 파일명
#         start : 덤프할 영역의 시작 위치
#         size  : 덤프할 크기
#         width : 한줄에 보여줄 문자의 개수
# -------------------------------------------------------------------------
class HexDump:
    def __init__(self):
        pass

    '''
    @staticmethod
    def file(fname, start, size=0x200, width=16):
        fp = open(fname, "rb")
        fp.seek(start)
        row = start % width  # 열
        col = (start / width) * width  # 행
        r_size = 0
        line_start = row
        while True:
            if r_size + (width - line_start) < size:
                r_char = (width - line_start)  # 읽어야할 문자 수
                r_size += (width - line_start)
            else:
                r_char = size - r_size
                r_size = size

            # print line_start, r_char
            line = fp.read(r_char)
            if len(line) == 0:
                break
            # 주소 값
            output = "%08X : " % col
            # Hex 값
            output += line_start * "   " + "".join("%02x " % ord(c) for c in line)
            output += "  " + (width - (line_start + r_char)) * "   "
            # 문자 값
            output += line_start * " "
            output += "".join(['.', c][HexDump.is_printable(c)] for c in line)
            print output
            col += width
            line_start = 0
            if r_size == size:
                break
        fp.close()
    '''

    # -------------------------------------------------------------------------
    # 함수명 : Buffer
    # 설  명 : 주어진 버퍼에 대해 Hex 덤프를 보여준다.
    # 인자값 : fbuf   : 버퍼
    #         start : 덤프할 영역의 시작 위치
    #         size  : 덤프할 크기
    #         width : 한줄에 보여줄 문자의 개수
    # -------------------------------------------------------------------------
    @staticmethod
    def buffer(buf, start, size=0x200, width=16):
        # 주어진 크기보다 크면 버퍼가 작다면 인자값을 조정
        if len(buf) < size:
            size = len(buf)
        row = start % width  # 열
        col = (start / width)  # 행
        # [row ... width*col]
        # [width*col ... width * (col+1)]
        r_size = 0
        line_start = row + (col * width)
        # print hex(line_start), hex(width*(col+1))
        # print hex(row), hex(col)
        while True:
            line = buf[line_start:width * (col + 1)]

            if len(line) == 0:
                break
            if (r_size + len(line)) < size:
                pass
            else:
                # print hex(line_start), hex(line_start + (size - r_size))
                line = line[0:(size - r_size)]
                r_size = size - len(line)
            # 주소 값
            output = "%08X : " % ((line_start / width) * width)
            # Hex 값
            output += row * "   " + "".join("%02x " % ord(c) for c in line)
            output += "  " + (width - (row + len(line))) * "   "
            # 문자 값
            output += row * " "
            output += "".join(['.', c][HexDump.is_printable(c)] for c in line)
            print output
            line_start = width * (col + 1)
            col += 1
            row = 0
            r_size += len(line)
            if r_size == size:
                break

    # -------------------------------------------------------------------------
    # 함수명 : is_printable
    # 설  명 : 주어진 문자가 출력 가능한 문자인지를 확인한다.
    # 인자값 : char  : 문자
    # 반환값 : True  : 출력 가능한 문자
    #          False : 출력 할 수 없는 문자
    # -------------------------------------------------------------------------
    @staticmethod
    def is_printable(char):
        c = ord(char)
        if 0x20 <= c <= 0x80:
            return True
        else:
            return False


# -------------------------------------------------------------------------
# 엔진 오류 메시지를 정의
# -------------------------------------------------------------------------
class Error(Exception):
    pass


# ---------------------------------------------------------------------
# 데이터 읽기
# ---------------------------------------------------------------------
def get_uint16(buf, off):
    return struct.unpack('<H', buf[off:off + 2])[0]


def get_uint32(buf, off):
    return struct.unpack('<L', buf[off:off + 4])[0]


def MsiBase64Encode(x):
    ct = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'
    if x > 63:
        return None

    return ord(ct[x])


def DecodeStreamName(name):
    wch = []
    och = []

    for i in range(len(name) / 2):
        wch.append(get_uint16(name, i * 2))

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
def get_block_link(no, bbd_or_sbd):
    ret = []

    data = bbd_or_sbd

    next_b = no

    if next_b != 0xfffffffe:
        ret.append(next_b)

        while True:
            next_b = get_uint32(data, next_b * 4)
            if next_b == 0xfffffffe:
                break

            if ret.count(next_b) != 0:  # 이미 링크가 존재하면 종료
                break

            ret.append(next_b)

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
    num_of_bbd_blocks = get_uint32(buf, 0x2c)

    xbbd_start_block = get_uint32(buf, 0x44)
    num_of_xbbd_blocks = get_uint32(buf, 0x48)

    bsize = 1 << get_uint16(buf, 0x1e)

    if verbose:
        vprint(None, 'Num of BBD Blocks', '%d' % num_of_bbd_blocks)
        vprint(None, 'XBBD Start', '%08X' % xbbd_start_block)
        vprint(None, 'Num of XBBD Blocks', '%d' % num_of_xbbd_blocks)

    if num_of_bbd_blocks > 109:  # bbd list 개수가 109보다 크면 xbbd를 가져와야 함
        next_b = xbbd_start_block

        for i in range(num_of_xbbd_blocks):
            t_data = get_bblock(buf, next_b, bsize)
            bbd_list_array += t_data[:-4]
            next_b = get_uint32(t_data, bsize-4)

    return bbd_list_array[:num_of_bbd_blocks*4], num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block


# ---------------------------------------------------------------------
# OLE의 BBD list의 index를 Offset으로 리턴한다.
# ---------------------------------------------------------------------
def get_bbd_list_index_to_offset(buf, idx):
    num_of_bbd_blocks = get_uint32(buf, 0x2c)

    xbbd_start_block = get_uint32(buf, 0x44)
    # num_of_xbbd_blocks = get_uint32(buf, 0x48)

    bsize = 1 << get_uint16(buf, 0x1e)

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
            next_b = get_uint32(t_buf, bsize-4)

        return (next_b + 1) * bsize + (off * 4)


# ---------------------------------------------------------------------
# OLE 파일인지 확인한다.
# ---------------------------------------------------------------------
def is_olefile(filename):
    try:
        fp = open(filename, 'rb')
        buf = fp.read(8)
        fp.close()

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
        self.sbd = None
        self.root = None
        self.pps = None
        self.small_block = None
        self.root_list_array = None

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
        self.bsize = 1 << get_uint16(self.mm, 0x1e)
        self.ssize = 1 << get_uint16(self.mm, 0x20)

        if self.verbose:
            vprint('Header')
            vprint(None, 'Big Block Size', '%d' % self.bsize)
            vprint(None, 'Small Block Size', '%d' % self.ssize)
            print
            HexDump.buffer(self.mm, 0, 0x60)
            print

        # bbd 읽기
        self.bbd_list_array, num_of_bbd_blocks, num_of_xbbd_blocks, xbbd_start_block = \
            get_bbd_list_array(self.mm, self.verbose)

        if self.verbose:
            print
            if num_of_bbd_blocks < 109:
                HexDump.buffer(self.mm, 0x4c, num_of_bbd_blocks * 4)
            else:
                HexDump.buffer(self.mm, 0x4c, num_of_bbd_blocks * 109)

                next_b = xbbd_start_block
                for i in range(num_of_xbbd_blocks):
                    t_data = get_bblock(self.mm, next_b, self.bsize)
                    print
                    HexDump.buffer(self.mm, (next_b+1) * self.bsize)
                    next_b = get_uint32(t_data, self.bsize-4)

        self.bbd = ''
        for i in range(num_of_bbd_blocks):
            no = get_uint32(self.bbd_list_array, i*4)
            self.bbd += get_bblock(self.mm, no, self.bsize)

        if self.verbose:
            open('bbd.dmp', 'wb').write(self.bbd)
            print
            vprint('BBD')
            print
            HexDump.buffer(self.bbd, 0, 0x80)

        # Root 읽기
        root_startblock = get_uint32(self.mm, 0x30)
        root_list_array = get_block_link(root_startblock, self.bbd)
        self.root_list_array = root_list_array

        self.root = ''
        for no in root_list_array:
            self.root += get_bblock(self.mm, no, self.bsize)

        if self.verbose:
            open('root.dmp', 'wb').write(self.root)
            print
            vprint('ROOT')
            vprint(None, 'Start Blocks', '%d' % root_startblock)
            print
            HexDump.buffer(self.root, 0, 0x80)

        # sbd 읽기
        sbd_startblock = get_uint32(self.mm, 0x3c)
        num_of_sbd_blocks = get_uint32(self.mm, 0x40)
        sbd_list_array = get_block_link(sbd_startblock, self.bbd)

        self.sbd = ''
        for no in sbd_list_array:
            self.sbd += get_bblock(self.mm, no, self.bsize)

        if self.verbose:
            open('sbd.dmp', 'wb').write(self.sbd)
            print
            vprint('SBD')
            vprint(None, 'Start Blocks', '%d' % sbd_startblock)
            vprint(None, 'Num of SBD Blocks', '%d' % num_of_sbd_blocks)
            print
            HexDump.buffer(self.sbd, 0, 0x80)

        # PPS 읽기
        self.pps = []
        for i in range(len(self.root) / 0x80):
            p = {}
            pps = self.root[i*0x80:(i+1)*0x80]

            t_size = get_uint16(pps, 0x40)

            if t_size != 0:
                p['Name'] = DecodeStreamName(pps[0:t_size-2]).decode('UTF-16LE', 'replace')
            else:
                p['Name'] = ''

            p['Type'] = ord(pps[0x42])
            p['Prev'] = get_uint32(pps, 0x44)
            p['Next'] = get_uint32(pps, 0x48)
            p['Dir'] = get_uint32(pps, 0x4c)
            p['Start'] = get_uint32(pps, 0x74)
            p['Size'] = get_uint32(pps, 0x78)

            self.pps.append(p)

        if self.verbose:
            print
            vprint('Property Storage')
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
                t = ''
                t += '   - ' if p['Prev'] == 0xffffffff else '%4d ' % p['Prev']
                t += '   - ' if p['Next'] == 0xffffffff else '%4d ' % p['Next']
                t += '   - ' if p['Dir'] == 0xffffffff else '%4d ' % p['Dir']
                t += '       - ' if p['Start'] == 0xffffffff else '%8X ' % p['Start']

                print '    ' + '%2d %-35s %d %22s %8d' % (self.pps.index(p), p['Name'], p['Type'], t, p['Size'])

        # PPS 전체 경로 구하기
        self.__deep = 0
        self.__full_list = []

        self.__get_pps_path()

        # small block link 얻기
        self.small_block = get_block_link(self.pps[0]['Start'], self.bbd)
        if self.verbose:
            print
            vprint('Small Blocks')
            print self.small_block

    # ---------------------------------------------------------------------
    # PPS 전체 경로 구하기 (내장)
    # ---------------------------------------------------------------------
    def __get_pps_path(self, node=0, prefix=''):
        if node == 0:
            pps_name = ''
            name = prefix + pps_name
        else:
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

            def read(self):
                pps = self.parent.pps[self.node]
                sb = pps['Start']
                size = pps['Size']

                if size >= 0x1000:
                    self.read_size = self.parent.bsize
                    self.fat = self.parent.bbd
                else:
                    self.read_size = self.parent.ssize
                    self.fat = self.parent.sbd

                list_array = get_block_link(sb, self.fat)

                data = ''
                if size >= 0x1000:
                    for n in list_array:
                        off = (n+1) * self.read_size
                        data += self.parent.mm[off:off+self.read_size]
                else:
                    for n in list_array:
                        off = (self.parent.small_block[n / 8] + 1) * self.parent.bsize
                        off += (n % 8) * self.parent.ssize
                        data += self.parent.mm[off:off + self.read_size]

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
            raise Error('PPS name is invalid.')

        # self.init(self.mm)
        # return

        ow = OleWriteStream(self.mm, self.pps, self.bsize, self.ssize, self.bbd, self.sbd,
                            self.root_list_array, self.small_block, self.verbose)
        t = ow.write(no, data)
        if t:
            self.init(t)  # 새롭게 OLE 재로딩

    # ---------------------------------------------------------------------
    # 스트림 또는 스토리지를 삭제한다.
    # ---------------------------------------------------------------------
    def delete(self, name):
        for p in self.__full_list:
            if p['Name'] == name:
                no = p['Node']
                break
        else:
            no = -1

        if no == -1:
            raise Error('PPS name is invalid.')

        # print no

        ow = OleWriteStream(self.mm, self.pps, self.bsize, self.ssize, self.bbd, self.sbd,
                            self.root_list_array, self.small_block, self.verbose)
        t = ow.delete(no)
        if t:
            self.init(t)  # 새롭게 OLE 재로딩

# ---------------------------------------------------------------------
# OleWriteStream 클래스
# ---------------------------------------------------------------------
class OleWriteStream:
    def __init__(self, mm, pps, bsize, ssize, bbd, sbd, root_list_array, small_block, verbose):
        self.verbose = verbose

        self.mm = mm
        self.pps = pps
        self.bsize = bsize
        self.ssize = ssize
        self.bbd = bbd
        self.sbd = sbd
        self.root_list_array = root_list_array
        self.small_block = small_block

    def delete(self, no):
        target_pps = self.pps[no]
        pps_prev = target_pps['Prev']
        pps_next = target_pps['Next']
        pps_dir = target_pps['Dir']

        # Prev 조정하기 (no가 Prev에 존재하는 경우)
        for i, pps in enumerate(self.pps):
            if pps['Prev'] == no:
                self.__set_pps_header(i, pps_prev=pps_prev)
                break

        # Prev 조정하기 (no가 Dir에 존재하는 경우)
        for i, pps in enumerate(self.pps):
            if pps['Dir'] == no:
                self.__set_pps_header(i, pps_dir=pps_prev)
                break

        # Prev 조정하기 (no가 Next에 존재하는 경우)
        for i, pps in enumerate(self.pps):
            if pps['Next'] == no:
                self.__set_pps_header(i, pps_next=pps_prev)
                break

        # Next 수정하기
        if pps_next != 0xffffffff:
            t_no = self.pps[pps_prev]['Next']
            if t_no != 0xffffffff:
                while True:
                    if self.pps[t_no]['Next'] == 0xffffffff:
                        self.__set_pps_header(t_no, pps_next=pps_next)
                        break
                    else:
                        t_no = self.pps[t_no]['Next']
            else:
                self.__set_pps_header(pps_prev, pps_next=pps_next)

        # PPS 정보를 삭제함
        self.__set_pps_header(no, size=0, start=0xffffffff, pps_prev=0xffffffff, pps_next=0xffffffff, pps_dir=0xffffffff)

        # 만약 해당 pps가 dir을 가졌다면 하부는 모두 0xffffffff로 정리
        if pps_dir != 0xffffffff:
            fl = [pps_dir]

            while len(fl):
                f_no = fl.pop(0)
                t_prev = self.pps[f_no]['Prev']
                t_next = self.pps[f_no]['Next']
                t_dir = self.pps[f_no]['Dir']
                fl += [x for x in [t_prev, t_next, t_dir] if x != 0xffffffff]

                self.__set_pps_header(f_no, size=0, start=0xffffffff, pps_prev=0xffffffff, pps_next=0xffffffff,
                                      pps_dir=0xffffffff)

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

                    t_link = get_block_link(org_sb, self.bbd)  # 이전 링크 수집하기
                    t_link = self.__decrease_bbd_link(t_link, n)  # 필요한 개수로 링크 줄이기

                    # Big block 영역에 bsize 만큼씩 Overwrite
                    self.__write_data_to_big_block(t_data, t_link)

                    # PPS 크기 수정
                    self.__set_pps_header(no, size=len(data))
                else:
                    # raise error('Not Support : BBD -> BBD (Inc)')

                    n = (len(data) / self.bsize) + (1 if (len(data) % self.bsize) else 0)
                    t_data = data + ('\x00' * ((n * self.bsize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                    t_link = get_block_link(org_sb, self.bbd)  # 이전 링크 수집하기

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
                t_link = get_block_link(org_sb, self.sbd)  # 이전 링크 수집하기

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
                    n = get_uint32(bbd_list_array, i*4)
                    self.bbd += get_bblock(self.mm, n, self.bsize)

                # 새로운 Small Block 링크가 필요하다
                self.small_block = get_block_link(self.pps[0]['Start'], self.bbd)

                # Small block 영역에 ssize 만큼씩 Overwrite
                self.__write_data_to_small_bolck(t_data, t_link)

                # PPS 크기 수정, start 블록 수정
                self.__set_pps_header(no, size=len(data), start=t_link[0])

                # 이전 BBD의 링크는 모두 삭제한다.
                t_link = get_block_link(org_sb, self.bbd)  # 이전 링크 수집하기

                bbd = self.bbd
                for no in t_link:
                    bbd = bbd[:no*4] + '\xff\xff\xff\xff' + bbd[(no+1)*4:]

                self.__modify_bbd(bbd)

            else:  # 기존에는 SBD 사용
                if org_size >= len(data):
                    # raise error('Not Support : SBD -> SBD (Dec)')  # 지원 완료

                    n = (len(data) / self.ssize) + (1 if (len(data) % self.ssize) else 0)
                    t_data = data + ('\x00' * ((n*self.ssize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                    t_link = get_block_link(org_sb, self.sbd)  # 이전 링크 수집하기
                    t_link = self.__decrease_sbd_link(t_link, n)  # 필요한 개수로 링크 줄이기

                    # Small block 영역에 ssize 만큼씩 Overwrite
                    self.__write_data_to_small_bolck(t_data, t_link)

                    # PPS 크기 수정
                    self.__set_pps_header(no, size=len(data))
                else:
                    # raise error('Not Support : SBD -> SBD (Inc)')  # 추가 개발 필요

                    n = (len(data) / self.ssize) + (1 if (len(data) % self.ssize) else 0)
                    t_data = data + ('\x00' * ((n*self.ssize) - len(data)))  # 여분의 크기를 data 뒤쪽에 추가하기

                    t_link = get_block_link(org_sb, self.sbd)  # 이전 링크 수집하기

                    t_num = 0
                    if (len(t_link) * self.ssize) < len(t_data):  # 블록 추가해야 하나?
                        t_size = len(t_data) - (len(t_link) * self.ssize)
                        t_num = (t_size / self.ssize) + (1 if (t_size % self.ssize) else 0)

                        self.__add_small_block_num(t_num)  # 필요한 블록 수 추가하기

                    # 수집된 마지막 링크 이후에 존재하는 사용하지 않는 블록을 수집한다.
                    t_link = self.__modify_small_block_link(t_link, t_num)

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
    def __set_pps_header(self, node, size=None, start=None, pps_prev=None, pps_next=None, pps_dir=None):
        n = self.root_list_array[node / 4]

        buf = get_bblock(self.mm, n, self.bsize)
        off = ((node % 4) * 0x80)

        if size is not None:
            t_off = off + 0x78
            buf = buf[:t_off] + struct.pack('<L', size) + buf[t_off + 4:]

        if start:
            t_off = off + 0x74
            buf = buf[:t_off] + struct.pack('<L', start) + buf[t_off + 4:]

        if pps_prev:
            t_off = off + 0x44
            buf = buf[:t_off] + struct.pack('<L', pps_prev) + buf[t_off + 4:]

        if pps_next:
            t_off = off + 0x48
            buf = buf[:t_off] + struct.pack('<L', pps_next) + buf[t_off + 4:]

        if pps_dir:
            t_off = off + 0x4C
            buf = buf[:t_off] + struct.pack('<L', pps_dir) + buf[t_off + 4:]

        self.__set_bblock(n, buf)

        if self.verbose:
            print
            buf = get_bblock(self.mm, n, self.bsize)
            HexDump.buffer(buf, 0, 0x200)

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
                t_link.append(get_uint32(self.sbd, i * 4))

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
            sbd_startblock = get_uint32(self.mm, 0x3c)
            sbd_list_array = get_block_link(sbd_startblock, self.bbd)

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
                t_link.append(get_uint32(self.bbd, i * 4))

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
                bbd_list_array.append(get_uint32(t, i * 4))

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
            no = get_uint32(bbd_list_array, i*4)
            bbd += get_bblock(self.mm, no, self.bsize)

        bbd_link = []
        for i in range(len(bbd) / 4):
            bbd_link.append(get_uint32(bbd, i*4))

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
            old_num_bbd = get_uint32(self.mm, 0x2c)

            xbbd_start_block = get_uint32(self.mm, 0x44)
            num_of_xbbd_blocks = get_uint32(self.mm, 0x48)

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
                        next_b = get_uint32(t_data, self.bsize-4)

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
                # print hex(no), hex(seg), hex(off), hex(get_uint32(bbd_list_array, seg*4))

                t_no = get_uint32(bbd_list_array, seg*4)
                t_off = ((t_no + 1) * self.bsize) + (off * 4)

                self.mm = self.mm[:t_off] + '\xfd\xff\xff\xff' + self.mm[t_off+4:]

                # print repr(self.mm[t_off:t_off+4])

                # t = get_bblock(self.mm, t_no, self.bsize)
                # print repr(t)
                # t = get_uint32(t, off*4)
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
            sbd_link.append(get_uint32(self.sbd, i*4))

        # 사용하지 않는 SBD 링크를 찾는다.
        free_link = [i for i, no in enumerate(sbd_link) if (no == 0xffffffff and i < r_size / self.ssize)]

        if len(free_link) >= num:  # 여유분이 충분히 존재함...
            return  # 추가할 필요 없음
        else:  # 여유분이 부족함. 따라서 Root를 늘려야 함
            size = num * self.ssize  # 추가해야 할 용량
            add_big_num = (size / self.bsize) + (1 if (size % self.bsize) else 0)  # 추가해야 할 Big Block 개수

            self.__add_big_block_num(add_big_num)  # Big Block 추가 요청

            t_link = get_block_link(r_no, self.bbd)  # 이전 Small Block의 링크를 구함
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
            no = get_uint32(bbd_list_array, i*4)
            bbd += get_bblock(self.mm, no, self.bsize)

        if self.verbose:
            open('bbd.dm2', 'wb').write(bbd)

        bbd_link = []
        for i in range(len(bbd) / 4):
            bbd_link.append(get_uint32(bbd, i*4))

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
            sbd_link.append(get_uint32(sbd, i*4))

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
        sbd_no = get_uint32(self.mm, 0x3c)
        sbd_list_array = get_block_link(sbd_no, self.bbd)
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
        bbd_list_array, _, _, _ = get_bbd_list_array(self.mm)

        for i in range(len(bbd_list_array) / 4):
            no = get_uint32(bbd_list_array, i * 4)
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
        info['version'] = '1.0'  # 버전
        info['title'] = 'OLE Library'  # 엔진 설명
        info['kmd_name'] = 'ole'  # 엔진 파일 이름

        return info

    # ---------------------------------------------------------------------
    # format(self, filehandle, filename, filename_ex)
    # 파일 포맷을 분석한다.
    # 입력값 : filehandle - 파일 핸들
    #          filename   - 파일 이름
    #          filename_ex - 압축 파일 내부 파일 이름
    # 리턴값 : {파일 포맷 분석 정보} or None
    # ---------------------------------------------------------------------
    def format(self, filehandle, filename, filename_ex):
        fileformat = {}  # 포맷 정보를 담을 공간
        ret = {}

        if is_olefile(filename):  # OLE 헤더와 동일
            ret['ff_ole'] = 'OLE'

        return ret
