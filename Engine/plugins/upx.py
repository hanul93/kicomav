# -*- coding:utf-8 -*-

"""
Copyright (C) 2013 Nurilab.

Author: Kei Choi(hanul93@gmail.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
"""

__revision__ = '$LastChangedRevision: 2 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'


import struct
import mmap
import pefile # pefile.kmd가 우선순위로 로딩되어야 함


HEADERS = \
'\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00' \
'\xB0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x1A\x00\x00\x00\x00\x00' \
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD0\x00\x00\x00' \
'\x0E\x1F\xB4\x09\xBA\x0D\x00\xCD\x21\xB4\x4C\xCD\x21\x54\x68\x69' \
'\x73\x20\x66\x69\x6C\x65\x20\x77\x61\x73\x20\x63\x72\x65\x61\x74' \
'\x65\x64\x20\x62\x79\x20\x43\x6C\x61\x6D\x41\x56\x20\x66\x6F\x72' \
'\x20\x69\x6E\x74\x65\x72\x6E\x61\x6C\x20\x75\x73\x65\x20\x61\x6E' \
'\x64\x20\x73\x68\x6F\x75\x6C\x64\x20\x6E\x6F\x74\x20\x62\x65\x20' \
'\x72\x75\x6E\x2E\x0D\x0A\x43\x6C\x61\x6D\x41\x56\x20\x2D\x20\x41' \
'\x20\x47\x50\x4C\x20\x76\x69\x72\x75\x73\x20\x73\x63\x61\x6E\x6E' \
'\x65\x72\x20\x2D\x20\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77\x2E' \
'\x63\x6C\x61\x6D\x61\x76\x2E\x6E\x65\x74\x0D\x0A\x24\x00\x00\x00'

UPX_NRV2B = '\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc'
UPX_NRV2D = '\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb'
UPX_NRV2E = '\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a'
UPX_LZMA1 = '\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90'
UPX_LZMA2 = '\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90'

def PESALIGN(o,a) :
    if (a) :
        ret = (((o)/(a)+((o)%(a)!=0))*(a))
    else :
        ret = (o)

    return ret

def ROR(x, n, bits = 32):
    mask = (2L**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

def ROL(x, n, bits = 32):
    return ROR(x, bits - n, bits)

def checkpe(dst, dsize, pehdr) :
    try :
        if struct.unpack('<L', dst[pehdr:pehdr+4])[0] != 0x4550 :
            raise SystemError

        valign = struct.unpack('<L', dst[pehdr+0x38:pehdr+0x38+4])[0]
        if not valign : raise SystemError

        sectcnt = struct.unpack('<H', dst[pehdr+6:pehdr+8])[0]
        if not sectcnt : raise SystemError

        sections_pos = pehdr + 0xF8

        if (sections_pos + (sectcnt * 0x28)) > dsize : 
            raise SystemError
    except :
        sections_pos = 0
        valign       = 0
        sectcnt      = 0
        pass

    return sections_pos, valign, sectcnt

def ModifyCallAddr(src, dest, ep, upx0, upx1, baseaddr) :
    try :
        # Call 개수 확인    
        ssize = len(src)
        pos = ep - upx1
        call_count = -1

        while True :
            if (pos > ssize - 13) :
                break

            if ord(src[pos  ]) == 0xE9 and \
               ord(src[pos+3]) == 0xFF and \
               ord(src[pos+4]) == 0xFF and \
               ord(src[pos+5]) == 0x5E and \
               ord(src[pos+6]) == 0x89 and \
               ord(src[pos+7]) == 0xF7 and \
               ord(src[pos+8]) == 0xB9 :
                call_count = struct.unpack('<L', src[pos+9:pos+13])[0]
                break
            else :
                pos += 1

        if call_count == -1 : raise SystemError

        # Call Address 수정
        dst = ''
        pos = 0
        dcur = 0
        dsize = len(dest)

        while call_count :
            if (pos > dsize - 5) :
                break

            if (ord(dest[pos]) == 0xE9 or ord(dest[pos]) == 0xE8) and \
               ord(dest[pos+1]) == 0x01 :
                eax = struct.unpack('<L', dest[pos+1:pos+5])[0]
                ax = eax & 0xFFFF
                ax >>= 8
                eax &= 0xFFFF0000
                eax |= ax
                eax = ROL(eax, 0x10)
                ah = (eax & 0xFF00) >> 8
                al = (eax & 0x00FF) << 8
                ax = ah | al
                eax &= 0xFFFF0000
                eax |= ax
                eax = uint32(eax - (baseaddr+upx0+pos+1))
                eax = uint32(eax + (baseaddr+upx0))
                dst += dest[dcur:pos+1]
                dst += struct.pack('<L', eax)
                
                pos += 5
                dcur = pos
                call_count -= 1
            else :
                pos += 1

        dst += dest[dcur:]
        '''
        fp = open('call.dmp', 'wb')
        fp.write(dst)
        fp.close()
        '''
    except :
        return None

    return dst

def RebuildPE(src, ssize, dst, dsize, ep, upx0, upx1, magic, dend) :
    try :
        foffset = uint32(0xD0 + 0xF8)

        if len(src) == 0 or len(dst) == 0 :
            raise SystemError

        for valign in magic :
            if (ep - upx1 + valign <= ssize - 5) and            \
                ord(src[ep - upx1 + valign - 2]) == 0x8D and    \
                ord(src[ep - upx1 + valign - 1]) == 0xBE :
                break

        if not valign and (ep - upx1 + 0x80 < ssize-8) :
            i = 0
            while True :
                b1 = ord(src[ep - upx1 + 0x80 + 0 + i])
                b2 = ord(src[ep - upx1 + 0x80 + 1 + i])

                if b1 == 0x8D and b2 == 0xBE :
                    b3 = ord(src[ep - upx1 + 0x80 + 6 + i])
                    b4 = ord(src[ep - upx1 + 0x80 + 7 + i])

                    if b3 == 0x8B and b4 == 0x07 :
                        valign = 0x80 + i + 2
                        break
                i += 1

        if valign and ISCONTAINED(0, ssize, ep - upx1 + valign, 4) :
            dst_imports = struct.unpack('<l', src[ep - upx1 + valign:ep - upx1 + valign + 4])[0]

            realstuffsz = dst_imports

            if realstuffsz >= dsize :
                raise SystemError
            else :
                pehdr = dst_imports
                
                
                while (pehdr + 8 < dsize) and (struct.unpack('<l', dst[pehdr:pehdr+4])[0]) :
                    pehdr += 8
                    while (pehdr + 2 < dsize) and ord(dst[pehdr]) :
                        pehdr += 1
                        while (pehdr + 2 < dsize) and ord(dst[pehdr]) :
                            pehdr += 1
                        pehdr += 1
                    pehdr += 1
                pehdr += 4

                sections, valign, sectcnt = checkpe(dst, dsize, pehdr)
                if not sections : pehdr = 0

        if not pehdr and dend > (0xF8 + 0x28) :
            pehdr = dend - 0xF8 - 0x28
            if int32(pehdr) < 0 : raise SystemError

            while True :
                sections, valign, sectcnt = checkpe(dst, dsize, pehdr)
                if sections : break
                pehdr -= 1

            realstuffsz = pehdr
            if not realstuffsz : raise SystemError

        if not pehdr :
            rebsz = uint32(PESALIGN(dend, 0x1000))
            # print hex(rebsz)
            # To Do

        foffset = PESALIGN(foffset + 0x28 * sectcnt, valign)

        for upd in range(sectcnt) :
            t = struct.unpack('<L', dst[sections+8:sections+12])[0]
            vsize = uint32(PESALIGN(t, valign))

            t = struct.unpack('<L', dst[sections+12:sections+16])[0]
            urva  = uint32(PESALIGN(t, valign))

            if  not (upx0 + realstuffsz >= urva + vsize) : 
                raise SystemError

            t = struct.pack('<LLLL', vsize, urva, vsize, foffset)
            dest = dst[:sections+8]
            dest += t
            dest += dst[sections+24:]
            dst   = dest

            foffset += vsize
            sections += 0x28


        t = struct.pack('<L', valign)
        dest = dst[:pehdr+0x3C]
        dest += t
        dest += dst[pehdr+0x3C+4:]
        dst   = dest

        newbuf = ['\x00'] * foffset

        for i in range(len(HEADERS)) :
            newbuf[i] = HEADERS[i]

        for i in range(0xf8+0x28*sectcnt) :
            newbuf[0xD0 + i] = dst[pehdr + i]

        sections = pehdr + 0xF8

        for upd in range(sectcnt) :
            t1 = struct.unpack('<L', dst[sections+20:sections+24])[0]
            t2 = struct.unpack('<L', dst[sections+12:sections+16])[0]
            t3 = struct.unpack('<L', dst[sections+16:sections+20])[0]

            for i in range(t3) :
                newbuf[t1 + i] = dst[t2 - upx0 + i]

            sections += 0x28

        if foffset > dsize + 8192 : raise SystemError

        dsize = foffset

        upx_d = ''
        for ch in newbuf :
            upx_d += ch
    except :
        return None

    return upx_d

def int32(iv) :
    if iv & 0x80000000 :
        iv = -0x100000000 + iv
    return iv   

def uint32(iv) :
    return iv & 0xFFFFFFFF

def ISCONTAINED(bb, bb_size, sb, sb_size) :
    c1 = (bb_size) > 0
    c2 = (sb_size) > 0
    c3 = (sb_size) <= (bb_size)
    c4 = (sb) >= (bb)
    c5 = ((sb) + (sb_size)) <= ((bb) + (bb_size))
    c6 = ((sb) + (sb_size)) > (bb)
    c7 = (sb) < ((bb) + (bb_size))

    if c1 and c2 and c3 and c4 and c5 and c6 and c7 :
        return True
    else :
        return False

def doubleebx(src, myebx, scur, ssize) :
    oldebx = myebx
    
    try :
        myebx = (myebx * 2) & 0xFFFFFFFF
        if not (oldebx & 0x7fffffff) :
            if not ISCONTAINED(0, ssize, scur, 4) :
                return -1, myebx, scur
            oldebx = struct.unpack('<L', src[scur:scur+4])[0]
            myebx = uint32(oldebx * 2 + 1)
            scur += 4
        return (oldebx >> 31), myebx, scur
    except :
        return -1, myebx, scur


def upx_inflate2b(src, dsize, ep, upx0, upx1, baseaddr) :
    ret   = -1
    dest  = ''    
    myebx = 0
    scur  = 0
    dcur  = 0
    dst   = ['\x00'] * dsize
    ssize = len(src)
    unp_offset = -1

    try :
        while True :
            while True :
                oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                if oob != 1 : break

                if scur>=ssize or dcur>=dsize :
                    raise SystemError

                dst[dcur]  = src[scur]
                dcur += 1
                scur += 1

            if oob == -1 :
                raise SystemError

            backbytes = 1

            while True :
                oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                if oob == -1 :
                    raise SystemError

                backbytes = backbytes * 2 + oob

                oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                if oob == -1 :
                    raise SystemError
                    
                if oob :
                    break

            backbytes -= 3
            
            if backbytes >= 0 :
                if scur >= ssize :
                    raise SystemError
                backbytes <<= 8
                backbytes += ord(src[scur])
                scur += 1
                backbytes ^= 0xFFFFFFFF

                if not backbytes :
                    break
                unp_offset = int32(backbytes)

            backsize, myebx, scur = doubleebx(src, myebx, scur, len(src))
            backsize &=  0xFFFFFFFF
            if backsize == 0xFFFFFFFF :
                raise SystemError

            oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
            if oob == -1 :
                raise SystemError

            backsize = backsize * 2 + oob

            if not backsize :
                backsize += 1

                while True :
                    oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                    if oob == -1 :
                        raise SystemError

                    backsize = backsize * 2 + oob

                    oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                    if oob != 0 :
                        break

                if oob == -1 :
                    raise SystemError

                backsize += 2

            if (unp_offset & 0xFFFFFFFF ) < 0xFFFFF300 :
                backsize += 1

            backsize += 1

            if not ISCONTAINED(0, dsize, dcur+unp_offset, backsize) or not ISCONTAINED(0, dsize, dcur, backsize) or unp_offset >= 0 :
                raise SystemError

            for i in range(backsize) :
                dst[dcur + i] = dst[dcur + unp_offset + i]

            dcur += backsize

        # 압축 해제 이미지 
        dest = ''
        for ch in dst :
            dest += ch

        # Call 주소 조정
        dest = ModifyCallAddr(src, dest, ep, upx0, upx1, baseaddr)

        '''
        fp = open('upx_img.dmp', 'wb')
        fp.write(dest)
        fp.close()
        '''

        # PE 파일로 조립하기  
        magic=[0x108,0x110,0xd5,0]
        dest = RebuildPE(src, ssize, dest, dsize, ep, upx0, upx1, magic, dcur)

        '''
        fp = open('upx_build.dmp', 'wb')
        fp.write(dest)
        fp.close()
        '''

        ret = 0
    except :
        pass

    return ret, dest


#---------------------------------------------------------------------
# KavMain 클래스
# 키콤백신 엔진 모듈임을 나타내는 클래스이다.
# 이 클래스가 없으면 백신 엔진 커널 모듈에서 로딩하지 않는다.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # init(self, plugins)
    # 백신 엔진 모듈의 초기화 작업을 수행한다.
    #-----------------------------------------------------------------
    def init(self, plugins) : # 백신 모듈 초기화
        return 0

    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = __author__    # 제작자
        info['version'] = __version__  # 버전
        info['title'] = 'UPX Unpacker' # 엔진 설명
        info['kmd_name'] = 'upx'       # 엔진 파일명
        return info

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # 포맷 분석기이다.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
    # def arclist(self, scan_file_struct, format) :
        fp = None
        mm = None
        file_scan_list = [] # 검사 대상 정보를 모두 가짐

        try :
            # 미리 분석된 파일 포맷중에 PE 포맷이 있는가?
            fformat   = format['ff_pe']
            pe_format = fformat['pe']
            ep_foff   = pe_format['EntryPointRaw']

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            if   mm[ep_foff+0x69:ep_foff+0x69+13] == UPX_NRV2B : arc_name = 'arc_upx!nrv2b'
            elif mm[ep_foff+0x71:ep_foff+0x71+13] == UPX_NRV2B : arc_name = 'arc_upx!nrv2b'
            elif mm[ep_foff+0x69:ep_foff+0x69+13] == UPX_NRV2D : arc_name = 'arc_upx!nrv2d'
            elif mm[ep_foff+0x71:ep_foff+0x71+13] == UPX_NRV2D : arc_name = 'arc_upx!nrv2d'
            elif mm[ep_foff+0x69:ep_foff+0x69+13] == UPX_NRV2E : arc_name = 'arc_upx!nrv2e'
            elif mm[ep_foff+0x71:ep_foff+0x71+13] == UPX_NRV2E : arc_name = 'arc_upx!nrv2e'
            else :
                raise SystemError

            name = 'UPX'
            file_scan_list.append([arc_name, name])
        except :
            pass

        if mm != None : mm.close()
        if fp != None : fp.close()

        return file_scan_list


    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # 주어진 압축된 파일명으로 파일을 해제한다.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        fp = None
        mm = None

        try :
            if arc_engine_id[0:7] != 'arc_upx' :
                raise SystemError

            filename = arc_in_name

            # UPX로 압축된 파일 열기
            fp = open(arc_name, 'rb') 
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            pe_format = pefile.PEparse(mm) # PE 포맷 분석

            pe_img   = pe_format['ImageBase']
            pe_ep    = pe_format['EntryPoint']
            sections = pe_format['Sections']
            ep_raw   = pe_format['EntryPointRaw'] # EP의 Raw 위치
            ep_nsec  = pe_format['EntryPoint_in_Section'] # EP는 몇번째 섹션에 있는가?

            foff  = 0
            ssize = 0
            dsize = 0
            for section in sections :
                ssize = section['VirtualSize']
                rva = section['RVA']
                if rva <= pe_ep and rva+ssize > pe_ep :
                    foff  = section['PointerRawData']
                    i = sections.index(section)
                    if i != 0 :
                        upx0  = sections[i-1]['RVA']
                        upx1  = sections[i  ]['RVA']
                        dsize = sections[i-1]['VirtualSize'] + ssize
                    break

            if ssize == 0 or dsize == 0:
                raise SystemError

            upx_data_rva = struct.unpack('<l', mm[ep_raw+2:ep_raw+6])[0]
            sec_rva      = sections[ep_nsec]['RVA']

            skew = (upx_data_rva - sec_rva - pe_img)

            if mm[ep_raw+1] != '\xBE' or skew <= 0 or skew > 0xFFF :
                skew = 0
            elif skew > ssize :
                skew = 0
            else :
                raise SystemError

            data = mm[foff+skew:foff+ssize-skew]

            unpack_data = '' # UPX 해제된 이미지

            if arc_engine_id[8:] == 'nrv2b' : # UPX 알고리즘 중 nrv2b 압축인가?
                ret_val, unpack_data = upx_inflate2b(data, dsize, pe_ep, upx0, upx1, pe_img)

            mm.close()
            fp.close()

            mm = None
            fp = None

            if unpack_data == '' : # 압축 해제 실패
                raise SystemError

            return unpack_data
        except :
            pass

        if mm != None : mm.close()
        if fp != None : fp.close()

        return None
