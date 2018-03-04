# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import struct
import kernel
import kavutil
import zlib
import cPickle
import cryptolib
import StringIO

try:
    import yara
    LOAD_YARA = True
except ImportError:
    LOAD_YARA = False


# -------------------------------------------------------------------------
# ASN1 클래스 : PE 파일 Authenticode signature format
# -------------------------------------------------------------------------
class ASN1:
    def __init__(self):
        self.data = None
        self.name_count = {}

    def set_data(self, data):
        self.data = data

    def hex_string(self, data):
        d = ['%02X' % ord(x) for x in data]
        return ' '.join(d)

    def parse(self):
        return self.__parse_asn1(self.data)

    def __parse_asn1(self, data, deep=0):
        ret = []

        d = data

        while len(d) > 2:
            t, l, d1, off = self.get_asn1_data(d)

            if self.is_constructed(t):
                deep += 1
                ret.append(self.__parse_asn1(d1, deep))
                deep -= 1
            else:
                x1 = self.hex_string(d1)
                ttype = t & 0x1f
                if ttype == 0x6:  # Type이 ObjectIdentifier이면...
                    ret.append(x1)
                elif ttype in [0x13, 0x14, 0xC, 0x16]:  # Type이 0x13이면 String 같음
                    ret.append(d1)
                elif ttype == 0x17:  # Type이 0x17이면 Time 같음
                    ret.append(d1)
                else:
                    ret.append(x1)

            if deep ==0:
                break

            d = d[off+l:]

        return ret

    # 주어진 Type이 폴더인지 알아낸다.
    def is_constructed(self, val):
        return val & 0x20 == 0x20

    # ASN1의 길이를 얻는다.
    def get_asn1_len(self, data):
        val = ord(data[1])

        if val & 0x80 == 0:
            return val, 2
        else:
            data_len = val & 0x7f

            val = int(data[2:2 + data_len].encode('hex'), 16)
            return val, 2+data_len

    # ASN1의 데이터를 얻는다.
    def get_asn1_data(self, data):
        asn1_type = ord(data[0])
        asn1_len, off = self.get_asn1_len(data)
        asn1_data = data[off:off+asn1_len]
        return asn1_type, asn1_len, asn1_data, off


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
        self.verbose = verbose
        self.sig_num_yara = 0

        # Yara 모듈이 없을 경우 엔질 로딩 실패 처리
        if not LOAD_YARA:
            return -1

        # Adware Yara 룰 로딩
        try:
            b = open(os.path.join(plugins_path, 'adware.y01'), 'rb').read()
            self.sig_num_yara = kavutil.get_uint32(b, 4)
            if b[:4] == 'KAVS':
                t = zlib.decompress(b[12:])

                buff = StringIO.StringIO(t)
                self.adware_gen = yara.load(file=buff)
        except:
            self.adware_gen = None

        return 0  # 플러그인 엔진 초기화 성공

    # ---------------------------------------------------------------------
    # uninit(self)
    # 플러그인 엔진을 종료한다.
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    # ---------------------------------------------------------------------
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # ---------------------------------------------------------------------
    # scan(self, filehandle, filename, fileformat)
    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    #         fileformat  - 파일 포맷
    #         filename_ex - 파일 이름 (압축 내부 파일 이름)
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex):  # 악성코드 검사
        try:
            mm = filehandle

            # 미리 분석된 파일 포맷중에 PE 포맷이 있는가?
            if 'ff_pe' in fileformat:
                # Cert를 이용해 악성코드를 검사한다.
                ret = self.__scan_asn1(filehandle, filename, fileformat, filename_ex)
                if ret[0]:  # 악성코드 발견이면 종료
                    return ret

                # rdata를 이용해 악성코드를 검사한다.
                if self.adware_gen:
                    ret = self.__scan_rdata(filehandle, filename, fileformat, filename_ex)
                    if ret[0]:  # 악성코드 발견이면 종료
                        return ret
        except IOError:
            pass

        # 악성코드를 발견하지 못했음을 리턴한다.
        return False, '', -1, kernel.NOT_FOUND

    # ---------------------------------------------------------------------
    # Cert 정보에서 Adware 배포자를 검사한다.
    # ---------------------------------------------------------------------
    def __scan_asn1(self, filehandle, filename, fileformat, filename_ex):
        mm = filehandle

        ff = fileformat['ff_pe']

        cert_off = ff['pe'].get('CERTIFICATE_Offset', 0)
        cert_size = ff['pe'].get('CERTIFICATE_Size', 0)

        if cert_off != 0 and cert_size != 0:
            if self.verbose:
                print '-' * 79
                kavutil.vprint('Engine')
                kavutil.vprint(None, 'Engine', 'adware.kmd')

            # 인증서 추출
            cert_data = mm[cert_off:cert_off + cert_size]
            asn1 = ASN1()
            asn1.set_data(cert_data[8:])
            try:
                r = asn1.parse()

                # Signed Data 이면서 버전 정보가 1인가?
                if r[0][0] == '2A 86 48 86 F7 0D 01 07 02' and r[0][1][0][0] == '01':
                    signeddata = r[0][1][0]
                    certificates = signeddata[3]

                    signerinfo = r[0][1][0][-1]
                    issuer_and_serialnumber = signerinfo[0][1]
                    issuer_serial = issuer_and_serialnumber[1]

                    for cert in certificates:
                        if cert[0][1] == issuer_serial:  # 동일한 일련번호 찾기
                            for x in cert[0][5]:
                                if x[0][0] == '55 04 03':  # Common Name
                                    signer_name = x[0][1]
                                    break
                            else:
                                continue  # no break encountered
                            break
                    else:
                        raise IndexError

                    # 일련번호의 길이가 제각각이라 md5 고정길이로 만듬
                    fmd5 = cryptolib.md5(issuer_serial)
                    fsize = kavutil.get_uint16(fmd5.decode('hex'), 0)

                    if self.verbose:
                        kavutil.vprint('Signer')
                        kavutil.vprint(None, 'Name', signer_name)
                        kavutil.vprint(None, 'Serial Number', issuer_serial)

                        msg = '%d:%s:  # %s, %s\n' % (fsize, fmd5, signer_name, cryptolib.sha256(mm))
                        open('adware.mdb', 'at').write(msg)

                    if fsize and kavutil.handle_pattern_md5.match_size('adware', fsize):
                        vname = kavutil.handle_pattern_md5.scan('adware', fsize, fmd5)
                        if vname:
                            pos = ff['pe'].get('EntryPointRaw', 0)
                            if mm[pos:pos + 4] == '\xff\x25\x00\x20':
                                pf = 'MSIL'
                            else:
                                pf = 'Win32'

                            vname = kavutil.normal_vname(vname, pf)
                            return True, vname, 0, kernel.INFECTED
            except IndexError:
                pass

        # 악성코드를 발견하지 못했음을 리턴한다.
        return False, '', -1, kernel.NOT_FOUND

    # ---------------------------------------------------------------------
    # rdata에 Adware에서 자주 사용하는 문자열을 검사한다.
    # ---------------------------------------------------------------------
    def __scan_rdata(self, filehandle, filename, fileformat, filename_ex):
        mm = filehandle

        ff = fileformat['ff_pe']

        if ff['pe']['SectionNumber'] > 2:
            section = ff['pe']['Sections'][1]  # .rdata
            foff = section['PointerRawData']
            fsize = section['SizeRawData']

            ret = self.adware_gen.match(data=mm[foff:foff + fsize])
            if len(ret):
                vname = ret[0].meta.get('KicomAV', ret[0].rule)  # KicomAV meta 정보 확인
                return True, vname, 0, kernel.INFECTED

        # 악성코드를 발견하지 못했음을 리턴한다.
        return False, '', -1, kernel.NOT_FOUND

    # ---------------------------------------------------------------------
    # disinfect(self, filename, malware_id)
    # 악성코드를 치료한다.
    # 입력값 : filename    - 파일 이름
    #        : malware_id - 치료할 악성코드 ID
    # 리턴값 : 악성코드 치료 여부
    # ---------------------------------------------------------------------
    def disinfect(self, filename, malware_id):  # 악성코드 치료
        try:
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if malware_id == 0:
                os.remove(filename)  # 파일 삭제
                return True  # 치료 완료 리턴
        except IOError:
            pass

        return False  # 치료 실패 리턴

    # ---------------------------------------------------------------------
    # listvirus(self)
    # 진단/치료 가능한 악성코드의 리스트를 알려준다.
    # 리턴값 : 악성코드 리스트
    # ---------------------------------------------------------------------
    def listvirus(self):  # 진단 가능한 악성코드 리스트
        vlist = kavutil.handle_pattern_md5.get_sig_vlist('adware')
        vlist = list(set(vlist))
        vlist.sort()

        vlists = []
        for vname in vlist:
            vname = kavutil.normal_vname(vname)
            if vname.find('<p>'):
                vlists.append(vname.replace('<p>', 'Win32'))
                vlists.append(vname.replace('<p>', 'MSIL'))
            else:
                vlists.append(vname)

        vlists.sort()
        return vlists

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.1'      # 버전
        info['title'] = 'Adware Scan Engine'  # 엔진 설명
        info['kmd_name'] = 'adware'  # 엔진 파일 이름
        s_num = kavutil.handle_pattern_md5.get_sig_num('adware') * 2  # 진단/치료 가능한 악성코드 수
        s_num += self.sig_num_yara
        info['sig_num'] =s_num

        return info
