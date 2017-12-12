# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import re
import kernel
import kavutil
import cryptolib

# CA
root_ca = {
    '00df6b36ea98c80eadb0073f1cc55f12': 'DigiCert Assured ID Code Signing CA-1',
    '2463771b9866ff7b13ed18967ca64172': 'VeriSign Class 3 Code Signing 2010 CA',
    '92c1b5435deb5c966e7faf658151702e': 'Go Daddy Secure Certification Authority',
    'c6dc85650aae0d331eb85346a2215837': 'GlobalSign CodeSigning CA - G2',
    '1b3f805da201e048a769ee207a543a1c': 'VeriSign Class 3 Public Primary Certification Authority - G5',
    '5b893aacad447b3f25c1592c5b4c24bd': 'COMODO Code Signing CA 2',
    '99795c12d11384bb73393696d94496f7': 'AddTrust External CA Root',
    'f573ac54dfd6fb82b0059f304ec4f091': 'UTN-USERFirst-Object',
    '6f32db305d320f51445f9cd946a7bc36': 'Certum CA',
    '0d49b1ef636d7b77cbb27f70585a1ed0': 'Certum Level III CA',
    '6cbf089d921fa6c102554587b62f6562': 'Certum Trusted Network CA',
    'a231f778343c770d2c6e21a9cb7eaf2a': 'Certum Code Signing CA',
    'bfbca0a79da05faa979f70f75b56bfab': 'Thawte Timestamping CA',
    'e2550a4ff3248b05ba525861d7e5a12b': 'DigiCert Assured ID Root CA',
    '7879774fc2eb438ed3248b328c16be8e': 'Symantec SHA256 TimeStamping CA',
    'ee91406be407a281b430e28a24153455': 'Microsoft Code Verification Root',
    '0ae61bc24f70c173f42ff2983acf41ff': 'Symantec Time Stamping Services CA - G2',
    'fdbeb9127e23fab3e19b578a9d6d4920': 'Certification Authority of WoSign',
    '882d32e9b560bd27000832ccb7cebeb5': 'Symantec Class 3 SHA256 Code Signing CA',
    '3f24843eff2b32ab9f84eff836faa138': 'DigiCert SHA2 Assured ID Code Signing CA',
    'dd902610461459ae2ac1d29fa6f934d8': 'Symantec SHA256 TimeStamping Signer - G1',
    '511df12e11d09ef6ffb8960bc8e48c2a': 'Symantec Time Stamping Services Signer - G4',
    '203951806534410c6d0992d08f5a2a2d': 'VeriSign Universal Root Certification Authority',
    '5f1858aefd218bd5cdb8187bc0be25c2': 'thawte Primary Root CA',
    'fc7323c665f25b915a8d2c8c3a1c43d0': 'Thawte Code Signing CA - G2',
    '2eedd6ce03ef886ab20051ec63e7d17f': 'COMODO RSA Code Signing CA',
    '4d91354b5dc10d2771e2b05bd77a8b58': 'Microsoft Timestamping PCA',
    '841c35150c6cf0fa1b70d02fff66f242': 'Microsoft Code Signing PCA',
    'b016306dde9f96d5ea344e788c34cbc1': 'VeriSign Class 3 Code Signing 2004 CA',
    'd91da0bcb4d9dc6ea8ea462a231f1010': 'VeriSign Time Stamping Services CA',
    'e9f9a620abc8b57f101e7f841672ac74': 'Microsoft Windows Verification Intermediate PCA',
    'd3f6378d39a33f2cb7e13e32e1409b49': 'GlobalSign Root CA',
    '2974e8729c8713831f1e4b477afdc0ab': 'DigiCert Assured ID CA-1',
    '36d1948364aeeb8419387bbecff1d567': 'GlobalSign ObjectSign CA',
    'bc6f0d562350d3f669b3c203210dbf0c': 'Thawte Premium Server CA',
    'fb374766133ab1de6d22f740aa08cbb9': 'COMODO Time Stamping Signer',
    'f6a29f5ba7b3523221cea09ada0de7a4': 'DigiCert Timestamp Responder',
    '8c2ca830d46600361a01dc691394739d': 'thawte SHA256 Code Signing CA',
    'a25c349a964b3b0fc7b299a4e0cd13d1': 'WoSign Class 3 Code Signing CA',
    'ef1c510fe31d42cd0f4f2003690abbc4': 'GlobalSign Timestamping CA - G2',
    '8eba8cbf3efaa5f7dd31b63213a9553e': 'WoSign Time Stamping Signer',
    '0ca77d0cb754d92744349e9b764beaf7': 'GlobalSign CodeSigning CA - SHA256 - G2',
    '2ed9e7c532f259802ed96d0e36fdc039': 'GlobalSign Time Stamping Authority',
    'ad40bb9d5feee9aec27e2f33f813db04': 'COMODO RSA Certification Authority',
    '3336cc222eaaa64923e00113e7864e14': 'GlobalSign Primary Object Publishing CA'
}

# 인증서 정보
strdict = {
    0x11: 'PostalCode',
    0x6: 'C',
    0x8: 'S',
    0x7: 'L',
    0x9: 'STREET',
    0x3: 'CN',
    0xA: 'O',
    0xB: 'OU',
    0x5: 'SERIALNUMBER'
}


# 인증서 정보 추출
def get_subj(data):
    if data[0] == '\x31' and data[2] == '\x30' and data[4:8] == '06035504'.decode('hex'):
        s = ord(data[10])
        return 11+s, ord(data[8]), data[11:11+s]

    return None, None, None


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

        self.p_subj = re.compile(r'\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02')

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
                ff = fileformat['ff_pe']

                cert_off = ff['pe'].get('CERTIFICATE_Offset', 0)
                cert_size = ff['pe'].get('CERTIFICATE_Size', 0)
                
                if cert_off != 0 and cert_size != 0:
                    # 인증서 추출
                    cert_data = mm[cert_off:cert_off + cert_size]

                    if self.verbose:
                        print '-' * 79
                        kavutil.vprint('Engine')
                        kavutil.vprint(None, 'Engine', 'adware.kmd')

                    # String 추출
                    if len(cert_data):
                        if self.verbose:
                            print
                            kavutil.vprint('X.509')

                        for p in self.p_subj.finditer(cert_data):
                            off = p.span()[0]

                            if self.verbose:
                                print '-' * 40

                            while True:
                                t = get_subj(cert_data[off:])
                                if not t[0]:
                                    break

                                if self.verbose:
                                    s = strdict.get(t[1], 'None')
                                    msg = '%02X : %s = %s' % (t[1], s, t[2])
                                    print '    [-] %02X : %s = %s' % (t[1], s, t[2])

                                off += t[0]

                                if t[1] == 0x3:  # CN
                                    buf = t[2]
                                    fsize = len(buf)

                                    if self.verbose:
                                        fmd5 = cryptolib.md5(buf)
                                        print '    [-] %d:%s:  # %s' % (fsize, fmd5, buf)

                                    if fsize and kavutil.handle_pattern_md5.match_size('adware', fsize):
                                        fmd5 = cryptolib.md5(buf)
                                        # print fsize, fmd5
                                        vname = kavutil.handle_pattern_md5.scan('adware', fsize, fmd5)
                                        if vname:
                                            pos = ff['pe'].get('EntryPointRaw', 0)
                                            if mm[pos:pos+4] == '\xff\x25\x00\x20':
                                                pf = 'MSIL'
                                            else:
                                                pf = 'Win32'
                                                # print hex(pos), repr(mm[pos:pos+4])
                                            vname = kavutil.normal_vname(vname, pf)
                                            return True, vname, 0, kernel.INFECTED

                                    if self.verbose:
                                        fmd5 = cryptolib.md5(buf)
                                        if not root_ca.get(fmd5, None):  # 알려진 CA는 제외
                                            # 악성코드 탐지가 안될때 패턴 작업을 위해 파일에 기록
                                            fsha256 = cryptolib.sha256(mm)
                                            msg = '%d:%s:  # %s, %s\n' % (fsize, fmd5, buf, fsha256)
                                            open('adware.mdb', 'at').write(msg)

                        if self.verbose:
                            # a = raw_input('>> ')
                            pass

        except IOError:
            pass

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
        info['version'] = '1.0'      # 버전
        info['title'] = 'Adware Scan Engine'  # 엔진 설명
        info['kmd_name'] = 'adware'  # 엔진 파일 이름
        info['sig_num'] = kavutil.handle_pattern_md5.get_sig_num('adware') * 2  # 진단/치료 가능한 악성코드 수

        return info
