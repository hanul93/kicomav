# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
Adware Engine Plugin

This plugin handles adware detection using certificate analysis and YARA rules.
"""

import contextlib
import io
import logging
import os
import zlib

from kicomav.plugins import cryptolib
from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import MalwareDetectorBase

try:
    import yara

    LOAD_YARA = True
except ImportError:
    LOAD_YARA = False

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# ASN1 Class: PE file Authenticode signature format
# -------------------------------------------------------------------------
class ASN1:
    def __init__(self):
        self.data = None
        self.name_count = {}

    def set_data(self, data):
        self.data = data

    def hex_string(self, data):
        d = ["%02X" % int(x) for x in data]
        return " ".join(d)

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
                ttype = t & 0x1F
                if ttype == 0x6 or ttype not in [0x13, 0x14, 0xC, 0x16, 0x17]:
                    ret.append(x1)
                else:
                    ret.append(d1)
            if deep == 0:
                break

            d = d[off + l :]

        return ret

    def is_constructed(self, val):
        return val & 0x20 == 0x20

    def get_asn1_len(self, data):
        val = int(data[1])

        if val & 0x80 == 0:
            return val, 2

        data_len = val & 0x7F

        val = int(data[2 : 2 + data_len].hex(), 16)
        return val, 2 + data_len

    def get_asn1_data(self, data):
        asn1_type = int(data[0])
        asn1_len, off = self.get_asn1_len(data)
        asn1_data = data[off : off + asn1_len]
        return asn1_type, asn1_len, asn1_data, off


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """Adware malware detector plugin.

    This plugin provides functionality for:
    - Detecting adware using certificate analysis
    - Detecting adware using YARA rules on rdata section
    """

    def __init__(self):
        """Initialize the Adware Engine plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Adware Scan Engine",
            kmd_name="adware",
        )
        self.sig_num_yara = 0
        self.adware_gen = None

    def _load_virus_database(self) -> int:
        """Load virus patterns.

        Returns:
            0 for success
        """
        if not LOAD_YARA:
            return 0

        # Load Adware Yara rules
        kicomav_paths = self._get_rule_path("kicomav")
        if not kicomav_paths:
            return 0

        for kicomav_path in kicomav_paths:
            with contextlib.suppress(Exception):
                with open(os.path.join(kicomav_path, "adware.y01"), "rb") as fp:
                    b = fp.read()
                    if b[:4] == b"KAVS":
                        t = zlib.decompress(b[12:])

                        buff = io.BytesIO(t)
                        self.adware_gen = yara.load(file=buff)

                        # If the signature is loaded, get the number of signatures
                        self.sig_num_yara = kavutil.get_uint32(b, 4)
                        break  # Successfully loaded, stop searching

        return 0

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        s_num = 0
        if kavutil.handle_pattern_md5:
            s_num = kavutil.handle_pattern_md5.get_sig_num("adware") * 2
        s_num += self.sig_num_yara
        info["sig_num"] = s_num
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        vlist = kavutil.handle_pattern_md5.get_sig_vlist("adware")
        vlists = []
        if not vlist:
            return vlists
        vlist = sorted(set(vlist))
        for vname in vlist:
            vname = kavutil.normal_vname(vname)
            if vname.find("<p>"):
                vlists.extend((vname.replace("<p>", "Win32"), vname.replace("<p>", "MSIL")))
            else:
                vlists.append(vname)

        vlists.sort()
        return vlists

    def scan(self, filehandle, filename, fileformat, filename_ex):
        """Scan for malware.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            fileformat: Format info from format() method
            filename_ex: Extended filename info

        Returns:
            Tuple of (found, malware_name, malware_id, result)
        """
        try:
            mm = filehandle

            # Is PE format in the pre-analyzed file format?
            if "ff_pe" in fileformat:
                # Check for malware using the certificate
                ret = self.__scan_asn1(filehandle, filename, fileformat, filename_ex)
                if ret[0]:
                    return ret

                # Check for malware using rdata
                if self.adware_gen:
                    ret = self.__scan_rdata(filehandle, filename, fileformat, filename_ex)
                    if ret[0]:
                        return ret

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)

        return False, "", -1, kernel.NOT_FOUND

    def __scan_asn1(self, filehandle, filename, fileformat, filename_ex):
        """Check the Adware distributor using the certificate information."""
        mm = filehandle

        ff = fileformat["ff_pe"]

        cert_off = ff["pe"].get("CERTIFICATE_Offset", 0)
        cert_size = ff["pe"].get("CERTIFICATE_Size", 0)

        if cert_off != 0 and cert_size != 0:
            if self.verbose:
                print("-" * 79)
                kavutil.vprint("Engine")
                kavutil.vprint(None, "Engine", "adware")

            # Extract the certificate
            cert_data = mm[cert_off : cert_off + cert_size]
            asn1 = ASN1()
            asn1.set_data(cert_data[8:])

            with contextlib.suppress(IndexError):
                r = asn1.parse()

                # Is it Signed Data and the version information is 1?
                if r[0][0] == "2A 86 48 86 F7 0D 01 07 02" and r[0][1][0][0] == "01":
                    signeddata = r[0][1][0]
                    certificates = signeddata[3]

                    signerinfo = r[0][1][0][-1]
                    issuer_and_serialnumber = signerinfo[0][1]
                    issuer_serial = issuer_and_serialnumber[1]

                    for cert in certificates:
                        if cert[0][1] == issuer_serial:
                            for x in cert[0][5]:
                                if x[0][0] == "55 04 03":
                                    signer_name = x[0][1]
                                    break
                            else:
                                continue
                            break
                    else:
                        raise IndexError

                    # The length of the serial number is different
                    fmd5 = cryptolib.md5(issuer_serial.encode("utf-8"))
                    fsize = kavutil.get_uint16(bytes.fromhex(fmd5), 0)

                    if self.verbose:
                        kavutil.vprint("Signer")
                        kavutil.vprint(None, "Name", signer_name)
                        kavutil.vprint(None, "Serial Number", issuer_serial)

                        msg = "%d:%s:  # %s, %s\n" % (
                            fsize,
                            fmd5,
                            signer_name,
                            cryptolib.sha256(mm),
                        )

                        with open("adware.mdb", "at") as f:
                            f.write(msg)

                    if fsize and kavutil.handle_pattern_md5.match_size("adware", fsize):
                        if vname := kavutil.handle_pattern_md5.scan("adware", fsize, fmd5):
                            pos = ff["pe"].get("EntryPointRaw", 0)
                            pf = "MSIL" if mm[pos : pos + 4] == b"\xff\x25\x00\x20" else "Win32"
                            vname = kavutil.normal_vname(vname, pf)
                            return True, vname, kernel.DISINFECT_DELETE, kernel.INFECTED

        return False, "", -1, kernel.NOT_FOUND

    def __scan_rdata(self, filehandle, filename, fileformat, filename_ex):
        """Check for strings frequently used by Adware in rdata."""
        mm = filehandle

        ff = fileformat["ff_pe"]

        if ff["pe"]["SectionNumber"] > 2:
            section = ff["pe"]["Sections"][1]  # .rdata
            foff = section["PointerRawData"]
            fsize = section["SizeRawData"]

            ret = self.adware_gen.match(data=mm[foff : foff + fsize])
            if len(ret):
                vname = ret[0].meta.get("KicomAV", ret[0].rule)
                return True, vname, kernel.DISINFECT_DELETE, kernel.INFECTED

        return False, "", -1, kernel.NOT_FOUND

    def disinfect(self, filename, malware_id):
        """Disinfect malware.

        Args:
            filename: Path to infected file
            malware_id: Malware ID to disinfect

        Returns:
            True if successful, False otherwise
        """
        try:
            if malware_id == kernel.DISINFECT_DELETE:
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False
