# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
UPX Unpacker Engine Plugin

This plugin handles UPX-packed PE executables for scanning.
"""

import mmap
import os
import struct
import logging

from kicomav.plugins import kernel
from kicomav.plugins import kavutil
from kicomav.plugins import pe
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# UPX constants and helper data
# -------------------------------------------------------------------------
HEADERS = (
    b"\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00"
    b"\xB0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x1A\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD0\x00\x00\x00"
    b"\x0E\x1F\xB4\x09\xBA\x0D\x00\xCD\x21\xB4\x4C\xCD\x21\x54\x68\x69"
    b"\x73\x20\x66\x69\x6C\x65\x20\x77\x61\x73\x20\x63\x72\x65\x61\x74"
    b"\x65\x64\x20\x62\x79\x20\x4B\x69\x63\x6F\x6D\x41\x56\x2E\x20\x0D"
    b"\x0A\x43\x6F\x70\x79\x72\x69\x67\x68\x74\x20\x28\x63\x29\x20\x31"
    b"\x39\x39\x35\x2D\x32\x30\x31\x37\x20\x4B\x65\x69\x20\x43\x68\x6F"
    b"\x69\x2E\x20\x41\x6C\x6C\x20\x72\x69\x67\x68\x74\x73\x20\x72\x65"
    b"\x73\x65\x72\x76\x65\x64\x2E\x0D\x0A\x4B\x69\x63\x6F\x6D\x41\x56"
    b"\x20\x57\x65\x62\x20\x3A\x20\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77"
    b"\x77\x2E\x6B\x69\x63\x6F\x6D\x61\x76\x2E\x63\x6F\x6D\x0D\x0A\x24"
)

UPX_NRV2B = b"\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc"
UPX_NRV2D = b"\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb"
UPX_NRV2E = b"\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a"
UPX_LZMA1 = b"\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90"
UPX_LZMA2 = b"\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90"


# -------------------------------------------------------------------------
# UPX helper functions
# -------------------------------------------------------------------------
def PESALIGN(o, a):
    return (o // a + (o % a != 0)) * a if a else o


def ROR(x, n, bits=32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))


def ROL(x, n, bits=32):
    return ROR(x, bits - n, bits)


def checkpe(dst, dsize, pehdr):
    try:
        if kavutil.get_uint32(dst, pehdr) != 0x4550:
            raise SystemError

        valign = kavutil.get_uint32(dst, pehdr + 0x38)
        if not valign:
            raise SystemError

        sectcnt = kavutil.get_uint16(dst, pehdr + 6)
        if not sectcnt:
            raise SystemError

        sections_pos = pehdr + 0xF8

        if (sections_pos + (sectcnt * 0x28)) > dsize:
            raise SystemError
    except Exception:
        sections_pos = 0
        valign = 0
        sectcnt = 0

    return sections_pos, valign, sectcnt


def ModifyCallAddr(src: bytes, dest: bytes, ep: int, upx0: int, upx1: int, baseaddr: int) -> bytes:
    try:
        ssize = len(src)
        pos = ep - upx1
        call_count = -1

        while not pos > ssize - 13:
            if (
                src[pos] == 0xE9
                and src[pos + 3] == 0xFF
                and src[pos + 4] == 0xFF
                and src[pos + 5] == 0x5E
                and src[pos + 6] == 0x89
                and src[pos + 7] == 0xF7
                and src[pos + 8] == 0xB9
            ):
                call_count = kavutil.get_uint32(src, pos + 9)
                break
            else:
                pos += 1

        if call_count == -1:
            raise SystemError

        dst = []
        pos = 0
        dcur = 0
        dsize = len(dest)

        while call_count and pos <= dsize - 5:
            if dest[pos] in {0xE9, 0xE8} and dest[pos + 1] == 0x01:
                eax = kavutil.get_uint32(dest, pos + 1)
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
                eax = uint32(eax - (baseaddr + upx0 + pos + 1))
                eax = uint32(eax + (baseaddr + upx0))
                dst += dest[dcur : pos + 1]
                dst += struct.pack("<L", eax)

                pos += 5
                dcur = pos
                call_count -= 1
            else:
                pos += 1

        dst += dest[dcur:]
        dst = bytes(dst)
    except Exception:
        return b""

    return dst


def RebuildPE(
    src: bytes, ssize: int, dst: bytes, dsize: int, ep: int, upx0: int, upx1: int, magic: list[int], dend: int
) -> bytes:
    try:
        valign = 0
        pehdr = 0
        sectcnt = 0
        sections = 0
        realstuffsz = 0
        foffset = uint32(0xD0 + 0xF8)

        if len(src) == 0 or len(dst) == 0:
            raise SystemError

        for valign in magic:
            if (
                (ep - upx1 + valign <= ssize - 5)
                and src[ep - upx1 + valign - 2] == 0x8D
                and src[ep - upx1 + valign - 1] == 0xBE
            ):
                break

        if not valign and (ep - upx1 + 0x80 < ssize - 8):
            i = 0
            while True:
                b1 = src[ep - upx1 + 0x80 + 0 + i]
                b2 = src[ep - upx1 + 0x80 + 1 + i]

                if b1 == 0x8D and b2 == 0xBE:
                    b3 = src[ep - upx1 + 0x80 + 6 + i]
                    b4 = src[ep - upx1 + 0x80 + 7 + i]

                    if b3 == 0x8B and b4 == 0x07:
                        valign = 0x80 + i + 2
                        break
                i += 1

        if valign and ISCONTAINED(0, ssize, ep - upx1 + valign, 4):
            dst_imports = struct.unpack("<l", src[ep - upx1 + valign : ep - upx1 + valign + 4])[0]

            realstuffsz = dst_imports

            if realstuffsz >= dsize:
                raise SystemError

            pehdr = dst_imports

            while (pehdr + 8 < dsize) and (struct.unpack("<l", dst[pehdr : pehdr + 4])[0]):
                pehdr += 8
                while (pehdr + 2 < dsize) and dst[pehdr]:
                    pehdr += 1
                    while (pehdr + 2 < dsize) and dst[pehdr]:
                        pehdr += 1
                    pehdr += 1
                pehdr += 1
            pehdr += 4

            sections, valign, sectcnt = checkpe(dst, dsize, pehdr)
            if not sections:
                pehdr = 0

        if not pehdr and dend > (0xF8 + 0x28):
            pehdr = dend - 0xF8 - 0x28

            while int32(pehdr) > 0:
                sections, valign, sectcnt = checkpe(dst, dsize, pehdr)
                if sections:
                    break
                pehdr -= 1

            realstuffsz = pehdr
            if not realstuffsz:
                raise SystemError

        if not pehdr:
            rebsz = uint32(PESALIGN(dend, 0x1000))
            # To Do

        foffset = PESALIGN(foffset + 0x28 * sectcnt, valign)

        for _ in range(sectcnt):
            t = kavutil.get_uint32(dst, sections + 8)
            vsize = uint32(PESALIGN(t, valign))

            t = kavutil.get_uint32(dst, sections + 12)
            urva = uint32(PESALIGN(t, valign))

            if not (upx0 + realstuffsz >= urva + vsize):
                raise SystemError

            t = struct.pack("<LLLL", vsize, urva, vsize, foffset)
            dest = dst[: sections + 8]
            dest += t
            dest += dst[sections + 24 :]
            dst = dest

            foffset += vsize
            sections += 0x28

        t = struct.pack("<L", valign)
        dest = dst[: pehdr + 0x3C]
        dest += t
        dest += dst[pehdr + 0x3C + 4 :]
        dst = dest

        newbuf = [0] * foffset

        for i in range(len(HEADERS)):
            newbuf[i] = HEADERS[i]

        for i in range(0xF8 + 0x28 * sectcnt):
            newbuf[0xD0 + i] = dst[pehdr + i]

        sections = pehdr + 0xF8

        for _ in range(sectcnt):
            t1 = kavutil.get_uint32(dst, sections + 20)
            t2 = kavutil.get_uint32(dst, sections + 12)
            t3 = kavutil.get_uint32(dst, sections + 16)

            for i in range(t3):
                newbuf[t1 + i] = dst[t2 - upx0 + i]

            sections += 0x28

        if foffset > dsize + 8192:
            raise SystemError

        dsize = foffset

        upx_d = bytes(newbuf)
    except Exception:
        return b""

    return upx_d


def int32(iv):
    if iv & 0x80000000:
        iv = -0x100000000 + iv
    return iv


def uint32(iv):
    return iv & 0xFFFFFFFF


def ISCONTAINED(bb, bb_size, sb, sb_size):
    c1 = bb_size > 0
    c2 = sb_size > 0
    c3 = sb_size <= bb_size
    c4 = sb >= bb
    c5 = (sb + sb_size) <= (bb + bb_size)
    c6 = (sb + sb_size) > bb
    c7 = sb < (bb + bb_size)

    return c1 and c2 and c3 and c4 and c5 and c6 and c7


def doubleebx(src, myebx, scur, ssize):
    oldebx = myebx

    try:
        myebx = (myebx * 2) & 0xFFFFFFFF
        if not (oldebx & 0x7FFFFFFF):
            if not ISCONTAINED(0, ssize, scur, 4):
                return -1, myebx, scur
            oldebx = kavutil.get_uint32(src, scur)
            myebx = uint32(oldebx * 2 + 1)
            scur += 4
        return (oldebx >> 31), myebx, scur
    except Exception:
        return -1, myebx, scur


def upx_inflate2b(src: bytes, dsize: int, ep: int, upx0: int, upx1: int, baseaddr: int) -> tuple[int, bytes]:
    ret = -1
    dest = ""
    myebx = 0
    scur = 0
    dcur = 0
    dst = [0] * dsize
    ssize = len(src)
    unp_offset = -1

    try:
        while True:
            while True:
                oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                if oob != 1:
                    break

                if scur >= ssize or dcur >= dsize:
                    raise SystemError

                dst[dcur] = src[scur]
                dcur += 1
                scur += 1

            if oob == -1:
                raise SystemError

            backbytes = 1

            while True:
                oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                if oob == -1:
                    raise SystemError

                backbytes = backbytes * 2 + oob

                oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                if oob == -1:
                    raise SystemError

                if oob:
                    break

            backbytes -= 3

            if backbytes >= 0:
                if scur >= ssize:
                    raise SystemError
                backbytes <<= 8
                backbytes += src[scur]
                scur += 1
                backbytes ^= 0xFFFFFFFF

                if not backbytes:
                    break
                unp_offset = int32(backbytes)

            backsize, myebx, scur = doubleebx(src, myebx, scur, len(src))
            backsize &= 0xFFFFFFFF
            if backsize == 0xFFFFFFFF:
                raise SystemError

            oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
            if oob == -1:
                raise SystemError

            backsize = backsize * 2 + oob

            if not backsize:
                backsize += 1

                while True:
                    oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                    if oob == -1:
                        raise SystemError

                    backsize = backsize * 2 + oob

                    oob, myebx, scur = doubleebx(src, myebx, scur, len(src))
                    if oob != 0:
                        break

                if oob == -1:
                    raise SystemError

                backsize += 2

            if (unp_offset & 0xFFFFFFFF) < 0xFFFFF300:
                backsize += 1

            backsize += 1

            if (
                not ISCONTAINED(0, dsize, dcur + unp_offset, backsize)
                or not ISCONTAINED(0, dsize, dcur, backsize)
                or unp_offset >= 0
            ):
                raise SystemError

            for i in range(backsize):
                dst[dcur + i] = dst[dcur + unp_offset + i]

            dcur += backsize

        dest = bytes(dst)

        # Adjust call address
        dest = ModifyCallAddr(src, dest, ep, upx0, upx1, baseaddr)

        # Rebuild PE file
        magic = [0x108, 0x110, 0xD5, 0]
        dest = RebuildPE(src, ssize, dest, dsize, ep, upx0, upx1, magic, dcur)

        ret = 0
    except:
        return -1, b""

    return ret, dest


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """UPX unpacker plugin.

    This plugin provides functionality for:
    - Detecting UPX-packed PE executables
    - Unpacking UPX-compressed files
    """

    def __init__(self):
        """Initialize the UPX plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="UPX Unpacker Engine",
            kmd_name="upx",
        )

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["make_arc_type"] = kernel.MASTER_DELETE
        return info

    def arclist(self, filename, fileformat, password=None):
        """List UPX-packed file.

        Args:
            filename: Path to PE file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        fp = None
        mm = None
        file_scan_list = []

        if "ff_pe" not in fileformat:
            return file_scan_list

        pe_info = fileformat["ff_pe"]["pe"]
        ep_foff = pe_info["EntryPointRaw"]

        try:
            fp = open(filename, "rb")
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            if mm[ep_foff + 0x69 : ep_foff + 0x69 + 13] == UPX_NRV2B:
                arc_name = "arc_upx!nrv2b"
            elif mm[ep_foff + 0x71 : ep_foff + 0x71 + 13] == UPX_NRV2B:
                arc_name = "arc_upx!nrv2b"
            elif mm[ep_foff + 0x69 : ep_foff + 0x69 + 13] == UPX_NRV2D:
                arc_name = "arc_upx!nrv2d"
            elif mm[ep_foff + 0x71 : ep_foff + 0x71 + 13] == UPX_NRV2D:
                arc_name = "arc_upx!nrv2d"
            elif mm[ep_foff + 0x69 : ep_foff + 0x69 + 13] == UPX_NRV2E:
                arc_name = "arc_upx!nrv2e"
            elif mm[ep_foff + 0x71 : ep_foff + 0x71 + 13] == UPX_NRV2E:
                arc_name = "arc_upx!nrv2e"
            else:
                raise ValueError

            if self.verbose:
                self._print_upx_debug_info(filename, arc_name)

            file_scan_list.append([arc_name, "UPX"])

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except ValueError:
            pass  # Not UPX packed
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)
        finally:
            if mm:
                mm.close()
            if fp:
                fp.close()

        return file_scan_list

    def _print_upx_debug_info(self, filename, arc_name):
        """Print UPX debug information."""
        print("-" * 79)
        kavutil.vprint("Engine")
        kavutil.vprint(None, "Engine", "upx")
        kavutil.vprint(None, "File name", os.path.split(filename)[-1])

        print()
        kavutil.vprint("UPX : only support 'nrv2b' compress method.")
        kavutil.vprint(None, "Compress Method", arc_name.split("!")[-1])
        print()

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Unpack UPX-compressed file.

        Args:
            arc_engine_id: Engine ID ('arc_upx!...')
            arc_name: Path to PE file
            fname_in_arc: Name of file to extract

        Returns:
            Unpacked file data, or None on error
        """
        fp = None
        mm = None
        data = None

        if "arc_upx" not in arc_engine_id:
            return None

        try:
            fp = open(arc_name, "rb")
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            p = pe.PE(mm, False, arc_name)
            pe_format = p.parse()
            if pe_format is None:
                raise ValueError

            pe_img = pe_format["ImageBase"]
            pe_ep = pe_format["EntryPoint"]
            sections = pe_format["Sections"]
            ep_raw = pe_format["EntryPointRaw"]
            ep_nsec = pe_format["EntryPoint_in_Section"]

            foff = 0
            ssize = 0
            dsize = 0

            for section in sections:
                ssize = section["VirtualSize"]
                rva = section["RVA"]
                if rva <= pe_ep < rva + ssize:
                    foff = section["PointerRawData"]
                    i = sections.index(section)
                    if i != 0:
                        upx0 = sections[i - 1]["RVA"]
                        upx1 = sections[i]["RVA"]
                        dsize = sections[i - 1]["VirtualSize"] + ssize
                    break

            if ssize == 0 or dsize == 0:
                raise ValueError

            upx_data_rva = kavutil.get_uint32(mm, ep_raw + 2)
            sec_rva = sections[ep_nsec]["RVA"]

            skew = upx_data_rva - sec_rva - pe_img

            if mm[ep_raw + 1] != b"\xBE" or skew <= 0 or skew > 0xFFF:
                skew = 0
            elif skew > ssize:
                skew = 0
            else:
                raise ValueError

            data = mm[foff + skew : foff + ssize - skew]

            unpack_data = ""

            if arc_engine_id[8:] == "nrv2b":
                try:
                    ret_val, unpack_data = upx_inflate2b(data, dsize, pe_ep, upx0, upx1, pe_img)
                except OverflowError as e:
                    raise ValueError from e

            if self.verbose:
                kavutil.vprint("Decompress")
                kavutil.vprint(None, "Compressed Size", "%d" % len(data))
                if unpack_data == "":
                    kavutil.vprint(None, "Decompress Size", "Error")
                else:
                    kavutil.vprint(None, "Decompress Size", "%d" % len(unpack_data))
                print()

            if unpack_data == "":
                raise ValueError

            data = unpack_data

        except (IOError, OSError) as e:
            logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
            data = None
        except ValueError:
            data = None
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)
            data = None
        finally:
            if mm:
                mm.close()
            if fp:
                fp.close()

        return data
