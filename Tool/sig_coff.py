import struct
import hashlib
import sys
import mmap

def k2crc32(data, offset, size) :
    try :
        data = data[offset:offset + size]
        md5 = hashlib.md5()
        md5.update(data)
        fmd5 = md5.digest()

        crc1 = struct.unpack('<L', fmd5[ 0: 4])[0]
        crc2 = struct.unpack('<L', fmd5[ 4: 8])[0]
        crc3 = struct.unpack('<L', fmd5[ 8:12])[0]
        crc4 = struct.unpack('<L', fmd5[12:16])[0]
    except :
        return 0

    return (crc1 ^ crc2 ^ crc3 ^ crc4)


if __name__ == '__main__' :
    try :
        fname  = sys.argv[1]
        offset = int(sys.argv[2], 16)
        size   = int(sys.argv[3], 16)

        fp = open(fname, 'rb')
        mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

        print hex(k2crc32(mm, offset, size))
        
        mm.close()
        fp.close()
    except :
        pass