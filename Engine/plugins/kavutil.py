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

__revision__ = '$LastChangedRevision: 3 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'


import struct
import string
import hashlib
import zlib
import marshal

class VDB :
    def __init__(self) :
        self.SigNum = 0
        self.Date   = 0
        self.Time   = 0

    def GetSigNum(self) :
        return self.SigNum

    def GetDate(self) :
        return self.Date

    def GetTime(self) :
        return self.Time

    def Load(self, fname) :
        data = None

        try :
            fp = open(fname, 'rb')
            buf = fp.read()
            fp.close()

            # 파일에 기록된 Sha256 해시값 추출
            f_sha256 = buf[len(buf)-0x40:]
            
            # 실제 해시 값 계산
            sha256 = hashlib.sha256()

            sha256hash = buf[:len(buf)-0x40]

            for i in range(3): 
                sha256.update(sha256hash)
                sha256hash = sha256.hexdigest()   
                
            if sha256hash != f_sha256 : # 해시가 다름
                raise SystemError
            
            # 주요 값 추출
            self.Date   = struct.unpack('<H', buf[4:6])[0]
            self.Time   = struct.unpack('<H', buf[6:8])[0]
            self.SigNum = struct.unpack('<L', buf[8:12])[0]

            # 압축 해제
            cimg = zlib.decompress(buf[12:len(buf)-0x40])
            data = marshal.loads(cimg)
        except :
            pass

        return data

class Structure(object):
    """Prepare structure object to extract members from data.
    
    Format is a list containing definitions for the elements
    of the structure.
    """
    
    STRUCT_SIZEOF_TYPES = {
    'x': 1, 'c': 1, 'b': 1, 'B': 1, 
    'h': 2, 'H': 2, 
    'i': 4, 'I': 4, 'l': 4, 'L': 4, 'f': 4,
    'q': 8, 'Q': 8, 'd': 8,
    's': 1 }    
    
    def __init__(self, format, data, file_offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = '<'
        self.__keys__ = []
        self.__warnings = []
        #self.values = {}
        self.__data__ = data 
        self.__format_length__ = 0
        self.__field_offsets__ = dict()
        self.__set_format__(format[1])
        self.__all_zeroes__ = False
        self.__unpacked_data_elms__ = None
        self.__file_offset__ = file_offset
        self.name = format[0]
    
    def analysis(self) :
        return self.__analysis__()
    
    '''
    def __new__(cls, *args, **kwds):
        it = cls.__dict__.get("__it__")
        if it is not None:
            return None # it 
        cls.__it__ = it = object.__new__(cls)
    
        if it.init(*args, **kwds) == 0 : # Error
            return None
        return it
    
    def init(self, format, data, file_offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = '<'
        self.__keys__ = []
        #self.values = {}
        self.__data__ = data 
        self.__format_length__ = 0
        self.__field_offsets__ = dict()
        self.__set_format__(format[1])
        self.__all_zeroes__ = False
        self.__unpacked_data_elms__ = None
        self.__file_offset__ = file_offset
        self.name = format[0]
        self.__run__ = self.__analysis__()
        return self.__run__
    '''
     
    def __get_format__(self):
        return self.__format__
        
    def get_field_absolute_offset(self, field_name):
        """Return the offset within the field for the requested field in the structure."""
        return self.__file_offset__ + self.__field_offsets__[field_name]

    def get_field_relative_offset(self, field_name):
        """Return the offset within the structure for the requested field."""
        return self.__field_offsets__[field_name]
    
    def get_file_offset(self):
        return self.__file_offset__
    
    def set_file_offset(self, offset):
        self.__file_offset__ = offset
    
    def all_zeroes(self):
        """Returns true is the unpacked data is all zeroes."""
        
        return self.__all_zeroes__
                
    def sizeof_type(self, t):
        count = 1
        _t = t
        if t[0] in string.digits:
            # extract the count
            count = int( ''.join([d for d in t if d in string.digits]) )
            _t = ''.join([d for d in t if d not in string.digits])
        return self.STRUCT_SIZEOF_TYPES[_t] * count
    
    def __set_format__(self, format):
        
        offset = 0
        for elm in format:
            if ',' in elm:
                elm_type, elm_name = elm.split(',', 1)
                self.__format__ += elm_type
                
                elm_names = elm_name.split(',')
                names = []
                for elm_name in elm_names:
                    if elm_name in self.__keys__:
                        search_list = [x[:len(elm_name)] for x in self.__keys__]
                        occ_count = search_list.count(elm_name)
                        elm_name = elm_name+'_'+str(occ_count)
                    names.append(elm_name)
                    self.__field_offsets__[elm_name] = offset

                offset += self.sizeof_type(elm_type)

                # Some PE header structures have unions on them, so a certain
                # value might have different names, so each key has a list of
                # all the possible members referring to the data.
                self.__keys__.append(names)
        
        self.__format_length__ = struct.calcsize(self.__format__)
        
    
    def sizeof(self):
        """Return size of the structure."""
        
        return self.__format_length__
        
    
    def __unpack__(self, data):
        
        if len(data) > self.__format_length__:
            data = data[:self.__format_length__]
        
        # OC Patch:
        # Some malware have incorrect header lengths.
        # Fail gracefully if this occurs
        # Buggy malware: a29b0118af8b7408444df81701ad5a7f
        #
        elif len(data) < self.__format_length__:
            raise PEFormatError('Data length less than expected header length.')
            
        
        if data.count(chr(0)) == len(data):
            self.__all_zeroes__ = True
        
        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for i in xrange(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
                #self.values[key] = self.__unpacked_data_elms__[i]
                setattr(self, key, self.__unpacked_data_elms__[i])
    
    
    def __pack__(self):
        
        new_values = []
        
        for i in xrange(len(self.__unpacked_data_elms__)):
            
            for key in self.__keys__[i]:
                new_val = getattr(self, key)
                old_val = self.__unpacked_data_elms__[i]
                
                # In the case of Unions, when the first changed value
                # is picked the loop is exited
                if new_val != old_val:
                    break
            
            new_values.append(new_val)
        
        return struct.pack(self.__format__, *new_values)
                
    
    def __str__(self):
        return '\n'.join( self.dump() )

    
    def __repr__(self):
        return '<Structure: %s>' % (' '.join( [' '.join(s.split()) for s in self.dump()] ))
        
    
    def dump(self, indentation=0):
        """Returns a string representation of the structure."""
        
        #dump = []
        #dump.append('[%s]' % self.name)
    
        dump = ''
        dump += ('[%s]\n' % self.name)    

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:
                
                val = getattr(self, key)
                if isinstance(val, int) or isinstance(val, long):
                    val_str = '0x%-8X' % (val)
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val_str += ' [%s UTC]' % time.asctime(time.gmtime(val))
                        except exceptions.ValueError, e:
                            val_str += ' [INVALID TIME]'
                else:
                    val_str = ''.join(filter(lambda c:c != '\0', str(val)))
                
                '''
                dump.append('0x%-8X 0x%-3X %-30s %s\n' % (
                    self.__field_offsets__[key] + self.__file_offset__, 
                    self.__field_offsets__[key], key+':', val_str))
                '''
        
                dump += ('0x%-8X 0x%-3X %-30s %s\n' % (
                    self.__field_offsets__[key] + self.__file_offset__, 
                    self.__field_offsets__[key], key+':', val_str))        

        return dump

        
    def __analysis__(self):
        try :
            self.__unpack__(self.__data__)
        except :
            self.__warnings.append(
                    'Corrupt header "%s" at file offset %d. Exception' % (
                            self.name, self.__file_offset__ ))
            #print self.__warnings
            return 0 # Error
        
        return 1 # Success



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
    # uninit(self)
    # 백신 엔진 모듈의 종료화 작업을 수행한다.
    #-----------------------------------------------------------------
    def uninit(self) : # 백신 모듈 종료화
        return 0

    #-----------------------------------------------------------------
    # getinfo(self)
    # 백신 엔진 모듈의 주요 정보를 알려준다. (버전, 제작자...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # 사전형 변수 선언
        info['author'] = __author__    # 제작자
        info['version'] = __version__  # 버전
        info['title'] = 'KicomAV Util' # 엔진 설명
        info['kmd_name'] = 'kavutil'   # 엔진 파일명
        return info
