# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)


import os
import zipfile
import json

import kernel
import kavutil


# -------------------------------------------------------------------------
# XML 파서
# -------------------------------------------------------------------------
try:
    from defusedexpat import pyexpat as expat
except ImportError:
    from xml.parsers import expat
from xml.sax.saxutils import XMLGenerator
from xml.sax.xmlreader import AttributesImpl
try:  # pragma no cover
    from cStringIO import StringIO
except ImportError:  # pragma no cover
    try:
        from StringIO import StringIO
    except ImportError:
        from io import StringIO

from collections import OrderedDict

try:
    _basestring = basestring
except NameError:
    _basestring = str
try:
    _unicode = unicode
except NameError:
    _unicode = str


class ParsingInterrupted(Exception):
    pass


class _DictSAXHandler(object):
    def __init__(self,
                 item_depth=0,
                 item_callback=lambda *args: True,
                 xml_attribs=True,
                 attr_prefix='@',
                 cdata_key='#text',
                 force_cdata=False,
                 cdata_separator='',
                 postprocessor=None,
                 dict_constructor=OrderedDict,
                 strip_whitespace=True,
                 namespace_separator=':',
                 namespaces=None,
                 force_list=None):
        self.path = []
        self.stack = []
        self.data = []
        self.item = None
        self.item_depth = item_depth
        self.xml_attribs = xml_attribs
        self.item_callback = item_callback
        self.attr_prefix = attr_prefix
        self.cdata_key = cdata_key
        self.force_cdata = force_cdata
        self.cdata_separator = cdata_separator
        self.postprocessor = postprocessor
        self.dict_constructor = dict_constructor
        self.strip_whitespace = strip_whitespace
        self.namespace_separator = namespace_separator
        self.namespaces = namespaces
        self.namespace_declarations = OrderedDict()  # 무조건 dict는 OrderedDict로 하기
        self.force_list = force_list

    def _build_name(self, full_name):
        if not self.namespaces:
            return full_name

        i = full_name.rfind(self.namespace_separator)

        if i == -1:
            return full_name

        namespace, name = full_name[:i], full_name[i+1:]
        short_namespace = self.namespaces.get(namespace, namespace)

        if not short_namespace:  # 네임스페이스 처리해야 하나?
            return name
        else:
            return self.namespace_separator.join((short_namespace, name))

    # 속성 값을 dict에 추가한다.
    def _attrs_to_dict(self, attrs):
        if isinstance(attrs, dict):
            return attrs

        return self.dict_constructor(zip(attrs[0::2], attrs[1::2]))

    # 시작 이름을 네임스페이스 처리 여부를 결정한다.
    def startNamespaceDecl(self, prefix, uri):
        self.namespace_declarations[prefix or ''] = uri

    # 시작 요소를 처리한다.
    def startElement(self, full_name, attrs):
        name = self._build_name(full_name)
        attrs = self._attrs_to_dict(attrs)

        if attrs and self.namespace_declarations:
            attrs['xmlns'] = self.namespace_declarations
            self.namespace_declarations = OrderedDict()

        self.path.append((name, attrs or None))

        if len(self.path) > self.item_depth:  # 깊이가 깊어지면...
            self.stack.append((self.item, self.data))
            if self.xml_attribs:
                attr_entries = []
                for key, value in attrs.items():
                    key = self.attr_prefix+self._build_name(key)
                    if self.postprocessor:
                        entry = self.postprocessor(self.path, key, value)
                    else:
                        entry = (key, value)
                    if entry:
                        attr_entries.append(entry)
                attrs = self.dict_constructor(attr_entries)
            else:
                attrs = None

            self.item = attrs or None
            self.data = []

    # 종료 요소를 처리한다.
    def endElement(self, full_name):
        name = self._build_name(full_name)

        if len(self.path) == self.item_depth:
            item = self.item
            if item is None:
                item = (None if not self.data
                        else self.cdata_separator.join(self.data))

            should_continue = self.item_callback(self.path, item)

            if not should_continue:
                raise ParsingInterrupted()

        if len(self.stack):
            data = (None if not self.data
                    else self.cdata_separator.join(self.data))
            item = self.item
            self.item, self.data = self.stack.pop()

            if self.strip_whitespace and data:
                data = data.strip() or None

            if data and self.force_cdata and item is None:
                item = self.dict_constructor()

            if item is not None:
                if data:
                    self.push_data(item, self.cdata_key, data)
                self.item = self.push_data(self.item, name, item)
            else:
                self.item = self.push_data(self.item, name, data)
        else:
            self.item = None
            self.data = []
        self.path.pop()

    def characters(self, data):
        if not self.data:
            self.data = [data]
        else:
            self.data.append(data)

    def push_data(self, item, key, data):
        if self.postprocessor is not None:
            result = self.postprocessor(self.path, key, data)
            if result is None:
                return item
            key, data = result

        if item is None:
            item = self.dict_constructor()

        try:
            value = item[key]
            if isinstance(value, list):
                value.append(data)
            else:
                item[key] = [value, data]
        except KeyError:
            if self._should_force_list(key, data):
                item[key] = [data]
            else:
                item[key] = data
        return item

    def _should_force_list(self, key, value):
        if not self.force_list:
            return False

        if isinstance(self.force_list, bool):
            return self.force_list

        try:
            return key in self.force_list
        except TypeError:
            return self.force_list(self.path[:-1], key, value)

# xml을 파싱한다.
def xml_parse(xml_input, encoding=None, expat=expat, process_namespaces=False,
          namespace_separator=':', disable_entities=True, **kwargs):

    handler = _DictSAXHandler(namespace_separator=namespace_separator, **kwargs)

    if isinstance(xml_input, _unicode):
        if not encoding:
            encoding = 'utf-8'

        xml_input = xml_input.encode(encoding)

    if not process_namespaces:
        namespace_separator = None

    parser = expat.ParserCreate(encoding, namespace_separator)

    try:
        parser.ordered_attributes = True
    except AttributeError:
        pass

    parser.StartNamespaceDeclHandler = handler.startNamespaceDecl
    parser.StartElementHandler = handler.startElement
    parser.EndElementHandler = handler.endElement
    parser.CharacterDataHandler = handler.characters
    parser.buffer_text = True

    if disable_entities:
        try:
            feature = "http://apache.org/xml/features/disallow-doctype-decl"
            parser._reader.setFeature(feature, True)
        except AttributeError:
            parser.DefaultHandler = lambda x: None
            parser.ExternalEntityRefHandler = lambda *x: 1

    if hasattr(xml_input, 'read'):
        parser.ParseFile(xml_input)
    else:
        parser.Parse(xml_input, True)

    return handler.item


def _process_namespace(name, namespaces, ns_sep=':', attr_prefix='@'):
    if not namespaces:
        return name

    try:
        ns, name = name.rsplit(ns_sep, 1)
    except ValueError:
        pass
    else:
        ns_res = namespaces.get(ns.strip(attr_prefix))
        name = '{}{}{}{}'.format(
            attr_prefix if ns.startswith(attr_prefix) else '',
            ns_res, ns_sep, name) if ns_res else name

    return name


def _emit(key, value, content_handler,
          attr_prefix='@',
          cdata_key='#text',
          depth=0,
          preprocessor=None,
          pretty=False,
          newl='\n',
          indent='\t',
          namespace_separator=':',
          namespaces=None,
          full_document=True):
    key = _process_namespace(key, namespaces, namespace_separator, attr_prefix)

    if preprocessor is not None:
        result = preprocessor(key, value)
        if result is None:
            return

        key, value = result

    if (not hasattr(value, '__iter__')
            or isinstance(value, _basestring)
            or isinstance(value, dict)):
        value = [value]

    for index, v in enumerate(value):
        if full_document and depth == 0 and index > 0:
            raise ValueError('document with multiple roots')

        if v is None:
            v = OrderedDict()
        elif isinstance(v, bool):
            if v:
                v = _unicode('true')
            else:
                v = _unicode('false')
        elif not isinstance(v, dict):
            v = _unicode(v)

        if isinstance(v, _basestring):
            v = OrderedDict(((cdata_key, v),))

        cdata = None
        attrs = OrderedDict()
        children = []

        for ik, iv in v.items():
            if ik == cdata_key:
                cdata = iv
                continue

            if ik.startswith(attr_prefix):
                ik = _process_namespace(ik, namespaces, namespace_separator,
                                        attr_prefix)
                if ik == '@xmlns' and isinstance(iv, dict):
                    for k, v in iv.items():
                        attr = 'xmlns{}'.format(':{}'.format(k) if k else '')
                        attrs[attr] = _unicode(v)
                    continue
                if not isinstance(iv, _unicode):
                    iv = _unicode(iv)
                attrs[ik[len(attr_prefix):]] = iv
                continue

            children.append((ik, iv))

        if pretty:
            content_handler.ignorableWhitespace(depth * indent)

        content_handler.startElement(key, AttributesImpl(attrs))

        if pretty and children:
            content_handler.ignorableWhitespace(newl)

        for child_key, child_value in children:
            _emit(child_key, child_value, content_handler,
                  attr_prefix, cdata_key, depth+1, preprocessor,
                  pretty, newl, indent, namespaces=namespaces,
                  namespace_separator=namespace_separator)

        if cdata is not None:
            content_handler.characters(cdata)

        if pretty and children:
            content_handler.ignorableWhitespace(depth * indent)

        content_handler.endElement(key)

        if pretty and depth:
            content_handler.ignorableWhitespace(newl)


def unparse(input_dict, output=None, encoding='utf-8', full_document=True,
            short_empty_elements=False,
            **kwargs):
    if full_document and len(input_dict) != 1:  # 루트가 없으면 에러
        raise ValueError('Document must have exactly one root.')

    must_return = False

    if output is None:
        output = StringIO()
        must_return = True

    if short_empty_elements:
        content_handler = XMLGenerator(output, encoding, True)
    else:
        content_handler = XMLGenerator(output, encoding)

    if full_document:
        content_handler.startDocument()

    for key, value in input_dict.items():
        _emit(key, value, content_handler, full_document=full_document,
              **kwargs)

    if full_document:
        content_handler.endDocument()

    if must_return:
        value = output.getvalue()
        try:  # pragma no cover
            value = value.decode(encoding)
        except AttributeError:  # pragma no cover
            pass
        return value


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
        self.handle = {}  # 압축 파일 핸들
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
    # scan(self, filehandle, filename, fileformat)
    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    #         fileformat  - 파일 포맷
    #         filename_ex - 파일 이름 (압축 내부 파일 이름)
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    # ---------------------------------------------------------------------
    def scan(self, filehandle, filename, fileformat, filename_ex):  # 악성코드 검사
        zfile = None
        mm = filehandle

        try:
            if 'ff_hwpx' in fileformat:
                if self.verbose:
                    print ('-' * 79)
                    kavutil.vprint('Engine')
                    kavutil.vprint(None, 'Engine', 'hwpx.kmd')
                    kavutil.vprint(None, 'File name', os.path.split(filename)[-1])
                    print ()

                zfile = zipfile.ZipFile(filename)  # zip 파일 열기

                for name in zfile.namelist():
                    if name.lower().find('mimetype') != -1:
                        data = zfile.read(name)

                        if self.verbose:
                            kavutil.vprint('mimetype')
                            kavutil.vprint(None, 'body', '%s' % data)
                            print ()

                        if data != 'application/hwp+zip':
                            if zfile:
                                zfile.close()

                            return True, 'Exploit.HWPX.Generic', 0, kernel.INFECTED

                    elif name.lower().find('preview/prvtext.txt') != -1:
                        pass  # PrevText.txt는 검사하지 않음

                    elif name.lower().find('bindata') == -1:  # Bindata 이외의 파일들은 주로 XML
                        try:
                            data = zfile.read(name)
                            dict_data = xml_parse(data)

                            if self.verbose:
                                kavutil.vprint(name)
                                print (json.dumps(dict_data, indent=2))
                                print ()
                        except:
                            if zfile:
                                zfile.close()

                            return True, 'Exploit.HWPX.Generic', 0, kernel.INFECTED

        except IOError:
            pass

        if zfile:
            zfile.close()

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
        vlist = list()  # 리스트형 변수 선언

        vlist.append('Exploit.HWPX.Generic')

        return vlist

    # ---------------------------------------------------------------------
    # getinfo(self)
    # 플러그인 엔진의 주요 정보를 알려준다. (제작자, 버전, ...)
    # 리턴값 : 플러그인 엔진 정보
    # ---------------------------------------------------------------------
    def getinfo(self):  # 플러그인 엔진의 주요 정보
        info = dict()  # 사전형 변수 선언

        info['author'] = 'Kei Choi'  # 제작자
        info['version'] = '1.0'  # 버전
        info['title'] = 'Hwpx Engine'  # 엔진 설명
        info['kmd_name'] = 'hwpx'  # 엔진 파일 이름
        # info['engine_type'] = kernel.ARCHIVE_ENGINE  # 엔진 타입
        # info['make_arc_type'] = kernel.MASTER_PACK  # 악성코드 치료 후 재압축 유무
        info['sig_num'] = len(self.listvirus())  # 진단/치료 가능한 악성코드 수

        return info

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
            zfile = zipfile.ZipFile(filename)  # zip 파일 열기
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

        # 미리 분석된 파일 포맷중에 HWPX 포맷이 있는가?
        if 'ff_hwpx' in fileformat:
            zfile = self.__get_handle(filename)

            # bindata 폴더 데이터만 압축 해제해서 다음 엔진으로 전달
            for name in zfile.namelist():
                if name.lower().find('bindata') != -1:
                    file_scan_list.append(['arc_hwpx', name])

        return file_scan_list

    # ---------------------------------------------------------------------
    # unarc(self, arc_engine_id, arc_name, fname_in_arc)
    # 입력값 : arc_engine_id - 압축 엔진 ID
    #          arc_name      - 압축 파일
    #          fname_in_arc   - 압축 해제할 파일 이름
    # 리턴값 : 압축 해제된 내용 or None
    # ---------------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id == 'arc_hwpx':
            zfile = self.__get_handle(arc_name)
            try:
                data = zfile.read(fname_in_arc)
                return data
            except zipfile.BadZipfile:
                pass

        return None

    # ---------------------------------------------------------------------
    # arcclose(self)
    # 압축 파일 핸들을 닫는다.
    # ---------------------------------------------------------------------
    def arcclose(self):
        for fname in self.handle.keys():
            zfile = self.handle[fname]
            zfile.close()
            self.handle.pop(fname)
