# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
HWPX File Format Engine Plugin

This plugin handles HWPX (Hangul Word Processor XML) format for malware detection.
"""

import contextlib
import json
import logging
import os
import zipfile

from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.plugin_base import ArchivePluginBase

# Module logger
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# XML parser
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
    def __init__(
        self,
        item_depth=0,
        item_callback=lambda *args: True,
        xml_attribs=True,
        attr_prefix="@",
        cdata_key="#text",
        force_cdata=False,
        cdata_separator="",
        postprocessor=None,
        dict_constructor=OrderedDict,
        strip_whitespace=True,
        namespace_separator=":",
        namespaces=None,
        force_list=None,
    ):
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
        self.namespace_declarations = OrderedDict()  # dict is always OrderedDict
        self.force_list = force_list

    def _build_name(self, full_name):
        if not self.namespaces:
            return full_name

        i = full_name.rfind(self.namespace_separator)

        if i == -1:
            return full_name

        namespace, name = full_name[:i], full_name[i + 1 :]
        if short_namespace := self.namespaces.get(namespace, namespace):
            return self.namespace_separator.join((short_namespace, name))
        else:
            return name

    # Add attribute values to dict
    def _attrs_to_dict(self, attrs):
        if isinstance(attrs, dict):
            return attrs

        return self.dict_constructor(zip(attrs[::2], attrs[1::2]))

    # Determine whether to process the namespace for the start name
    def startNamespaceDecl(self, prefix, uri):
        self.namespace_declarations[prefix or ""] = uri

    # Process the start element
    def startElement(self, full_name, attrs):
        name = self._build_name(full_name)
        attrs = self._attrs_to_dict(attrs)

        if attrs and self.namespace_declarations:
            attrs["xmlns"] = self.namespace_declarations
            self.namespace_declarations = OrderedDict()

        self.path.append((name, attrs or None))

        if len(self.path) > self.item_depth:  # If the depth is deeper...
            self.stack.append((self.item, self.data))
            if self.xml_attribs:
                attr_entries = []
                for key, value in attrs.items():
                    key = self.attr_prefix + self._build_name(key)
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

    # Process the end element
    def endElement(self, full_name):
        name = self._build_name(full_name)

        if len(self.path) == self.item_depth:
            item = self.item
            if item is None:
                item = self.cdata_separator.join(self.data) if self.data else None

            should_continue = self.item_callback(self.path, item)

            if not should_continue:
                raise ParsingInterrupted()

        if len(self.stack):
            self.process_element_end_data(name)
        else:
            self.item = None
            self.data = []
        self.path.pop()

    def process_element_end_data(self, name):
        data = self.cdata_separator.join(self.data) if self.data else None
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
            item[key] = [data] if self._should_force_list(key, data) else data
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


# Parse XML
def xml_parse(
    xml_input,
    encoding=None,
    expat=expat,
    process_namespaces=False,
    namespace_separator=":",
    disable_entities=True,
    **kwargs,
):

    handler = _DictSAXHandler(namespace_separator=namespace_separator, **kwargs)

    if isinstance(xml_input, _unicode):
        if not encoding:
            encoding = "utf-8"

        xml_input = xml_input.encode(encoding)

    if not process_namespaces:
        namespace_separator = None

    parser = expat.ParserCreate(encoding, namespace_separator)

    with contextlib.suppress(AttributeError):
        parser.ordered_attributes = True

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

    if hasattr(xml_input, "read"):
        parser.ParseFile(xml_input)
    else:
        parser.Parse(xml_input, True)

    return handler.item


def _process_namespace(name, namespaces, ns_sep=":", attr_prefix="@"):
    if not namespaces:
        return name

    try:
        ns, name = name.rsplit(ns_sep, 1)
    except ValueError:
        pass
    else:
        ns_res = namespaces.get(ns.strip(attr_prefix))
        name = f'{attr_prefix if ns.startswith(attr_prefix) else ""}{ns_res}{ns_sep}{name}' if ns_res else name

    return name


def _emit(
    key,
    value,
    content_handler,
    attr_prefix="@",
    cdata_key="#text",
    depth=0,
    preprocessor=None,
    pretty=False,
    newl="\n",
    indent="\t",
    namespace_separator=":",
    namespaces=None,
    full_document=True,
):
    key = _process_namespace(key, namespaces, namespace_separator, attr_prefix)

    if preprocessor is not None:
        result = preprocessor(key, value)
        if result is None:
            return

        key, value = result

    if not hasattr(value, "__iter__") or isinstance(value, (_basestring, dict)):
        value = [value]

    for index, v in enumerate(value):
        if full_document and depth == 0 and index > 0:
            raise ValueError("document with multiple roots")

        if v is None:
            v = OrderedDict()
        elif isinstance(v, bool):
            v = _unicode("true") if v else _unicode("false")
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
                ik = _process_namespace(ik, namespaces, namespace_separator, attr_prefix)
                if ik == "@xmlns" and isinstance(iv, dict):
                    for k, v in iv.items():
                        attr = f'xmlns{f":{k}" if k else ""}'
                        attrs[attr] = _unicode(v)
                    continue
                if not isinstance(iv, _unicode):
                    iv = _unicode(iv)
                attrs[ik[len(attr_prefix) :]] = iv
                continue

            children.append((ik, iv))

        if pretty:
            content_handler.ignorableWhitespace(depth * indent)

        content_handler.startElement(key, AttributesImpl(attrs))

        if pretty and children:
            content_handler.ignorableWhitespace(newl)

        for child_key, child_value in children:
            _emit(
                child_key,
                child_value,
                content_handler,
                attr_prefix,
                cdata_key,
                depth + 1,
                preprocessor,
                pretty,
                newl,
                indent,
                namespaces=namespaces,
                namespace_separator=namespace_separator,
            )

        if cdata is not None:
            content_handler.characters(cdata)

        if pretty and children:
            content_handler.ignorableWhitespace(depth * indent)

        content_handler.endElement(key)

        if pretty and depth:
            content_handler.ignorableWhitespace(newl)


def unparse(input_dict, output=None, encoding="utf-8", full_document=True, short_empty_elements=False, **kwargs):
    if full_document and len(input_dict) != 1:  # If the root is missing, an error occurs
        raise ValueError("Document must have exactly one root.")

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
        _emit(key, value, content_handler, full_document=full_document, **kwargs)

    if full_document:
        content_handler.endDocument()

    if must_return:
        value = output.getvalue()
        with contextlib.suppress(AttributeError):
            value = value.decode(encoding)

        return value


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """HWPX malware detector and archive handler plugin.

    This plugin provides functionality for:
    - Detecting HWPX exploits
    - Extracting files from HWPX archives
    - Scanning XML content for malware
    """

    def __init__(self):
        """Initialize the HWPX plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Hwpx Engine",
            kmd_name="hwpx",
        )

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = len(self.listvirus())
        return info

    def listvirus(self):
        """Get list of detectable viruses.

        Returns:
            List of virus names
        """
        return ["Exploit.HWPX.Generic"]

    def __get_handle(self, filename):
        """Get or create handle for HWPX file.

        Args:
            filename: Path to HWPX file

        Returns:
            ZipFile object or None
        """
        if filename in self.handle:
            return self.handle.get(filename, None)

        try:
            zfile = zipfile.ZipFile(filename)
            self.handle[filename] = zfile
            return zfile

        except (IOError, OSError, zipfile.BadZipFile) as e:
            logger.debug("Failed to open HWPX file %s: %s", filename, e)

        return None

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
        zfile = None
        result = (False, "", -1, kernel.NOT_FOUND)

        try:
            if "ff_hwpx" not in fileformat:
                return result

            if self.verbose:
                print("-" * 79)
                kavutil.vprint("Engine")
                kavutil.vprint(None, "Engine", "hwpx")
                kavutil.vprint(None, "File name", os.path.split(filename)[-1])
                print()

            zfile = zipfile.ZipFile(filename)

            for name in zfile.namelist():
                if name.lower().find("mimetype") != -1:
                    data = zfile.read(name)

                    if self.verbose:
                        kavutil.vprint("mimetype")
                        kavutil.vprint(None, "body", f"{data}")
                        print()

                    if data != b"application/hwp+zip":
                        result = (True, "Exploit.HWPX.Generic", 0, kernel.INFECTED)
                        return result

                elif name.lower().find("preview/prvtext.txt") != -1:
                    pass  # PrevText.txt is not scanned

                elif name.lower().find("bindata") == -1:
                    try:
                        data = zfile.read(name)
                        if data[:5] == b"<?xml":
                            dict_data = xml_parse(data)

                            if self.verbose:
                                kavutil.vprint(name)
                                print(json.dumps(dict_data, indent=2))
                                print()
                    except Exception:
                        result = (True, "Exploit.HWPX.Generic", 0, kernel.INFECTED)
                        return result

        except (IOError, OSError) as e:
            logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error scanning %s: %s", filename, e)
        finally:
            if zfile:
                zfile.close()

        return result

    def disinfect(self, filename, malware_id):
        """Disinfect malware.

        Args:
            filename: Path to infected file
            malware_id: Malware ID to disinfect

        Returns:
            True if successful, False otherwise
        """
        try:
            if malware_id == 0:
                # CWE-73: Safe file deletion
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive.

        Args:
            filename: Path to HWPX file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_hwpx" not in fileformat:
            return file_scan_list

        try:
            zfile = self.__get_handle(filename)
            if zfile is None:
                return file_scan_list

            # Only decompress the bindata folder data
            file_scan_list.extend(["arc_hwpx", name] for name in zfile.namelist() if name.lower().find("bindata") != -1)

        except (IOError, OSError) as e:
            logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_hwpx')
            arc_name: Path to HWPX file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        if arc_engine_id != "arc_hwpx":
            return None

        try:
            zfile = self.__get_handle(arc_name)
            if zfile is None:
                return None

            return zfile.read(fname_in_arc)

        except (IOError, OSError, zipfile.BadZipFile) as e:
            logger.debug("Archive extract error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None

    def arcclose(self):
        """Close all open archive handles."""
        for fname in list(self.handle.keys()):
            try:
                zfile = self.handle.get(fname)
                if zfile:
                    zfile.close()
            except (IOError, OSError) as e:
                logger.debug("Archive close IO error for %s: %s", fname, e)
            except Exception as e:
                logger.debug("Archive close error for %s: %s", fname, e)
            finally:
                self.handle.pop(fname, None)
