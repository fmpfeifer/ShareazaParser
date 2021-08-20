#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2014, Fabio Melo Pfeifer
#
# This file is part of ShareazaParser. ShareazaParser is free software:
# you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import base64
import csv
import datetime
import getopt
import os.path
import struct
import sys
import traceback
import uuid

__author__ = "Fábio Melo Pfefer"
__copyright__ = "Copyright 2014, Fabio Melo Pfeifer"
__credits__ = ["Fábio Melo Pfeifer"]
__license__ = "GPL"
__version__ = "0.5"
__maintainer__ = "Fábio Pfeifer"
__email__ = "fmpfeifer@gmail.com"
__status__ = "Beta"


# utilities


def encode_guid(h):
    guid = uuid.UUID(bytes=h)

    return str(guid)


def encode_in_addr(addr):
    b = struct.unpack("!BBBB", addr)
    fmt = "{:d}.{:d}.{:d}.{:d}"
    return fmt.format(b)


def encode_in_addr_v6(addr):
    s = struct.unpack("4s4s4s4s4s4s4s4s", encode_hex(addr))
    return "{}:{}:{}:{}:{}:{}:{}:{}".format(*tuple(map(_reencode, s)))


def encode_hex(s):
    return base64.b16encode(s)


def encode_base32(s):
    return base64.b32encode(s)


def encode_base64(s):
    return base64.b64encode(s)


encoders = {
    "hex": encode_hex,
    "base16": encode_hex,
    "base32": encode_base32,
    "base64": encode_base64,
    "guid": encode_guid,
}


def _reencode(b):
    if isinstance(b, bool):
        return str(b)
    if isinstance(b, bytes):
        return b.decode("utf-8")
    return b


def convert_to_epoch(timestamp):
    return timestamp / 10000000 - 11644473600


def convert_to_csv_timestamp(epoch):
    return epoch / 86400.0 + 25569


def format_datetime(epoch):
    try:
        return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return "0000-00-00 00:00:00"


class FileWriter:
    """Output generator"""

    def __init__(self, file_handle, level):
        self.level = level
        self.file_handle = file_handle
        self.ident = 1

    def out(self, level, fmt, text=None):
        if text is None:
            if level <= self.level:
                print(("  " * (self.ident - 1)) + _reencode(fmt), file=self.file_handle)
        else:
            if type(text) is tuple:
                self.out(level, fmt.format(*map(_reencode, text)))
            else:
                self.out(level, fmt, (text,))

    def inc_ident(self):
        self.ident += 1

    def dec_ident(self):
        self.ident -= 1


class CSVWriter:
    """CSV Output generator"""

    def __init__(self, file_handle, header):
        self.file_handle = file_handle
        titles = list(map(lambda x: x[0], header))
        self.fmt = list(map(lambda x: x[1], header))
        self.csvwriter = csv.writer(file_handle, delimiter=";")
        self.csvwriter.writerow(titles)

    def out(self, row):
        self.csvwriter.writerow([fmt.format(_reencode(data)) for data, fmt in zip(row, self.fmt)])


class MFCParser:
    """Simple CArchive parser"""

    def __init__(self, filename):
        self._file = open(filename, "rb")
        self.position = 0

    def close(self):
        self._file.close()

    def _read(self, fmt, n):
        return struct.unpack(fmt, self.read_bytes(n))[0]

    def read_bytes(self, n):
        buff = self._file.read(n)
        self.position += len(buff)
        return buff

    def read_int(self):
        return self._read("<i", 4)

    def read_uint(self):
        return self._read("<I", 4)

    def read_short(self):
        return self._read("<h", 2)

    def read_ushort(self):
        return self._read("<H", 2)

    def read_long(self):
        return self._read("<q", 8)

    def read_ulong(self):
        return self._read("<Q", 8)

    def read_bool(self):
        n = self.read_int()
        if n == 0:
            return False
        return True

    def read_byte(self):
        return self._read("<b", 1)

    def read_ubyte(self):
        return self._read("<B", 1)

    def read_file_time(self):
        return self._read("<Q", 8)

    def read_hash(self, n, encoder="hex"):
        ret = b"\0" * n
        valid = self.read_bool()
        if valid:
            ret = self.read_bytes(n)
        return encoders[encoder](ret)

    def _read_string_len(self):
        b_length = self.read_ubyte()
        if b_length < 0xFF:
            return b_length

        w_length = self.read_ushort()
        if w_length == 0xFFFE:
            return -1  # Unicode String prefix, length will follow
        elif w_length == 0xFFFF:
            w_length = self.read_ushort()
            return w_length
        return w_length

    def read_count(self):
        n = self.read_ushort()
        if n == 0xFFFF:
            return self.read_uint()
        return n

    def read_string(self):
        w_length = self._read_string_len()
        s_unicode = False
        if w_length == -1:
            w_length = self._read_string_len()
            s_unicode = True

        ret = ""
        if w_length != 0:
            if s_unicode:
                ret = self.read_bytes(w_length * 2).decode("UTF-16LE")
            else:
                ret = self.read_bytes(w_length).decode("UTF-8")

        return ret


class XMLAttribute:
    def __init__(self):
        self.name = ""
        self.value = ""

    def serialize(self, ar):
        self.name = ar.read_string()
        self.value = ar.read_string()


class XMLElement:
    def __init__(self):
        self.attributes = []
        self.elements = []
        self.name = ""
        self.value = ""

    def serialize(self, ar):
        self.name = ar.read_string()
        self.value = ar.read_string()
        n = ar.read_count()
        for i in range(n):
            attr = XMLAttribute()
            attr.serialize(ar)
            if attr.name != "":
                self.attributes.append(attr)
                # verify if attr existis
        n = ar.read_count()
        for i in range(n):
            el = XMLElement()
            el.serialize(ar)
            self.elements.append(el)

    def print_state(self, f, inXml=False):
        f.inc_ident()
        if self.name != "":
            if not inXml:
                f.out(3, "XML Data")
            strElem = "<" + self.name
            for a in self.attributes:
                strElem += " " + a.name + '="' + a.value + '"'
            if self.value == "" and len(self.elements) == 0:
                strElem += "/>"
                f.out(3, strElem)
            else:
                strElem += ">"
                f.out(3, strElem)
                if self.value != "":
                    f.out(3, self.value)
                if len(self.elements) != 0:
                    for e in self.elements:
                        e.print_state(f, True)
                f.out(3, "</" + self.name + ">")
        f.dec_ident()


################################################################################################


# Searches.dat parser


class QuerySearch:
    def __init__(self):
        self.guid = ""
        self.sSearch = ""
        self.sha1 = ""
        self.tiger = ""
        self.ed2k = ""
        self.bth = ""
        self.md5 = ""
        self.uri = ""
        self.xml = XMLElement()
        self.wantURL = False
        self.wantDN = False
        self.wantXML = False
        self.wantCOM = False
        self.wantPFS = False
        self.minSize = 0
        self.maxSize = 0

    def print_state(self, f):
        f.out(0, "QUERY SEARCH")
        f.inc_ident()
        f.out(0, "GUID: " + self.guid)
        f.out(0, "Search: " + self.sSearch)
        f.out(2, "SHA1: " + self.sha1)
        f.out(2, "Tiger: " + self.tiger)
        f.out(2, "ED2K: " + self.ed2k)
        f.out(2, "BTH: " + self.bth)
        f.out(2, "MD5: " + self.md5)
        f.out(3, "URI: " + self.uri)
        self.xml.print_state(f)
        f.out(3, "Want URL: " + str(self.wantURL))
        f.out(3, "Want DN: " + str(self.wantDN))
        f.out(3, "Want XML: " + str(self.wantXML))
        f.out(3, "Want COM: " + str(self.wantCOM))
        f.out(3, "Want PFS: " + str(self.wantPFS))
        f.out(3, "Min Size: {:d}".format(self.minSize))
        f.out(3, "Max Size: {:d}".format(self.maxSize))
        f.dec_ident()

    def serialize(self, ar):
        self.version = ar.read_int()
        # assert version >= 4
        self.guid = encode_guid(ar.read_bytes(16))
        self.sSearch = ar.read_string()
        self.sha1 = ar.read_hash(20)
        self.tiger = ar.read_hash(24)
        self.ed2k = ar.read_hash(16)
        self.bth = ar.read_hash(20, encoder="base32")

        if self.version >= 7:
            self.md5 = ar.read_hash(16)

        self.uri = ar.read_string()

        if len(self.uri) > 0:
            self.xml.serialize(ar)

        if self.version >= 5:
            self.wantURL = ar.read_bool()
            self.wantDN = ar.read_bool()
            self.wantXML = ar.read_bool()
            self.wantCOM = ar.read_bool()
            self.wantPFS = ar.read_bool()

        if self.version >= 8:
            self.minSize = ar.read_ulong()
            self.maxSize = ar.read_ulong()


class QueryHit:
    def __init__(self):
        self.searchId = ""
        self.protocolid = 0
        self.clientId = ""
        self.address = ""
        self.addressv6 = ""
        self.port = 0
        self.speed = 0
        self.s_speed = ""
        self.s_code = ""
        self.push = False
        self.busy = False
        self.stable = False
        self.measured = False
        self.upslots = 0
        self.upqueue = 0
        self.chat = False
        self.browsehost = False

        self.sha1 = ""
        self.tiger = ""
        self.ed2k = ""
        self.bth = ""
        self.md5 = ""
        self.url = ""
        self.name = ""
        self.index = 0
        self.bSize = False

        self.size = 0
        self.hitSources = 0
        self.partial = 0
        self.preview = False
        self.s_preview = ""
        self.collection = False
        self.schemaURI = ""
        self.schemaPlural = ""
        self.xml = XMLElement()
        self.rating = 0
        self.comments = ""

        self.matched = False
        self.exactMatch = False
        self.bogus = False
        self.download = False
        self.nick = ""

    def print_state(self, f):
        f.out(0, "QUERY HIT")
        f.inc_ident()
        f.out(1, "Search ID: " + self.searchId)
        f.out(3, "Protocol ID: {:d}".format(self.protocolid))
        f.out(1, "Client ID: " + self.clientId)
        f.out(1, "Address: {}:{:d}".format(self.address, self.port))
        f.out(1, "AddressV6: {}:{:d}".format(self.addressv6, self.port))
        f.out(2, "Speed: {:d} ({})".format(self.speed, self.s_speed))
        f.out(2, "Code: " + self.s_code)
        f.out(3, "Push: " + str(self.push))
        f.out(3, "Busy: " + str(self.busy))
        f.out(3, "Stable:" + str(self.stable))
        f.out(3, "Measured: " + str(self.measured))
        f.out(3, "UPSlots: {:d}  UPQueue: {:d}".format(self.upslots, self.upqueue))
        f.out(3, "Chat: " + str(self.chat))
        f.out(3, "BrowseHost: " + str(self.browsehost))
        f.out(2, "SHA1: " + self.sha1)
        f.out(2, "Tiger: " + self.tiger)
        f.out(2, "ED2K: " + self.ed2k)
        f.out(2, "BTH:" + self.bth)
        f.out(2, "MD5: " + self.md5)
        f.out(1, "URL: " + self.url)
        f.out(0, "Name: " + self.name.encode("UTF-8"))
        f.out(2, "Index: {:d}".format(self.index))
        f.out(3, "bSize: " + str(self.bSize))
        f.out(2, "Size: {:d}".format(self.size))
        f.out(3, "Hit Sources: {:d}".format(self.hitSources))
        f.out(2, "Partial: " + str(self.partial))
        f.out(3, "Has Preview: " + str(self.preview))
        f.out(3, "Preview: " + self.s_preview)
        f.out(3, "Collection: " + str(self.collection))
        f.out(3, "SchemaURI: " + str(self.schemaURI))
        self.xml.print_state(f)
        f.out(3, "Rating: {:d}".format(self.rating))
        f.out(2, "Comments: " + self.comments)
        f.out(3, "Matched: " + str(self.matched))
        f.out(3, "Exact Match: " + str(self.exactMatch))
        f.out(3, "Bogus: " + str(self.bogus))
        f.out(3, "Download: " + str(self.download))
        f.out(1, "Nick: " + self.nick)
        f.dec_ident()

    def serialize(self, ar, version):
        self.searchId = encode_guid(ar.read_bytes(16))
        if version >= 9:
            self.protocolid = ar.read_int()
        self.clientId = encode_guid(ar.read_bytes(16))
        self.address = encode_in_addr(ar.read_bytes(4))
        if version >= 16:
            self.addressv6 = encode_in_addr_v6(ar.read_bytes(16))
        self.port = ar.read_ushort()
        self.speed = ar.read_uint()
        self.s_speed = ar.read_string()
        self.s_code = ar.read_string()

        self.push = ar.read_bool()
        self.busy = ar.read_bool()
        self.stable = ar.read_bool()
        self.measured = ar.read_bool()
        self.upslots = ar.read_int()
        self.upqueue = ar.read_int()
        self.chat = ar.read_bool()
        self.browsehost = ar.read_bool()

        self.sha1 = ar.read_hash(20)
        self.tiger = ar.read_hash(24)
        self.ed2k = ar.read_hash(16)

        if version >= 13:
            self.bth = ar.read_hash(20, encoder="base32")
            self.md5 = ar.read_hash(16)

        self.url = ar.read_string()
        self.name = ar.read_string()
        self.index = ar.read_uint()
        self.bSize = ar.read_bool()

        if version >= 10:
            self.size = ar.read_ulong()
        else:
            self.size = ar.read_uint()

        self.hitSources = ar.read_uint()
        self.partial = ar.read_uint()
        self.preview = ar.read_bool()
        self.s_preview = ar.read_string()

        if version >= 11:
            self.collection = ar.read_bool()

        self.schemaURI = ar.read_string()
        self.schemaPlural = ar.read_string()  # unused
        if len(self.schemaURI) > 0:
            self.xml.serialize(ar)

        self.rating = ar.read_int()
        self.comments = ar.read_string()

        self.matched = ar.read_bool()
        if version >= 12:
            self.exactMatch = ar.read_bool()
        self.bogus = ar.read_bool()
        self.download = ar.read_bool()
        if version >= 15:
            self.nick = ar.read_string()


class MatchFile:
    def __init__(self):
        self.hits = []
        self.size = 0
        self.s_size = ""
        self.sha1 = ""
        self.tiger = ""
        self.ED2K = ""
        self.bth = ""
        self.md5 = ""
        self.busy = False
        self.push = False
        self.stable = False
        self.speed = 0
        self.s_speed = ""
        self.expanded = False
        self.existing = False
        self.download = False
        self.onevalid = False
        self.nPreview = 0
        self.preview = ""
        self.total = 0
        self.time = ""

    def print_state(self, f):
        f.out(0, "MATCH FILE")
        f.inc_ident()
        f.out(1, "Size: {:d} ({})".format(self.size, self.s_size))
        f.out(0, "SHA1: " + self.sha1)
        f.out(2, "Tiger: " + self.tiger)
        f.out(1, "ED2K: " + self.ED2K)
        f.out(2, "BTH: " + self.bth)
        f.out(2, "MD5: " + self.md5)
        f.out(3, "Busy: " + str(self.busy))
        f.out(3, "Push: " + str(self.push))
        f.out(3, "Stable: " + str(self.stable))
        f.out(3, "Speed: {:d} ({})".format(self.speed, self.s_speed))
        f.out(3, "Expanded: " + str(self.expanded))
        f.out(3, "Existing: " + str(self.existing))
        f.out(3, "Download: " + str(self.download))
        f.out(2, "One Valid: " + str(self.onevalid))
        f.out(3, "Preview Size: {:d}".format(self.nPreview))
        f.out(3, "Preview: " + self.preview.encode("base64"))
        f.out(1, "Total Hits: {:d}".format(self.total))
        for h in self.hits:
            h.print_state(f)
        f.out(3, "Time: ##TODO - decode CTime struct")
        f.dec_ident()

    def serialize(self, ar, version):
        if version >= 10:
            self.size = ar.read_ulong()
        else:
            self.size = ar.read_uint()

        self.s_size = ar.read_string()
        self.sha1 = ar.read_hash(20)
        self.tiger = ar.read_hash(24)
        self.ED2K = ar.read_hash(16)
        if version >= 13:
            self.bth = ar.read_hash(20, encoder="base32")
            self.md5 = ar.read_hash(16)

        self.busy = ar.read_bool()
        self.push = ar.read_bool()
        self.stable = ar.read_bool()
        self.speed = ar.read_uint()
        self.s_speed = ar.read_string()
        self.expanded = ar.read_bool()
        self.existing = ar.read_bool()
        self.download = ar.read_bool()
        self.onevalid = ar.read_bool()
        self.nPreview = ar.read_count()
        if self.nPreview != 0:
            self.preview = ar.read_bytes(self.nPreview)
        self.total = ar.read_count()
        for i in range(self.total):
            hit = QueryHit()
            hit.serialize(ar, version)
            self.hits.append(hit)
        if version >= 14:
            self.time = ar.read_bytes(12)


class MatchList:
    def __init__(self):
        self.files = []
        self.version = 0
        self.s_filter = ""
        self.filterBusy = False
        self.filterPush = False
        self.filterUnstable = False
        self.filterReject = False
        self.filterLocal = False
        self.filterBogus = False
        self.filterDRM = False
        self.filterAdult = False
        self.filterComents = False
        self.filterPartial = False
        self.filterSuspicious = False
        self.bRegExp = False
        self.filterMinSize = 0
        self.filterMaxSize = 0
        self.filterSources = 0
        self.sortColumn = 0
        self.sortDir = False
        self.nFiles = 0

    def print_state(self, f):
        f.out(0, "MATCH LIST")
        f.inc_ident()
        f.out(3, "Version: {:d}".format(self.version))
        f.out(0, "Filter String: " + self.s_filter)
        f.out(
            2,
            "Filter .. Busy: {!s}, Push: {!s}, Unstable: {!s}, Reject: {!s}, Local: {!s}, Bogus: {!s}".format(
                self.filterBusy,
                self.filterPush,
                self.filterUnstable,
                self.filterReject,
                self.filterLocal,
                self.filterBogus,
            ),
        )
        f.out(
            2,
            "Filter .. DRM: {!s}, Adult: {!s}, Suspicious: {!s}, RegExp: {!s}".format(
                self.filterDRM,
                self.filterAdult,
                self.filterSuspicious,
                self.bRegExp,
            ),
        )
        f.out(2, "Filter .. Coments: {!s}, Partial: {!s}".format(str(self.filterComents), str(self.filterPartial)))
        f.out(2, "Filter ..Min Size: {:d}, MaxSize: {:d}".format(self.filterMinSize, self.filterMaxSize))
        f.out(3, "FilterSources: {:d}".format(self.filterSources))
        f.out(3, "Sort Column: {:d}".format(self.sortColumn))
        f.out(3, "Sort Dir: " + str(self.sortDir))
        f.out(1, "Files: {:d}".format(self.nFiles))
        for fi in self.files:
            fi.print_state(f)
        f.dec_ident()

    def serialize(self, ar):
        self.version = ar.read_int()
        # assert version >= 8

        self.s_filter = ar.read_string()
        self.filterBusy = ar.read_bool()
        self.filterPush = ar.read_bool()
        self.filterUnstable = ar.read_bool()
        self.filterReject = ar.read_bool()
        self.filterLocal = ar.read_bool()
        self.filterBogus = ar.read_bool()

        if self.version >= 12:
            self.filterDRM = ar.read_bool()
            self.filterAdult = ar.read_bool()
            self.filterSuspicious = ar.read_bool()
            self.bRegExp = ar.read_bool()

        if self.version >= 17:
            self.filterComents = ar.read_bool()
            self.filterPartial = ar.read_bool()

        if self.version >= 10:
            self.filterMinSize = ar.read_ulong()
            self.filterMaxSize = ar.read_ulong()
        else:
            self.filterMinSize = ar.read_uint()
            self.filterMaxSize = ar.read_uint()

        self.filterSources = ar.read_uint()
        self.sortColumn = ar.read_int()
        self.sortDir = ar.read_bool()

        self.nFiles = ar.read_count()
        for i in range(self.nFiles):
            pfile = MatchFile()
            pfile.serialize(ar, self.version)
            self.files.append(pfile)


class BaseMatchSearch:
    def __init__(self):
        self.schema = ""
        self.matchList = MatchList()

    def serialize(self, ar):
        self.schema = ar.read_string()
        self.matchList.serialize(ar)

    def print_state(self, f):
        f.out(0, "BASE MATCH SEARCH")
        f.inc_ident()
        f.out(3, "Schema: " + self.schema)
        self.matchList.print_state(f)
        f.dec_ident()


class ManagedSearch:
    def __init__(self):
        self.version = 0
        self.allowG2 = False
        self.allowG1 = False
        self.allowED2K = False
        self.allowDC = False
        self.priority = 0
        self.active = False
        self.receive = False
        self.querySearch = QuerySearch()

    def serialize(self, ar):
        self.version = ar.read_int()
        # assert version < 2
        self.querySearch.serialize(ar)
        self.priority = ar.read_int()
        self.active = ar.read_bool()
        self.receive = ar.read_bool()

        if self.version >= 3:
            self.allowG2 = ar.read_bool()
            self.allowG1 = ar.read_bool()
            self.allowED2K = ar.read_bool()

        if self.version >= 4:
            self.allowDC = ar.read_bool()

    def print_state(self, f):
        f.out(0, "MANAGED SEARCH")
        f.inc_ident()
        f.out(3, "Version: {:d}".format(self.version))
        f.out(2, "Allow G2: " + str(self.allowG2))
        f.out(2, "Allow G1: " + str(self.allowG1))
        f.out(2, "Allow ED2K: " + str(self.allowED2K))
        f.out(2, "Allow DC: " + str(self.allowDC))
        f.out(2, "Priority: {:d}".format(self.priority))
        f.out(2, "Active: " + str(self.active))
        f.out(2, "Receive: " + str(self.receive))
        self.querySearch.print_state(f)
        f.dec_ident()


class SearchWnd:
    def __init__(self):
        self.version = 0
        self.managedSearches = []

    def serialize(self, ar):
        self.version = ar.read_int()
        # assert version == 1
        n = ar.read_count()

        for i in range(n):
            s = ManagedSearch()
            s.serialize(ar)
            self.managedSearches.append(s)

        self.baseMatchSearch = BaseMatchSearch()
        self.baseMatchSearch.serialize(ar)

    def print_state(self, f):
        f.out(0, "SEARCH WINDOW")
        f.inc_ident()
        f.out(3, "Version: {:d}".format(self.version))
        for m in self.managedSearches:
            m.print_state(f)
        self.baseMatchSearch.print_state(f)
        f.dec_ident()


class Searches:
    def __init__(self):
        self.searchWindows = []

    def serialize(self, ar):
        while ar.read_count() == 1:
            s = SearchWnd()
            s.serialize(ar)
            self.searchWindows.append(s)

    def print_state(self, f):
        f.out(0, "SEARCHES")
        f.inc_ident()
        for s in self.searchWindows:
            s.print_state(f)
        f.dec_ident()


#################################################################################################


# Library1.dat and Library2.dat parser


_tri_state_decode = {0: "Unknown", 1: "False", 2: "True"}


class LibraryDictionary:
    def __init__(self):
        self.wordsCount = 0

    def print_state(self, f):
        f.out(3, "LIBRARY DICTIONARY")
        f.inc_ident()
        f.out(3, "Words Count: {:d}".format(self.wordsCount))
        f.dec_ident()

    def serialize(self, ar, version):
        if version >= 29:
            self.wordsCount = ar.read_uint()


class SharedSource:
    def __init__(self):
        self.url = ""
        self.time = 0

    def print_state(self, f):
        f.out(2, "SHARED SOURCE")
        f.inc_ident()
        f.out(2, "URL: " + self.url)
        f.out(2, "Time: {:f} ({} UTC)".format(self.time, format_datetime(self.time)))
        f.dec_ident()

    def serialize(self, ar, version):
        self.url = ar.read_string()
        if version >= 10:
            self.time = convert_to_epoch(ar.read_ulong())
        else:
            self.time = convert_to_epoch(ar.read_uint())


class LibraryFile:
    """Represents a file in the Library"""

    csvheader = [
        ("Path", "{}"),
        ("Name", "{}"),
        ("Index", "{:d}"),
        ("Size", "{:d}"),
        ("Time", "{:0.8f}"),
        ("FormattedTime (UTC)", "{}"),
        ("Shared", "{}"),
        ("VirtualSize", "{:d}"),
        ("VirtualBase", "{:d}"),
        ("SHA1", "{}"),
        ("Tiger", "{}"),
        ("MD5", "{}"),
        ("ED2K", "{}"),
        ("BTH", "{}"),
        ("Verify", "{}"),
        ("URI", "{}"),
        ("MetadataAuto", "{}"),
        ("MetadataTime", "{:0.8f}"),
        ("FormattedMetadataTime (UTC)", "{}"),
        ("MetadataModified", "{}"),
        ("Rating", "{:d}"),
        ("Comments", "{}"),
        ("ShareTags", "{}"),
        ("HitsTotal", "{}"),
        ("UploadsTotal", "{}"),
        ("CachedPreview", "{}"),
        ("Bogus", "{}"),
    ]

    def __init__(self, parentFolder=None):
        self.metadata = XMLElement()
        self.shared_sources = []
        self.name = ""
        self.index = 0
        self.size = 0
        self.time = 0
        self.shared = 0
        self.virtualSize = 0
        self.virtualBase = 0
        self.sha1 = ""
        self.tiger = ""
        self.md5 = ""
        self.ed2k = ""
        self.bth = ""
        self.verify = 0
        self.uri = ""
        self.metadata_auto = False
        self.metadata_time = 0
        self.rating = 0
        self.comments = ""
        self.share_tags = ""
        self.metadata_modified = False
        self.hist_total = 0
        self.uploads_total = 0
        self.cached_preview = False
        self.bogus = False
        self.parentFolder = parentFolder

    def get_inherited_shared(self):
        inShared = self.shared
        if inShared == 0 and self.parentFolder is not None:
            inShared = self.parentFolder.get_inherited_shared()
        return inShared

    def print_state(self, f):
        f.out(0, "LIBRARY FILE")
        f.inc_ident()
        f.out(0, "Name: {}", self.name)
        f.out(3, "Index: {:d}", self.index)
        f.out(2, "Size: {:d}", self.size)
        f.out(3, "Time: {:f} ({} UTC)", (self.time, format_datetime(self.time)))
        f.out(2, "Shared: {}", _tri_state_decode[self.get_inherited_shared()])
        f.out(
            3,
            "Virtual Size: {:d}, Virtual Base: {:d}",
            (self.virtualSize, self.virtualBase),
        )
        f.out(2, "SHA1: {}", self.sha1)
        f.out(2, "Tiger: {}", self.tiger)
        f.out(2, "MD5: {}", self.md5)
        f.out(2, "ED2K: {}", self.ed2k)
        f.out(2, "BTH: {}", self.bth)
        f.out(3, "Verify: {}", _tri_state_decode[self.verify])
        f.out(3, "URI: {}", self.uri)
        f.out(
            3,
            "Metadata Auto: {}, Metadata Time: {:f}, Metadata Modified: {}",
            (self.metadata_auto, self.metadata_time, self.metadata_modified),
        )
        self.metadata.print_state(f)
        f.out(3, "Rating: {:d}", self.rating)
        f.out(3, "Comments: {}", self.comments)
        f.out(3, "Share Tags: {}", self.share_tags)
        f.out(3, "Hist Total: {:d}", self.hist_total)
        f.out(3, "Uploads Total: {:d}", self.uploads_total)
        f.out(3, "Cached Preview: {}", self.cached_preview)
        f.out(3, "Bogus: {}", self.bogus)
        for s in self.shared_sources:
            s.print_state(f)

        f.dec_ident()

    def print_to_csv(self, writer, path):
        row = [
            path,
            self.name,
            self.index,
            self.size,
            convert_to_csv_timestamp(self.time),
            format_datetime(self.time),
            _tri_state_decode[self.get_inherited_shared()],
            self.virtualSize,
            self.virtualBase,
            self.sha1,
            self.tiger,
            self.md5,
            self.ed2k,
            self.bth,
            _tri_state_decode[self.verify],
            self.uri,
            self.metadata_auto,
            convert_to_csv_timestamp(self.metadata_time),
            format_datetime(self.metadata_time),
            self.metadata_modified,
            self.rating,
            self.comments,
            self.share_tags,
            self.hist_total,
            self.uploads_total,
            self.cached_preview,
            self.bogus,
        ]
        writer.out(row)

    def serialize(self, ar, version):
        self.name = ar.read_string()
        self.index = ar.read_uint()
        if version >= 17:
            self.size = ar.read_ulong()
        else:
            self.size = ar.read_uint()
        self.time = convert_to_epoch(ar.read_ulong())
        if version >= 5:
            self.shared = ar.read_uint()  # TRISATE: 0 - unknown, 1 FALSE, 2 TRUE
        else:
            b = ar.read_byte()
            if b == 0:
                self.shared = 1  # FALSE
            else:
                self.shared = 0  # UNKNOWN

        if version >= 21:
            self.virtualSize = ar.read_ulong()
            if self.virtualSize > 0:
                self.virtualBase = ar.read_ulong()

        self.sha1 = ar.read_hash(20)
        if version >= 8:
            self.tiger = ar.read_hash(24)
        if version >= 11:
            self.md5 = ar.read_hash(16)
            self.ed2k = ar.read_hash(16)
        if version >= 26:
            self.bth = ar.read_hash(20, encoder="base32")
        if version >= 4:
            self.verify = ar.read_uint()  # TRISTATE
        self.uri = ar.read_string()
        if len(self.uri) > 0:
            if version < 27:
                self.metadata_auto = ar.read_bool()
                if not self.metadata_auto:
                    self.metadata_time = convert_to_epoch(ar.read_ulong())
            self.metadata.serialize(ar)
        if version >= 13:
            self.rating = ar.read_int()
            self.comments = ar.read_string()
            if version >= 16:
                self.share_tags = ar.read_string()
            if version >= 27:
                self.metadata_auto = ar.read_bool()
                self.metadata_time = convert_to_epoch(ar.read_ulong())
            else:
                if self.metadata_auto and (self.rating != 0 or len(self.comments) > 0):
                    self.metadata_time = convert_to_epoch(ar.read_ulong())
        self.metadata_modified = False
        self.hist_total = ar.read_uint()
        self.uploads_total = ar.read_uint()
        if version >= 14:
            self.cached_preview = ar.read_bool()
        if version >= 20:
            self.bogus = ar.read_bool()
        if version >= 2:
            n = ar.read_count()
            for i in range(n):
                shared_source = SharedSource()
                shared_source.serialize(ar, version)
                self.shared_sources.append(shared_source)


class LibraryMaps:
    def __init__(self):
        self.libraryFiles = []
        self.nextIndex = 0
        self.indexMapCount = 0
        self.nameMapCount = 0
        self.pathMapCount = 0

    def print_state(self, f):
        f.out(0, "LIBRARY MAPS")
        f.inc_ident()
        f.out(3, "Next Index: {:d}", self.nextIndex)
        f.out(3, "Index Map Count: {:d}", self.indexMapCount)
        f.out(3, "Name Map Count: {:d}", self.nameMapCount)
        f.out(3, "Path Map Count: {:d}", self.pathMapCount)
        for lf in self.libraryFiles:
            lf.print_state(f)
        f.dec_ident()

    def serialize1(self, ar, version):
        self.nextIndex = ar.read_uint()
        if version >= 28:
            self.indexMapCount = ar.read_uint()
            self.nameMapCount = ar.read_uint()
            self.pathMapCount = ar.read_uint()

    def serialize2(self, ar, version, idx_to_file_dict):
        if version >= 18:
            n = ar.read_count()
            for _ in range(n):
                f = LibraryFile()
                f.serialize(ar, version)
                self.libraryFiles.append(f)
                idx_to_file_dict[f.index] = f


class LibraryFolder:
    def __init__(self, idx_to_file_dict, parentFolder=None):
        self.folders = []
        self.files = []
        self.n_files = 0
        self.n_volume = 0
        self.path = ""
        self.shared = 0
        self.expanded = False
        self.idx_to_file_dict = idx_to_file_dict
        self.parentFolder = parentFolder

    def get_inherited_shared(self):
        inShared = self.shared
        if inShared == 0 and self.parentFolder is not None:
            inShared = self.parentFolder.get_inherited_shared()
        return inShared

    def print_state(self, f):
        f.out(0, "LIBRARY FOLDER")
        f.inc_ident()
        f.out(1, "Files: {:d}", self.n_files)
        f.out(1, "Volume: {:d}", self.n_volume)
        f.out(0, "Path: {}", self.path)
        f.out(0, "Shared: {}", _tri_state_decode[self.get_inherited_shared()])
        f.out(3, "Expanded: {}", self.expanded)
        for fold in self.folders:
            fold.print_state(f)
        for fi in self.files:
            fi.print_state(f)
        f.dec_ident()

    def print_to_csv(self, w):
        for fold in self.folders:
            fold.print_to_csv(w)
        for fi in self.files:
            fi.print_to_csv(w, self.path)

    def serialize(self, ar, version):
        self.path = ar.read_string()
        if version >= 5:
            self.shared = ar.read_uint()  # TRISATE: 0 - unknown, 1 FALSE, 2 TRUE
        else:
            b = ar.read_byte()
            if b == 0:
                self.shared = 1  # FALSE
            else:
                self.shared = 0  # UNKNOWN
        if version >= 3:
            self.expanded = ar.read_bool()
        n = ar.read_count()
        for i in range(n):
            folder = LibraryFolder(self.idx_to_file_dict, self)
            folder.serialize(ar, version)
            self.folders.append(folder)
            self.n_files += folder.n_files
            self.n_volume += folder.n_volume
        n = ar.read_count()
        for i in range(n):
            file = LibraryFile(self)
            file.serialize(ar, version)
            self.files.append(file)
            self.n_files += 1
            self.n_volume += file.size
            self.idx_to_file_dict[file.index] = file


class AlbumFolder:
    def __init__(self):
        self.xml = XMLElement()
        self.album_folders = []
        self.album_file_indexes = []
        self.schema_uri = ""
        self.coll_sha1 = ""
        self.guid = ""
        self.name = ""
        self.expanded = False
        self.auto_delete = False
        self.best_view = ""

    def print_state(self, f):
        f.out(0, "ALBUM FOLDER")
        f.inc_ident()
        f.out(0, "Name: {}", self.name)
        f.out(2, "GUID: {}", self.guid)
        f.out(3, "Collection SHA1: {}", self.coll_sha1)
        f.out(3, "Schema URI: {}", self.schema_uri)
        f.out(3, "Expanded: {}", self.expanded)
        f.out(3, "Auto Delete: {}", self.auto_delete)
        f.out(3, "Best View: {}", self.best_view)
        self.xml.print_state(f)
        f.out(3, "Files Indexes: {}", str(self.album_file_indexes))
        for fold in self.album_folders:
            fold.print_state(f)
        f.dec_ident()

    def print_to_csv(self, w, idx_to_file_dict, path=None):
        if path is None:
            path = "[ALBUM]/" + self.name
        else:
            path += "/" + self.name
        for fold in self.album_folders:
            fold.print_to_csv(w, idx_to_file_dict, path)
        for idx in self.album_file_indexes:
            if idx in idx_to_file_dict:
                file = idx_to_file_dict[idx]
                file.print_to_csv(w, path)

    def serialize(self, ar, version):
        self.schema_uri = ar.read_string()
        if ar.read_count() != 0:
            self.xml.serialize(ar)
        if version >= 19:
            self.coll_sha1 = ar.read_hash(20)
        if version >= 24:
            self.guid = ar.read_hash(16, encoder="guid")
        self.name = ar.read_string()
        self.expanded = ar.read_bool()
        self.auto_delete = ar.read_bool()
        if version >= 9:
            self.best_view = ar.read_string()
        for i in range(ar.read_count()):
            af = AlbumFolder()
            af.serialize(ar, version)
            self.album_folders.append(af)
        for i in range(ar.read_count()):
            idx = ar.read_uint()
            self.album_file_indexes.append(idx)


class LibraryFolders:
    def __init__(self, idx_to_file_dict):
        self.folders = []
        self.idx_to_file_dict = idx_to_file_dict
        self.album_root = AlbumFolder()

    def print_state(self, f):
        f.out(0, "LIBRARY FOLDERS")
        f.inc_ident()
        for fold in self.folders:
            fold.print_state(f)
        self.album_root.print_state(f)
        f.dec_ident()

    def print_to_csv(self, w):
        for fold in self.folders:
            fold.print_to_csv(w)
        self.album_root.print_to_csv(w, self.idx_to_file_dict)

    def serialize(self, ar, version):
        n = ar.read_count()
        for _ in range(n):
            libFolder = LibraryFolder(self.idx_to_file_dict)
            libFolder.serialize(ar, version)
            self.folders.append(libFolder)
        if version >= 6:
            self.album_root.serialize(ar, version)


class LibraryRecent:
    def __init__(self):
        self.time = 0
        self.index = 0

    def print_state(self, f):
        f.out(2, "LIBRARY RECENT")
        f.inc_ident()
        f.out(2, "Time: {:f}", self.time)
        f.out(2, "Index: {:d}", self.index)
        f.dec_ident()

    def serialize(self, ar, version):
        self.time = convert_to_epoch(ar.read_ulong())
        self.index = ar.read_uint()


class LibraryHistory:
    def __init__(self):
        self.list = []
        self.last_seeded_torrent_path = ""
        self.last_seeded_torrent_name = ""
        self.last_seeded_torrent_tlastseeded = 0
        self.last_seeded_torrent_bth = ""

    def print_state(self, f):
        f.out(2, "LIBRARY HISTORY")
        f.inc_ident()
        f.out(2, "Last Seeded Torrent Path: {}", self.last_seeded_torrent_path)
        f.out(2, "Last Seeded Torrent Name: {}", self.last_seeded_torrent_name)
        f.out(
            2,
            "Last Seeded Torrent Time Last Seeded: {:d} ({} UTC)",
            (
                self.last_seeded_torrent_tlastseeded,
                format_datetime(self.last_seeded_torrent_tlastseeded),
            ),
        )
        f.out(2, "Last Seeded Torrent BTH: {}", self.last_seeded_torrent_bth)
        for rec in self.list:
            rec.print_state(f)
        f.dec_ident()

    def serialize(self, ar, version):
        for i in range(ar.read_count()):
            recent = LibraryRecent()
            recent.serialize(ar, version)
            self.list.append(recent)
        if version > 22:
            self.last_seeded_torrent_path = ar.read_string()
            if len(self.last_seeded_torrent_path) > 0:
                self.last_seeded_torrent_name = ar.read_string()
                self.last_seeded_torrent_tlastseeded = convert_to_epoch(ar.read_uint())
                self.last_seeded_torrent_bth = ar.read_hash(20, encoder="base32")


class Library:
    """Library.dat parser"""

    def __init__(self, number):
        self.number = number
        self.time = None
        self.version = 0
        self.idx_to_file_dict = dict()
        self.libraryDictionary = LibraryDictionary()
        self.libraryMaps = LibraryMaps()
        self.libraryFolders = LibraryFolders(self.idx_to_file_dict)
        self.libraryHistory = LibraryHistory()

    def serialize(self, ar):
        self.time = ar.read_file_time()
        self.version = ar.read_int()
        self.libraryDictionary.serialize(ar, self.version)
        self.libraryMaps.serialize1(ar, self.version)
        self.libraryFolders.serialize(ar, self.version)
        self.libraryHistory.serialize(ar, self.version)
        self.libraryMaps.serialize2(ar, self.version, self.idx_to_file_dict)

    def print_state(self, f):
        f.out(0, "LIBRARY {:d}", self.number)
        f.inc_ident()
        f.out(3, "Version: {:d}", self.version)
        f.out(3, "Time: ##TODO - decode FILETIME struct")
        self.libraryFolders.print_state(f)
        self.libraryHistory.print_state(f)
        self.libraryMaps.print_state(f)
        self.libraryDictionary.print_state(f)
        f.dec_ident()

    def print_to_csv(self, w):
        self.libraryFolders.print_to_csv(w)


############################################################################################################

# Main Part


def usage(command):
    print("ShareazaParser - a parser for Shareaza's Library1.dat, Library2.dat and Searches.dat")
    print("Version: {}".format(__version__))
    print("This program needs python version >= 3.5")
    print("")
    print("Usage:")
    print("{} [-h] [-l level] [-c] [-s]".format(command))
    print("")
    print(" -h: print this help and exits")
    print(" -c: output text to stdout")
    print(" -l level  (--level=level):")
    print("   Choose output level (only valid for text output):")
    print("     0 - Very Important: Only very important information is displayed")
    print("     1 - Important: Important information and level 0 information is displayed")
    print("     2 - Useful: Useful information and level 1 information is displayed")
    print("     3 - Debug(default): All available information is displayed")
    print(" -s: generate csv spreadsheet (instead of text)")
    print("")
    print(" Timestamps are exported as Unix epoch in text files, or as Excel date in csv files.")


def main(command, argv):
    parsed = False
    level = 3
    tostdout = False
    tocsv = False

    try:
        opts, _ = getopt.getopt(argv, "hl:cs", ["level="])
    except getopt.GetoptError:
        usage(command)
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            usage(command)
            sys.exit()
        elif opt == "-s":
            tocsv = True
        elif opt in ("-l", "--level"):
            try:
                level = int(arg)
            except Exception:
                usage(command)
                sys.exit(2)
            if level < 0 or level > 3:
                usage(command)
                sys.exit(2)
        elif opt == "-c":
            tostdout = True

    if os.path.isfile("Searches.dat"):
        if not tocsv:
            try:
                parser = MFCParser("Searches.dat")
                s = Searches()
                s.serialize(parser)
                parser.close()
                if tostdout:
                    fout = sys.stdout
                else:
                    fout = open("Searches.txt", "wt", encoding="utf-8")
                out = FileWriter(fout, level)
                s.print_state(out)
                if not tostdout:
                    fout.close()
                parsed = True
            except Exception as inst:
                print(type(inst))
                print(inst.args)
                print(inst)
                _, _, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback, file=sys.stderr)

    for lib in [1, 2]:
        if os.path.isfile("Library{:d}.dat".format(lib)):
            try:
                parser = MFCParser("Library{:d}.dat".format(lib))
                library = Library(lib)
                library.serialize(parser)
                parser.close()
                if tocsv:
                    with open("Library{:d}.csv".format(lib), "wt", encoding="utf-8", newline="") as fout:
                        writer = CSVWriter(fout, LibraryFile.csvheader)
                        library.print_to_csv(writer)
                else:
                    try:
                        if tostdout:
                            fout = sys.stdout
                        else:
                            fout = open("Library{:d}.txt".format(lib), "wt", encoding="utf-8")
                        out = FileWriter(fout, level)
                        library.print_state(out)
                    finally:
                        if not tostdout:
                            fout.close()
                parsed = True
            except Exception as inst:
                print(type(inst))
                print(inst.args)
                print(inst)
                _, _, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback, file=sys.stderr)

    if not parsed:
        print(
            "No file found for parsing. Make sure Searches.dat, Library1.dat or Library2.dat is in current directory.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[0], sys.argv[1:])
