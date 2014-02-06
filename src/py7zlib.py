#!/usr/bin/python -u
#
# Python Bindings for LZMA
#
# Copyright (c) 2004-2010 by Joachim Bauch, mail@joachim-bauch.de
# 7-Zip Copyright (C) 1999-2010 Igor Pavlov
# LZMA SDK Copyright (C) 1999-2010 Igor Pavlov
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# $Id$
#
"""Read from and write to 7zip format archives.
"""

from binascii import unhexlify
import lzma
from struct import pack, unpack
from zlib import crc32
from io import BytesIO

READ_BLOCKSIZE                   = 65536

MAGIC_7Z                         = unhexlify('377abcaf271c')  # '7z\xbc\xaf\x27\x1c'

PROPERTY_END                     = unhexlify('00')  # '\x00'
PROPERTY_HEADER                  = unhexlify('01')  # '\x01'
PROPERTY_ARCHIVE_PROPERTIES      = unhexlify('02')  # '\x02'
PROPERTY_ADDITIONAL_STREAMS_INFO = unhexlify('03')  # '\x03'
PROPERTY_MAIN_STREAMS_INFO       = unhexlify('04')  # '\x04'
PROPERTY_FILES_INFO              = unhexlify('05')  # '\x05'
PROPERTY_PACK_INFO               = unhexlify('06')  # '\x06'
PROPERTY_UNPACK_INFO             = unhexlify('07')  # '\x07'
PROPERTY_SUBSTREAMS_INFO         = unhexlify('08')  # '\x08'
PROPERTY_SIZE                    = unhexlify('09')  # '\x09'
PROPERTY_CRC                     = unhexlify('0a')  # '\x0a'
PROPERTY_FOLDER                  = unhexlify('0b')  # '\x0b'
PROPERTY_CODERS_UNPACK_SIZE      = unhexlify('0c')  # '\x0c'
PROPERTY_NUM_UNPACK_STREAM       = unhexlify('0d')  # '\x0d'
PROPERTY_EMPTY_STREAM            = unhexlify('0e')  # '\x0e'
PROPERTY_EMPTY_FILE              = unhexlify('0f')  # '\x0f'
PROPERTY_ANTI                    = unhexlify('10')  # '\x10'
PROPERTY_NAME                    = unhexlify('11')  # '\x11'
PROPERTY_CREATION_TIME           = unhexlify('12')  # '\x12'
PROPERTY_LAST_ACCESS_TIME        = unhexlify('13')  # '\x13'
PROPERTY_LAST_WRITE_TIME         = unhexlify('14')  # '\x14'
PROPERTY_ATTRIBUTES              = unhexlify('15')  # '\x15'
PROPERTY_COMMENT                 = unhexlify('16')  # '\x16'
PROPERTY_ENCODED_HEADER          = unhexlify('17')  # '\x17'

# number of seconds between 1601/01/01 and 1970/01/01 (UTC)
# used to adjust 7z FILETIME to Python timestamp
TIMESTAMP_ADJUST                 = -11644473600

def toTimestamp(filetime):
    """Convert 7z FILETIME to Python timestamp."""
    # FILETIME is 100-nanosecond intervals since 1601/01/01 (UTC)
    return (filetime / 10000000.0) + TIMESTAMP_ADJUST

class ArchiveError(Exception):
    pass

class FormatError(ArchiveError):
    pass

class UnsupportedCompressionMethodError(ArchiveError):
    pass

class ArchiveTimestamp(int):
    """Windows FILETIME timestamp."""
    
    def __repr__(self):
        return '%s(%d)' % (type(self).__name__, self)
    
    def as_datetime(self):
        """Convert FILETIME to Python datetime object."""
        from datetime import fromtimestamp, timezone
        return fromtimestamp(toTimestamp(self), timezone.utc)

class Base(object):
    """ base class with support for various basic read/write functions """
    
    def _readReal64Bit(self, file):
        res = file.read(8)
        a, b = unpack('<LL', res)
        return b << 32 | a, res
    
    def _read64Bit(self, file):
        from functools import reduce
        b = ord(file.read(1))
        mask = 0x80
        for i in range(8):
            if b & mask == 0:
                bytes = list(unpack('%dB' % i, file.read(i)))
                bytes.reverse()
                value = (bytes and reduce(lambda x, y: x << 8 | y, bytes)) or 0
                highpart = b & (mask - 1)
                return value + (highpart << (i * 8))
            
            mask >>= 1

    def _readBoolean(self, file, count, checkall=0):
        if checkall:
            alldefined = file.read(1)
            if alldefined != unhexlify('00'):
                return [True] * count
            
        result = []
        b = 0
        mask = 0
        for i in range(count):
            if mask == 0:
                b = ord(file.read(1))
                mask = 0x80
            result.append(b & mask != 0)
            mask >>= 1
        
        return result

    def checkcrc(self, crc, data):
        check = crc32(data) & 0xffffffff
        return crc == check


class PackInfo(Base):
    """ informations about packed streams """
    
    def __init__(self, file):
        self.packpos = self._read64Bit(file)
        self.numstreams = self._read64Bit(file)
        id = file.read(1)
        if id == PROPERTY_SIZE:
            self.packsizes = [self._read64Bit(file) for x in range(self.numstreams)]
            id = file.read(1)
            
            if id == PROPERTY_CRC:
                self.crcs = [self._read64Bit(file) for x in range(self.numstreams)]
                id = file.read(1)
            
        if id != PROPERTY_END:
            raise FormatError('end id expected but %s found' % repr(id))

class Folder(Base):
    """ a "Folder" represents a stream of compressed data """
    
    def __init__(self, file):
        numcoders = self._read64Bit(file)
        self.coders = []
        self.digestdefined = False
        totalin = 0
        self.totalout = 0
        for i in range(numcoders):
            while True:
                b = ord(file.read(1))
                methodsize = b & 0xf
                issimple = b & 0x10 == 0
                noattributes = b & 0x20 == 0
                last_alternative = b & 0x80 == 0
                c = {}
                c['method'] = file.read(methodsize)
                if not issimple:
                    c['numinstreams'] = self._read64Bit(file)
                    c['numoutstreams'] = self._read64Bit(file)
                else:
                    c['numinstreams'] = 1
                    c['numoutstreams'] = 1
                totalin += c['numinstreams']
                self.totalout += c['numoutstreams']
                if not noattributes:
                    c['properties'] = file.read(self._read64Bit(file))
                self.coders.append(c)
                if last_alternative:
                    break
        
        numbindpairs = self.totalout - 1
        self.bindpairs = []
        for i in range(numbindpairs):
            self.bindpairs.append((self._read64Bit(file), self._read64Bit(file), ))
        
        numpackedstreams = totalin - numbindpairs
        self.packed_indexes = []
        if numpackedstreams == 1:
            for i in range(totalin):
                if self.findInBindPair(i) < 0:
                    self.packed_indexes.append(i)
        elif numpackedstreams > 1:
            for i in range(numpackedstreams):
                self.packed_indexes.append(self._read64Bit(file))

    def getUnpackSize(self):
        if not self.unpacksizes:
            return 0
            
        r = list(range(len(self.unpacksizes)))
        r.reverse()
        for i in r:
            if self.findOutBindPair(i):
                return self.unpacksizes[i]
        
        raise TypeError('not found')

    def findInBindPair(self, index):
        for idx in range(len(self.bindpairs)):
            a, b = self.bindpairs[idx]
            if a == index:
                return idx
        return -1

    def findOutBindPair(self, index):
        for idx in range(len(self.bindpairs)):
            a, b = self.bindpairs[idx]
            if b == index:
                return idx
        return -1
        
class Digests(Base):
    """ holds a list of checksums """
    
    def __init__(self, file, count):
        self.defined = self._readBoolean(file, count, checkall=1)
        self.crcs = [unpack('<L', file.read(4))[0] for x in range(count)]
    
UnpackDigests = Digests

class UnpackInfo(Base):
    """ combines multiple folders """

    def __init__(self, file):
        id = file.read(1)
        if id != PROPERTY_FOLDER:
            raise FormatError('folder id expected but %s found' % repr(id))
        self.numfolders = self._read64Bit(file)
        self.folders = []
        external = file.read(1)
        if external == unhexlify('00'):
            self.folders = [Folder(file) for x in range(self.numfolders)]
        elif external == unhexlify('01'):
            self.datastreamidx = self._read64Bit(file)
        else:
            raise FormatError('0x00 or 0x01 expected but %s found' % repr(external))
        
        id = file.read(1)
        if id != PROPERTY_CODERS_UNPACK_SIZE:
            raise FormatError('coders unpack size id expected but %s found' % repr(id))
        
        for folder in self.folders:
            folder.unpacksizes = [self._read64Bit(file) for x in range(folder.totalout)]
            
        id = file.read(1)
        if id == PROPERTY_CRC:
            digests = UnpackDigests(file, self.numfolders)
            for idx in range(self.numfolders):
                folder = self.folders[idx]
                folder.digestdefined = digests.defined[idx]
                folder.crc = digests.crcs[idx]
                
            id = file.read(1)
        
        if id != PROPERTY_END:
            raise FormatError('end id expected but %s found' % repr(id))
            
class SubstreamsInfo(Base):
    """ defines the substreams of a folder """
    
    def __init__(self, file, numfolders, folders):
        self.digests = []
        self.digestsdefined = []
        id = file.read(1)
        if id == PROPERTY_NUM_UNPACK_STREAM:
            self.numunpackstreams = [self._read64Bit(file) for x in range(numfolders)]
            id = file.read(1)
        else:        
            self.numunpackstreams = []
            for idx in range(numfolders):
                self.numunpackstreams.append(1)
        
        if id == PROPERTY_SIZE:
            self.unpacksizes = []
            for i in range(len(self.numunpackstreams)):
                sum = 0
                for j in range(1, self.numunpackstreams[i]):
                    size = self._read64Bit(file)
                    self.unpacksizes.append(size)
                    sum += size
                self.unpacksizes.append(folders[i].getUnpackSize() - sum)
                assert folders[i].getUnpackSize() > sum
                
            id = file.read(1)

        numdigests = 0
        numdigeststotal = 0
        for i in range(numfolders):
            numsubstreams = self.numunpackstreams[i]
            if numsubstreams != 1 or not folders[i].digestdefined:
                numdigests += numsubstreams
            numdigeststotal += numsubstreams
        
        if id == PROPERTY_CRC:
            digests = Digests(file, numdigests)
            didx = 0
            for i in range(numfolders):
                folder = folders[i]
                numsubstreams = self.numunpackstreams[i]
                if numsubstreams == 1 and folder.digestdefined:
                    self.digestsdefined.append(True)
                    self.digests.append(folder.crc)
                else:
                    for j in range(numsubstreams):
                        self.digestsdefined.append(digests.defined[didx])
                        self.digests.append(digests.crcs[didx])
                        didx += 1
                            
            id = file.read(1)
            
        if id != PROPERTY_END:
            raise FormatError('end id expected but %r found' % id)

        if not self.digestsdefined:
            self.digestsdefined = [False] * numdigeststotal
            self.digests = [0] * numdigeststotal

class StreamsInfo(Base):
    """ informations about compressed streams """
    
    def __init__(self, file):
        id = file.read(1)
        if id == PROPERTY_PACK_INFO:
            self.packinfo = PackInfo(file)
            id = file.read(1)
        
        if id == PROPERTY_UNPACK_INFO:
            self.unpackinfo = UnpackInfo(file)
            id = file.read(1)
            
        if id == PROPERTY_SUBSTREAMS_INFO:
            self.substreamsinfo = SubstreamsInfo(file, self.unpackinfo.numfolders, self.unpackinfo.folders)
            id = file.read(1)
        
        if id != PROPERTY_END:
            raise FormatError('end id expected but %s found' % repr(id))

class FilesInfo(Base):
    """ holds file properties """
    
    def _readTimes(self, file, files, name):
        defined = self._readBoolean(file, len(files), checkall=1)
        
        # NOTE: the "external" flag is currently ignored, should be 0x00
        external = file.read(1)
        for i in range(len(files)):
            if defined[i]:
                files[i][name] = ArchiveTimestamp(self._readReal64Bit(file)[0])
            else:
                files[i][name] = None

    def __init__(self, file):
        self.numfiles = self._read64Bit(file)
        self.files = [{'emptystream': False} for x in range(self.numfiles)]
        numemptystreams = 0
        while True:
            typ = self._read64Bit(file)
            if typ > 255:
                raise FormatError('invalid type, must be below 256, is %d' % typ)
                
            typ = pack('B', typ)
            if typ == PROPERTY_END:
                break
                
            size = self._read64Bit(file)
            buffer = BytesIO(file.read(size))
            if typ == PROPERTY_EMPTY_STREAM:
                isempty = self._readBoolean(buffer, self.numfiles)
                list(map(lambda x, y: x.update({'emptystream': y}), self.files, isempty))
                for x in isempty:
                    if x: numemptystreams += 1
                emptyfiles = [False] * numemptystreams
                antifiles = [False] * numemptystreams
            elif typ == PROPERTY_EMPTY_FILE:
                emptyfiles = self._readBoolean(buffer, numemptystreams)
            elif typ == PROPERTY_ANTI:
                antifiles = self._readBoolean(buffer, numemptystreams)
            elif typ == PROPERTY_NAME:
                external = buffer.read(1)
                if external != unhexlify('00'):
                    self.dataindex = self._read64Bit(buffer)
                    # XXX: evaluate external
                    raise NotImplementedError
                    
                for f in self.files:
                    name = ''
                    while True:
                        ch = buffer.read(2)
                        if ch == unhexlify('0000'):
                            f['filename'] = name
                            break
                        name += ch.decode('utf-16')
            elif typ == PROPERTY_CREATION_TIME:
                self._readTimes(buffer, self.files, 'creationtime')
            elif typ == PROPERTY_LAST_ACCESS_TIME:
                self._readTimes(buffer, self.files, 'lastaccesstime')
            elif typ == PROPERTY_LAST_WRITE_TIME:
                self._readTimes(buffer, self.files, 'lastwritetime')
            elif typ == PROPERTY_ATTRIBUTES:
                defined = self._readBoolean(buffer, self.numfiles, checkall=1)
                for i in range(self.numfiles):
                    f = self.files[i]
                    if defined[i]:
                        f['attributes'] = unpack('<L', buffer.read(4))[0]
                    else:
                        f['attributes'] = None
            else:
                raise FormatError('invalid type %r' % (typ))
        
class Header(Base):
    """ the archive header """
    
    def __init__(self, file):
        id = file.read(1)
        if id == PROPERTY_ARCHIVE_PROPERTIES:
            self.properties = ArchiveProperties(file)
            id = file.read(1)
        
        if id == PROPERTY_ADDITIONAL_STREAMS_INFO:
            self.additional_streams = StreamsInfo(file)
            id = file.read(1)
        
        if id == PROPERTY_MAIN_STREAMS_INFO:
            self.main_streams = StreamsInfo(file)
            id = file.read(1)
            
        if id == PROPERTY_FILES_INFO:
            self.files = FilesInfo(file)
            id = file.read(1)
            
        if id != PROPERTY_END:
            raise FormatError('end id expected but %s found' % (repr(id)))

class ArchiveFile(Base):
    """ wrapper around a file in the archive """
    
    def __init__(self, info, start, src_start, size, folder, archive, maxsize=None):
        self.digest = None
        self._archive = archive
        self._file = archive._file
        self._start = start
        self._src_start = src_start
        self._folder = folder
        self.size = size
        # maxsize is only valid for solid archives
        self._maxsize = maxsize
        for k, v in info.items():
            setattr(self, k, v)

class Archive7z(Base):
    """ the archive itself """
    
    def __init__(self, filename, password=None):
        self._filename = filename
        self._file = open(filename, 'rb')
        file = self._file
        self.password = password
        self.header = file.read(len(MAGIC_7Z))
        if self.header != MAGIC_7Z:
            raise FormatError('not a 7z file')
        self.version = unpack('BB', file.read(2))

        self.startheadercrc = unpack('<L', file.read(4))[0]
        self.nextheaderofs, data = self._readReal64Bit(file)
        crc = crc32(data)
        self.nextheadersize, data = self._readReal64Bit(file)
        crc = crc32(data, crc)
        data = file.read(4)
        self.nextheadercrc = unpack('<L', data)[0]
        crc = crc32(data, crc) & 0xffffffff
        if crc != self.startheadercrc:
            raise FormatError('invalid header data')
        self.afterheader = file.tell()
        
        file.seek(self.nextheaderofs, 1)
        buffer = BytesIO(file.read(self.nextheadersize))
        if not self.checkcrc(self.nextheadercrc, buffer.getvalue()):
            raise FormatError('invalid header data')
        
        while True:
            id = buffer.read(1)
            if not id or id == PROPERTY_HEADER:
                break
                
            if id != PROPERTY_ENCODED_HEADER:
                raise TypeError('Unknown field: %r' % (id))
            
            streams = StreamsInfo(buffer)
            file.seek(self.afterheader + 0)
            data = bytes('', 'ascii')
            idx = 0
            for folder in streams.unpackinfo.folders:
                file.seek(streams.packinfo.packpos, 1)
                props = folder.coders[0]['properties']
                for idx in range(len(streams.packinfo.packsizes)):
                    tmp = file.read(streams.packinfo.packsizes[idx])
                    data += lzma.decompress(props+pack('<Q',folder.unpacksizes[idx])+tmp)
                
                if folder.digestdefined:
                    if not self.checkcrc(folder.crc, data):
                        raise FormatError('invalid block data')
                        
            buffer = BytesIO(data)
        
        self.files = []
        if not id:
            # empty archive
            self.solid = False
            self.numfiles = 0
            self.filenames = []
            return
        
        self.header = Header(buffer)
        files = self.header.files
        folders = self.header.main_streams.unpackinfo.folders
        packinfo = self.header.main_streams.packinfo
        subinfo = self.header.main_streams.substreamsinfo
        packsizes = packinfo.packsizes
        self.solid = packinfo.numstreams == 1
        if hasattr(subinfo, 'unpacksizes'):
            unpacksizes = subinfo.unpacksizes
        else:
            unpacksizes = [x.unpacksizes[-1] for x in folders]
        
        fidx = 0
        obidx = 0
        src_pos = self.afterheader
        pos = 0
        folder_pos = src_pos
        maxsize = (self.solid and packinfo.packsizes[0]) or None
        for idx in range(files.numfiles):
            info = files.files[idx]
            if info['emptystream']:
                continue
            
            folder = folders[fidx]
            folder.solid = subinfo.numunpackstreams[fidx] > 1
            maxsize = (folder.solid and packinfo.packsizes[fidx]) or None
            if folder.solid:
                # file is part of solid archive
                info['compressed'] = None
            elif obidx < len(packsizes):
                # file is compressed
                info['compressed'] = packsizes[obidx]
            else:
                # file is not compressed
                info['compressed'] = unpacksizes[obidx]
            info['uncompressed'] = unpacksizes[obidx]
            file = ArchiveFile(info, pos, src_pos, unpacksizes[obidx], folder, self, maxsize=maxsize)
            if subinfo.digestsdefined[obidx]:
                file.digest = subinfo.digests[obidx]
            self.files.append(file)
            if folder.solid:
                pos += unpacksizes[obidx]
            else:
                src_pos += info['compressed']
            obidx += 1
            if obidx in self.get_folder_transition_indexes(subinfo.numunpackstreams):
                folder_pos += packinfo.packsizes[fidx]
                src_pos = folder_pos
                fidx += 1

        self.numfiles = len(self.files)
        self.filenames = map(lambda x: x.filename, self.files)

    # Find archive file indexes when folder transitions occur
    def get_folder_transition_indexes(self, numunpackstreams):
        accum = 0
        result = []
        for x in numunpackstreams:
            accum += x
            result.append(accum)
        return result

    # interface like TarFile
    def getmember(self, name):
        # XXX: store files in dictionary
        for f in self.files:
            if f.filename == name:
                return f
                
        return None
        
    def getmembers(self):
        return self.files
        
    def getnames(self):
        return self.filenames

    def list(self, verbose=True):
        print ('total %d files in %sarchive' % (self.numfiles, (self.solid and 'solid ') or ''))
        if not verbose:
            print ('\n'.join(self.filenames))
            return
            
        for f in self.files:
            extra = (f.compressed and '%10d ' % (f.compressed)) or ' '
            print ('%10d%s%.8x %s' % (f.size, extra, f.digest, f.filename))

    def get_lzma_coder(self, coders):
        # 1, 2, or 4 streams per folder. 4-cases so far have all shown up as
        # LZMA-LZMA-LZMA-BCJ2 (reversed from what 7z l -slt displays), which
        # means that either way the last listed method wins.
        assert len(coders) >= 1
        return coders[-1]

    def get_lzma_filters(self, coders):
        from lzma import FILTER_LZMA1, FILTER_LZMA2, FILTER_X86

        dict_size = None
        for coder in coders:
            if 'properties' in coder:
                new_dict_size = unpack('<I', coder['properties'][1:5])[0]
                if not dict_size or new_dict_size > dict_size:
                    dict_size = new_dict_size

        method = self.get_lzma_coder(coders)['method']

        if method == unhexlify("030101"):
            return [{'id':FILTER_LZMA1, 'dict_size':dict_size, 'nice_len': 273}]
        if method == unhexlify("03030103"): # BCJ/LZMA1
            # http://sourceforge.net/p/lzmautils/discussion/708858/thread/7bd9799e/
            # See comment elsewhere about liblzma brokenness
            # Should be able to specify FILTER_X86 directly as
            # part of this filter chain but channot.
            return [{'id':FILTER_LZMA1, 'dict_size':dict_size, 'nice_len': 273}]
        if method == unhexlify("0303011b"): # BCJ2/LZMA1
            return [{'id':FILTER_LZMA1, 'dict_size':dict_size,  'nice_len': 273}]

        raise UnsupportedCompressionMethodError

    def unpack_raw(self, data, memlimit=None, filters=None):
        # Based on lzma.decompress(...), but allows use of
        # FORMAT_RAW sans embedded end-of-stream marker, since 7z
        # files usually don't have them.
        from lzma import LZMADecompressor, FORMAT_RAW
        results = []
        while True:
            decomp = LZMADecompressor(FORMAT_RAW, memlimit, filters)
            results.append(decomp.decompress(data))
            if not decomp.unused_data:
                return b"".join(results)
            # There is unused data left over. Proceed to next stream.
            data = decomp.unused_data

    def get_pack_positions(self):
        from itertools import accumulate
        packinfo = self.header.main_streams.packinfo
        packoffsets = [self.afterheader+packinfo.packpos]+list(packinfo.packsizes)
        return list(accumulate(packoffsets))

    def get_folder_pack_indexes(self):
        # Create mapping from folder -> pack index
        packindex = 0
        indexes = {}
        for folder in self.header.main_streams.unpackinfo.folders:
            indexes[folder] = packindex
            packindex += self.get_lzma_coder(folder.coders)['numinstreams']
        return indexes

    def get_folder_reader(self):
        # Ensure extraction or verification reads each folder at most once if read in file order.
        # For now, keep entire decompressed folder in RAM.
        packindexes = self.get_folder_pack_indexes()
        cur_folder = None
        cur_unpacked = None
        def inner_fn(folder):
            nonlocal cur_folder, cur_unpacked
            if cur_folder == folder:
                return cur_unpacked

            coder = self.get_lzma_coder(folder.coders)
            numstreams = coder['numinstreams']
            packsizes = self.header.main_streams.packinfo.packsizes

            src_pos = self.get_pack_positions()[packindexes[folder]]
            filecontents = open(self._filename, 'rb').read()
            packindex = packindexes[folder]

            BCJ_GARBAGE = b'abcdefgh'
            if len(folder.coders) == 1:
                raw = filecontents[src_pos:src_pos+sum(packsizes[packindex:packindex+numstreams])]
                cur_unpacked = self.unpack_raw(raw, filters = self.get_lzma_filters(folder.coders))
            elif len(folder.coders) == 2:
                # TODO: assert is BCJ
                # http://sourceforge.net/p/lzmautils/discussion/708858/thread/da2a47a8/
                # "LZMA1+BCJ made by 7-Zip" observes that "In liblzma, the BCJ decoder
                # won't give the last bytes before LZMA1 has told the BCJ decoder that
                # the end of the LZMA1 stream has been reached". Compensate via working
                # LZM1 decoder which allows one to append a few garbage bytes to stream
                # which one /then/ basically runs through the BCJ decoder alone via the
                # .compress(preset = 0) => decompress(FILTER_X86) dance.
                filters = self.get_lzma_filters(folder.coders)
                raw = filecontents[src_pos:src_pos+sum(packsizes[packindex:packindex+numstreams])]
                stunt_unpack = self.unpack_raw(raw, filters = filters)+BCJ_GARBAGE
                stunt_pack = lzma.compress(stunt_unpack, format=lzma.FORMAT_RAW, filters=[{'id':lzma.FILTER_LZMA1, 'preset':0}])

                cur_unpacked = self.unpack_raw(stunt_pack, filters = [{'id':lzma.FILTER_X86}]+filters)
            elif len(folder.coders) == 4:
                # FIX/TODO: assert that it's (copy, lzma1, lzma2)*3, bcj2

                bcj2_bufs = [None for _ in range(3)]
                # coder index => stream index rearrangement
                for ci, si in [(0, 3), (1, 2), (2, 0)]:
                    buf_base = src_pos + sum(packsizes[packindex:packindex+si])
                    buf_packed = filecontents[buf_base:buf_base+packsizes[packindex+si]]
                    bcj2_bufs[ci] = self.unpack_raw(buf_packed, filters = self.get_lzma_filters(folder.coders[ci:ci+1]))

                buf3_base = src_pos + sum(packsizes[packindex:packindex+1])
                buf3 = filecontents[buf3_base:buf3_base+packsizes[packindex+1]]

                cur_unpacked = Bcj2().decode(bcj2_bufs[2], bcj2_bufs[1], bcj2_bufs[0], buf3)
            else:
                raise FormatError

            # Unpacking can over-run by 1 byte
            if len(cur_unpacked) == folder.getUnpackSize()+1 or len(folder.coders) == 2:
                cur_unpacked = cur_unpacked[:folder.getUnpackSize()]
            if len(cur_unpacked) != folder.getUnpackSize():
                raise FormatError
            cur_folder = folder
            return cur_unpacked

        return inner_fn

    def test7z(self):
        read_folder = self.get_folder_reader()

        prev_folder = None
        for member in self.getmembers():
            # does member.size always == member.uncompressed?
            if member.emptystream:
                continue

            if prev_folder != member._folder:
                offset = 0
                prev_folder = member._folder

            data = read_folder(member._folder)[offset:offset+member.uncompressed]

            if crc32(data) != member.digest:
                return False

            offset += member.uncompressed

        return True

class Bcj2:
    def RC_TEST(self):
        if self.buf3_pos == len(self.buf3):
            raise ArchiveError

    def initalize(self, ):
        self.kNumBitModelTotalBits = 11
        self.kBitModelTotal = 1 << self.kNumBitModelTotalBits
        self.p = [self.kBitModelTotal >> 1 for _ in range(256 + 2)]

        # RC_INIT2
        self.code = 0
        self.range = 0xFFFFFFFF
        for i in range(5):
            self.RC_TEST()
            self.code = ((self.code << 8) | self.buf3[self.buf3_pos]) & 0xFFFFFFFF
            self.buf3_pos += 1

    def NORMALIZE(self):
        if self.range < (1<<24): # kTopValue = 1 << kNumTopBits = 1 << 24
            self.RC_TEST()
            self.range = (self.range << 8) & 0xFFFFFFFF
            self.code = ((self.code << 8) | self.buf3[self.buf3_pos]) & 0xFFFFFFFF
            self.buf3_pos += 1

    def decode(self, buf0, buf1, buf2, buf3):
        # Based on public-domain bcj2.c by Igor Pavlov
        buf0_pos, buf1_pos, buf2_pos, self.buf3, self.buf3_pos = 0, 0, 0, buf3, 0
        self.initalize()

        in_pos = 0
        out_buf = BytesIO()
        ttt, self.bound = 0, 0
        b0 = None

        from re import compile
        bcj_re = compile(b'[\xe8\xe9]|\x0f[\x80-\x8f]')
        while True:
            b1 = buf0[in_pos]

            if (b1 & 0xFE) == 0xE8 or (b0 == 0x0F and (b1 & 0xF0) == 0x80):
                out_buf.write(bytes([b1]))
                in_pos += 1
            else:
                # Copy unmodified portions between jumps
                prev_in_pos = in_pos
                try:
                    in_pos = bcj_re.search(buf0, in_pos).end(0)
                except:
                    out_buf.write(buf0[prev_in_pos:])
                    return out_buf.getbuffer()
                b0, b1 = buf0[in_pos-2], buf0[in_pos-1]
                out_buf.write(buf0[prev_in_pos:in_pos])

            # The rest of this function is expensive, but rare
            # relative to decompressed file sizes.
            if buf0_pos == len(buf0):
                break

            p_ind = b0 if b1 == 0xE8 else 256 if b1 == 0xE9 else 257

            ttt = self.p[p_ind]
            kNumMoveBits = 5
            self.bound = (self.range >> self.kNumBitModelTotalBits) * ttt
            # IF_BIT_0
            if self.code < self.bound:
                # UPDATE_0
                self.range = self.bound
                self.p[p_ind] = ttt + ((self.kBitModelTotal - ttt) >> kNumMoveBits)
                self.NORMALIZE()

                b0 = b1
            else:
                # UPDATE_1
                self.range -= self.bound
                self.code -= self.bound
                self.p[p_ind] = ttt - (ttt >> kNumMoveBits)
                self.NORMALIZE()

                if b1 == 0xE8:
                    tmp_bufpos = buf1_pos
                    v = lambda i:buf1[tmp_bufpos+i]
                    if len(buf1) - buf1_pos < 4:
                        raise ArchiveError
                    buf1_pos += 4
                else:
                    tmp_bufpos = buf2_pos
                    v = lambda i:buf2[tmp_bufpos+i]
                    if buf2_pos + 4 > len(buf2):
                        raise ArchiveError
                    buf2_pos += 4

                dest = ((v(0)<<24|(v(1)<<16)|(v(2)<<8)|v(3)) - len(out_buf.getbuffer()) - 4)%(1<<32)
                out_buf.write(pack('<I',dest))
                b0 = (dest >> 24) & 0xff

        return out_buf.getbuffer()

if __name__ == '__main__':
    f = Archive7z('test.7z').test7z()
    f = Archive7z('pylzma.7z').test7z()
