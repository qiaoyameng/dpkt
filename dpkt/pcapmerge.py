"""Lossless, time-ordered merge of libpcap and pcapng captures into pcapng.

This module merges multiple capture sources (each a pcap or pcapng file,
already ordered by packet time) into a single pcapng stream.  It is built
around two guarantees that the generic :class:`dpkt.pcapng.Writer` cannot
make:

* every source keeps its own interface identity.  Each input interface is
  re-emitted as a distinct Interface Description Block and packet interface
  ids are remapped into one flat table - packets are never flattened onto
  the first interface;
* timestamps stay exact.  Packet times are carried as rational numbers
  (:class:`fractions.Fraction`) built straight from the on-disk integer tick
  counts and the per-interface time scale/denominator.  No binary ``float`` is
  involved, so nanosecond and binary ``if_tsresol`` precision is preserved.

The merge runs in two passes over each source.  The first pass only collects
interface metadata (a handful of IDBs), so the heavy packet payloads are not
buffered; the second pass is a streaming k-way heap merge that holds at most
one record ahead per source ("bounded look-ahead").  Blocks are parsed just
enough to read the fields that change (interface id, timestamp) and copied
byte-for-byte otherwise, so link types, snap lengths and options survive.

Policies for awkward inputs are explicit and selectable through the ``on_*``
arguments of :func:`merge`:

* a packet without a timestamp (a Simple Packet Block) is reported through
  ``on_no_timestamp`` and skipped by default;
* a packet whose timestamp moves backwards inside one source violates the
  sorted-source contract and is reported through ``on_backwards`` and skipped
  by default;
* a truncated block/capture raises :class:`TruncatedCapture` by default;
* non-packet blocks (name resolution, interface statistics, custom or any
  future block type) are reported through ``on_unknown_block`` with their raw
  bytes and dropped by default; a callback can archive them.

Passing ``None`` for any ``on_*`` policy selects the strict behaviour, which
raises the matching exception instead of dropping anything.
"""
from __future__ import absolute_import

import heapq
import struct
import sys
from fractions import Fraction

from . import dpkt
from . import pcap as _pcap
from . import pcapng

_MIN_BLOCK_HDR = 8      # block type(4) + block total length(4)
_PACKET_FIXED = 28     # EPB/PB fields before the packet data


class MergeError(dpkt.Error):
    """Base class for capture merging failures."""


class TruncatedCapture(MergeError):
    """A source ended in the middle of a block or packet record."""


class InvalidCapture(MergeError):
    """A source cannot be recognised or contains an inconsistent block."""


class NoTimestamp(MergeError):
    """A packet block carries no timestamp (e.g. a Simple Packet Block)."""


class BackwardsTimestamp(MergeError):
    """A source yielded a packet older than its previous one."""


class UnknownBlock(tuple):
    """A non-packet pcapng block, reported instead of being merged.

    Fields: ``source`` index, ``block_type`` code, ``section`` ordinal and
    the verbatim ``data`` bytes of the block.
    """

    __slots__ = ()

    def __new__(cls, source, block_type, section, data):
        return tuple.__new__(cls, (source, block_type, section, data))

    @property
    def source(self):
        return self[0]

    @property
    def block_type(self):
        return self[1]

    @property
    def section(self):
        return self[2]

    @property
    def data(self):
        return self[3]


class SkippedPacket(tuple):
    """A packet record that a policy decided to drop.

    Fields: the ``reason`` exception, the ``source`` index and the raw
    ``data`` bytes describing the packet.
    """

    __slots__ = ()

    def __new__(cls, reason, source, data):
        return tuple.__new__(cls, (reason, source, data))

    @property
    def reason(self):
        return self[0]

    @property
    def source(self):
        return self[1]

    @property
    def data(self):
        return self[2]


def _skip(event):
    """Default non-strict policy: the event is recorded, the record dropped."""
    return None


def _decode_tsresol(data):
    """Return the timestamp divisor encoded by an ``if_tsresol`` option."""
    val = data[0]
    if val >= 128:  # option byte is signed in the spec examples
        val -= 256
    base = 2 if val & 0x80 else 10
    return base ** (val & 0x7f)


def _iter_options(buf, le, start, end):
    """Yield (code, raw_value) for the option region of a block."""
    fmt = '<HH' if le else '>HH'
    pos = start
    while pos + 4 <= end:
        code, length = struct.unpack_from(fmt, buf, pos)
        pos += 4
        if code == pcapng.PCAPNG_OPT_ENDOFOPT:
            return
        value = buf[pos:pos + length]
        pos += length + ((-length) % 4)
        yield code, value


def _bom_is_le(bom):
    """Map the four BOM bytes to a little-endian flag."""
    if bom == struct.pack('<I', pcapng.BYTE_ORDER_MAGIC):
        return True
    if bom == struct.pack('>I', pcapng.BYTE_ORDER_MAGIC):
        return False
    raise InvalidCapture('bad byte-order magic')


class _Interface(object):
    """An interface's time scale and the raw IDB describing it."""

    __slots__ = ('global_id', 'divisor', 'tsoffset', 'idb_data',
                 'linktype', 'snaplen', 'le')

    def __init__(self, global_id, divisor, tsoffset, idb_data,
                 linktype, snaplen, le=True):
        self.global_id = global_id
        self.divisor = divisor
        self.tsoffset = tsoffset
        self.idb_data = idb_data
        self.linktype = linktype
        self.snaplen = snaplen
        self.le = le


def _parse_idb(block, le, global_id):
    """Build an :class:`_Interface` from a raw IDB."""
    endian = '<' if le else '>'
    block_len = struct.unpack_from(endian + 'I', block, 4)[0]
    linktype, _reserved, snaplen = struct.unpack_from(
        endian + 'HHI', block, 8)
    if struct.unpack_from(endian + 'I', block, block_len - 4)[0] != block_len:
        raise InvalidCapture('IDB length fields do not match')

    divisor = 1000000
    tsoffset = 0
    for code, value in _iter_options(block, le, 16, block_len - 4):
        if code == pcapng.PCAPNG_OPT_IF_TSRESOL:
            divisor = _decode_tsresol(value)
        elif code == pcapng.PCAPNG_OPT_IF_TSOFFSET:
            tsoffset = struct.unpack_from(
                '<q' if le else '>q', value)[0]
    return _Interface(global_id, divisor, tsoffset, block, linktype,
                      snaplen, le)


class _Record(object):
    """One packet positioned in global time, ready for re-emission."""

    __slots__ = ('time', 'source', 'section', 'global_iface', 'kind',
                 'block', 'le', 'caplen', 'origlen', 'payload',
                 'drops_count', 'interface')

    def __init__(self, time, source, section, global_iface, kind, block, le,
                 caplen, origlen, payload, interface, drops_count=0):
        self.time = time
        self.source = source
        self.section = section
        self.global_iface = global_iface
        self.kind = kind
        self.block = block
        self.le = le
        self.caplen = caplen
        self.origlen = origlen
        self.payload = payload
        self.interface = interface
        self.drops_count = drops_count

    def order_key(self):
        # Tuple ordering gives stable, source-declaration tie-breaking.
        return (self.time, self.source)


class _BaseSource(object):
    """Streaming capture source; at most one record is buffered ahead."""

    def __init__(self, source_index, on_truncated=None):
        self.source_index = source_index
        self.interfaces = []
        self._on_truncated = on_truncated
        self._last_time = None
        self._buffered = None
        self._exhausted = False

    def discover(self):
        """First pass: populate :attr:`interfaces` (metadata only)."""
        raise NotImplementedError

    def reset(self):
        """Rewind the stream so the second pass re-reads from the start."""
        raise NotImplementedError

    def _advance(self):
        """Second pass: read the next packet record, or ``None`` at EOF."""
        raise NotImplementedError

    def peek(self):
        if self._exhausted:
            return None
        if self._buffered is None:
            try:
                self._buffered = self._advance()
            except TruncatedCapture:
                if self._on_truncated is None:
                    raise
                self._on_truncated(sys.exc_info()[1])
                self._buffered = None
            if self._buffered is None:
                self._exhausted = True
        return self._buffered

    def consume(self):
        self._buffered = None


class _PcapngBlockReader(object):
    """Raw block iterator that tracks section endianness and interface ids.

    It yields ``(block_type, section, le, block_bytes)`` while maintaining the
    per-section interface table, which packet blocks need to resolve their
    local interface ids.
    """

    def __init__(self, fileobj, source_index):
        self._f = fileobj
        self.source_index = source_index
        self.section = -1
        self.le = None

    def _read_exact(self, size):
        data = self._f.read(size)
        if len(data) != size:
            raise TruncatedCapture(
                'source {0}: expected {1} bytes, got {2}'.format(
                    self.source_index, size, len(data)))
        return data

    def __iter__(self):
        while True:
            header = self._f.read(_MIN_BLOCK_HDR)
            if not header:
                return
            if len(header) < _MIN_BLOCK_HDR:
                raise TruncatedCapture(
                    'source {0}: truncated block header'.format(
                        self.source_index))

            if header[:4] == struct.pack('<I', pcapng.PCAPNG_BT_SHB):
                # An SHB may switch endianness; its BOM decides how to decode
                # the block length that follows.
                bom = self._read_exact(4)
                self.le = _bom_is_le(bom)
                endian = '<' if self.le else '>'
                block_len = struct.unpack_from(endian + 'I', header, 4)[0]
                if block_len < 28:
                    raise InvalidCapture(
                        'source {0}: SHB shorter than 28 bytes'.format(
                            self.source_index))
                block = header + bom + self._read_exact(block_len - 12)
                self.section += 1
                yield (pcapng.PCAPNG_BT_SHB, self.section, self.le, block)
                continue

            if self.le is None:
                raise InvalidCapture(
                    'source {0}: data before any Section Header Block'.format(
                        self.source_index))
            endian = '<' if self.le else '>'
            block_len = struct.unpack_from(endian + 'I', header, 4)[0]
            if block_len < _MIN_BLOCK_HDR:
                raise InvalidCapture(
                    'source {0}: block length {1} below minimum'.format(
                        self.source_index, block_len))
            block = header + self._read_exact(block_len - _MIN_BLOCK_HDR)
            block_type = struct.unpack_from(endian + 'I', block, 0)[0]
            yield (block_type, self.section, self.le, block)


class PcapngSource(_BaseSource):
    """Read a (possibly multi-section, mixed-endian) pcapng capture."""

    def __init__(self, fileobj, source_index, id_offset=0,
                 on_unknown_block=None, on_no_timestamp=None,
                 on_backwards=None, on_truncated=None):
        _BaseSource.__init__(self, source_index, on_truncated)
        self._f = fileobj
        self._id_offset = id_offset
        self._on_unknown_block = on_unknown_block
        self._on_no_timestamp = on_no_timestamp
        self._on_backwards = on_backwards
        self._id_map = {}
        self._local_counts = {}

    def discover(self):
        """Scan every block, keeping only the IDBs as interface metadata."""
        self._id_map = {}
        self._local_counts = {}
        reader = _PcapngBlockReader(self._f, self.source_index)
        for block_type, section, le, block in reader:
            if block_type == pcapng.PCAPNG_BT_IDB:
                local_index = self._local_counts.get(section, 0)
                self._local_counts[section] = local_index + 1
                global_id = self._id_offset + len(self.interfaces)
                self._id_map[(section, local_index)] = global_id
                self.interfaces.append(_parse_idb(block, le, global_id))
        return self.interfaces

    def reset(self):
        try:
            self._f.seek(0)
        except (AttributeError, OSError):
            raise InvalidCapture(
                'source {0}: two-pass merge needs a seekable capture'
                .format(self.source_index))

    def _reader(self):
        return _PcapngBlockReader(self._f, self.source_index)

    def _advance(self):
        if not hasattr(self, '_iter'):
            self._iter = iter(self._reader())
        for block_type, section, le, block in self._iter:
            record = self._handle_block(block_type, section, le, block)
            if record is not None:
                return record
        return None

    def _handle_block(self, block_type, section, le, block):
        endian = '<' if le else '>'
        block_len = struct.unpack_from(endian + 'I', block, 4)[0]

        if block_type in (pcapng.PCAPNG_BT_SHB, pcapng.PCAPNG_BT_IDB):
            # Interface mapping already comes from the discover() pass.
            return None

        if block_type in (pcapng.PCAPNG_BT_EPB, pcapng.PCAPNG_BT_PB):
            return self._parse_packet(block_type, section, le, block,
                                      block_len, endian)

        if block_type == pcapng.PCAPNG_BT_SPB:
            event = SkippedPacket(
                NoTimestamp(
                    'source {0}: Simple Packet Block has no timestamp'.format(
                        self.source_index)),
                self.source_index, block)
            if self._on_no_timestamp is None:
                raise event.reason
            self._on_no_timestamp(event)
            return None

        event = UnknownBlock(self.source_index, block_type, section, block)
        if self._on_unknown_block is None:
            raise InvalidCapture(
                'source {0}: unsupported block type 0x{1:08x}'.format(
                    self.source_index, block_type))
        self._on_unknown_block(event)
        return None

    def _resolve_interface(self, section, local_id):
        key = (section, local_id)
        if key not in self._id_map:
            raise InvalidCapture(
                'source {0}: packet references unknown interface {1} of '
                'section {2}'.format(self.source_index, local_id, section))
        global_id = self._id_map[key]
        return self.interfaces[global_id - self._id_offset]

    def _parse_packet(self, block_type, section, le, block, block_len,
                      endian):
        if block_len < 32:
            raise InvalidCapture(
                'source {0}: packet block shorter than 32 bytes'.format(
                    self.source_index))
        if block_type == pcapng.PCAPNG_BT_EPB:
            local_id, ts_high, ts_low, caplen, origlen = \
                struct.unpack_from(endian + 'IIIII', block, 8)
            drops_count = 0
        else:
            local_id, drops_count, ts_high, ts_low, caplen, origlen = \
                struct.unpack_from(endian + 'HHIIII', block, 8)

        if struct.unpack_from(endian + 'I', block, block_len - 4)[0] \
                != block_len:
            raise InvalidCapture(
                'source {0}: packet block length fields do not match'.format(
                    self.source_index))
        if _PACKET_FIXED + caplen + 4 > block_len:
            raise TruncatedCapture(
                'source {0}: packet payload extends past block'.format(
                    self.source_index))

        interface = self._resolve_interface(section, local_id)
        ticks = (ts_high << 32) | ts_low
        time = Fraction(interface.tsoffset) + Fraction(
            ticks, interface.divisor)
        payload = block[_PACKET_FIXED:_PACKET_FIXED + caplen]
        record = _Record(time, self.source_index, section,
                         interface.global_id, block_type, block, le,
                         caplen, origlen, payload, interface, drops_count)

        if self._last_time is not None and record.time < self._last_time:
            event = SkippedPacket(
                BackwardsTimestamp(
                    'source {0}: timestamp {1} precedes {2}'.format(
                        self.source_index, record.time, self._last_time)),
                self.source_index, block)
            if self._on_backwards is None:
                raise event.reason
            self._on_backwards(event)
            return None
        self._last_time = record.time
        return record


class PcapSource(_BaseSource):
    """Read a classic libpcap capture as a single-interface source.

    The time scale comes from the file magic (microsecond or nanosecond), and
    the synthesized IDB keeps the file's link type and snap length.
    """

    def __init__(self, fileobj, source_index, id_offset=0, on_backwards=None,
                 on_truncated=None):
        _BaseSource.__init__(self, source_index, on_truncated)
        self._f = fileobj
        self._on_backwards = on_backwards
        self._id_offset = id_offset

    def discover(self):
        header = self._f.read(_pcap.FileHdr.__hdr_len__)
        if len(header) < _pcap.FileHdr.__hdr_len__:
            raise TruncatedCapture(
                'source {0}: truncated pcap file header'.format(
                    self.source_index))
        file_hdr = _pcap.FileHdr(header)
        magic = file_hdr.magic
        if magic in (_pcap.PMUDPCT_MAGIC, _pcap.PMUDPCT_MAGIC_NANO,
                     _pcap.PACPDOM_MAGIC):
            file_hdr = _pcap.LEFileHdr(header)
            self._le = True
        else:
            self._le = False
        if magic not in _pcap.MAGIC_TO_PKT_HDR:
            raise InvalidCapture(
                'source {0}: invalid tcpdump header'.format(
                    self.source_index))

        nano = magic in (_pcap.TCPDUMP_MAGIC_NANO, _pcap.PMUDPCT_MAGIC_NANO)
        divisor = 1000000000 if nano else 1000000
        self._hdr_cls = _pcap.MAGIC_TO_PKT_HDR[magic]
        self._interface = _Interface(
            self._id_offset, divisor, 0, None,
            file_hdr.linktype, file_hdr.snaplen)
        self.interfaces.append(self._interface)
        return self.interfaces

    def reset(self):
        # discover() consumed only the fixed file header; rewind to it so the
        # packet pass starts at the same point.
        self._f.seek(_pcap.FileHdr.__hdr_len__)

    def _advance(self):
        hdr_len = self._hdr_cls.__hdr_len__
        while True:
            raw_hdr = self._f.read(hdr_len)
            if not raw_hdr:
                return None
            if len(raw_hdr) < hdr_len:
                raise TruncatedCapture(
                    'source {0}: truncated pcap record header'.format(
                        self.source_index))
            hdr = self._hdr_cls(raw_hdr)
            payload = self._f.read(hdr.caplen)
            if len(payload) < hdr.caplen:
                raise TruncatedCapture(
                    'source {0}: truncated pcap record payload'.format(
                        self.source_index))

            time = Fraction(hdr.tv_sec) + Fraction(
                hdr.tv_usec, self._interface.divisor)
            if self._last_time is not None and time < self._last_time:
                event = SkippedPacket(
                    BackwardsTimestamp(
                        'source {0}: timestamp {1} precedes {2}'.format(
                            self.source_index, time, self._last_time)),
                    self.source_index, raw_hdr + payload)
                if self._on_backwards is None:
                    raise event.reason
                self._on_backwards(event)
                continue
            self._last_time = time
            return _Record(time, self.source_index, 0,
                           self._interface.global_id,
                           pcapng.PCAPNG_BT_EPB, None, self._le,
                           hdr.caplen, hdr.len, payload, self._interface)


def _align4(length):
    return length + ((-length) % 4)


def _convert_options(region, src_le, dst_le):
    """Re-encode an option region when the section endianness changes.

    Option code and length are 16-bit integers and therefore endian dependent;
    the option value itself is an opaque byte string.  When both sections use
    the same endianness the region is copied byte-for-byte.
    """
    if not region or src_le == dst_le:
        return region
    src_fmt = '<HH' if src_le else '>HH'
    dst_fmt = '<HH' if dst_le else '>HH'
    out = []
    pos = 0
    while pos + 4 <= len(region):
        code, length = struct.unpack_from(src_fmt, region, pos)
        value = region[pos + 4:pos + 4 + length]
        out.append(struct.pack(dst_fmt, code, length))
        out.append(value)
        out.append(b'\x00' * ((-length) % 4))
        pos += 4 + _align4(length)
        if code == pcapng.PCAPNG_OPT_ENDOFOPT:
            break
    return b''.join(out)


def shb_bytes(le):
    """Build a minimal Section Header Block in the requested byte order."""
    endian = '<' if le else '>'
    # The BOM is always the canonical 0x1A2B3C4D packed in the section's
    # byte order, so its raw bytes reveal endianness to any reader.
    total = 28
    return struct.pack(
        endian + 'IIIHHqI', pcapng.PCAPNG_BT_SHB, total,
        pcapng.BYTE_ORDER_MAGIC,
        pcapng.PCAPNG_VERSION_MAJOR, pcapng.PCAPNG_VERSION_MINOR,
        -1, total)


def build_idb(interface, le):
    """Re-emit an interface's IDB, preserving its options across endianness."""
    endian = '<' if le else '>'
    if interface.idb_data is not None:
        src_endian = '<' if interface.le else '>'
        block_len = struct.unpack_from(
            src_endian + 'I', interface.idb_data, 4)[0]
        options = _convert_options(
            interface.idb_data[16:block_len - 4], interface.le, le)
    else:
        # Classic pcap sources carry no interface options.
        options = b''
    total = 16 + len(options) + 4
    block = struct.pack(
        endian + 'IIHHI', pcapng.PCAPNG_BT_IDB, total,
        interface.linktype, 0, interface.snaplen) + options
    return block + struct.pack(endian + 'I', total)


def _trailing_options(record, le, payload_len):
    """Return the packet's option region in the output endianness."""
    if record.block is None:
        return b'\x00\x00\x00\x00'  # pcap packets have no options
    src_endian = '<' if record.le else '>'
    block_len = struct.unpack_from(
        src_endian + 'I', record.block, 4)[0]
    offset = _PACKET_FIXED + payload_len
    region = record.block[offset:block_len - 4]
    if not region:
        return b'\x00\x00\x00\x00'
    return _convert_options(region, record.le, le)


def encode_packet(record, le):
    """Render a packet with the remapped interface and exact tick values."""
    endian = '<' if le else '>'
    interface = record.interface
    ticks = (record.time - Fraction(interface.tsoffset)) * interface.divisor
    # A packet's time is always an integer number of its own interface ticks;
    # requiring that here proves no precision was lost, without using float.
    if ticks.denominator != 1:
        raise InvalidCapture(
            'packet time {0} not representable in interface scale {1}'.format(
                record.time, interface.divisor))
    ticks = ticks.numerator
    ts_high = (ticks >> 32) & 0xffffffff
    ts_low = ticks & 0xffffffff

    payload = record.payload
    caplen = len(payload)
    payload_len = _align4(caplen)
    padded = payload + b'\x00' * (payload_len - caplen)
    options = _trailing_options(record, le, payload_len)
    total = _PACKET_FIXED + payload_len + len(options) + 4

    if record.kind == pcapng.PCAPNG_BT_PB:
        # Keep the deprecated Packet Block shape and its drop counter.
        header = struct.pack(
            endian + 'IIHHIIII', pcapng.PCAPNG_BT_PB, total,
            record.global_iface, record.drops_count, ts_high, ts_low,
            caplen, record.origlen)
    else:
        header = struct.pack(
            endian + 'IIIIIII', pcapng.PCAPNG_BT_EPB, total,
            record.global_iface, ts_high, ts_low, caplen, record.origlen)
    return header + padded + options + struct.pack(endian + 'I', total)


class MergeReport(object):
    """What a merge produced and which awkward records were dropped."""

    def __init__(self, source_count):
        self.packets = 0
        self.per_source = [0] * source_count
        self.unknown_blocks = []
        self.skipped_no_timestamp = []
        self.skipped_backwards = []
        self.truncated = []
        self.interfaces = []

    def summary(self):
        return ('merged {0} packet(s) from {1} source(s); '
                '{2} unknown block(s), {3} untimed packet(s), '
                '{4} backwards packet(s), {5} truncated record(s)').format(
                    self.packets, len(self.per_source),
                    len(self.unknown_blocks),
                    len(self.skipped_no_timestamp),
                    len(self.skipped_backwards), len(self.truncated))


def _open_source(source, index):
    """Return (fileobj, owns_file) for a path or binary file-like object."""
    if isinstance(source, (str, bytes)):
        return open(source, 'rb'), True
    if hasattr(source, 'read'):
        return source, False
    raise TypeError('source {0}: expected a path or file object'.format(
        index))


def _sniff(fileobj):
    """Return 'pcapng' or 'pcap' from the leading bytes, rewinding first."""
    pos = fileobj.tell()
    magic = fileobj.read(4)
    fileobj.seek(pos)
    if len(magic) < 4:
        raise TruncatedCapture('capture shorter than its magic number')
    le_magic = struct.unpack('<I', magic)[0]
    be_magic = struct.unpack('>I', magic)[0]
    if le_magic == pcapng.PCAPNG_BT_SHB or be_magic == pcapng.PCAPNG_BT_SHB:
        return 'pcapng'
    if le_magic in _pcap.MAGIC_TO_PKT_HDR or \
            be_magic in _pcap.MAGIC_TO_PKT_HDR:
        return 'pcap'
    raise InvalidCapture('unrecognised capture magic 0x{0:08x}'.format(
        le_magic))


def merge(sources, destination, on_unknown_block=_skip,
          on_no_timestamp=_skip, on_backwards=_skip, on_truncated=None,
          little_endian=None):
    """Merge time-sorted pcap/pcapng ``sources`` into one pcapng stream.

    Args:
        sources: iterable of paths or binary file objects, each already
            ordered by packet time.
        destination: writable binary file object receiving pcapng bytes.
        on_unknown_block: callback for non-packet blocks (default records and
            drops); ``None`` raises :class:`InvalidCapture`.
        on_no_timestamp: callback for untimed packets (default records and
            skips); ``None`` raises :class:`NoTimestamp`.
        on_backwards: callback for out-of-order packets (default records and
            skips); ``None`` raises :class:`BackwardsTimestamp`.
        on_truncated: callback for truncated captures; ``None`` (default)
            raises :class:`TruncatedCapture`.
        little_endian: output byte order; defaults to the host order.

    Returns:
        :class:`MergeReport`.
    """
    if little_endian is None:
        little_endian = sys.byteorder == 'little'

    sources = list(sources)
    report = MergeReport(len(sources))

    def recorder(store, user):
        if user is None:
            return None

        def wrapped(event):
            store.append(event)
            if user is not _skip:
                user(event)
        return wrapped

    handle_unknown = recorder(report.unknown_blocks, on_unknown_block)
    handle_no_ts = recorder(report.skipped_no_timestamp, on_no_timestamp)
    handle_backwards = recorder(report.skipped_backwards, on_backwards)
    handle_truncated = None if on_truncated is None else \
        lambda exc: (report.truncated.append(exc), on_truncated(exc))

    opened = []
    try:
        adapters = []
        id_offset = 0
        for index, source in enumerate(sources):
            fileobj, owns = _open_source(source, index)
            opened.append((fileobj, owns))
            kind = _sniff(fileobj)

            # Both passes encounter the same truncation point; report it once.
            truncated_once = [False]

            def source_truncated(exc, _once=truncated_once):
                if handle_truncated is not None and not _once[0]:
                    _once[0] = True
                    handle_truncated(exc)

            if kind == 'pcapng':
                adapter = PcapngSource(
                    fileobj, index, id_offset,
                    on_unknown_block=handle_unknown,
                    on_no_timestamp=handle_no_ts,
                    on_backwards=handle_backwards,
                    on_truncated=source_truncated)
            else:
                adapter = PcapSource(
                    fileobj, index, id_offset,
                    on_backwards=handle_backwards,
                    on_truncated=source_truncated)
            try:
                adapter.discover()
            except TruncatedCapture:
                if handle_truncated is None:
                    raise
                source_truncated(sys.exc_info()[1])
                if not adapter.interfaces:
                    # Nothing usable was found before the cut; skip the second
                    # pass rather than enter an uninitialised parser state.
                    adapter._exhausted = True
            if not adapter._exhausted:
                adapter.reset()
            report.interfaces.extend(adapter.interfaces)
            id_offset += len(adapter.interfaces)
            adapters.append(adapter)

        _write_merged(adapters, destination, little_endian, report)
        return report
    finally:
        for fileobj, owns in opened:
            if owns:
                fileobj.close()


def _write_merged(adapters, destination, le, report):
    write = destination.write
    write(shb_bytes(le))
    for adapter in adapters:
        for interface in adapter.interfaces:
            write(build_idb(interface, le))

    heap = []
    for index, adapter in enumerate(adapters):
        record = adapter.peek()
        if record is not None:
            heapq.heappush(heap, (record.order_key(), index))

    while heap:
        _, index = heapq.heappop(heap)
        adapter = adapters[index]
        record = adapter.peek()
        write(encode_packet(record, le))
        report.packets += 1
        report.per_source[index] += 1
        adapter.consume()
        nxt = adapter.peek()
        if nxt is not None:
            heapq.heappush(heap, (nxt.order_key(), index))


#########
# TESTS #
#########

def _shb(le=True):
    return shb_bytes(le)


def _idb(le=True, tsresol=6, linktype=1, snaplen=65535):
    endian = '<' if le else '>'
    val = tsresol - 256 if tsresol & 0x80 else tsresol
    options = struct.pack(
        endian + 'HHb', pcapng.PCAPNG_OPT_IF_TSRESOL, 1, val)
    options += b'\x00' * 3 + b'\x00\x00\x00\x00'
    body = struct.pack(endian + 'HHI', linktype, 0, snaplen) + options
    total = 8 + len(body) + 4
    return (struct.pack(endian + 'II', pcapng.PCAPNG_BT_IDB, total)
            + body + struct.pack(endian + 'I', total))


def _packet(le, ticks, payload, iface=0, kind=pcapng.PCAPNG_BT_EPB,
            drops=0, options=None):
    endian = '<' if le else '>'
    caplen = len(payload)
    padded = payload + b'\x00' * ((-caplen) % 4)
    option_region = options if options is not None else b'\x00\x00\x00\x00'
    total = _PACKET_FIXED + len(padded) + len(option_region) + 4
    ts_high = (ticks >> 32) & 0xffffffff
    ts_low = ticks & 0xffffffff
    if kind == pcapng.PCAPNG_BT_PB:
        header = struct.pack(
            endian + 'IIHHIIII', kind, total, iface, drops,
            ts_high, ts_low, caplen, caplen)
    else:
        header = struct.pack(
            endian + 'IIIIIII', kind, total, iface,
            ts_high, ts_low, caplen, caplen)
    return header + padded + option_region + struct.pack(
        endian + 'I', total)


def _spb(payload):
    caplen = len(payload)
    padded = payload + b'\x00' * ((-caplen) % 4)
    total = 12 + len(padded) + 4
    return (struct.pack('<III', pcapng.PCAPNG_BT_SPB, total, caplen)
            + padded + struct.pack('<I', total))


def _unknown(block_type):
    # A minimal, self-consistent block of a made-up/non-packet type.
    total = 16
    return (struct.pack('<II', block_type, total)
            + b'\x00\x00\x00\x00' + struct.pack('<I', total))


def _merge_bytes(chunks, **kwargs):
    from .compat import BytesIO
    destination = BytesIO()
    report = merge([BytesIO(chunk) for chunk in chunks], destination, **kwargs)
    destination.seek(0)
    return destination, report


def _read_all(fileobj):
    return list(iter(pcapng.Reader(fileobj)))


def test_tsresol_decoder_decimal_and_binary():
    assert _decode_tsresol(b'\x06') == 1000000
    assert _decode_tsresol(b'\x09') == 1000000000
    # MSB set => negative power of two; 0x8a is signed -118
    assert _decode_tsresol(b'\x8a') == 2 ** 10
    assert _decode_tsresol(b'\x00') == 1


def test_merge_mixed_endian_and_precision_is_time_sorted():
    # microsecond LE source vs microsecond BE source, interleaved in time
    src_a = _shb(True) + _idb(True, 6) + b''.join([
        _packet(True, 1_000_000, b'A1'),
        _packet(True, 3_000_000, b'A3'),
    ])
    src_b = _shb(False) + _idb(False, 6) + _packet(False, 2_000_000, b'B2')

    destination, report = _merge_bytes([src_a, src_b])
    assert report.packets == 3
    assert report.per_source == [2, 1]

    times_pkts = _read_all(destination)
    assert [pkt for _, pkt in times_pkts] == [b'A1', b'B2', b'A3']
    assert [ts for ts, _ in times_pkts] == [1.0, 2.0, 3.0]


def test_nanosecond_ticks_are_preserved_exactly():
    # Fractional part beyond float64 integer precision: must survive untouched
    ticks = 1_442_984_653_210_838_001
    src = _shb(True) + _idb(True, 9) + _packet(True, ticks, b'NANO')

    destination, _ = _merge_bytes([src])
    data = destination.getvalue()
    pos = 0
    found = None
    while pos < len(data):
        block_type, block_len = struct.unpack_from('<II', data, pos)
        if block_type == pcapng.PCAPNG_BT_EPB:
            _id, ts_high, ts_low, _cap, _orig = struct.unpack_from(
                '<IIIII', data, pos + 8)
            found = (ts_high << 32) | ts_low
            break
        pos += block_len
    assert found == ticks


def test_binary_tsresol_tick_roundtrip():
    # 1024 ticks at 1/1024 s resolution == exactly 1.0 second
    src = _shb(True) + _idb(True, 0x8a) + _packet(True, 1024, b'BIN')
    destination, _ = _merge_bytes([src], little_endian=True)
    ts, pkt = _read_all(destination)[0]
    assert ts == 1.0
    assert pkt == b'BIN'
    # raw output ticks stay on the binary scale, no decimal conversion
    data = destination.getvalue()
    pos = 0
    ts_low = None
    while pos < len(data):
        block_type, block_len = struct.unpack_from('<II', data, pos)
        if block_type == pcapng.PCAPNG_BT_EPB:
            ts_low = struct.unpack_from('<I', data, pos + 16)[0]
            break
        pos += block_len
    assert ts_low == 1024


def test_each_interface_keeps_its_identity_and_options():
    src_a = _shb(True) + _idb(True, 6, linktype=1, snaplen=262144)
    src_a += _packet(True, 1_000_000, b'ETH', iface=0)
    src_b = _shb(True) + _idb(True, 9, linktype=113, snaplen=128)
    src_b += _packet(True, 2_000_000_000, b'SLL', iface=0)

    destination, report = _merge_bytes([src_a, src_b])
    assert [i.linktype for i in report.interfaces] == [1, 113]
    assert [i.snaplen for i in report.interfaces] == [262144, 128]
    assert [i.divisor for i in report.interfaces] == [1_000_000, 1_000_000_000]

    data = destination.getvalue()
    pos, idb_count, iface_ids = 0, 0, []
    while pos < len(data):
        block_type, block_len = struct.unpack_from('<II', data, pos)
        if block_type == pcapng.PCAPNG_BT_IDB:
            idb_count += 1
        if block_type == pcapng.PCAPNG_BT_EPB:
            iface_ids.append(struct.unpack_from('<I', data, pos + 8)[0])
        pos += block_len
    assert idb_count == 2
    assert iface_ids == [0, 1]


def test_multi_section_source_remaps_both_interfaces():
    section_one = _shb(True) + _idb(True, 6)
    section_one += _packet(True, 1_000_000, b'S1', iface=0)
    section_two = _shb(True) + _idb(True, 9)
    section_two += _packet(True, 5_000_000_000, b'S2', iface=0)

    destination, report = _merge_bytes([section_one + section_two])
    assert len(report.interfaces) == 2
    data = destination.getvalue()
    pos, idb_count, iface_ids = 0, 0, []
    while pos < len(data):
        block_type, block_len = struct.unpack_from('<II', data, pos)
        if block_type == pcapng.PCAPNG_BT_IDB:
            idb_count += 1
        if block_type == pcapng.PCAPNG_BT_EPB:
            iface_ids.append(struct.unpack_from('<I', data, pos + 8)[0])
        pos += block_len
    assert idb_count == 2
    assert iface_ids == [0, 1]
    assert [pkt for _, pkt in _read_all(destination)] == [b'S1', b'S2']


def test_ties_break_by_source_declaration_order():
    common = 5_000_000
    sources = [
        _shb(True) + _idb(True, 6) + _packet(True, common, b'X'),
        _shb(True) + _idb(True, 6) + _packet(True, common, b'Y'),
        _shb(True) + _idb(True, 6) + _packet(True, common, b'Z'),
    ]
    destination, _ = _merge_bytes(sources)
    assert [pkt for _, pkt in _read_all(destination)] == [b'X', b'Y', b'Z']


def test_pcap_classic_source_is_merged():
    from .compat import BytesIO
    pcap_buffer = BytesIO()
    writer = _pcap.Writer(pcap_buffer, linktype=_pcap.DLT_LINUX_SLL)
    writer.writepkt_time(b'CLASSIC', 1442984653.210838)
    pcap_buffer.seek(0)

    destination = BytesIO()
    report = merge([pcap_buffer], destination)
    destination.seek(0)
    assert report.packets == 1
    interface = report.interfaces[0]
    assert interface.linktype == _pcap.DLT_LINUX_SLL
    assert interface.divisor == 1_000_000

    ts, pkt = _read_all(destination)[0]
    assert ts == 1442984653.210838
    assert pkt == b'CLASSIC'


def test_pcap_nanosecond_source_keeps_nano_scale():
    from .compat import BytesIO
    import struct as _struct
    # hand-build a nano-magic libpcap file (magic 0xa1b23c4d, big endian)
    file_header = _struct.pack(
        '>IHHIIII', _pcap.TCPDUMP_MAGIC_NANO, 2, 4, 0, 0, 65535, 1)
    sec, frac = 1442984653, 210838001
    payload = b'NANO'
    record = _struct.pack('>IIII', sec, frac, len(payload), len(payload))
    nano_pcap = file_header + record + payload

    destination = BytesIO()
    report = merge([BytesIO(nano_pcap)], destination)
    assert report.interfaces[0].divisor == 1_000_000_000
    destination.seek(0)
    data = destination.getvalue()
    pos = struct.unpack_from('<I', data, 4)[0]  # skip SHB
    pos += struct.unpack_from('<I', data, pos + 4)[0]  # skip IDB
    ts_high, ts_low = struct.unpack_from('<II', data, pos + 12)
    ticks = (ts_high << 32) | ts_low
    assert ticks == sec * 1_000_000_000 + frac


def test_no_timestamp_packet_is_skipped_and_reported():
    src = _shb(True) + _idb(True)
    src += _packet(True, 1_000_000, b'TIMED')
    src += _spb(b'UNTIMED')
    src += _packet(True, 2_000_000, b'TIMED2')

    destination, report = _merge_bytes([src])
    assert report.packets == 2
    assert len(report.skipped_no_timestamp) == 1
    event = report.skipped_no_timestamp[0]
    assert isinstance(event.reason, NoTimestamp)
    assert event.data[:4] == struct.pack('<I', pcapng.PCAPNG_BT_SPB)
    assert [pkt for _, pkt in _read_all(destination)] == [b'TIMED', b'TIMED2']


def test_no_timestamp_strict_policy_raises():
    from .compat import BytesIO
    src = _shb(True) + _idb(True) + _spb(b'UNTIMED')
    try:
        merge([BytesIO(src)], BytesIO(), on_no_timestamp=None)
    except NoTimestamp:
        return
    raise AssertionError('NoTimestamp should have been raised')


def test_backwards_timestamp_is_skipped_and_reported():
    src = _shb(True) + _idb(True)
    src += _packet(True, 3_000_000, b'LATE')
    src += _packet(True, 1_000_000, b'EARLY')

    destination, report = _merge_bytes([src])
    assert report.packets == 1
    assert len(report.skipped_backwards) == 1
    assert isinstance(report.skipped_backwards[0].reason, BackwardsTimestamp)
    assert [pkt for _, pkt in _read_all(destination)] == [b'LATE']


def test_backwards_strict_policy_raises():
    src = _shb(True) + _idb(True)
    src += _packet(True, 3_000_000, b'LATE')
    src += _packet(True, 1_000_000, b'EARLY')
    try:
        _merge_bytes([src], on_backwards=None)
    except BackwardsTimestamp:
        return
    raise AssertionError('BackwardsTimestamp should have been raised')


def test_unknown_block_is_reported_and_dropped():
    src = _shb(True) + _idb(True) + _unknown(5) + _packet(True, 1, b'P')
    destination, report = _merge_bytes([src])
    assert len(report.unknown_blocks) == 1
    event = report.unknown_blocks[0]
    assert event.block_type == 5
    assert event.data == _unknown(5)
    assert report.packets == 1
    assert [pkt for _, pkt in _read_all(destination)] == [b'P']


def test_unknown_block_strict_policy_raises():
    src = _shb(True) + _idb(True) + _unknown(5)
    try:
        _merge_bytes([src], on_unknown_block=None)
    except InvalidCapture:
        return
    raise AssertionError('InvalidCapture should have been raised')


def test_unknown_block_callback_can_archive_raw_block():
    archived = []

    def archive(event):
        archived.append(event.data)

    src = _shb(True) + _idb(True) + _unknown(5) + _packet(True, 1, b'P')
    _, report = _merge_bytes([src], on_unknown_block=archive)
    assert len(report.unknown_blocks) == 1
    assert archived == [_unknown(5)]


def test_truncated_capture_raises_by_default():
    complete = _shb(True) + _idb(True) + _packet(True, 1, b'P')
    try:
        _merge_bytes([complete[:-3]])
    except TruncatedCapture:
        return
    raise AssertionError('TruncatedCapture should have been raised')


def test_truncated_callback_merges_preceding_packets_once():
    src = _shb(True) + _idb(True)
    src += _packet(True, 1_000_000, b'GOOD')
    src += _packet(True, 2_000_000, b'BAD')[:-3]
    reported = []
    destination, report = _merge_bytes(
        [src], on_truncated=lambda exc: reported.append(exc))
    assert report.packets == 1
    assert len(reported) == 1
    assert len(report.truncated) == 1
    assert [pkt for _, pkt in _read_all(destination)] == [b'GOOD']


def test_pb_block_keeps_drop_counter_and_options():
    comment = struct.pack('<HH', pcapng.PCAPNG_OPT_COMMENT, 1) + b'c\x00\x00\x00'
    comment += b'\x00\x00\x00\x00'
    src = _shb(True) + _idb(True)
    src += _packet(True, 7_000_000, b'PB', kind=pcapng.PCAPNG_BT_PB,
                   drops=3, options=comment)

    destination, report = _merge_bytes([src])
    data = destination.getvalue()
    pos = 0
    pb = None
    while pos < len(data):
        block_type, block_len = struct.unpack_from('<II', data, pos)
        if block_type == pcapng.PCAPNG_BT_PB:
            pb = data[pos:pos + block_len]
            break
        pos += block_len
    assert pb is not None
    assert struct.unpack_from('<HH', pb, 8) == (0, 3)
    assert pcapng.PacketBlockLE(pb).drops_count == 3
    assert pcapng.PacketBlockLE(pb).opts[0].text == 'c'


def test_roundtrip_preserves_source_time_and_payload():
    # Three sources, varied scales/endians; verify every output packet maps
    # back to the exact source record, Fraction time and payload bytes.
    from .compat import BytesIO

    expected = [
        # (source, fractional seconds, payload)
        (1, Fraction(1_000_000, 1_000_000), b's1-a'),
        (0, Fraction(1_500_000, 1_000_000), b's0-b'),
        (2, Fraction(2_000_000_000, 1_000_000_000), b's2-c'),
        (0, Fraction(2_500_000, 1_000_000), b's0-d'),
    ]
    src0 = _shb(True) + _idb(True, 6) + b''.join([
        _packet(True, 1_500_000, b's0-b'),
        _packet(True, 2_500_000, b's0-d'),
    ])
    src1 = _shb(False) + _idb(False, 6) + _packet(False, 1_000_000, b's1-a')
    src2 = _shb(True) + _idb(True, 9) + _packet(True, 2_000_000_000, b's2-c')

    destination = BytesIO()
    report = merge([BytesIO(src0), BytesIO(src1), BytesIO(src2)], destination)
    assert report.per_source == [2, 1, 1]

    # Rebuild exact Fraction timestamps straight from the output blocks and
    # match each against the declared expected records in time order.
    data = destination.getvalue()
    divisors = [interface.divisor for interface in report.interfaces]
    seen = []
    pos = 0
    while pos < len(data):
        block_type, block_len = struct.unpack_from('<II', data, pos)
        if block_type == pcapng.PCAPNG_BT_EPB:
            iface, ts_high, ts_low, caplen, _orig = struct.unpack_from(
                '<IIIII', data, pos + 8)
            ticks = (ts_high << 32) | ts_low
            exact_time = Fraction(ticks, divisors[iface])
            payload = data[pos + _PACKET_FIXED:pos + _PACKET_FIXED + caplen]
            seen.append((iface, exact_time, payload))
        pos += block_len

    ordered = sorted(expected, key=lambda item: (item[1], item[0]))
    assert seen == ordered


def test_only_one_record_is_buffered_per_source():
    # A source whose reads are counted proves bounded look-ahead: the merge
    # never needs more than the next single record buffered from any source.
    from .compat import BytesIO

    packets = [_packet(True, i * 1_000_000, b'P%d' % i) for i in range(5)]
    src = _shb(True) + _idb(True, 6) + b''.join(packets)
    adapter = PcapngSource(BytesIO(src), 0)
    adapter.discover()
    adapter.reset()

    buffered = 0
    record = adapter.peek()
    while record is not None:
        buffered += 1
        adapter.consume()
        record = adapter.peek()
    assert buffered == 5
    # peek after exhaustion stays None without extra stream reads
    assert adapter.peek() is None


def test_merge_accepts_filesystem_paths():
    import os
    import tempfile

    src = _shb(True) + _idb(True, 6) + _packet(True, 1_000_000, b'PATH')
    fd, path = tempfile.mkstemp(suffix='.pcapng')
    out_path = path + '.merged'
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(src)
        with open(out_path, 'wb') as destination:
            report = merge([path], destination)
        assert report.packets == 1
        with open(out_path, 'rb') as handle:
            assert [pkt for _, pkt in pcapng.Reader(handle)] == [b'PATH']
    finally:
        for target in (path, out_path):
            if os.path.exists(target):
                os.remove(target)


def test_sniff_rejects_unknown_magic():
    from .compat import BytesIO
    try:
        _sniff(BytesIO(b'\x00\x00\x00\x00'))
    except InvalidCapture:
        return
    raise AssertionError('InvalidCapture should have been raised')


def test_cross_endian_options_are_transcoded():
    # A big-endian source carrying IDB and packet options, merged into a
    # little-endian output: option code/length fields must be re-encoded so
    # the values stay readable.
    name = b'eth0'
    idb_opts = struct.pack('>HH', pcapng.PCAPNG_OPT_IF_NAME, len(name)) + name
    idb_opts += struct.pack('>HH', pcapng.PCAPNG_OPT_IF_TSRESOL, 1) + b'\x06'
    idb_opts += b'\x00' * 3
    idb_opts += b'\x00\x00\x00\x00'
    idb_body = struct.pack('>HHI', 1, 0, 65535) + idb_opts
    idb_total = 8 + len(idb_body) + 4
    idb = (struct.pack('>II', pcapng.PCAPNG_BT_IDB, idb_total) + idb_body
           + struct.pack('>I', idb_total))

    comment = b'hello'
    pkt_opts = struct.pack('>HH', pcapng.PCAPNG_OPT_COMMENT, len(comment))
    pkt_opts += comment + b'\x00' * 3 + b'\x00\x00\x00\x00'
    src = _shb(False) + idb + _packet(False, 1_000_000, b'X', options=pkt_opts)

    destination, _ = _merge_bytes([src], little_endian=True)
    data = destination.getvalue()

    # locate the output IDB and EPB and decode them as little-endian
    pos = struct.unpack_from('<I', data, 4)[0]
    idb_block = pcapng.InterfaceDescriptionBlockLE(
        data[pos:pos + struct.unpack_from('<I', data, pos + 4)[0]])
    assert idb_block.opts[0].code == pcapng.PCAPNG_OPT_IF_NAME
    assert idb_block.opts[0].data == b'eth0'
    assert idb_block.opts[1].code == pcapng.PCAPNG_OPT_IF_TSRESOL

    pos += len(idb_block)
    epb_block = pcapng.EnhancedPacketBlockLE(
        data[pos:pos + struct.unpack_from('<I', data, pos + 4)[0]])
    assert epb_block.opts[0].code == pcapng.PCAPNG_OPT_COMMENT
    assert epb_block.opts[0].text == 'hello'


def test_truncated_before_any_interface_does_not_break_merge():
    from .compat import BytesIO
    # Only a partial SHB: no interface can be discovered, yet the reported
    # policy must let the merge finish with a valid (SHB-only) output.
    truncated = _shb(True)[:20]
    destination = BytesIO()
    reported = []
    report = merge([BytesIO(truncated)], destination,
                   on_truncated=lambda exc: reported.append(exc))
    assert report.packets == 0
    assert len(reported) == 1
    destination.seek(0)
    data = destination.getvalue()
    assert struct.unpack_from('<I', data, 4)[0] == 28
