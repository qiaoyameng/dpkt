# $Id: netflow.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Cisco Netflow."""
from __future__ import print_function
from __future__ import absolute_import

import struct
import time

from . import dpkt
from .compat import compat_izip, compat_ord
from .utils import inet_to_str, mac_to_str


class NetflowBase(dpkt.Packet):
    """Base class for Cisco Netflow packets.

    NetFlow is a feature that was introduced on Cisco routers around 1996 that provides the ability to collect IP
    network traffic as it enters or exits an interface. By analyzing the data provided by NetFlow, a network
    administrator can determine things such as the source and destination of traffic, class of service, and the causes
    of congestion.

    https://www.ciscopress.com/articles/article.asp?p=2812391&seqNum=3

    Attributes:
        __hdr__: Header fields of NetflowBase.
    """

    __hdr__ = (
        ('version', 'H', 1),
        ('count', 'H', 0),
        ('sys_uptime', 'I', 0),
        ('unix_sec', 'I', 0),
        ('unix_nsec', 'I', 0)
    )

    def __len__(self):
        return self.__hdr_len__ + (len(self.data[0]) * self.count)

    def __bytes__(self):
        # for now, don't try to enforce any size limits
        self.count = len(self.data)
        return self.pack_hdr() + b''.join(map(bytes, self.data))

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        buf = self.data
        l_ = []
        while buf:
            flow = self.NetflowRecord(buf)
            l_.append(flow)
            buf = buf[len(flow):]
        self.data = l_

    class NetflowRecordBase(dpkt.Packet):
        """Base class for netflow v1-v7 netflow records.

        TODO: Longer class information....

        Attributes:
            __hdr__: Header fields of NetflowRecordBase.
            TODO.
        """

        # performance optimizations
        def __len__(self):
            # don't bother with data
            return self.__hdr_len__

        def __bytes__(self):
            # don't bother with data
            return self.pack_hdr()

        def unpack(self, buf):
            # don't bother with data
            for k, v in compat_izip(self.__hdr_fields__,
                                    struct.unpack(self.__hdr_fmt__, buf[:self.__hdr_len__])):
                setattr(self, k, v)
            self.data = b""


class Netflow1(NetflowBase):
    """Netflow Version 1.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Netflow Version 1.
        TODO.
    """

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v1 flow record.

        TODO: Longer class information....

        Attributes:
            __hdr__: Header fields of Netflow Version 1 flow record.
            TODO.
        """

        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'H', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('pad2', 'B', 0),
            ('pad3', 'H', 0),
            ('reserved', 'I', 0)
        )


# FYI, versions 2-4 don't appear to have ever seen the light of day.

class Netflow5(NetflowBase):
    """Netflow Version 5.

    Popular NetFlow version on many routers from different vendors. Limited to IPv4 flows.

    Attributes:
        __hdr__: Header fields of Netflow Version 5.
    """

    __hdr__ = NetflowBase.__hdr__ + (
        ('flow_sequence', 'I', 0),
        ('engine_type', 'B', 0),
        ('engine_id', 'B', 0),
        ('reserved', 'H', 0),
    )

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v5 flow record.

        Attributes:
            __hdr__: Header fields of Netflow Version 5 flow record.
        """

        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('pad2', 'H', 0),
        )


class Netflow6(NetflowBase):
    """Netflow Version 6.

    (Obsolete.) No longer supported by Cisco, but may be found in the field.

    Attributes:
        __hdr__: Header fields of Netflow Version 6.
    """

    __hdr__ = Netflow5.__hdr__

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v6 flow record.

        Attributes:
            __hdr__: Header fields of Netflow Version 6 flow record.
        """

        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('in_encaps', 'B', 0),
            ('out_encaps', 'B', 0),
            ('peer_nexthop', 'I', 0),
        )


class Netflow7(NetflowBase):
    """Netflow Version 7.

    (Obsolete.) Like version 5, with a source router field.

    Attributes:
        __hdr__: Header fields of Netflow Version 7.
    """

    __hdr__ = NetflowBase.__hdr__ + (
        ('flow_sequence', 'I', 0),
        ('reserved', 'I', 0),
    )

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v6 flow record.

        TODO: Longer class information....

        Attributes:
            __hdr__: Header fields of Netflow Version 6 flow record.
            TODO.
        """

        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('flags', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('pad2', 'H', 0),
            ('router_sc', 'I', 0),
        )


# No support for v8 yet.

# ---------------------------------------------------------------------------
# NetFlow v9 (RFC 3954)
#
# Unlike the fixed-layout versions above, v9 carries Template FlowSets that
# describe the layout of the Data FlowSets which follow.  The stateless
# Netflow9 parser below unpacks every FlowSet header and Template record from
# the wire; decoding of Data FlowSets requires a Netflow9Collector which owns
# the per-exporter / per-observation-domain template cache.
# ---------------------------------------------------------------------------

# reserved FlowSet IDs; every FlowSet ID >= V9_MIN_DATA_FLOWSET_ID is a
# Data FlowSet and equals the Template ID of its records (RFC 3954 sections
# 5.2/6)
V9_TEMPLATE_FLOWSET_ID = 0
V9_OPTIONS_TEMPLATE_FLOWSET_ID = 1
V9_MIN_DATA_FLOWSET_ID = 256

# Field Length 0xFFFF marks an IPFIX-style variable-length field (RFC 7011
# section 3.2); such layouts are not decoded by this implementation
V9_VARIABLE_LENGTH = 0xFFFF

# Options Template scope field types (RFC 3954 section 6.1)
V9_SCOPE_SYSTEM = 1
V9_SCOPE_INTERFACE = 2
V9_SCOPE_LINE_CARD = 3
V9_SCOPE_CACHE = 4
V9_SCOPE_TEMPLATE = 5

# collector defaults, see Netflow9Collector for the exact semantics
V9_DEFAULT_TEMPLATE_TIMEOUT = 1800.0   # seconds, RFC 3954 section 8
V9_DEFAULT_PENDING_LIMIT = 64          # buffered packets waiting for a template
V9_DEFAULT_PENDING_MAX_BYTES = 1 << 20


def _decode_int(buf):
    if not buf:
        return 0
    return int(''.join('%02x' % compat_ord(byte) for byte in buf), 16)


def _decode_ipv4(buf):
    if len(buf) != 4:
        return buf
    return inet_to_str(buf)


def _decode_ipv6(buf):
    if len(buf) != 16:
        return buf
    return inet_to_str(buf)


def _decode_mac(buf):
    if len(buf) != 6:
        return buf
    return mac_to_str(buf)


def _decode_bytes(buf):
    return buf


# Field Type Definitions from RFC 3954 section 8.  Each entry maps a field
# type to (canonical RFC name, decoder); the decoder is only used when the
# on-wire length matches the field's fixed definition.  Fields whose length is
# vendor dependent in v9 (counters, AS numbers, interface indexes) are still
# fixed-width once instantiated in a Template and decode as integers.
_V9_FIELD_TYPES = {
    1:  ('IN_BYTES', _decode_int),
    2:  ('IN_PKTS', _decode_int),
    3:  ('FLOWS', _decode_int),
    4:  ('PROTOCOL', _decode_int),
    5:  ('TOS', _decode_int),
    6:  ('TCP_FLAGS', _decode_int),
    7:  ('L4_SRC_PORT', _decode_int),
    8:  ('IPV4_SRC_ADDR', _decode_ipv4),
    9:  ('SRC_MASK', _decode_int),
    10: ('INPUT_SNMP', _decode_int),
    11: ('L4_DST_PORT', _decode_int),
    12: ('IPV4_DST_ADDR', _decode_ipv4),
    13: ('DST_MASK', _decode_int),
    14: ('OUTPUT_SNMP', _decode_int),
    15: ('IPV4_NEXT_HOP', _decode_ipv4),
    16: ('SRC_AS', _decode_int),
    17: ('DST_AS', _decode_int),
    18: ('BGP_IPV4_NEXT_HOP', _decode_ipv4),
    19: ('MUL_DST_PKTS', _decode_int),
    20: ('MUL_DST_BYTES', _decode_int),
    21: ('LAST_SWITCHED', _decode_int),
    22: ('FIRST_SWITCHED', _decode_int),
    23: ('OUT_BYTES', _decode_int),
    24: ('OUT_PKTS', _decode_int),
    27: ('IPV6_SRC_ADDR', _decode_ipv6),
    28: ('IPV6_DST_ADDR', _decode_ipv6),
    29: ('IPV6_SRC_MASK', _decode_int),
    30: ('IPV6_DST_MASK', _decode_int),
    31: ('IPV6_FLOW_LABEL', _decode_int),
    32: ('ICMP_TYPE', _decode_int),
    33: ('MUL_IGMP_TYPE', _decode_int),
    34: ('SAMPLING_INTERVAL', _decode_int),
    35: ('SAMPLING_ALGORITHM', _decode_int),
    36: ('FLOW_ACTIVE_TIMEOUT', _decode_int),
    37: ('FLOW_INACTIVE_TIMEOUT', _decode_int),
    38: ('ENGINE_TYPE', _decode_int),
    39: ('ENGINE_ID', _decode_int),
    40: ('TOTAL_BYTES_EXP', _decode_int),
    41: ('TOTAL_PKTS_EXP', _decode_int),
    42: ('TOTAL_FLOWS_EXP', _decode_int),
    43: ('IPV4_ROUTER_SC', _decode_ipv4),
    44: ('IPV4_SRC_PREFIX', _decode_ipv4),
    45: ('IPV4_DST_PREFIX', _decode_ipv4),
    46: ('MPLS_TOP_LABEL_TYPE', _decode_int),
    47: ('MPLS_TOP_LABEL_IP_ADDR', _decode_ipv4),
    48: ('FLOW_SAMPLER_ID', _decode_int),
    49: ('FLOW_SAMPLER_MODE', _decode_int),
    50: ('FLOW_SAMPLER_RANDOM_INTERVAL', _decode_int),
    55: ('DST_TOS', _decode_int),
    56: ('SRC_MAC', _decode_mac),
    57: ('DST_MAC', _decode_mac),
    58: ('SRC_VLAN', _decode_int),
    59: ('DST_VLAN', _decode_int),
    60: ('IP_PROTOCOL_VERSION', _decode_int),
    61: ('DIRECTION', _decode_int),
    62: ('IPV6_NEXT_HOP', _decode_ipv6),
    63: ('BGP_IPV6_NEXT_HOP', _decode_ipv6),
    64: ('IPV6_OPTION_HEADERS', _decode_int),
    70: ('MPLS_LABEL_1', _decode_bytes),
    71: ('MPLS_LABEL_2', _decode_bytes),
    72: ('MPLS_LABEL_3', _decode_bytes),
    73: ('MPLS_LABEL_4', _decode_bytes),
    74: ('MPLS_LABEL_5', _decode_bytes),
    75: ('MPLS_LABEL_6', _decode_bytes),
    76: ('MPLS_LABEL_7', _decode_bytes),
    77: ('MPLS_LABEL_8', _decode_bytes),
    78: ('MPLS_LABEL_9', _decode_bytes),
    79: ('MPLS_LABEL_10', _decode_bytes),
    80: ('OUT_DST_MAC', _decode_mac),
    81: ('OUT_SRC_MAC', _decode_mac),
}


# Scope field types reuse numeric IDs 1..5 of the regular field space with
# distinct meaning (RFC 3954 section 6.1)
_V9_SCOPE_TYPES = {
    V9_SCOPE_SYSTEM: 'SYSTEM',
    V9_SCOPE_INTERFACE: 'INTERFACE',
    V9_SCOPE_LINE_CARD: 'LINE_CARD',
    V9_SCOPE_CACHE: 'CACHE',
    V9_SCOPE_TEMPLATE: 'TEMPLATE',
}


class V9Field(object):
    """One field specifier in a Template or Options Template record."""

    def __init__(self, field_type, length, position, scope=False):
        self.type = field_type
        self.length = length
        self.position = position
        self.scope = scope

    @property
    def variable(self):
        return self.length == V9_VARIABLE_LENGTH

    @property
    def name(self):
        if self.scope:
            try:
                return 'SCOPE_%s' % _V9_SCOPE_TYPES[self.type]
            except KeyError:
                return 'SCOPE_%d' % self.type
        try:
            return _V9_FIELD_TYPES[self.type][0]
        except KeyError:
            return 'FIELD_%d' % self.type

    def __repr__(self):
        return 'V9Field(type=%d, length=%d, name=%r)' % (self.type, self.length, self.name)


class V9Template(object):
    """A Template or Options Template definition.

    ``fields`` contains the Option fields (or all fields for a plain
    Template) in wire order; ``scopes`` contains the leading Options Template
    scope fields.  ``version`` is the collector-assigned generation number so
    that a data record can always be traced back to the exact definition used
    to decode it.
    """

    def __init__(self, template_id, fields, scopes=None, options=False,
                 version=1, received_at=None, updated_at=None,
                 exporter=None, source_id=None, raw=None):
        self.template_id = template_id
        self.fields = list(fields)
        self.scopes = list(scopes or [])
        self.options = options
        self.version = version
        self.received_at = received_at
        self.updated_at = updated_at
        self.exporter = exporter
        self.source_id = source_id
        self.raw = raw or b''

    @property
    def scope_count(self):
        return len(self.scopes)

    @property
    def all_fields(self):
        return list(self.scopes) + list(self.fields)

    @property
    def record_length(self):
        """Fixed record length, or None when the layout is unsupported."""
        if self.unsupported_reason is not None:
            return None
        return sum(f.length for f in self.all_fields)

    @property
    def variable_fields(self):
        return [f for f in self.all_fields if f.variable]

    @property
    def unsupported_reason(self):
        if not self.all_fields:
            return 'template has no field definitions'
        for field in self.all_fields:
            if field.length == V9_VARIABLE_LENGTH:
                return 'variable-length field %d (0xFFFF) is not supported' % field.type
            if field.length == 0:
                return 'zero-length field %d is not supported' % field.type
        return None

    def __repr__(self):
        return ('V9Template(id=%d, options=%r, version=%d, fields=%r)'
                % (self.template_id, self.options, self.version, self.all_fields))


class V9DataRecord(object):
    """A decoded Data or Options Data record.

    ``values`` maps the RFC field names to decoded Python values.  Fields
    known from the RFC are decoded only when their explicit template length
    matches the fixed definition; anything else (unknown field types,
    vendor-specific widths, truncation) is kept as raw bytes under ``raw``.
    """

    def __init__(self, template, values, raw, index, offset, complete=True,
                 issues=None):
        self.template = template
        self.template_id = template.template_id
        self.template_version = template.version
        self.source_id = template.source_id
        self.exporter = template.exporter
        self.values = values
        self.raw = raw
        self.index = index
        self.offset = offset
        self.complete = complete
        self.issues = list(issues or [])

    @property
    def options(self):
        return self.template.options

    def __getitem__(self, key):
        return self.values[key]

    def get(self, key, default=None):
        return self.values.get(key, default)

    def __repr__(self):
        return ('V9DataRecord(template_id=%d, version=%d, index=%d, values=%r)'
                % (self.template_id, self.template_version, self.index, self.values))


class Netflow9FlowSet(dpkt.Packet):
    """Common FlowSet header (RFC 3954 section 5.2)."""

    __hdr__ = (
        ('flowset_id', 'H', 0),
        ('length', 'H', 0),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.length < self.__hdr_len__:
            raise dpkt.UnpackError(
                'invalid NetFlow v9 FlowSet length %d' % self.length)
        if len(buf) < self.length:
            raise dpkt.NeedData(
                'FlowSet declares %d bytes, got %d' % (self.length, len(buf)))
        self.body = buf[self.__hdr_len__:self.length]
        self.padding = b''

    def __len__(self):
        return self.length

    def __bytes__(self):
        return self.pack_hdr() + bytes(self.body) + bytes(self.padding)


class Netflow9TemplateFlowSet(Netflow9FlowSet):
    """Template FlowSet (FlowSet ID 0), holding one or more V9Template."""

    def unpack(self, buf):
        Netflow9FlowSet.unpack(self, buf)
        self.templates = []
        body = self.body
        while body:
            if len(body) < 4:
                # trailing alignment padding
                self.padding = body
                self.body = self.body[:-len(body)]
                break
            template_id, field_count = struct.unpack('!HH', body[:4])
            if template_id < V9_MIN_DATA_FLOWSET_ID and field_count == 0:
                # zero-filled alignment padding at a template record boundary
                self.padding = body
                self.body = self.body[:-len(body)]
                break
            if template_id < V9_MIN_DATA_FLOWSET_ID:
                raise dpkt.UnpackError(
                    'invalid template ID %d (must be >= %d)'
                    % (template_id, V9_MIN_DATA_FLOWSET_ID))
            needed = 4 + field_count * 4
            if len(body) < needed:
                raise dpkt.NeedData(
                    'template %d declares %d fields, %d bytes remain'
                    % (template_id, field_count, len(body)))
            fields = []
            for index in range(field_count):
                field_type, field_len = struct.unpack(
                    '!HH', body[4 + index * 4:8 + index * 4])
                fields.append(V9Field(field_type, field_len, index))
            self.templates.append(
                V9Template(template_id, fields, options=False, raw=body[:needed]))
            body = body[needed:]


class Netflow9OptionsTemplateFlowSet(Netflow9FlowSet):
    """Options Template FlowSet (FlowSet ID 1)."""

    def unpack(self, buf):
        Netflow9FlowSet.unpack(self, buf)
        self.templates = []
        body = self.body
        while body:
            if len(body) < 6:
                self.padding = body
                self.body = self.body[:-len(body)]
                break
            template_id, scope_len, option_len = struct.unpack('!HHH', body[:6])
            if template_id < V9_MIN_DATA_FLOWSET_ID:
                if not scope_len and not option_len:
                    # zero-filled alignment padding at a record boundary
                    self.padding = body
                    self.body = self.body[:-len(body)]
                    break
                raise dpkt.UnpackError(
                    'invalid options template ID %d (must be >= %d)'
                    % (template_id, V9_MIN_DATA_FLOWSET_ID))
            scope_count = scope_len // 4
            option_count = option_len // 4
            needed = 6 + scope_len + option_len
            if len(body) < needed:
                raise dpkt.NeedData(
                    'options template %d needs %d bytes, %d remain'
                    % (template_id, needed, len(body)))
            scopes, fields = [], []
            cursor = 6
            for index in range(scope_count):
                field_type, field_len = struct.unpack('!HH', body[cursor:cursor + 4])
                scopes.append(V9Field(field_type, field_len, index, scope=True))
                cursor += 4
            for index in range(option_count):
                field_type, field_len = struct.unpack('!HH', body[cursor:cursor + 4])
                fields.append(V9Field(field_type, field_len, index))
                cursor += 4
            self.templates.append(
                V9Template(template_id, fields, scopes=scopes, options=True,
                           raw=body[:needed]))
            body = body[needed:]


class Netflow9DataFlowSet(Netflow9FlowSet):
    """A Data FlowSet.

    Stateless parsing keeps the raw records; the collector decodes them once
    the corresponding template is available.
    """

    def unpack(self, buf):
        Netflow9FlowSet.unpack(self, buf)
        self.records_raw = self.body
        self.records = []
        self.decoded = False


def _unique_name(values, name):
    """Disambiguate field names when a Template repeats a field type."""
    if name not in values:
        return name
    suffix = 2
    while '%s_%d' % (name, suffix) in values:
        suffix += 1
    return '%s_%d' % (name, suffix)


def _decode_record(template, record_bytes, index, offset):
    values = {}
    issues = []
    cursor = 0
    for field in template.all_fields:
        chunk = record_bytes[cursor:cursor + field.length]
        cursor += field.length
        name = _unique_name(values, field.name)
        spec = _V9_FIELD_TYPES.get(field.type)
        if spec is None or (field.scope and field.type not in _V9_SCOPE_TYPES):
            # unknown field type: keep the original bytes verbatim
            values[name] = chunk
            issues.append('unknown field type %d at position %d'
                          % (field.type, field.position))
            continue
        _, decoder = spec
        if decoder in (_decode_ipv4, _decode_ipv6, _decode_mac):
            # address fields only render as strings at their canonical width
            expected = {_decode_ipv4: 4, _decode_ipv6: 16,
                        _decode_mac: 6}[decoder]
            if field.length != expected:
                values[name] = chunk
                issues.append(
                    'field %s has non-canonical length %d (expected %d)'
                    % (name, field.length, expected))
                continue
        try:
            values[name] = decoder(chunk)
        except (ValueError, struct.error):
            values[name] = chunk
            issues.append('field %s could not be decoded' % name)
    return V9DataRecord(template, values, record_bytes, index, offset,
                        issues=issues)


class Netflow9(NetflowBase):
    """Netflow Version 9 (RFC 3954).

    The header is followed by Template, Options Template and Data FlowSets.
    This class unpacks the FlowSet headers and any template definitions;
    interpreting Data FlowSets requires the template cache of a
    Netflow9Collector.

    Attributes:
        __hdr__: Header fields of Netflow Version 9.
    """

    __hdr__ = NetflowBase.__hdr__ + (
        ('sequence', 'I', 0),
        ('source_id', 'I', 0),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.flowsets = []
        body = self.data
        while body:
            if len(body) < Netflow9FlowSet.__hdr_len__:
                raise dpkt.NeedData(
                    'truncated FlowSet header: %d bytes remain' % len(body))
            flowset_id, flowset_len = struct.unpack('!HH', body[:4])
            if flowset_len < Netflow9FlowSet.__hdr_len__:
                raise dpkt.UnpackError(
                    'invalid NetFlow v9 FlowSet length %d for FlowSet %d'
                    % (flowset_len, flowset_id))
            if flowset_id == V9_TEMPLATE_FLOWSET_ID:
                flowset = Netflow9TemplateFlowSet(body)
            elif flowset_id == V9_OPTIONS_TEMPLATE_FLOWSET_ID:
                flowset = Netflow9OptionsTemplateFlowSet(body)
            elif flowset_id >= V9_MIN_DATA_FLOWSET_ID:
                flowset = Netflow9DataFlowSet(body)
            else:
                flowset = Netflow9FlowSet(body)
            self.flowsets.append(flowset)
            body = body[len(flowset):]
        self.data = self.flowsets

    @property
    def templates(self):
        """Template definitions carried by this packet, if any."""
        templates = []
        for flowset in self.flowsets:
            templates.extend(getattr(flowset, 'templates', []))
        return templates

    def __len__(self):
        return self.__hdr_len__ + sum(len(flowset) for flowset in self.flowsets)

    def __bytes__(self):
        self.count = len(self.flowsets)
        return self.pack_hdr() + b''.join(bytes(flowset) for flowset in self.flowsets)


class V9TemplateCacheEntry(object):
    """One (exporter session, source_id, template_id) cache slot."""

    def __init__(self, template):
        self.template = template
        self.version = template.version
        self.received_at = template.received_at
        self.first_seen = template.received_at
        self.replacement_count = 0
        self.expired = False

    def __repr__(self):
        return ('V9TemplateCacheEntry(id=%d, version=%d, expired=%r)'
                % (self.template.template_id, self.version, self.expired))


class Netflow9Collector(object):
    """Collector-side NetFlow v9 state.

    Template cache isolation
        Every exporter stream is identified by an opaque ``session`` value
        (the caller normally passes the exporter IP address) together with the
        packet's ``source_id`` (RFC 3954 Observation Domain).  Templates are
        stored under the triple ``(session, source_id, template_id)``; two
        exporters may therefore reuse the same Template ID without interfering.

    Replacement / versioning
        A definition received for an existing key replaces it immediately
        (RFC 3954 section 7), even when the field list is byte-for-byte
        identical.  Each accepted definition gets a fresh, monotonically
        increasing ``version`` (per exporter session).  A data record decoded
        later always records the ``template_version`` that was actually used,
        so a record buffered before an update keeps its old definition.

    Expiry
        An entry expires at ``received_at + template_timeout``.  Refreshes
        replace the entry (new version) and reset the expiry clock.  Expired
        entries are never used to decode data; decoding raises
        :class:`V9TemplateNotFound` with ``expired=True`` and the template
        remains visible through :meth:`Netflow9Collector.state` until it is
        evicted.

    Restart detection
        RFC 3954 restarts lose all template state.  Observation-Domain
        restarts are detected by ``sys_uptime`` going backwards for the same
        session (and source_id, when ``session_scope`` is per-domain).
        Cache invalidation is immediate and the reason is remembered in the
        collector's ``restart_count``/``last_restart`` state.  ``flow_sequence``
        decreases are also treated as a restart by default; both heuristics
        can be disabled independently.  Explicit :meth:`invalidate` is always
        available for out-of-band restarts.

    Data-before-template buffering
        Unknown Data FlowSets are buffered as raw records under a bounded
        budget (``pending_limit`` packets and ``pending_max_bytes`` bytes,
        oldest data dropped first).  Once a template arrives, buffered packets
        from the same session/source_id are replayed with the template in
        effect at replay time; each resulting record records that version.
    """

    def __init__(self, session=None, template_timeout=V9_DEFAULT_TEMPLATE_TIMEOUT,
                 pending_limit=V9_DEFAULT_PENDING_LIMIT,
                 pending_max_bytes=V9_DEFAULT_PENDING_MAX_BYTES,
                 session_scope='exporter', restart_on_uptime=True,
                 restart_on_sequence=True, clock=None):
        self.default_session = session
        self.template_timeout = template_timeout
        self.pending_limit = pending_limit
        self.pending_max_bytes = pending_max_bytes
        self.session_scope = session_scope
        self.restart_on_uptime = restart_on_uptime
        self.restart_on_sequence = restart_on_sequence
        self._clock = clock
        self._templates = {}
        self._sessions = {}
        self._pending = {}
        self._pending_order = []
        self._pending_seq = 0
        self._pending_bytes = 0
        self._template_versions = {}
        self.restart_count = 0
        self.last_restart = None
        self.pending_dropped = 0

    # -- time and keys ----------------------------------------------------

    def _now(self):
        if self._clock is None:
            return time.time()
        return self._clock()

    def _key(self, session, source_id):
        return (session, source_id)

    def _session_key(self, session, source_id):
        if self.session_scope == 'exporter':
            return session
        return (session, source_id)

    def _check_expiry(self, entry, now):
        if entry.expired:
            return True
        if self.template_timeout is None:
            return False
        if now - entry.received_at < self.template_timeout:
            return False
        entry.expired = True
        return True

    # -- restart detection -------------------------------------------------

    def _observe_packet(self, session, source_id, packet, now):
        skey = self._session_key(session, source_id)
        previous = self._sessions.get(skey)
        restarted = False
        reason = None
        if previous is not None:
            if (self.restart_on_uptime and packet.sys_uptime < previous['uptime']):
                restarted = True
                reason = 'sys_uptime went backwards (%d -> %d)' % (
                    previous['uptime'], packet.sys_uptime)
            elif (self.restart_on_sequence and
                  packet.sequence < previous['sequence']):
                restarted = True
                reason = 'flow_sequence went backwards (%d -> %d)' % (
                    previous['sequence'], packet.sequence)
        if restarted:
            self._invalidate_session(session, source_id, reason, now)
        self._sessions[skey] = {
            'uptime': packet.sys_uptime,
            'sequence': packet.sequence,
            'unix_sec': packet.unix_sec,
            'packets': previous['packets'] + 1 if previous else 1,
        }
        return restarted

    def invalidate(self, session, source_id=None, reason='manual invalidate'):
        """Drop templates for one session (or all when ``session`` is None)."""
        now = self._now()
        if session is None:
            for entries in list(self._templates.values()):
                for entry in entries.values():
                    entry.expired = True
            self._templates.clear()
            self._pending.clear()
            self._pending_order = []
            self._pending_bytes = 0
            self.restart_count += 1
            self.last_restart = {'time': now, 'reason': reason,
                                 'session': None, 'source_id': None}
            return
        self._invalidate_session(session, source_id, reason, now)

    def _invalidate_session(self, session, source_id, reason, now):
        if source_id is None:
            keys = [key for key in self._templates if key[0] == session]
        else:
            keys = [self._key(session, source_id)]
        for key in keys:
            entries = self._templates.pop(key, None)
            if entries:
                for entry in entries.values():
                    entry.expired = True
        self._drop_pending(session, source_id)
        self.restart_count += 1
        self.last_restart = {'time': now, 'reason': reason,
                             'session': session, 'source_id': source_id}

    # -- template storage -------------------------------------------------

    def _next_version(self, session):
        version = self._template_versions.get(session, 0) + 1
        self._template_versions[session] = version
        return version

    def learn(self, template, exporter=None, source_id=None, now=None):
        """Install or replace a template definition.

        The template is cloned and its ``version`` assigned here.  Returns the
        stored :class:`V9Template`.
        """
        now = self._now() if now is None else now
        session = exporter if exporter is not None else self.default_session
        source_id = source_id if source_id is not None else getattr(self, '_default_source_id', 0)
        version = self._next_version(session)
        stored = V9Template(
            template.template_id, template.fields, scopes=template.scopes,
            options=template.options, version=version, received_at=now,
            updated_at=now, exporter=session, source_id=source_id,
            raw=template.raw)
        entries = self._templates.setdefault(self._key(session, source_id), {})
        previous = entries.get(stored.template_id)
        entry = V9TemplateCacheEntry(stored)
        if previous is not None:
            entry.replacement_count = previous.replacement_count + 1
        entry.first_seen = previous.first_seen if previous is not None else now
        entries[stored.template_id] = entry
        return stored

    def lookup(self, template_id, exporter=None, source_id=None, now=None):
        now = self._now() if now is None else now
        session = exporter if exporter is not None else self.default_session
        source_id = source_id if source_id is not None else getattr(self, '_default_source_id', 0)
        entries = self._templates.get(self._key(session, source_id))
        if not entries:
            raise V9TemplateNotFound(template_id, session, source_id,
                                     reason='no templates cached')
        entry = entries.get(template_id)
        if entry is None:
            raise V9TemplateNotFound(template_id, session, source_id,
                                     reason='template not cached')
        if self._check_expiry(entry, now):
            raise V9TemplateNotFound(template_id, session, source_id,
                                     reason='template expired', expired=True)
        return entry.template

    # -- packet ingestion -------------------------------------------------

    def feed(self, packet, exporter=None, session=None, now=None):
        """Ingest one parsed (or raw) Export Packet.

        Returns a :class:`V9PacketResult` holding every decoded record,
        FlowSet-level statuses and the provenance (session, source_id,
        sequence, uptime).
        """
        if not isinstance(packet, Netflow9):
            packet = parse_packet(packet)
        now = self._now() if now is None else now
        exporter = exporter if exporter is not None else self.default_session
        session = session if session is not None else exporter
        self._default_source_id = packet.source_id
        result = V9PacketResult(
            session=session, exporter=exporter, source_id=packet.source_id,
            sequence=packet.sequence, sys_uptime=packet.sys_uptime,
            unix_sec=packet.unix_sec, count=packet.count)
        restarted = self._observe_packet(session, packet.source_id, packet, now)
        result.restarted = restarted
        if restarted:
            result.restart_reason = self.last_restart['reason']

        learned = []
        for flowset in packet.flowsets:
            templates = getattr(flowset, 'templates', None)
            if templates is not None and isinstance(
                    flowset, (Netflow9TemplateFlowSet,
                              Netflow9OptionsTemplateFlowSet)):
                for template in templates:
                    stored = self.learn(template, exporter=session,
                                        source_id=packet.source_id, now=now)
                    learned.append(stored)
                    result.templates_learned.append(stored)
            elif isinstance(flowset, Netflow9DataFlowSet):
                self._handle_data_flowset(result, flowset, session,
                                          packet.source_id, now)
        if learned:
            self._replay_pending(session, packet.source_id, result)
        return result

    def _handle_data_flowset(self, result, flowset, session, source_id, now):
        try:
            template = self.lookup(flowset.flowset_id, exporter=session,
                                   source_id=source_id, now=now)
        except V9TemplateNotFound as exc:
            result.buffered_ids.append(flowset.flowset_id)
            self._buffer_pending(session, source_id, flowset.flowset_id,
                                 flowset.body, result)
            flowset.status = 'awaiting-template'
            flowset.reason = exc.reason
            result.flowset_statuses.append({
                'flowset_id': flowset.flowset_id,
                'template_id': flowset.flowset_id,
                'template_version': None,
                'status': 'awaiting-template',
                'reason': exc.reason,
                'records': 0,
            })
            return
        flowset.template = template
        flowset.template_version = template.version
        records, status, reason = self._decode_flowset_records(
            flowset, template)
        flowset.records = records
        flowset.decoded = status in ('ok', 'padding')
        flowset.status = status
        flowset.reason = reason
        result.flowset_statuses.append({
            'flowset_id': flowset.flowset_id,
            'template_id': template.template_id,
            'template_version': template.version,
            'status': status,
            'reason': reason,
            'records': len(records),
        })
        result.records.extend(records)
        for record in records:
            record.sequence = result.sequence
            record.sys_uptime = result.sys_uptime
            record.unix_sec = result.unix_sec
            record.session = result.session
            record.source_id = result.source_id

    def _decode_flowset_records(self, flowset, template):
        if template.unsupported_reason is not None:
            return [], 'unsupported-layout', template.unsupported_reason
        length = template.record_length
        body = flowset.body
        records = []
        offset = 0
        remaining = len(body)
        while remaining:
            if remaining < length:
                # RFC 3954 permits zero padding at the end of a FlowSet.  It
                # is never decoded as a record; a non-zero short tail is a
                # truncated record and is reported as such.
                if _is_padding(body[offset:]):
                    return records, ('ok' if records else 'padding'), None
                return records, 'incomplete', (
                    'record needs %d bytes, %d remain' % (length, remaining))
            chunk = body[offset:offset + length]
            record = _decode_record(template, chunk, len(records), offset)
            records.append(record)
            offset += length
            remaining -= length
        return records, 'ok', None

    # -- data-before-template buffering ------------------------------------

    def _buffer_pending(self, session, source_id, template_id, body, result):
        key = (session, source_id, template_id)
        pending = self._pending.get(key)
        if pending is None:
            pending = []
            self._pending[key] = pending
        pending.append({'body': body, 'sequence': result.sequence,
                        'sys_uptime': result.sys_uptime,
                        'unix_sec': result.unix_sec, 'session': session,
                        'source_id': source_id})
        self._pending_seq += 1
        self._pending_order.append((key, self._pending_seq))
        self._pending_bytes += len(body)
        while (len(self._pending_order) > self.pending_limit or
               self._pending_bytes > self.pending_max_bytes):
            drop_key, _ = self._pending_order[0]
            queue = self._pending.get(drop_key)
            if not queue:
                self._pending_order.pop(0)
                continue
            dropped = queue.pop(0)
            self._pending_bytes -= len(dropped['body'])
            self._pending_order.pop(0)
            self.pending_dropped += 1
            if not queue:
                self._pending.pop(drop_key, None)

    def _drop_pending(self, session, source_id):
        keys = [key for key in self._pending
                if key[0] == session and
                (source_id is None or key[1] == source_id)]
        for key in keys:
            for item in self._pending.pop(key):
                self._pending_bytes -= len(item['body'])
        self._pending_order = [(key, seq) for key, seq in self._pending_order
                               if key in self._pending]

    def _replay_pending(self, session, source_id, result):
        keys = [key for key in list(self._pending)
                if key[0] == session and key[1] == source_id]
        for key in keys:
            _, _, template_id = key
            try:
                template = self.lookup(template_id, exporter=session,
                                       source_id=source_id)
            except V9TemplateNotFound:
                continue
            queue = self._pending.pop(key)
            self._pending_order = [(k, seq) for k, seq in self._pending_order
                                   if k != key]
            for item in queue:
                self._pending_bytes -= len(item['body'])
                fake = Netflow9DataFlowSet.__new__(Netflow9DataFlowSet)
                fake.flowset_id = template_id
                fake.length = 4 + len(item['body'])
                fake.body = item['body']
                fake.padding = b''
                fake.records_raw = item['body']
                records, status, reason = self._decode_flowset_records(
                    fake, template)
                fake.records = records
                fake.decoded = status in ('ok', 'padding')
                fake.status = status
                fake.reason = reason
                fake.template = template
                fake.template_version = template.version
                for record in records:
                    record.sequence = item['sequence']
                    record.sys_uptime = item['sys_uptime']
                    record.unix_sec = item['unix_sec']
                    record.session = session
                    record.source_id = source_id
                    record.replayed = True
                result.flowset_statuses.append({
                    'flowset_id': template_id,
                    'template_id': template.template_id,
                    'template_version': template.version,
                    'status': status,
                    'reason': reason,
                    'records': len(records),
                    'replayed': True,
                    'original_sequence': item['sequence'],
                })
                result.records.extend(records)
                result.replayed_ids.append(template_id)

    # -- observation ------------------------------------------------------

    def state(self, exporter=None, source_id=None, now=None):
        """Return a JSON-friendly snapshot of the collector state.

        Template IDs are reported per ``(exporter session, source_id)``
        bucket.  ``version`` is the template generation, ``expires_in`` the
        remaining template lifetime in seconds, and ``pending`` the number of
        buffered Data FlowSet bodies still waiting for a template.
        """
        now = self._now() if now is None else now
        buckets = []
        for (session, sid), entries in sorted(
                self._templates.items(), key=lambda item: (str(item[0][0]), item[0][1])):
            if exporter is not None and session != exporter:
                continue
            if source_id is not None and sid != source_id:
                continue
            templates = []
            for template_id, entry in sorted(entries.items()):
                expired = self._check_expiry(entry, now)
                if self.template_timeout is None:
                    expires_in = None
                else:
                    expires_in = max(0.0, entry.received_at +
                                     self.template_timeout - now)
                templates.append({
                    'template_id': template_id,
                    'version': entry.version,
                    'options': entry.template.options,
                    'fields': len(entry.template.all_fields),
                    'unsupported': entry.template.unsupported_reason,
                    'expired': expired,
                    'expires_in': expires_in,
                    'replaced': entry.replacement_count,
                    'first_seen': entry.first_seen,
                    'last_seen': entry.received_at,
                })
            buckets.append({
                'exporter': session,
                'source_id': sid,
                'templates': templates,
            })
        pending = {}
        for (session, sid, template_id), queue in sorted(
                self._pending.items(), key=lambda item: (str(item[0][0]), item[0][1], item[0][2])):
            pending.setdefault(str((session, sid)), []).append(
                {'template_id': template_id, 'packets': len(queue),
                 'bytes': sum(len(item['body']) for item in queue)})
        session_state = {}
        for key, value in self._sessions.items():
            session_state[str(key)] = dict(value)
        return {
            'scope': self.session_scope,
            'template_timeout': self.template_timeout,
            'restart_count': self.restart_count,
            'last_restart': self.last_restart,
            'pending_packets': len(self._pending_order),
            'pending_bytes': self._pending_bytes,
            'pending_dropped': self.pending_dropped,
            'pending': pending,
            'sessions': session_state,
            'templates': buckets,
        }


class V9TemplateNotFound(dpkt.UnpackError):
    """Raised when a Data FlowSet cannot be matched to a live template."""

    def __init__(self, template_id, session, source_id, reason='',
                 expired=False):
        super(V9TemplateNotFound, self).__init__(reason or 'template %d not found' % template_id)
        self.template_id = template_id
        self.session = session
        self.source_id = source_id
        self.reason = reason
        self.expired = expired


class V9PacketResult(object):
    """Collector output for one Export Packet."""

    def __init__(self, session=None, exporter=None, source_id=0, sequence=0,
                 sys_uptime=0, unix_sec=0, count=0):
        self.session = session
        self.exporter = exporter
        self.source_id = source_id
        self.sequence = sequence
        self.sys_uptime = sys_uptime
        self.unix_sec = unix_sec
        self.count = count
        self.records = []
        self.templates_learned = []
        self.buffered_ids = []
        self.replayed_ids = []
        self.flowset_statuses = []
        self.restarted = False
        self.restart_reason = None

    def __repr__(self):
        return ('V9PacketResult(sequence=%d, source_id=%d, records=%d, '
                'learned=%d, buffered=%r, replayed=%r, restarted=%r)'
                % (self.sequence, self.source_id, len(self.records),
                   len(self.templates_learned), self.buffered_ids,
                   self.replayed_ids, self.restarted))


def _is_padding(buf):
    # RFC 3954: padding SHOULD be zeros, but any unparsable tail is kept
    return all(byte == 0 for byte in bytearray(buf))


def parse_packet(buf):
    """Parse a raw NetFlow v9 Export Packet (header + FlowSets)."""
    return Netflow9(buf)

def test_net_flow_v1_unpack():
    from binascii import unhexlify
    __sample_v1 = unhexlify(
        '00010018677a613c4200fc1c24930870ac012057c0a863f70a0002010003000a0000000100000228677a372c677a372c5c1b0050ac01112c10000'
        '0000004001bac011853ac18d9aac0a832020003001900000001000005dc677a377c677a377cd8e30050ac01062c100000000004001bac011418ac'
        '188dcdc0a832660003000700000001000005dc677a3790677a37908a81176fac0106361000000000040003ac0f2724ac01e51dc0a832060004001'
        'b0000000100000228677a3a38677a3a38a3511236ac2906fd180000000004001bac011645ac23178ec0a832060003001b0000000100000228677a'
        '3a4c677a3a4cc9ff0050ac1f0686020000000003001bac0d09ffac019995c0a832060004001b00000001000005dc677a3a58677a3a58ee390017a'
        'c0106de1000000000040003ac0e4ad8ac01ae2fc0a832060004001b00000001000005dc677a3a68677a3a68b36e0015ac01068110000000000400'
        '1bac012338ac01d92ac0a832060003001b00000001000005dc677a3a74677a3a7400008350ac2101ab100000000003001bac0a6037ac2a934ac0a'
        '832060004001b00000001000005dc677a3a74677a3a7400000000ac0132a91000000000040007ac0a471fac01fd4ac0a832060004001b00000001'
        '00000028677a3a88677a3a8821996987ac1e067e020000000003001bac0128c9ac0142c4c0a83202000300190000000100000028677a3a88677a3'
        'a887d360050ac0106fe100000000004001bac0b08e8ac0146e2c0a832020004001900000001000005dc677a3a9c677a3a9c60696987ac01063b10'
        '0000000004001bac011d24ac3cf0c3c0a832060003001b00000001000005dc677a3a9c677a3a9c46320014ac0106731800000000040003ac0b115'
        '1ac01de06c0a832060004001b00000001000005dc677a3ab0677a3ab0ef231a2bac2906e9100000000004001bac0c52d9ac016fe8c0a832020004'
        '001900000001000005dc677a3ac4677a3ac4136e006eac1906a81000000000030019ac013dddac017deec0a832660003000700000001000000286'
        '77a3ac4677a3ac40000dcbbac0101d3100000000004001bac0f28d1ac01cca5c0a832060004001b00000001000005dc677a3ad8677a3ad8c57317'
        '6fac1906231800000000030007ac0a855bc0a8636e0a0002010004000a00000001000005dc677a3ae4677a3ae4bf6c0050ac0106cf10000000000'
        '40007ac01301fac182145c0a832660003000700000001000005dc677a3b00677a3b00119504bec0a806ea100000000003000aac0130b6ac1ef4aa'
        'c0a832060003001b00000001000005dc677a3b34677a3b3488640017ac01061f100000000004001bac01235fac1eb009c0a832060003001b00000'
        '001000005dc677a3b48677a3b4881530050ac20064e100000000003001bac0104d9ac019463c0a832060003001b0000000100000228677a3b5c67'
        '7a3b5c55100050ac010650180000000004001bac013caeac2aac21c0a832060003001b00000001000000fa677a3b84677a3b840ce70050ac0111f'
        'd100000000004001bac011f1fac17ed69c0a832020003001900000001000005dc677a3b98677a3b98ba170016ac01067c1000000000030007'
    )
    nf = Netflow1(__sample_v1)
    assert len(nf.data) == 24
    # print repr(nfv1)


def test_net_flow_v5_unpack():
    from binascii import unhexlify
    buf_nf5_header = unhexlify(
        '0005001db5fac9d03a0b4142265677de9b73763100010000'
    )

    buf_nf5_records = list(map(unhexlify, (
        'ac0a86a6ac01aaf7c0a83232027100690000000100000228b5fa8114b5fa811435320050000006000000000000000000',
        'ac019144ac1443e4c0a83216006902710000000100000028b5fa9bbdb5fa9bbd005085d7000006000000000000000000',
        'ac17e2d7ac018c56c0a832320271006900000001000005dcb5fa6fb8b5fa6fb876e8176f000006000000000000000000',
        'ac0ef2e5ac0191b2c0a832320271006900000001000000fab5fa81eeb5fa81eed0eb0015000006000000000000000000',
        'ac0a436aac29a7090a000201027100db0000000100000228b5fa8592b5fa85928cb00035000006000000000000000000',
        'ac01963dac151aa8c0a832160069027100000001000005dcb5fa86e0b5fa86e0b4e700c2000006000000000000000000',
        'ac0156d1ac018615c0a832320271006900000001000005dcb5fa7d3ab5fa7d3a5b510050000006000000000000000000',
        'ac32f1b1ac2919ca0a000201027100db00000001000005dcb5fa83c3b5fa83c3162c0015000006000000000000000000',
        'ac0c4134ac019a7ac0a832320271006900000001000005dcb5fa8da7b5fa8da717330015000006000000000000000000',
        'ac1ed284ac29d8d20a000201027100db00000001000005dcb5fa8e97b5fa8e97372a176f000006000000000000000000',
        'ac01854aac2011fcc0a83216006902710000000100000228b5fa8834b5fa8834f5dd008f000006000000000000000000',
        'ac010480ac3c5b6e0a000201027100db00000001000005dcb5fa9d72b5fa9d7273240016000006000000000000000000',
        'ac01b94aac22c9d7c0a83216006902710000000100000028b5fa9072b5fa90720f8d00c2000006000000000000000000',
        'ac2aa310ac01b419c0a83232027100690000000100000028b5fa9203b5fa920370660015000006000000000000000000',
        'ac01ab6fac1e7f69c0a832160069027100000001000005dcb5fa937fb5fa937f00500b98000006000000000000000000',
        'ac0c0aeaac01a115c0a832320271006900000001000005dcb5fa79cfb5fa79cf5b3317e0000006000000000000000000',
        'ac01bbb3ac29758c0a000201006900db00000001000000fab5fa9433b5fa943300501eca000006000000000000000000',
        'ac0f4a60ac01ab94c0a83232027100690000000100000228b5fa875bb5fa875b9ad62fab000006000000000000000000',
        'ac2a0f93ac01b8a3c0a83232027100690000000100000028b5fa89bbb5fa89bb6ee10050000006000000000000000000',
        'ac0193a1ac16800cc0a83216006902710000000100000028b5fa8726b5fa872600000000000001000000000000000000',
        'ac01835aac1f52cdc0a832160069027100000001000005dcb5fa900db5fa900df72a008a000006000000000000000000',
        'ac0ce0adac01a856c0a832320271006900000001000005dcb5fa9cf6b5fa9cf6e57c1a2b000006000000000000000000',
        'ac1ecc54ac3c78260a000201027100db00000001000005dcb5fa80eab5fa80ea0000000000002f000000000000000000',
        'ac01bb18ac017c7ac0a832160069027100000001000000fab5fa8870b5fa887000500b7d000006000000000000000000',
        'ac170e72ac018fddc0a83232027100690000000100000228b5fa89f7b5fa89f70df7008a000006000000000000000000',
        'ac0abb04ac3cb0150a000201027100db00000001000005dcb5fa90a9b5fa90a99cd0008f000006000000000000000000',
        'ac0a7a3fac2903c80a000201027100db00000001000005dcb5fa7565b5fa7565eea60050000006000000000000000000',
        'ac01b505c0a8639f0a000201006900db00000001000005dcb5fa7bc7b5fa7bc7005086a9000006000000000000000000',
        'ac32a51bac2930bf0a000201027100db00000001000000fab5fa9b5ab5fa9b5a43f917e0000006000000000000000000',
    )))

    buf_input = buf_nf5_header + b''.join(buf_nf5_records)
    nf = Netflow5(buf_input)
    assert nf.version == 5
    assert nf.count == 29
    assert nf.sys_uptime == 3053111760
    assert nf.unix_sec == 973816130

    assert len(nf) == len(buf_input)
    assert bytes(nf) == buf_input

    assert len(nf.data) == 29
    for idx, record in enumerate(nf.data):
        assert bytes(record) == buf_nf5_records[idx]
        assert len(record) == 48


# ---------------------------------------------------------------------------
# NetFlow v9 tests.  All packets are constructed on the fly with struct.pack;
# no router, pcap file or network service is required.
# ---------------------------------------------------------------------------

def _v9_header(count, sequence, source_id, sys_uptime=1000, unix_sec=1700000000):
    return struct.pack('!HHIIIII', 9, count, sys_uptime, unix_sec, 0,
                       sequence, source_id)


def _v9_flowset(flowset_id, body, declared_length=None):
    if declared_length is None:
        padding = b'\x00' * ((-(len(body) + 4)) % 4)
        declared_length = 4 + len(body) + len(padding)
    else:
        padding = b'\x00' * (declared_length - 4 - len(body))
    return struct.pack('!HH', flowset_id, declared_length) + body + padding


def _v9_template_flowset(template_id, fields):
    body = struct.pack('!HH', template_id, len(fields))
    body += b''.join(struct.pack('!HH', ftype, flen) for ftype, flen in fields)
    return _v9_flowset(V9_TEMPLATE_FLOWSET_ID, body)


def _v9_options_template_flowset(template_id, scopes, options):
    scope_body = b''.join(struct.pack('!HH', ftype, flen)
                          for ftype, flen in scopes)
    option_body = b''.join(struct.pack('!HH', ftype, flen)
                           for ftype, flen in options)
    body = struct.pack('!HHH', template_id, len(scope_body),
                       len(option_body)) + scope_body + option_body
    return _v9_flowset(V9_OPTIONS_TEMPLATE_FLOWSET_ID, body)


_V9_TEST_FIELDS = [(8, 4), (12, 4), (4, 1), (7, 2), (11, 2), (2, 4)]


def _v9_flow_record(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                    proto=6, sport=1234, dport=80, packets=1000):
    return struct.pack('!4s4sBHHI', src, dst, proto, sport, dport, packets)


def test_net_flow_v9_header_and_template_unpack():
    raw = _v9_header(1, 0, 100) + _v9_template_flowset(256, _V9_TEST_FIELDS)
    nf = Netflow9(raw)
    assert nf.version == 9
    assert nf.source_id == 100
    assert nf.sequence == 0
    assert len(nf.flowsets) == 1
    flowset = nf.flowsets[0]
    assert isinstance(flowset, Netflow9TemplateFlowSet)
    assert flowset.flowset_id == 0
    template = flowset.templates[0]
    assert template.template_id == 256
    assert [f.type for f in template.fields] == [8, 12, 4, 7, 11, 2]
    assert [f.name for f in template.fields] == [
        'IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'PROTOCOL',
        'L4_SRC_PORT', 'L4_DST_PORT', 'IN_PKTS']
    assert template.record_length == 17
    assert bytes(nf) == raw


def test_net_flow_v9_multiple_templates_in_one_flowset():
    body = struct.pack('!HH', 256, 2) + struct.pack('!HHHH', 8, 4, 12, 4)
    body += struct.pack('!HH', 257, 1) + struct.pack('!HH', 4, 1)
    flowset = _v9_flowset(0, body)
    nf = Netflow9(_v9_header(1, 0, 1) + flowset)
    assert [t.template_id for t in nf.templates] == [256, 257]
    assert nf.templates[1].fields[0].type == 4


def test_net_flow_v9_template_flowset_padding_and_invalid_id():
    # zero bytes at a record boundary are padding, not an empty template
    body = (struct.pack('!HH', 256, 2) + struct.pack('!HHHH', 8, 4, 12, 4)
            + b'\x00' * 4)
    flowset = _v9_flowset(0, body, declared_length=4 + len(body))
    nf = Netflow9(_v9_header(1, 0, 1) + flowset)
    assert [t.template_id for t in nf.templates] == [256]
    assert nf.flowsets[0].padding == b'\x00' * 4
    assert bytes(nf) == _v9_header(1, 0, 1) + flowset

    # reserved template IDs cannot appear inside a Template FlowSet
    import pytest
    bad = _v9_flowset(0, struct.pack('!HH', 5, 1) + struct.pack('!HH', 8, 4))
    with pytest.raises(dpkt.UnpackError):
        Netflow9(_v9_header(1, 0, 1) + bad)


def test_net_flow_v9_options_template_unpack():
    flowset = _v9_options_template_flowset(
        300, [(V9_SCOPE_SYSTEM, 4)], [(36, 2), (37, 2)])
    nf = Netflow9(_v9_header(1, 0, 7) + flowset)
    flowset = nf.flowsets[0]
    assert isinstance(flowset, Netflow9OptionsTemplateFlowSet)
    template = flowset.templates[0]
    assert template.options is True
    assert template.template_id == 300
    assert [f.name for f in template.scopes] == ['SCOPE_SYSTEM']
    assert [f.name for f in template.fields] == [
        'FLOW_ACTIVE_TIMEOUT', 'FLOW_INACTIVE_TIMEOUT']
    assert template.record_length == 8


def test_net_flow_v9_stateless_data_flowset_keeps_raw():
    record = _v9_flow_record()
    raw = _v9_header(1, 0, 100) + _v9_flowset(256, record)
    nf = Netflow9(raw)
    flowset = nf.flowsets[0]
    assert isinstance(flowset, Netflow9DataFlowSet)
    assert flowset.flowset_id == 256
    # the 17-byte record is followed by 3 bytes of alignment padding
    assert flowset.records_raw == record + b'\x00' * 3
    assert flowset.decoded is False
    assert bytes(nf) == raw


def test_net_flow_v9_truncated_packet_raises():
    import pytest
    # header claims a FlowSet longer than the buffer
    with pytest.raises(dpkt.NeedData):
        Netflow9(_v9_header(1, 0, 1) + struct.pack('!HH', 256, 64) + b'\x00' * 8)
    # truncated FlowSet header
    with pytest.raises(dpkt.NeedData):
        Netflow9(_v9_header(1, 0, 1) + b'\x01')
    # truncated export packet header
    with pytest.raises(dpkt.NeedData):
        Netflow9(b'\x00\x09\x00')
    # template record with too few field bytes
    with pytest.raises(dpkt.NeedData):
        Netflow9(_v9_header(1, 0, 1) + _v9_flowset(
            0, struct.pack('!HH', 256, 2) + struct.pack('!HH', 8, 4)))


def test_net_flow_v9_collector_decodes_with_template():
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    raw = (_v9_header(2, 0, 100) + _v9_template_flowset(256, _V9_TEST_FIELDS)
           + _v9_flowset(256, _v9_flow_record()))
    result = collector.feed(raw, exporter='10.0.0.1')
    assert len(result.records) == 1
    record = result.records[0]
    assert record.values == {
        'IPV4_SRC_ADDR': '10.0.0.1', 'IPV4_DST_ADDR': '10.0.0.2',
        'PROTOCOL': 6, 'L4_SRC_PORT': 1234, 'L4_DST_PORT': 80,
        'IN_PKTS': 1000}
    assert record.template_id == 256
    assert record.template_version == 1
    assert record.sequence == 0
    assert record.source_id == 100
    assert record.session == '10.0.0.1'
    assert result.flowset_statuses[0]['status'] == 'ok'


def test_net_flow_v9_two_exporters_share_template_id():
    """Two fictional exporters reuse Template ID 256 with different layouts."""
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    shared_id = 256
    exporter_a = '192.0.2.10'
    exporter_b = '198.51.100.20'
    source_id = 50

    fields_a = [(8, 4), (12, 4), (1, 4)]
    fields_b = [(8, 4), (12, 4), (1, 8)]
    collector.feed(
        _v9_header(1, 0, source_id) + _v9_template_flowset(shared_id, fields_a),
        exporter=exporter_a)
    collector.feed(
        _v9_header(1, 0, source_id) + _v9_template_flowset(shared_id, fields_b),
        exporter=exporter_b)

    record_a = struct.pack('!4s4sI', b'\x0a\x01\x00\x01', b'\x0a\x01\x00\x02', 11)
    record_b = struct.pack('!4s4sQ', b'\x0a\x02\x00\x01', b'\x0a\x02\x00\x02', 22)
    result_a = collector.feed(
        _v9_header(1, 1, source_id) + _v9_flowset(shared_id, record_a),
        exporter=exporter_a)
    result_b = collector.feed(
        _v9_header(1, 1, source_id) + _v9_flowset(shared_id, record_b),
        exporter=exporter_b)

    assert result_a.records[0].values['IN_BYTES'] == 11
    assert result_b.records[0].values['IN_BYTES'] == 22
    assert result_a.records[0].values != result_b.records[0].values
    # separate cache buckets, each with its own version counter
    state = collector.state()
    buckets = {(b['exporter'], b['source_id']): b for b in state['templates']}
    assert set(buckets) == {(exporter_a, source_id), (exporter_b, source_id)}
    for bucket in buckets.values():
        assert bucket['templates'][0]['template_id'] == shared_id
        assert bucket['templates'][0]['version'] == 1


def test_net_flow_v9_template_update_replaces_and_bumps_version():
    """One template update: same ID, new field layout; rule per RFC 3954 sec 7."""
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    exporter, source_id = '192.0.2.10', 50
    v1_fields = [(8, 4), (12, 4), (2, 4)]
    v2_fields = [(8, 4), (12, 4), (2, 4), (1, 4)]

    first = collector.feed(
        _v9_header(1, 0, source_id) + _v9_template_flowset(256, v1_fields),
        exporter=exporter)
    assert first.templates_learned[0].version == 1

    # data decoded against version 1
    old_record = struct.pack('!4s4sI', b'\x0a\x01\x02\x03', b'\x0a\x01\x02\x04', 9)
    r1 = collector.feed(
        _v9_header(1, 1, source_id) + _v9_flowset(256, old_record),
        exporter=exporter)
    assert r1.records[0].template_version == 1

    # template update with the same ID
    update = collector.feed(
        _v9_header(1, 2, source_id) + _v9_template_flowset(256, v2_fields),
        exporter=exporter)
    updated = update.templates_learned[0]
    assert updated.version == 2
    assert [f.type for f in updated.fields] == [8, 12, 2, 1]
    state = collector.state(exporter=exporter, source_id=source_id)
    entry = state['templates'][0]['templates'][0]
    assert entry['version'] == 2
    assert entry['replaced'] == 1

    # subsequent data binds to the new version
    new_record = struct.pack('!4s4sII', b'\x0a\x01\x02\x05',
                             b'\x0a\x01\x02\x06', 3, 700)
    r2 = collector.feed(
        _v9_header(1, 3, source_id) + _v9_flowset(256, new_record),
        exporter=exporter)
    assert r2.records[0].template_version == 2
    assert r2.records[0].values['IN_BYTES'] == 700


def test_net_flow_v9_data_before_template_buffered_and_replayed():
    """Data arrives first; it is buffered under a finite budget, then replayed."""
    clock = [0.0]
    collector = Netflow9Collector(pending_limit=8, pending_max_bytes=4096,
                                  clock=lambda: clock[0])
    exporter, source_id = '192.0.2.10', 50
    record = struct.pack('!4s4sI', b'\x0a\x01\x00\x01', b'\x0a\x01\x00\x02', 42)

    early = collector.feed(
        _v9_header(1, 1, source_id) + _v9_flowset(256, record),
        exporter=exporter)
    assert early.records == []
    assert early.buffered_ids == [256]
    assert collector.state()['pending_packets'] == 1
    assert collector.state()['pending']['(%r, %d)' % (exporter, source_id)] == [
        {'template_id': 256, 'packets': 1, 'bytes': 12}]

    # template arrives in a later packet; buffered record is replayed
    later = collector.feed(
        _v9_header(1, 2, source_id)
        + _v9_template_flowset(256, [(8, 4), (12, 4), (1, 4)]),
        exporter=exporter)
    assert len(later.records) == 1
    replayed = later.records[0]
    assert replayed.values['IN_BYTES'] == 42
    assert replayed.template_version == 1
    assert replayed.sequence == 1
    assert replayed.replayed is True
    assert collector.state()['pending_packets'] == 0


def test_net_flow_v9_buffered_record_keeps_its_own_template_version():
    """Buffered records decoded after an update still cite the version used."""
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    exporter, source_id = '192.0.2.10', 50

    # v1 template and one decoded record (version 1)
    collector.feed(_v9_header(1, 0, source_id)
                   + _v9_template_flowset(256, [(8, 4), (12, 4), (1, 4)]),
                   exporter=exporter)
    record_v1 = struct.pack('!4s4sI', b'\x01\x02\x03\x04', b'\x05\x06\x07\x08', 5)
    direct = collector.feed(
        _v9_header(1, 1, source_id) + _v9_flowset(256, record_v1),
        exporter=exporter)
    assert direct.records[0].template_version == 1

    # new observation domain data before a template exists there too
    other = collector.feed(
        _v9_header(1, 2, 99) + _v9_flowset(256, record_v1),
        exporter=exporter)
    assert other.buffered_ids == [256]

    # template arrives after the data, at version 2 for this domain
    replay = collector.feed(
        _v9_header(1, 3, 99)
        + _v9_template_flowset(256, [(8, 4), (12, 4), (1, 4)]),
        exporter=exporter)
    assert replay.records[0].template_version == 2
    assert replay.records[0].sequence == 2
    assert replay.records[0].source_id == 99
    assert replay.records[0].replayed is True


def test_net_flow_v9_pending_budget_evicts_oldest():
    collector = Netflow9Collector(pending_limit=2, pending_max_bytes=1 << 30)
    exporter, source_id = '192.0.2.10', 50
    for sequence in range(4):
        result = collector.feed(
            _v9_header(1, sequence, source_id)
            + _v9_flowset(256, b'\x00' * 4), exporter=exporter)
        assert result.buffered_ids == [256]
    state = collector.state()
    assert state['pending_packets'] == 2
    assert state['pending_dropped'] == 2

    # byte budget also caps the buffer
    byte_limited = Netflow9Collector(pending_limit=100, pending_max_bytes=8)
    for sequence in range(3):
        byte_limited.feed(
            _v9_header(1, sequence, source_id)
            + _v9_flowset(256, b'\x00' * 6), exporter=exporter)
    assert byte_limited.state()['pending_bytes'] == 8
    assert byte_limited.pending_dropped == 2


def test_net_flow_v9_truncated_data_flowset_is_not_a_record():
    """A short record, short tail and padding cannot be treated as complete."""
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    exporter, source_id = '192.0.2.10', 50
    fields = [(8, 4), (12, 4), (2, 4)]   # 12-byte fixed record
    collector.feed(_v9_header(1, 0, source_id)
                   + _v9_template_flowset(256, fields), exporter=exporter)

    # one complete record followed by a 3-byte tail
    good = struct.pack('!4s4sI', b'\x0a\x01\x02\x03', b'\x0a\x01\x02\x04', 7)
    tail = b'\x01\x02\x03'
    mixed = _v9_flowset(256, good + tail, declared_length=4 + len(good) + len(tail))
    mixed_result = collector.feed(
        _v9_header(1, 1, source_id) + mixed, exporter=exporter)
    assert len(mixed_result.records) == 1
    status = mixed_result.flowset_statuses[0]
    assert status['status'] == 'incomplete'
    assert '12 bytes, 3 remain' in status['reason']

    # completely truncated flowset: zero records, incomplete status
    truncated = _v9_flowset(256, b'\x0a\x01\x02\x03\x0a\x01\x02\x04\x00\x00',
                            declared_length=14)
    trunc_result = collector.feed(
        _v9_header(1, 2, source_id) + truncated, exporter=exporter)
    assert trunc_result.records == []
    assert trunc_result.flowset_statuses[0]['status'] == 'incomplete'
    assert '12 bytes, 10 remain' in trunc_result.flowset_statuses[0]['reason']

    # zero-only tail is accepted as alignment padding, not as a record
    padded = _v9_flowset(256, b'\x00\x00')
    pad_result = collector.feed(
        _v9_header(1, 3, source_id) + padded, exporter=exporter)
    assert pad_result.records == []
    assert pad_result.flowset_statuses[0]['status'] == 'padding'


def test_net_flow_v9_unknown_field_keeps_raw_bytes():
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    exporter, source_id = '192.0.2.10', 50
    # field type 600 is not defined by RFC 3954; its bytes must survive
    fields = [(8, 4), (600, 3), (4, 1)]
    collector.feed(_v9_header(1, 0, source_id)
                   + _v9_template_flowset(256, fields), exporter=exporter)
    record = b'\x0a\x00\x00\x01' + b'\xde\xad\xbe' + b'\x06'
    result = collector.feed(
        _v9_header(1, 1, source_id) + _v9_flowset(256, record),
        exporter=exporter)
    decoded = result.records[0]
    assert decoded.values['IPV4_SRC_ADDR'] == '10.0.0.1'
    assert decoded.values['FIELD_600'] == b'\xde\xad\xbe'
    assert decoded.values['PROTOCOL'] == 6
    assert decoded.raw == record
    assert any('unknown field type 600' in issue for issue in decoded.issues)


def test_net_flow_v9_variable_length_layout_marked_unsupported():
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    exporter, source_id = '192.0.2.10', 50
    fields = [(8, 4), (82, V9_VARIABLE_LENGTH)]
    learn = collector.feed(_v9_header(1, 0, source_id)
                           + _v9_template_flowset(257, fields),
                           exporter=exporter)
    template = learn.templates_learned[0]
    assert template.unsupported_reason is not None
    assert 'variable-length field 82' in template.unsupported_reason
    assert template.record_length is None

    # data for that template is not decoded but is explicitly marked
    result = collector.feed(
        _v9_header(1, 1, source_id)
        + _v9_flowset(257, b'\x0a\x01\x02\x03\x05hello'), exporter=exporter)
    assert result.records == []
    status = result.flowset_statuses[0]
    assert status['status'] == 'unsupported-layout'
    assert 'variable-length' in status['reason']
    state = collector.state(exporter=exporter, source_id=source_id)
    assert state['templates'][0]['templates'][0]['unsupported'] is not None


def test_net_flow_v9_template_expiry():
    clock = [0.0]
    collector = Netflow9Collector(template_timeout=10.0,
                                  clock=lambda: clock[0])
    exporter, source_id = '192.0.2.10', 50
    collector.feed(_v9_header(1, 0, source_id)
                   + _v9_template_flowset(256, [(8, 4)]), exporter=exporter)
    clock[0] = 5.0
    assert collector.lookup(256, exporter=exporter,
                            source_id=source_id).version == 1
    clock[0] = 20.0
    try:
        collector.lookup(256, exporter=exporter, source_id=source_id)
        assert False, 'expired template must not decode'
    except V9TemplateNotFound as exc:
        assert exc.expired is True
    state = collector.state(exporter=exporter, source_id=source_id)
    entry = state['templates'][0]['templates'][0]
    assert entry['expired'] is True
    assert entry['expires_in'] == 0.0

    # refresh before the deadline resets the clock and bumps the version
    clock[0] = 0.0
    collector2 = Netflow9Collector(template_timeout=10.0,
                                   clock=lambda: clock[0])
    collector2.feed(_v9_header(1, 0, source_id)
                    + _v9_template_flowset(256, [(8, 4)]), exporter=exporter)
    clock[0] = 8.0
    collector2.feed(_v9_header(1, 1, source_id)
                    + _v9_template_flowset(256, [(8, 4)]), exporter=exporter)
    clock[0] = 15.0
    refreshed = collector2.lookup(256, exporter=exporter, source_id=source_id)
    assert refreshed.version == 2
    entry = collector2.state(exporter=exporter)['templates'][0]['templates'][0]
    assert entry['expired'] is False
    assert entry['replaced'] == 1
    assert entry['first_seen'] == 0.0
    assert entry['last_seen'] == 8.0


def test_net_flow_v9_restart_on_uptime_and_sequence():
    exporter, source_id = '192.0.2.10', 50
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    collector.feed(_v9_header(1, 100, source_id, sys_uptime=900000)
                   + _v9_template_flowset(256, [(8, 4), (12, 4)]),
                   exporter=exporter)

    # sysUpTime going backwards invalidates the cache immediately
    restart = collector.feed(
        _v9_header(1, 0, source_id, sys_uptime=500)
        + _v9_template_flowset(256, [(8, 4), (12, 4)]), exporter=exporter)
    assert restart.restarted is True
    assert 'sys_uptime went backwards' in restart.restart_reason
    assert collector.restart_count == 1

    # sequence-only restart detection (uptime monotonic)
    clock[0] = 1.0
    second = collector.feed(
        _v9_header(1, 5, source_id, sys_uptime=600)
        + _v9_template_flowset(256, [(8, 4), (12, 4)]), exporter=exporter)
    seq_restart = collector.feed(
        _v9_header(1, 2, source_id, sys_uptime=700)
        + _v9_template_flowset(256, [(8, 4), (12, 4)]), exporter=exporter)
    assert second.restarted is False
    assert seq_restart.restarted is True
    assert 'flow_sequence went backwards' in seq_restart.restart_reason
    assert collector.restart_count == 2

    # heuristics can be disabled independently
    quiet = Netflow9Collector(restart_on_uptime=False,
                              restart_on_sequence=False)
    quiet.feed(_v9_header(1, 100, source_id, sys_uptime=900000)
               + _v9_template_flowset(256, [(8, 4)]), exporter=exporter)
    no_restart = quiet.feed(_v9_header(1, 0, source_id, sys_uptime=1)
                            + _v9_template_flowset(256, [(8, 4)]),
                            exporter=exporter)
    assert no_restart.restarted is False
    assert quiet.restart_count == 0


def test_net_flow_v9_restart_discards_pending_data():
    exporter, source_id = '192.0.2.10', 50
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    collector.feed(_v9_header(1, 0, source_id, sys_uptime=900)
                   + _v9_flowset(256, b'\x00' * 4), exporter=exporter)
    assert collector.state()['pending_packets'] == 1
    restart = collector.feed(_v9_header(1, 1, source_id, sys_uptime=10),
                             exporter=exporter)
    assert restart.restarted is True
    assert collector.state()['pending_packets'] == 0


def test_net_flow_v9_explicit_invalidate():
    exporter, source_id = '192.0.2.10', 50
    collector = Netflow9Collector()
    collector.feed(_v9_header(1, 0, source_id)
                   + _v9_template_flowset(256, [(8, 4)]), exporter=exporter)
    collector.invalidate(exporter, source_id, reason='clock change')
    assert collector.last_restart['reason'] == 'clock change'
    assert collector.state()['templates'] == []
    try:
        collector.lookup(256, exporter=exporter, source_id=source_id)
        assert False
    except V9TemplateNotFound as exc:
        assert exc.reason == 'no templates cached'


def test_net_flow_v9_options_data_record():
    clock = [0.0]
    collector = Netflow9Collector(clock=lambda: clock[0])
    exporter, source_id = '192.0.2.10', 50
    template = _v9_options_template_flowset(
        300, [(V9_SCOPE_INTERFACE, 4)], [(34, 4), (35, 1)])
    data = struct.pack('!IIB', 7, 1000, 2)  # interface, interval, algorithm
    result = collector.feed(
        _v9_header(2, 0, source_id) + template
        + _v9_flowset(300, data), exporter=exporter)
    record = result.records[0]
    assert record.options is True
    assert record.values == {
        'SCOPE_INTERFACE': 7, 'SAMPLING_INTERVAL': 1000,
        'SAMPLING_ALGORITHM': 2}
    assert record.template_version == 1
    state = collector.state(exporter=exporter, source_id=source_id)
    assert state['templates'][0]['templates'][0]['options'] is True


def test_net_flow_v9_session_state_and_sequence_provenance():
    exporter, source_id = '192.0.2.10', 50
    collector = Netflow9Collector()
    result = collector.feed(
        _v9_header(2, 17, source_id, sys_uptime=123456, unix_sec=1700000123)
        + _v9_template_flowset(256, [(8, 4), (12, 4)])
        + _v9_flowset(256, struct.pack('!4s4s', b'\x01\x01\x01\x01',
                                       b'\x02\x02\x02\x02')),
        exporter=exporter)
    record = result.records[0]
    assert record.sequence == 17
    assert record.sys_uptime == 123456
    assert record.unix_sec == 1700000123
    assert record.source_id == source_id
    assert record.session == exporter
    assert result.sequence == 17
    assert result.source_id == source_id
    session = collector.state()['sessions'][exporter]
    assert session == {'uptime': 123456, 'sequence': 17, 'unix_sec': 1700000123,
                       'packets': 1}


def test_net_flow_v9_full_scenario_two_exporters_update_and_truncation():
    """End-to-end scenario combining all three required verification cases."""
    exporter_a, exporter_b = '192.0.2.10', '198.51.100.20'
    source_id = 50
    clock = [0.0]
    collector = Netflow9Collector(pending_limit=8, clock=lambda: clock[0])

    # Both exporters advertise Template ID 256 with different layouts.
    collector.feed(_v9_header(1, 0, source_id)
                   + _v9_template_flowset(256, [(8, 4), (12, 4), (2, 4)]),
                   exporter=exporter_a)
    collector.feed(_v9_header(1, 0, source_id)
                   + _v9_template_flowset(256, [(8, 4), (12, 4), (2, 8)]),
                   exporter=exporter_b)

    # Exporter A sends a truncated Data FlowSet (template needs 12 bytes).
    short = _v9_flowset(256, b'\x0a\x01\x02\x03\x0a\x01\x02\x04',
                        declared_length=12)
    a_bad = collector.feed(_v9_header(1, 1, source_id) + short,
                           exporter=exporter_a)
    assert a_bad.records == []
    assert a_bad.flowset_statuses[0]['status'] == 'incomplete'

    # A complete record from each exporter decodes under its own template.
    a_good = collector.feed(
        _v9_header(1, 2, source_id)
        + _v9_flowset(256, struct.pack('!4s4sI', b'\x0a\x01\x00\x01',
                                       b'\x0a\x01\x00\x02', 500)),
        exporter=exporter_a)
    b_good = collector.feed(
        _v9_header(1, 1, source_id)
        + _v9_flowset(256, struct.pack('!4s4sQ', b'\x0a\x02\x00\x01',
                                       b'\x0a\x02\x00\x02', 900)),
        exporter=exporter_b)
    assert a_good.records[0].values['IN_PKTS'] == 500
    assert b_good.records[0].values['IN_PKTS'] == 900
    assert a_good.records[0].template_version == 1
    assert b_good.records[0].template_version == 1
    assert a_good.records[0].session == exporter_a
    assert b_good.records[0].session == exporter_b

    # Exporter A updates Template 256; later records bind to version 2.
    update = collector.feed(
        _v9_header(1, 3, source_id)
        + _v9_template_flowset(256, [(8, 4), (12, 4), (2, 4), (1, 4)]),
        exporter=exporter_a)
    assert update.templates_learned[0].version == 2
    a_new = collector.feed(
        _v9_header(1, 4, source_id)
        + _v9_flowset(256, struct.pack('!4s4sII', b'\x0a\x01\x00\x03',
                                       b'\x0a\x01\x00\x04', 600, 12345)),
        exporter=exporter_a)
    assert a_new.records[0].template_version == 2
    assert a_new.records[0].values['IN_BYTES'] == 12345

    # Exporter B is unaffected by A's update.
    b_again = collector.feed(
        _v9_header(1, 2, source_id)
        + _v9_flowset(256, struct.pack('!4s4sQ', b'\x0a\x02\x00\x03',
                                       b'\x0a\x02\x00\x04', 901)),
        exporter=exporter_b)
    assert b_again.records[0].template_version == 1
    assert b_again.records[0].values['IN_PKTS'] == 901

    state = collector.state()
    buckets = {(b['exporter'], b['source_id']): b for b in state['templates']}
    assert len(buckets) == 2
    assert buckets[(exporter_a, source_id)]['templates'][0]['version'] == 2
    assert buckets[(exporter_b, source_id)]['templates'][0]['version'] == 1
    assert state['restart_count'] == 0
