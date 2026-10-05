# -*- coding: utf-8 -*-
"""IP Flow Information Export (IPFIX) Protocol - RFC 7011 (version 10).

Stateful decoder: template and options template records are remembered per
(exporter, observation domain) so that subsequent data sets carrying only a
template ID can be interpreted.  Template state is never shared between
exporters or observation domains.
"""
from __future__ import absolute_import
from __future__ import print_function

import socket
import struct

from . import dpkt
from .compat import compat_ord

IPFIX_VERSION = 10

# Set IDs
TEMPLATE_SET_ID = 2
OPTIONS_TEMPLATE_SET_ID = 3
MIN_DATA_SET_ID = 256

# Field/template constants
VARIABLE_LENGTH = 0xFFFF
ENTERPRISE_BIT = 0x8000
WITHDRAW_ALL_TEMPLATES = 2
WITHDRAW_ALL_OPTIONS_TEMPLATES = 3
OPTIONS_TEMPLATE_WITHDRAWAL_FIELD_COUNT = 0xFFFF

_HDR_LEN = 16  # message header
_SET_HDR_LEN = 4


class IPFIXDecodeError(dpkt.UnpackError):
    """Raised when an IPFIX message is malformed.

    The ``offset`` attribute locates the error within the message.
    """

    def __init__(self, offset, message):
        self.offset = offset
        dpkt.UnpackError.__init__(self, 'offset %d: %s' % (offset, message))


# Subset of the IANA IPFIX Information Element registry, enterprise 0.
# element id -> (name, kind); kind drives value decoding.
_INFORMATION_ELEMENTS = {
    1: ('octetDeltaCount', 'uint'),
    2: ('packetDeltaCount', 'uint'),
    4: ('protocolIdentifier', 'uint'),
    5: ('ipClassOfService', 'uint'),
    6: ('tcpControlBits', 'uint'),
    7: ('sourceTransportPort', 'uint'),
    8: ('sourceIPv4Address', 'ipv4'),
    9: ('sourceIPv4PrefixLength', 'uint'),
    10: ('ingressInterface', 'uint'),
    11: ('destinationTransportPort', 'uint'),
    12: ('destinationIPv4Address', 'ipv4'),
    13: ('destinationIPv4PrefixLength', 'uint'),
    14: ('egressInterface', 'uint'),
    15: ('ipNextHopIPv4Address', 'ipv4'),
    21: ('flowEndSysUpTime', 'uint'),
    22: ('flowStartSysUpTime', 'uint'),
    27: ('sourceIPv6Address', 'ipv6'),
    28: ('destinationIPv6Address', 'ipv6'),
    32: ('icmpTypeCodeIPv4', 'uint'),
    56: ('sourceMacAddress', 'mac'),
    58: ('vlanId', 'uint'),
    59: ('postVlanId', 'uint'),
    60: ('ipVersion', 'uint'),
    61: ('flowDirection', 'uint'),
    80: ('destinationMacAddress', 'mac'),
    136: ('flowEndReason', 'uint'),
    148: ('flowId', 'uint'),
    152: ('flowStartMilliseconds', 'uint'),
    153: ('flowEndMilliseconds', 'uint'),
    225: ('postNATSourceIPv4Address', 'ipv4'),
    226: ('postNATDestinationIPv4Address', 'ipv4'),
}


def _decode_uint(raw):
    value = 0
    for ch in raw:
        value = (value << 8) | compat_ord(ch)
    return value


def _decode_value(element_id, enterprise_number, raw):
    """Decode a field value; unknown elements keep their raw bytes."""
    if enterprise_number is None:
        info = _INFORMATION_ELEMENTS.get(element_id)
        if info is not None:
            kind = info[1]
            if kind == 'uint':
                return _decode_uint(raw)
            if kind == 'ipv4' and len(raw) == 4:
                return socket.inet_ntop(socket.AF_INET, raw)
            if kind == 'ipv6' and len(raw) == 16:
                return socket.inet_ntop(socket.AF_INET6, raw)
            if kind == 'mac' and len(raw) == 6:
                return ':'.join('%02x' % compat_ord(ch) for ch in raw)
    return raw


class TemplateField(object):
    """One field specifier of a template record."""

    __slots__ = ('element_id', 'length', 'enterprise_number')

    def __init__(self, element_id, length, enterprise_number=None):
        self.element_id = element_id
        self.length = length
        self.enterprise_number = enterprise_number

    @property
    def is_enterprise(self):
        return self.enterprise_number is not None

    @property
    def is_variable_length(self):
        return self.length == VARIABLE_LENGTH

    @property
    def name(self):
        if self.enterprise_number is None:
            info = _INFORMATION_ELEMENTS.get(self.element_id)
            if info is not None:
                return info[0]
        return None

    def __repr__(self):
        return 'TemplateField(element_id=%d, length=%d, enterprise_number=%r)' % (
            self.element_id, self.length, self.enterprise_number)


class Template(object):
    """A template or options template registered by an exporter."""

    def __init__(self, template_id, fields, is_options=False, scope_field_count=0):
        self.template_id = template_id
        self.fields = fields
        self.is_options = is_options
        self.scope_field_count = scope_field_count

    @property
    def record_length(self):
        """Fixed record length, or None if the template has variable-length fields."""
        total = 0
        for field in self.fields:
            if field.is_variable_length:
                return None
            total += field.length
        return total

    @property
    def min_record_length(self):
        """Smallest possible encoded record size (variable fields count as 1)."""
        total = 0
        for field in self.fields:
            total += 1 if field.is_variable_length else field.length
        return total

    def __repr__(self):
        return 'Template(template_id=%d, fields=%r, is_options=%r)' % (
            self.template_id, self.fields, self.is_options)


class DecodedField(object):
    """A single decoded field of a data record."""

    __slots__ = ('element_id', 'enterprise_number', 'name', 'value', 'raw')

    def __init__(self, element_id, enterprise_number, name, value, raw):
        self.element_id = element_id
        self.enterprise_number = enterprise_number
        self.name = name
        self.value = value
        self.raw = raw

    def __repr__(self):
        return 'DecodedField(name=%r, value=%r)' % (self.name, self.value)


class DataRecord(object):
    """One record of a data set, decoded against a template."""

    def __init__(self, template, fields):
        self.template = template
        self.fields = fields

    def __getitem__(self, name):
        for field in self.fields:
            if field.name == name:
                return field.value
        raise KeyError(name)

    def __repr__(self):
        return 'DataRecord(template_id=%d, fields=%r)' % (
            self.template.template_id, self.fields)


class TemplateSet(object):
    """A parsed template set (set ID 2)."""

    set_id = TEMPLATE_SET_ID

    def __init__(self, templates, withdrawals):
        self.templates = templates
        self.withdrawals = withdrawals  # list of template IDs, or 'all'


class OptionsTemplateSet(object):
    """A parsed options template set (set ID 3)."""

    set_id = OPTIONS_TEMPLATE_SET_ID

    def __init__(self, templates, withdrawals):
        self.templates = templates
        self.withdrawals = withdrawals


class DataSet(object):
    """A data set decoded against a known template."""

    def __init__(self, template_id, template, records, padding):
        self.template_id = template_id
        self.template = template
        self.records = records
        self.padding = padding


class UnresolvedDataSet(object):
    """A data set whose template is unknown; raw bytes are preserved and no
    field layout is guessed."""

    def __init__(self, template_id, data, reason):
        self.template_id = template_id
        self.data = data
        self.reason = reason

    def __repr__(self):
        return 'UnresolvedDataSet(template_id=%d, reason=%r, len=%d)' % (
            self.template_id, self.reason, len(self.data))


class IPFIXMessage(object):
    """A decoded IPFIX message."""

    def __init__(self):
        self.version = IPFIX_VERSION
        self.length = 0
        self.export_time = 0
        self.sequence_number = 0
        self.observation_domain_id = 0
        self.sets = []

    def __repr__(self):
        return 'IPFIXMessage(odid=%d, seq=%d, sets=%r)' % (
            self.observation_domain_id, self.sequence_number, self.sets)


class IPFIXDecoder(object):
    """Stateful IPFIX v10 decoder.

    Templates are stored per (exporter, observation domain ID); ``exporter``
    is a caller-supplied identity (e.g. a ``(host, port)`` tuple) that keeps
    devices from interpreting each other's template IDs.
    """

    def __init__(self):
        self._templates = {}           # (exporter, odid) -> {template_id: Template}
        self._options_templates = {}   # (exporter, odid) -> {template_id: Template}

    def templates(self, exporter=None, observation_domain_id=0):
        """Return the live template table for the given exporter/domain."""
        return dict(self._templates.get((exporter, observation_domain_id), {}))

    def options_templates(self, exporter=None, observation_domain_id=0):
        """Return the live options template table for the given exporter/domain."""
        return dict(self._options_templates.get((exporter, observation_domain_id), {}))

    def decode(self, buf, exporter=None):
        """Decode one IPFIX message, updating and consulting template state."""
        if len(buf) < _HDR_LEN:
            raise IPFIXDecodeError(0, 'message header truncated: %d of %d bytes'
                                   % (len(buf), _HDR_LEN))
        (version, length, export_time, sequence_number,
         observation_domain_id) = struct.unpack_from('>HHIII', buf, 0)
        if version != IPFIX_VERSION:
            raise IPFIXDecodeError(0, 'unsupported version %d' % version)
        if length < _HDR_LEN:
            raise IPFIXDecodeError(0, 'invalid message length %d' % length)
        if len(buf) < length:
            raise IPFIXDecodeError(0, 'message truncated: %d of %d bytes'
                                   % (len(buf), length))

        msg = IPFIXMessage()
        msg.version = version
        msg.length = length
        msg.export_time = export_time
        msg.sequence_number = sequence_number
        msg.observation_domain_id = observation_domain_id

        key = (exporter, observation_domain_id)
        templates = self._templates.setdefault(key, {})
        options_templates = self._options_templates.setdefault(key, {})

        offset = _HDR_LEN
        while offset < length:
            if offset + _SET_HDR_LEN > length:
                raise IPFIXDecodeError(offset, 'set header truncated')
            set_id, set_length = struct.unpack_from('>HH', buf, offset)
            if set_length < _SET_HDR_LEN:
                raise IPFIXDecodeError(offset, 'invalid set length %d' % set_length)
            if offset + set_length > length:
                raise IPFIXDecodeError(offset, 'set of %d bytes overruns message (%d bytes left)'
                                       % (set_length, length - offset))
            body = buf[offset + _SET_HDR_LEN:offset + set_length]
            body_offset = offset + _SET_HDR_LEN

            if set_id == TEMPLATE_SET_ID:
                msg.sets.append(self._parse_template_set(
                    body, body_offset, templates, is_options=False))
            elif set_id == OPTIONS_TEMPLATE_SET_ID:
                msg.sets.append(self._parse_template_set(
                    body, body_offset, options_templates, is_options=True))
            elif set_id >= MIN_DATA_SET_ID:
                msg.sets.append(self._parse_data_set(
                    set_id, body, body_offset, templates, options_templates))
            else:
                raise IPFIXDecodeError(offset, 'reserved set ID %d' % set_id)
            offset += set_length
        return msg

    def _parse_template_set(self, body, body_offset, table, is_options):
        templates = []
        withdrawals = []
        offset = 0
        while offset < len(body):
            if offset + 4 > len(body):
                raise IPFIXDecodeError(body_offset + offset,
                                       'template record header truncated')
            template_id, field_count = struct.unpack_from('>HH', body, offset)
            offset += 4

            if is_options and field_count == OPTIONS_TEMPLATE_WITHDRAWAL_FIELD_COUNT:
                self._withdraw(table, template_id, WITHDRAW_ALL_OPTIONS_TEMPLATES,
                               withdrawals)
                continue
            if not is_options and field_count == 0:
                self._withdraw(table, template_id, WITHDRAW_ALL_TEMPLATES,
                               withdrawals)
                continue

            if template_id < MIN_DATA_SET_ID:
                raise IPFIXDecodeError(body_offset + offset - 4,
                                       'reserved template ID %d' % template_id)

            scope_field_count = 0
            if is_options:
                if offset + 2 > len(body):
                    raise IPFIXDecodeError(body_offset + offset,
                                           'options template scope count truncated')
                scope_field_count = struct.unpack_from('>H', body, offset)[0]
                offset += 2
                if scope_field_count > field_count:
                    raise IPFIXDecodeError(
                        body_offset + offset - 2,
                        'scope field count %d exceeds field count %d'
                        % (scope_field_count, field_count))

            fields = []
            for _ in range(field_count):
                if offset + 4 > len(body):
                    raise IPFIXDecodeError(body_offset + offset,
                                           'template field specifier truncated')
                element_id, field_length = struct.unpack_from('>HH', body, offset)
                offset += 4
                enterprise_number = None
                if element_id & ENTERPRISE_BIT:
                    if offset + 4 > len(body):
                        raise IPFIXDecodeError(body_offset + offset,
                                               'enterprise number truncated')
                    enterprise_number = struct.unpack_from('>I', body, offset)[0]
                    offset += 4
                    element_id &= ~ENTERPRISE_BIT
                fields.append(TemplateField(element_id, field_length,
                                            enterprise_number))

            template = Template(template_id, fields, is_options=is_options,
                                scope_field_count=scope_field_count)
            # a redefinition under the same ID replaces the previous template
            table[template_id] = template
            templates.append(template)

        if is_options:
            return OptionsTemplateSet(templates, withdrawals)
        return TemplateSet(templates, withdrawals)

    @staticmethod
    def _withdraw(table, template_id, withdraw_all_id, withdrawals):
        if template_id == withdraw_all_id:
            table.clear()
            withdrawals.append('all')
        else:
            table.pop(template_id, None)
            withdrawals.append(template_id)

    def _parse_data_set(self, template_id, body, body_offset, templates,
                        options_templates):
        template = templates.get(template_id)
        if template is None:
            template = options_templates.get(template_id)
        if template is None:
            return UnresolvedDataSet(template_id, body,
                                     'no template for ID %d' % template_id)

        records = []
        offset = 0
        min_length = template.min_record_length
        while len(body) - offset >= min_length:
            record, offset = self._decode_record(template, body, offset,
                                                 body_offset)
            records.append(record)
        # any remaining bytes are padding, shorter than one record
        padding = body[offset:]
        return DataSet(template_id, template, records, padding)

    def _decode_record(self, template, body, offset, body_offset):
        fields = []
        end = len(body)
        for spec in template.fields:
            if spec.is_variable_length:
                if offset + 1 > end:
                    raise IPFIXDecodeError(body_offset + offset,
                                           'variable-length field truncated')
                field_length = compat_ord(body[offset])
                offset += 1
                if field_length == 255:
                    if offset + 2 > end:
                        raise IPFIXDecodeError(body_offset + offset,
                                               'variable-length field truncated')
                    field_length = struct.unpack_from('>H', body, offset)[0]
                    offset += 2
            else:
                field_length = spec.length
            if offset + field_length > end:
                raise IPFIXDecodeError(
                    body_offset + offset,
                    'record overruns set: field %d needs %d bytes, %d left'
                    % (spec.element_id, field_length, end - offset))
            raw = body[offset:offset + field_length]
            offset += field_length
            fields.append(DecodedField(
                spec.element_id, spec.enterprise_number, spec.name,
                _decode_value(spec.element_id, spec.enterprise_number, raw),
                raw))
        return DataRecord(template, fields), offset


def _build_message(sets, odid=0, seq=0, export_time=1500000000):
    body = b''.join(sets)
    return struct.pack('>HHIII', IPFIX_VERSION, 16 + len(body),
                       export_time, seq, odid) + body


def _build_set(set_id, body):
    return struct.pack('>HH', set_id, 4 + len(body)) + body


def _template_record(template_id, fields):
    # fields: (element_id, length) or (element_id, length, enterprise_number)
    out = [struct.pack('>HH', template_id, len(fields))]
    for field in fields:
        if len(field) == 3:
            element_id, length, pen = field
            out.append(struct.pack('>HHI', element_id | ENTERPRISE_BIT,
                                   length, pen))
        else:
            out.append(struct.pack('>HH', field[0], field[1]))
    return b''.join(out)


def _options_template_record(template_id, scope_count, fields):
    record = _template_record(template_id, fields)
    return record[:4] + struct.pack('>H', scope_count) + record[4:]


def _template_set(*records):
    return _build_set(TEMPLATE_SET_ID, b''.join(records))


def _options_template_set(*records):
    return _build_set(OPTIONS_TEMPLATE_SET_ID, b''.join(records))


def _data_set(template_id, body):
    return _build_set(template_id, body)


def _withdraw_record(template_id):
    return struct.pack('>HH', template_id, 0)


def test_two_exporters_shared_template_id_with_withdrawal():
    decoder = IPFIXDecoder()
    exporter_a = ('10.0.0.1', 4739)
    exporter_b = ('10.0.0.2', 4739)

    # both exporters define template ID 256, with different layouts
    msg = decoder.decode(_build_message([_template_set(
        _template_record(256, [(8, 4), (12, 4)]))]), exporter=exporter_a)
    assert isinstance(msg.sets[0], TemplateSet)
    decoder.decode(_build_message([_template_set(
        _template_record(256, [(7, 2), (11, 2), (4, 1)]))]), exporter=exporter_b)

    # data sets decode per-exporter despite the shared template ID
    msg = decoder.decode(_build_message([
        _data_set(256, b'\x01\x02\x03\x04\x05\x06\x07\x08')]),
        exporter=exporter_a)
    record = msg.sets[0].records[0]
    assert record['sourceIPv4Address'] == '1.2.3.4'
    assert record['destinationIPv4Address'] == '5.6.7.8'

    msg = decoder.decode(_build_message([
        _data_set(256, b'\x00\x50\x01\xbb\x06')]), exporter=exporter_b)
    record = msg.sets[0].records[0]
    assert record['sourceTransportPort'] == 80
    assert record['destinationTransportPort'] == 443
    assert record['protocolIdentifier'] == 6

    # exporter A withdraws its template; exporter B is unaffected
    msg = decoder.decode(_build_message([_template_set(
        _withdraw_record(256))]), exporter=exporter_a)
    assert msg.sets[0].withdrawals == [256]

    msg = decoder.decode(_build_message([
        _data_set(256, b'\xde\xad\xbe\xef')]), exporter=exporter_a)
    unresolved = msg.sets[0]
    assert isinstance(unresolved, UnresolvedDataSet)
    assert unresolved.template_id == 256
    assert unresolved.data == b'\xde\xad\xbe\xef'

    msg = decoder.decode(_build_message([
        _data_set(256, b'\x00\x50\x01\xbb\x11')]), exporter=exporter_b)
    record = msg.sets[0].records[0]
    assert record['sourceTransportPort'] == 80
    assert record['protocolIdentifier'] == 17


def test_observation_domain_isolation():
    decoder = IPFIXDecoder()
    exporter = ('10.0.0.1', 4739)
    decoder.decode(_build_message([_template_set(
        _template_record(256, [(4, 1)]))], odid=1), exporter=exporter)

    # same exporter and template ID, different observation domain: unresolved
    msg = decoder.decode(_build_message([
        _data_set(256, b'\x06')], odid=2), exporter=exporter)
    assert isinstance(msg.sets[0], UnresolvedDataSet)

    msg = decoder.decode(_build_message([
        _data_set(256, b'\x06')], odid=1), exporter=exporter)
    assert msg.sets[0].records[0]['protocolIdentifier'] == 6


def test_enterprise_and_variable_length_fields():
    decoder = IPFIXDecoder()
    decoder.decode(_build_message([_template_set(_template_record(300, [
        (8, 4),
        (1000, VARIABLE_LENGTH, 29305),  # enterprise-specific, variable length
        (999, 3),                        # unknown IANA element
    ]))]), exporter='exp')

    # two records; the variable-length field uses the short form in the
    # first record and the long form (0xFF + 2-byte length) in the second
    body = (b'\x0a\x00\x00\x01' + b'\x03abc' + b'\x01\x02\x03' +
            b'\x0a\x00\x00\x02' + b'\xff\x00\x05hello' + b'\x04\x05\x06')
    msg = decoder.decode(_build_message([_data_set(300, body)]), exporter='exp')
    records = msg.sets[0].records
    assert len(records) == 2

    field = records[0].fields[1]
    assert field.element_id == 1000
    assert field.enterprise_number == 29305
    assert field.name is None
    assert field.value == b'abc'  # enterprise fields keep raw bytes

    field = records[1].fields[1]
    assert field.value == b'hello'

    unknown = records[0].fields[2]
    assert unknown.name is None
    assert unknown.value == b'\x01\x02\x03'  # unknown fields keep raw bytes
    assert records[0]['sourceIPv4Address'] == '10.0.0.1'


def test_options_template_isolated_from_templates():
    decoder = IPFIXDecoder()
    exporter = 'exp'
    # same ID 400 as a normal template and as an options template
    decoder.decode(_build_message([
        _template_set(_template_record(400, [(4, 1)])),
        _options_template_set(_options_template_record(
            400, 1, [(10, 4), (1, 8)])),
    ]), exporter=exporter)

    assert 400 in decoder.templates(exporter)
    assert 400 in decoder.options_templates(exporter)

    # normal templates win for data sets
    msg = decoder.decode(_build_message([
        _data_set(400, b'\x06')]), exporter=exporter)
    assert msg.sets[0].records[0]['protocolIdentifier'] == 6

    # withdraw the normal template; the options template takes over
    decoder.decode(_build_message([
        _template_set(_withdraw_record(400))]), exporter=exporter)
    msg = decoder.decode(_build_message([
        _data_set(400, b'\x00\x00\x00\x03' + b'\x00' * 7 + b'\x2a')]),
        exporter=exporter)
    record = msg.sets[0].records[0]
    assert record['ingressInterface'] == 3
    assert record['octetDeltaCount'] == 42


def test_template_redefinition():
    decoder = IPFIXDecoder()
    decoder.decode(_build_message([_template_set(
        _template_record(256, [(4, 1)]))]), exporter='exp')
    decoder.decode(_build_message([_template_set(
        _template_record(256, [(7, 2)]))]), exporter='exp')

    msg = decoder.decode(_build_message([
        _data_set(256, b'\x01\xbb')]), exporter='exp')
    assert msg.sets[0].records[0]['sourceTransportPort'] == 443


def test_data_set_without_template_is_unresolved():
    decoder = IPFIXDecoder()
    msg = decoder.decode(_build_message([
        _data_set(512, b'\x01\x02\x03\x04')]), exporter='exp')
    unresolved = msg.sets[0]
    assert isinstance(unresolved, UnresolvedDataSet)
    assert unresolved.template_id == 512
    assert unresolved.data == b'\x01\x02\x03\x04'


def test_message_header_fields():
    decoder = IPFIXDecoder()
    msg = decoder.decode(_build_message([], odid=7, seq=99), exporter='exp')
    assert msg.version == 10
    assert msg.length == 16
    assert msg.export_time == 1500000000
    assert msg.sequence_number == 99
    assert msg.observation_domain_id == 7
    assert msg.sets == []


def test_padding():
    decoder = IPFIXDecoder()
    decoder.decode(_build_message([_template_set(
        _template_record(256, [(8, 4)]))]), exporter='exp')
    # two 4-byte records followed by 3 padding bytes
    msg = decoder.decode(_build_message([
        _data_set(256, b'\x0a\x00\x00\x01\x0a\x00\x00\x02\x00\x00\x00')]),
        exporter='exp')
    data_set = msg.sets[0]
    assert len(data_set.records) == 2
    assert data_set.records[0]['sourceIPv4Address'] == '10.0.0.1'
    assert data_set.records[1]['sourceIPv4Address'] == '10.0.0.2'
    assert data_set.padding == b'\x00\x00\x00'


def test_error_offsets():
    import pytest
    decoder = IPFIXDecoder()

    # truncated header
    with pytest.raises(IPFIXDecodeError) as exc:
        decoder.decode(b'\x00\x0a\x00', exporter='exp')
    assert exc.value.offset == 0

    # message length beyond the buffer
    with pytest.raises(IPFIXDecodeError) as exc:
        decoder.decode(b'\x00\x0a\x00\x64' + b'\x00' * 12, exporter='exp')
    assert exc.value.offset == 0

    # set length overruns the message: set header starts at offset 16
    body = struct.pack('>HH', 256, 100)
    buf = struct.pack('>HHIII', 10, 16 + len(body), 0, 0, 0) + body
    with pytest.raises(IPFIXDecodeError) as exc:
        decoder.decode(buf, exporter='exp')
    assert exc.value.offset == 16

    # invalid set length
    buf = _build_message([struct.pack('>HH', 256, 3)])
    with pytest.raises(IPFIXDecodeError) as exc:
        decoder.decode(buf, exporter='exp')
    assert exc.value.offset == 16

    # reserved set ID
    buf = _build_message([_build_set(1, b'')])
    with pytest.raises(IPFIXDecodeError) as exc:
        decoder.decode(buf, exporter='exp')
    assert exc.value.offset == 16


def test_record_boundary_error_offset():
    import pytest
    decoder = IPFIXDecoder()
    decoder.decode(_build_message([_template_set(_template_record(256, [
        (8, 4), (1000, VARIABLE_LENGTH, 29305)]))]), exporter='exp')

    # variable-length field claims 10 bytes, only 2 remain in the set;
    # the field starts at message offset 16 (hdr) + 4 (set hdr) + 4 (ipv4)
    # + 1 (length byte) = 25
    body = b'\x0a\x00\x00\x01' + b'\x0a' + b'ab'
    buf = _build_message([_data_set(256, body)])
    with pytest.raises(IPFIXDecodeError) as exc:
        decoder.decode(buf, exporter='exp')
    assert exc.value.offset == 25


def test_template_record_truncated_error_offset():
    import pytest
    decoder = IPFIXDecoder()
    # template record declares 2 fields but only one specifier is present;
    # the missing specifier starts at 16 + 4 + 4 + 4 = 28
    record = struct.pack('>HH', 256, 2) + struct.pack('>HH', 8, 4)
    buf = _build_message([_template_set(record)])
    with pytest.raises(IPFIXDecodeError) as exc:
        decoder.decode(buf, exporter='exp')
    assert exc.value.offset == 28


def test_withdraw_all_templates():
    decoder = IPFIXDecoder()
    decoder.decode(_build_message([_template_set(
        _template_record(256, [(4, 1)]),
        _template_record(257, [(4, 1)]))]), exporter='exp')
    msg = decoder.decode(_build_message([_template_set(
        _withdraw_record(WITHDRAW_ALL_TEMPLATES))]), exporter='exp')
    assert msg.sets[0].withdrawals == ['all']
    assert decoder.templates('exp') == {}
