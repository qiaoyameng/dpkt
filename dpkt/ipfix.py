# -*- coding: utf-8 -*-
"""IP Flow Information Export (IPFIX) version 10."""
from __future__ import absolute_import

import struct
from collections import namedtuple

from . import dpkt
from .compat import compat_ord


VERSION = 10
HEADER_LEN = 16
SET_HEADER_LEN = 4
TEMPLATE_SET_ID = 2
OPTIONS_TEMPLATE_SET_ID = 3
MIN_TEMPLATE_ID = 256
VARIABLE_LENGTH = 0xffff
ENTERPRISE_BIT = 0x8000

UNKNOWN_TEMPLATE = 'unknown template'
RESERVED_SET = 'reserved set'


class IPFIXError(dpkt.Error):
    """An IPFIX decoding error located by an offset in the message."""

    def __init__(self, message='', offset=None):
        if offset is not None:
            message = '%s at offset %d' % (message, offset)
        super(IPFIXError, self).__init__(message)
        self.offset = offset


class IPFIXUnpackError(IPFIXError, dpkt.UnpackError):
    pass


class IPFIXNeedData(IPFIXError, dpkt.NeedData):
    pass


class IPFIX(dpkt.Packet):
    """IPFIX version 10 message header.

    Use :class:`IPFIXDecoder` for stateful template and data-set decoding.
    """

    __hdr__ = (
        ('version', 'H', VERSION),
        ('length', 'H', HEADER_LEN),
        ('export_time', 'I', 0),
        ('sequence_number', 'I', 0),
        ('observation_domain_id', 'I', 0),
    )


FieldSpec = namedtuple('FieldSpec', (
    'information_element_id',
    'field_length',
    'enterprise_number',
))

Template = namedtuple('Template', (
    'template_id',
    'fields',
    'scope_field_count',
    'options',
))

FieldValue = namedtuple('FieldValue', (
    'spec',
    'value',
    'offset',
))

DataRecord = namedtuple('DataRecord', (
    'template_id',
    'fields',
    'raw',
    'offset',
))

TemplateSet = namedtuple('TemplateSet', (
    'set_id',
    'templates',
    'withdrawn_template_ids',
    'redefined_template_ids',
    'offset',
    'length',
))

DataSet = namedtuple('DataSet', (
    'set_id',
    'template',
    'records',
    'raw',
    'offset',
    'length',
))

UnparsedSet = namedtuple('UnparsedSet', (
    'set_id',
    'data',
    'reason',
    'offset',
    'length',
))


def _is_variable_field(spec):
    return spec.field_length == VARIABLE_LENGTH


class ObservationDomain(object):
    """Templates scoped to one exporter and observation domain."""

    __slots__ = ('templates', 'options_templates')

    def __init__(self):
        self.templates = {}
        self.options_templates = {}


class _DomainView(object):
    """Mutable per-message view committed to an ObservationDomain on success."""

    __slots__ = ('templates', 'options_templates')

    def __init__(self, domain):
        self.templates = dict(domain.templates)
        self.options_templates = dict(domain.options_templates)

    def commit(self, domain):
        domain.templates.clear()
        domain.templates.update(self.templates)
        domain.options_templates.clear()
        domain.options_templates.update(self.options_templates)


class IPFIXDecoder(object):
    """Stateful IPFIX decoder.

    Templates are retained independently for each ``(exporter,
    observation_domain_id)`` pair. Ordinary templates and options templates are
    stored in separate maps.
    """

    def __init__(self):
        self.domains = {}

    def domain(self, exporter, observation_domain_id):
        key = (exporter, observation_domain_id)
        domain = self.domains.get(key)
        if domain is None:
            domain = ObservationDomain()
            self.domains[key] = domain
        return domain

    def reset(self, exporter=None, observation_domain_id=None):
        if exporter is None and observation_domain_id is None:
            self.domains = {}
            return
        keys = [
            key for key in self.domains
            if (exporter is None or key[0] == exporter) and
            (observation_domain_id is None or key[1] == observation_domain_id)
        ]
        for key in keys:
            del self.domains[key]

    def decode(self, buf, exporter):
        """Decode one IPFIX message and commit this decoder's templates."""
        if len(buf) < HEADER_LEN:
            raise IPFIXNeedData(
                'got %d bytes, IPFIX header needs at least %d' %
                (len(buf), HEADER_LEN), 0)

        try:
            message = IPFIX(buf)
        except dpkt.NeedData as error:
            raise IPFIXNeedData(str(error), 0)

        if message.version != VERSION:
            raise IPFIXUnpackError('invalid IPFIX version %d' % message.version, 0)
        if message.length < HEADER_LEN:
            raise IPFIXUnpackError('invalid IPFIX message length', 2)
        if message.length > len(buf):
            raise IPFIXNeedData(
                'message length %d exceeds buffer length %d' %
                (message.length, len(buf)), 2)
        if message.length < len(buf):
            raise IPFIXUnpackError(
                'message length %d is shorter than buffer length %d' %
                (message.length, len(buf)), 2)

        domain = self.domain(exporter, message.observation_domain_id)
        view = _DomainView(domain)
        message.exporter = exporter
        message.sets = []

        offset = HEADER_LEN
        while offset < message.length:
            set_offset = offset
            if offset + SET_HEADER_LEN > message.length:
                raise IPFIXUnpackError('truncated set header', set_offset)

            set_id, set_length = struct.unpack_from('>HH', buf, offset)
            if set_length < SET_HEADER_LEN:
                raise IPFIXUnpackError('invalid set length %d' % set_length, set_offset)
            set_end = offset + set_length
            if set_end < message.length and set_length % 4:
                raise IPFIXUnpackError(
                    'set length %d is not 4-byte aligned' % set_length, set_offset)
            if set_end > message.length:
                raise IPFIXUnpackError(
                    'set length %d exceeds message length' % set_length, set_offset)

            payload = buf[offset + SET_HEADER_LEN:set_end]
            if set_id == TEMPLATE_SET_ID:
                parsed_set = self._decode_template_set(
                    payload, set_offset, set_length, view, False)
            elif set_id == OPTIONS_TEMPLATE_SET_ID:
                parsed_set = self._decode_template_set(
                    payload, set_offset, set_length, view, True)
            elif set_id >= MIN_TEMPLATE_ID:
                parsed_set = self._decode_data_set(
                    payload, set_offset, set_length, set_id, view)
            elif set_id < TEMPLATE_SET_ID:
                raise IPFIXUnpackError(
                    'invalid set ID %d' % set_id, set_offset)
            else:
                parsed_set = UnparsedSet(
                    set_id, payload, RESERVED_SET, set_offset, set_length)

            message.sets.append(parsed_set)
            offset = set_end

        view.commit(domain)
        return message

    def unpack(self, buf, exporter):
        """Compatibility wrapper for :meth:`decode`."""
        return self.decode(buf, exporter)

    def _decode_template_set(self, payload, set_offset, set_length, view, options):
        templates = []
        withdrawn = []
        redefined = []
        defined_template_ids = set()
        pos = 0

        while pos < len(payload):
            if self._is_padding(payload, pos):
                break

            record_offset = set_offset + SET_HEADER_LEN + pos
            header_len = 6 if options else 4
            if len(payload) - pos < header_len:
                if self._is_padding(payload, pos):
                    break
                raise IPFIXUnpackError('truncated template record', record_offset)

            template_id = struct.unpack_from('>H', payload, pos)[0]
            if options:
                field_count = struct.unpack_from('>H', payload, pos + 2)[0]
                scope_count = struct.unpack_from('>H', payload, pos + 4)[0]
                total_fields = field_count
            else:
                scope_count = 0
                field_count = struct.unpack_from('>H', payload, pos + 2)[0]
                total_fields = field_count

            if template_id < MIN_TEMPLATE_ID:
                raise IPFIXUnpackError(
                    'invalid template ID %d' % template_id, record_offset)

            target_map = view.options_templates if options else view.templates
            is_withdrawal = field_count == 0 and scope_count == 0
            if is_withdrawal:
                withdrawn.append(template_id)
                target_map.pop(template_id, None)
                pos += header_len
                continue

            other_map = view.templates if options else view.options_templates
            if template_id in other_map:
                raise IPFIXUnpackError(
                    'template ID %d is already defined by another template type' %
                    template_id, record_offset)

            if field_count == 0 or total_fields == 0:
                raise IPFIXUnpackError(
                    'template %d has no field specifiers' % template_id, record_offset)
            if options and scope_count > total_fields:
                raise IPFIXUnpackError(
                    'options template %d has an invalid scope field count' %
                    template_id, record_offset)

            fields = []
            spec_pos = pos + header_len
            for field_index in range(total_fields):
                field_offset = set_offset + SET_HEADER_LEN + spec_pos
                if spec_pos + 4 > len(payload):
                    raise IPFIXUnpackError(
                        'truncated field specifier', field_offset)

                raw_information_element_id, field_length = struct.unpack_from(
                    '>HH', payload, spec_pos)
                enterprise_number = None
                spec_len = 4
                if raw_information_element_id & ENTERPRISE_BIT:
                    if spec_pos + 8 > len(payload):
                        raise IPFIXUnpackError(
                            'truncated enterprise field specifier', field_offset)
                    enterprise_number = struct.unpack_from('>I', payload, spec_pos + 4)[0]
                    spec_len = 8

                information_element_id = raw_information_element_id & 0x7fff
                if information_element_id == 0:
                    raise IPFIXUnpackError(
                        'invalid information element identifier', field_offset)
                if field_length == 0:
                    raise IPFIXUnpackError(
                        'invalid zero field length', field_offset + 2)

                fields.append(FieldSpec(
                    information_element_id, field_length, enterprise_number))
                spec_pos += spec_len

            if spec_pos > len(payload):
                raise IPFIXUnpackError('truncated template record', record_offset)

            template = Template(template_id, tuple(fields), scope_count, options)
            if template_id in target_map or template_id in defined_template_ids:
                redefined.append(template_id)
            defined_template_ids.add(template_id)
            target_map[template_id] = template
            templates.append(template)
            pos = spec_pos

        return TemplateSet(
            OPTIONS_TEMPLATE_SET_ID if options else TEMPLATE_SET_ID,
            tuple(templates), tuple(withdrawn), tuple(redefined),
            set_offset, set_length)

    def _decode_data_set(self, payload, set_offset, set_length, set_id, view):
        template = view.options_templates.get(set_id)
        if template is None:
            template = view.templates.get(set_id)
        if template is None:
            return UnparsedSet(
                set_id, payload, UNKNOWN_TEMPLATE, set_offset, set_length)

        records = []
        pos = 0
        fixed_length = self._template_fixed_length(template)
        while pos < len(payload):
            record_offset = set_offset + SET_HEADER_LEN + pos
            remaining = len(payload) - pos
            if fixed_length is not None:
                if remaining < fixed_length:
                    if remaining <= 3 and payload[pos:] == b'\x00' * remaining:
                        break
                    raise IPFIXUnpackError('invalid padding', record_offset)
            elif remaining <= 3 and payload[pos:] == b'\x00' * remaining:
                break

            try:
                record_len, record = self._decode_data_record(
                    payload, pos, record_offset, template)
            except IPFIXError:
                if self._is_padding(payload, pos):
                    break
                if remaining <= 3:
                    raise IPFIXUnpackError('invalid padding', record_offset)
                raise
            records.append(record)
            pos += record_len

        return DataSet(
            set_id, template, tuple(records), payload, set_offset, set_length)

    @staticmethod
    def _template_fixed_length(template):
        if any(_is_variable_field(spec) for spec in template.fields):
            return None
        return sum(spec.field_length for spec in template.fields)

    def _decode_data_record(self, payload, pos, record_offset, template):
        values = []
        start = pos

        for spec in template.fields:
            field_offset = record_offset + (pos - start)
            if _is_variable_field(spec):
                if pos >= len(payload):
                    raise IPFIXUnpackError(
                        'truncated variable-length field', field_offset)

                first_byte = compat_ord(payload[pos])
                if first_byte == 255:
                    if pos + 3 > len(payload):
                        raise IPFIXUnpackError(
                            'truncated long variable-length field', field_offset)
                    field_length = struct.unpack_from('>H', payload, pos + 1)[0]
                    if field_length == VARIABLE_LENGTH:
                        raise IPFIXUnpackError(
                            'invalid long variable-length field length', field_offset + 1)
                    value_start = pos + 3
                else:
                    field_length = first_byte
                    value_start = pos + 1

                value_end = value_start + field_length
                if value_end > len(payload):
                    raise IPFIXUnpackError(
                        'variable-length field exceeds record boundary', field_offset)
                value_offset = record_offset + (value_start - start)
            else:
                value_end = pos + spec.field_length
                if value_end > len(payload):
                    raise IPFIXUnpackError(
                        'field exceeds record boundary', field_offset)
                value_offset = record_offset + (pos - start)
                value_start = pos

            values.append(FieldValue(
                spec, payload[value_start:value_end], value_offset))
            pos = value_end

        raw = payload[start:pos]
        return pos - start, DataRecord(
            template.template_id, tuple(values), raw, record_offset)

    @staticmethod
    def _is_padding(payload, pos):
        remaining = len(payload) - pos
        return 0 < remaining <= 3 and payload[pos:pos + remaining] == b'\x00' * remaining


def _pad4(buf):
    return buf + b'\x00' * ((4 - len(buf) % 4) % 4)


def _ipfix_message(payload, observation_domain_id=0, message_length=None):
    length = message_length
    if length is None:
        length = HEADER_LEN + len(payload)
    return struct.pack(
        '>HHIII', VERSION, length, 1234, 1, observation_domain_id) + payload


def _set(set_id, body=b''):
    payload = _pad4(body)
    return struct.pack('>HH', set_id, SET_HEADER_LEN + len(payload)) + payload


def _field_spec(information_element_id, field_length, enterprise_number=None):
    if enterprise_number is None:
        return struct.pack(
            '>HH', information_element_id, field_length)
    return struct.pack(
        '>HHI', information_element_id | ENTERPRISE_BIT,
        field_length, enterprise_number)


def _template_record(template_id, fields, scope_field_count=0, options=False):
    field_specs = b''.join(fields)
    field_count = len(fields)
    if options:
        return struct.pack(
            '>HHH', template_id, field_count, scope_field_count) + field_specs
    return struct.pack('>HH', template_id, field_count) + field_specs


def _withdrawal_record(template_id, options=False):
    if options:
        return struct.pack('>HHH', template_id, 0, 0)
    return struct.pack('>HH', template_id, 0)


def test_exporter_templates_are_isolated_and_withdrawal_is_scoped():
    decoder = IPFIXDecoder()
    field = _field_spec(8, 4) + _field_spec(12, 4)
    template_message = _ipfix_message(
        _set(TEMPLATE_SET_ID, _template_record(256, [field[:4], field[4:]])))
    record = b'\x0a\x00\x00\x01\x0a\x00\x00\x02'
    data_message = _ipfix_message(_set(256, record))
    withdrawal_message = _ipfix_message(
        _set(TEMPLATE_SET_ID, _withdrawal_record(256)))

    first = decoder.decode(template_message, ('10.0.0.1', 4739))
    second = decoder.decode(template_message, ('10.0.0.2', 4739))
    assert first.observation_domain_id == second.observation_domain_id

    decoded = decoder.decode(data_message, ('10.0.0.1', 4739))
    assert decoded.sets[0].records[0].raw == record

    withdrawn = decoder.decode(withdrawal_message, ('10.0.0.1', 4739))
    assert withdrawn.sets[0].withdrawn_template_ids == (256,)

    unresolved = decoder.decode(data_message, ('10.0.0.1', 4739))
    assert unresolved.sets[0].reason == UNKNOWN_TEMPLATE
    assert unresolved.sets[0].data == record

    still_decoded = decoder.decode(data_message, ('10.0.0.2', 4739))
    assert still_decoded.sets[0].records[0].fields[1].value == b'\x0a\x00\x00\x02'


def test_observation_domains_and_options_templates_use_separate_state():
    decoder = IPFIXDecoder()
    ordinary = _set(
        TEMPLATE_SET_ID,
        _template_record(257, [_field_spec(8, 2), _field_spec(12, 2)]))
    options = _set(
        OPTIONS_TEMPLATE_SET_ID,
        _template_record(
            258,
            [_field_spec(149, 4), _field_spec(2, 2)],
            scope_field_count=1, options=True))
    decoder.decode(_ipfix_message(ordinary + options, 1), 'exporter')

    domain = decoder.domain('exporter', 1)
    assert 257 in domain.templates
    assert 257 not in domain.options_templates
    assert 258 in domain.options_templates
    assert domain.options_templates[258].scope_field_count == 1

    other_domain_data = _ipfix_message(_set(257, b'\x01\x02\x03\x04'), 2)
    unresolved = decoder.decode(other_domain_data, 'exporter')
    assert unresolved.sets[0].reason == UNKNOWN_TEMPLATE

    options_data = _ipfix_message(_set(258, b'\x00\x00\x00\x07\x00\x09\x00\x00'), 1)
    decoded = decoder.decode(options_data, 'exporter')
    assert len(decoded.sets[0].records) == 1
    assert decoded.sets[0].records[0].fields[0].value == b'\x00\x00\x00\x07'

    options_withdrawal = _ipfix_message(
        _set(OPTIONS_TEMPLATE_SET_ID, _withdrawal_record(258, options=True)), 1)
    decoder.decode(options_withdrawal, 'exporter')
    assert 258 not in domain.options_templates
    assert 257 in domain.templates


def test_enterprise_and_variable_length_fields_keep_raw_values():
    decoder = IPFIXDecoder()
    fields = [
        _field_spec(8, 4),
        _field_spec(30000, 2),
        _field_spec(100, VARIABLE_LENGTH, enterprise_number=42),
    ]
    template = _set(TEMPLATE_SET_ID, _template_record(300, fields))
    record = b'\x0a\x01\x02\x03\x12\x34\x03abc'
    data = _set(300, record)
    message = decoder.decode(_ipfix_message(template + data), 'exporter')

    decoded_record = message.sets[1].records[0]
    assert decoded_record.raw == record
    assert decoded_record.fields[1].value == b'\x12\x34'
    enterprise_field = decoded_record.fields[2]
    assert enterprise_field.spec.enterprise_number == 42
    assert enterprise_field.spec.information_element_id == 100
    assert enterprise_field.value == b'abc'
    assert enterprise_field.offset == 51

    long_record = b'\x09\x08\x07\x06\x56\x78\xff\x00\x05hello'
    long_message = decoder.decode(
        _ipfix_message(_set(300, long_record)), 'exporter')
    assert long_message.sets[0].records[0].fields[2].value == b'hello'


def test_template_redefinition_replaces_state_after_valid_parse():
    decoder = IPFIXDecoder()
    first = _set(
        TEMPLATE_SET_ID,
        _template_record(400, [_field_spec(8, 4)]))
    second = _set(
        TEMPLATE_SET_ID,
        _template_record(400, [_field_spec(8, 2)]))

    decoder.decode(_ipfix_message(first), 'exporter')
    redefined = decoder.decode(_ipfix_message(second), 'exporter')
    assert redefined.sets[0].redefined_template_ids == (400,)
    decoded = decoder.decode(
        _ipfix_message(_set(400, b'\x01\x02')), 'exporter')
    assert decoded.sets[0].records[0].fields[0].value == b'\x01\x02'

    decoder.decode(_ipfix_message(first), 'exporter')
    domain = decoder.domain('exporter', 0)
    assert domain.templates[400].fields[0].field_length == 4


def test_template_changes_apply_to_same_message_but_failures_are_atomic():
    decoder = IPFIXDecoder()
    template = _set(
        TEMPLATE_SET_ID,
        _template_record(401, [_field_spec(8, 2)]))
    data = _set(401, b'\x12\x34')
    decoded = decoder.decode(_ipfix_message(template + data), 'exporter')
    assert decoded.sets[1].records[0].fields[0].value == b'\x12\x34'

    malformed = _set(
        TEMPLATE_SET_ID,
        _template_record(402, [_field_spec(8, 1)]) +
        struct.pack('>HHHH', 403, 1, 8, 0))
    try:
        decoder.decode(_ipfix_message(malformed), 'exporter')
    except IPFIXError:
        pass
    else:
        raise AssertionError('malformed template message was accepted')

    domain = decoder.domain('exporter', 0)
    assert 401 in domain.templates
    assert 402 not in domain.templates


def test_data_set_without_template_is_explicitly_unresolved():
    decoder = IPFIXDecoder()
    raw_record = b'\x01\x02\x03'
    message = decoder.decode(_ipfix_message(_set(500, raw_record)), 'exporter')
    unresolved = message.sets[0]
    assert isinstance(unresolved, UnparsedSet)
    assert unresolved.set_id == 500
    assert unresolved.reason == UNKNOWN_TEMPLATE
    assert unresolved.data == raw_record + b'\x00'


def test_reserved_set_ids_are_rejected_with_set_offset():
    import pytest

    decoder = IPFIXDecoder()
    reserved = decoder.decode(
        _ipfix_message(struct.pack('>HH', 4, 4)), 'exporter')
    assert isinstance(reserved.sets[0], UnparsedSet)
    assert reserved.sets[0].reason == RESERVED_SET

    with pytest.raises(IPFIXError) as excinfo:
        decoder.decode(_ipfix_message(struct.pack('>HH', 1, 4)), 'exporter')
    assert excinfo.value.offset == 16


def test_last_set_may_omit_padding_and_zero_scope_options_are_accepted():
    decoder = IPFIXDecoder()
    template = _set(
        TEMPLATE_SET_ID,
        _template_record(700, [_field_spec(8, 1)]))
    decoder.decode(_ipfix_message(template), 'exporter')

    data_set = struct.pack('>HH', 700, 5) + b'\x07'
    message = decoder.decode(_ipfix_message(data_set), 'exporter')
    assert message.sets[0].records[0].fields[0].value == b'\x07'

    options = _set(
        OPTIONS_TEMPLATE_SET_ID,
        _template_record(701, [_field_spec(2, 2)], options=True))
    decoded = decoder.decode(_ipfix_message(options), 'exporter')
    assert decoded.sets[0].templates[0].scope_field_count == 0


def test_ipfix_errors_report_message_offsets():
    import pytest

    decoder = IPFIXDecoder()
    decoder.decode(
        _ipfix_message(_set(
            TEMPLATE_SET_ID,
            _template_record(600, [_field_spec(8, 4)]))), 'exporter')
    decoder.decode(
        _ipfix_message(_set(
            TEMPLATE_SET_ID,
            _template_record(603, [_field_spec(8, 3)]))), 'exporter')

    cases = (
        (struct.pack('>HHIII', 9, HEADER_LEN, 0, 0, 0), 0),
        (_ipfix_message(struct.pack('>HH', 600, 2)), 16),
        (_ipfix_message(struct.pack('>HH', 600, 5)), 16),
        (_ipfix_message(struct.pack('>HH', 600, 100)), 16),
        (_ipfix_message(_set(603, b'abc\x01')), 23),
        (_ipfix_message(_set(
            TEMPLATE_SET_ID,
            struct.pack('>HHHH', 601, 1, 8, 0))), 26),
    )
    for buf, offset in cases:
        with pytest.raises(IPFIXError) as excinfo:
            decoder.decode(buf, 'exporter')
        assert excinfo.value.offset == offset

    variable_template = _set(
        TEMPLATE_SET_ID,
        _template_record(602, [_field_spec(100, VARIABLE_LENGTH)]))
    decoder.decode(_ipfix_message(variable_template), 'exporter')
    truncated_variable = _ipfix_message(_set(602, b'\xff\x00\x0ashort'))
    with pytest.raises(IPFIXError) as excinfo:
        decoder.decode(truncated_variable, 'exporter')
    assert excinfo.value.offset == 20
