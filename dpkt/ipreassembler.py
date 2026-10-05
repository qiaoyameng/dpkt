# -*- coding: utf-8 -*-
"""IPv4 fragment reassembly."""
from __future__ import absolute_import

import struct
from collections import namedtuple

from . import dpkt
from .ip import IP, IP_HDR_LEN, IP_LEN_MAX, IP_MF, IP_OFFMASK


DROP_REASON_TIMEOUT = 'timeout'
DROP_REASON_OVERLAP = 'overlapping_fragment'
DROP_REASON_FRAGMENT_AFTER_END = 'fragment_after_end'
DROP_REASON_INVALID_TOTAL_LENGTH = 'invalid_total_length'
DROP_REASON_MAX_GROUPS = 'max_groups'
DROP_REASON_MAX_BUFFERED_BYTES = 'max_buffered_bytes'


IPFragmentKey = namedtuple('IPFragmentKey', ('src', 'dst', 'p', 'id'))
DroppedIPDatagram = namedtuple(
    'DroppedIPDatagram',
    ('key', 'reason', 'timestamp', 'buffered_bytes', 'fragment_count')
)


class _IPFragmentGroup(object):
    __slots__ = (
        'key', 'fragments', 'first_header', 'header_len',
        'payload_length', 'last_seen', 'buffered_bytes'
    )

    def __init__(self, key, timestamp):
        self.key = key
        self.fragments = []
        self.first_header = None
        self.header_len = None
        self.payload_length = None
        self.last_seen = timestamp
        self.buffered_bytes = 0


class IPReassembler(object):
    """Reassemble IPv4 fragments using caller-supplied timestamps.

    Fragments are grouped by source address, destination address, protocol
    and identification. ``add`` returns a complete datagram as bytes, or
    ``None`` while the datagram is incomplete. The first fragment supplies the
    IP header and options; later fragment headers are discarded.

    No timer thread is started. Callers supply the arrival timestamp with
    each fragment and call ``expire`` or ``advance_time`` to remove stale
    groups. Every discarded group is reported in ``dropped`` and through the
    optional ``on_drop`` callback.
    """

    def __init__(self, timeout=30.0, max_groups=1024, max_buffered_bytes=1024 * 1024,
                 on_drop=None):
        if timeout < 0:
            raise ValueError('timeout must be non-negative')
        if max_groups < 1:
            raise ValueError('max_groups must be positive')
        if max_buffered_bytes < 0:
            raise ValueError('max_buffered_bytes must be non-negative')

        self.timeout = timeout
        self.max_groups = max_groups
        self.max_buffered_bytes = max_buffered_bytes
        self.on_drop = on_drop
        self.groups = {}
        self.buffered_bytes = 0
        self.dropped = []

    def add(self, packet, timestamp):
        """Add one IPv4 packet or fragment and return a complete datagram.

        A complete, unfragmented IPv4 packet is returned unchanged. Fragment
        groups are completed only after the final fragment identifies the
        payload length and all bytes from offset zero are contiguous.
        """
        self.expire(timestamp)

        raw = bytes(packet)
        ip = IP(raw)
        offset = ip.offset * 8
        payload = bytes(ip.data)
        end = offset + len(payload)

        if not ip.mf and offset == 0:
            return raw

        key = IPFragmentKey(ip.src, ip.dst, ip.p, ip.id)
        group = self.groups.get(key)

        if group is None:
            if len(self.groups) >= self.max_groups:
                self._drop(None, key, DROP_REASON_MAX_GROUPS, timestamp)
                return None
            group = _IPFragmentGroup(key, timestamp)
            self.groups[key] = group

        if group.payload_length is not None and end > group.payload_length:
            self._drop(group, key, DROP_REASON_FRAGMENT_AFTER_END, timestamp)
            return None

        if not ip.mf:
            for fragment_start, fragment_end, _ in group.fragments:
                if fragment_end > end:
                    self._drop(group, key, DROP_REASON_FRAGMENT_AFTER_END, timestamp)
                    return None

        header_len = (ip.hl << 2)
        if offset == 0 and group.header_len is None:
            payload_length = group.payload_length if group.payload_length is not None else end
            if header_len + payload_length > IP_LEN_MAX:
                self._drop(group, key, DROP_REASON_INVALID_TOTAL_LENGTH, timestamp)
                return None

        added, conflicting = self._uncovered(group, offset, end, payload)
        if conflicting:
            self._drop(group, key, DROP_REASON_OVERLAP, timestamp)
            return None

        added_bytes = sum(part_end - part_start for part_start, part_end in added)
        header_bytes = header_len if offset == 0 and group.header_len is None else 0
        reserved_bytes = added_bytes + header_bytes
        if self.buffered_bytes + reserved_bytes > self.max_buffered_bytes:
            self._drop(group, key, DROP_REASON_MAX_BUFFERED_BYTES, timestamp)
            return None

        for fragment_start, fragment_end in added:
            group.fragments.append((
                fragment_start,
                fragment_end,
                payload[fragment_start - offset:fragment_end - offset]
            ))

        group.fragments.sort(key=lambda fragment: fragment[0])
        group.buffered_bytes += added_bytes
        self.buffered_bytes += added_bytes

        if offset == 0 and group.first_header is None:
            group.first_header = bytearray(raw[:header_len])
            group.header_len = header_len
            group.buffered_bytes += header_bytes
            self.buffered_bytes += header_bytes

        if not ip.mf:
            group.payload_length = end
            if group.header_len is not None and group.header_len + end > IP_LEN_MAX:
                self._drop(group, key, DROP_REASON_INVALID_TOTAL_LENGTH, timestamp)
                return None

        if timestamp > group.last_seen:
            group.last_seen = timestamp

        if self._is_complete(group):
            datagram = self._build_datagram(group)
            self._remove_group(group)
            return datagram
        return None

    def expire(self, timestamp):
        """Expire groups older than ``timestamp - timeout`` and return reports."""
        dropped = []
        for key, group in list(self.groups.items()):
            if timestamp - group.last_seen >= self.timeout:
                dropped.append(self._drop(group, key, DROP_REASON_TIMEOUT, timestamp))
        return dropped

    def pending_groups(self):
        """Return the fragment keys currently waiting for more fragments."""
        return list(self.groups)

    @property
    def group_count(self):
        """Number of fragment groups currently holding buffered data."""
        return len(self.groups)

    def _uncovered(self, group, start, end, data):
        uncovered = [(start, end)]
        conflicting = False

        for fragment_start, fragment_end, fragment_data in group.fragments:
            next_uncovered = []
            for uncovered_start, uncovered_end in uncovered:
                if uncovered_end <= fragment_start or uncovered_start >= fragment_end:
                    next_uncovered.append((uncovered_start, uncovered_end))
                    continue

                overlap_start = max(uncovered_start, fragment_start)
                overlap_end = min(uncovered_end, fragment_end)
                new_part = data[overlap_start - start:overlap_end - start]
                old_part = fragment_data[overlap_start - fragment_start:overlap_end - fragment_start]
                if new_part != old_part:
                    conflicting = True

                if uncovered_start < fragment_start:
                    next_uncovered.append((uncovered_start, fragment_start))
                if uncovered_end > fragment_end:
                    next_uncovered.append((fragment_end, uncovered_end))
            uncovered = next_uncovered

        return uncovered, conflicting

    def _is_complete(self, group):
        if group.first_header is None or group.payload_length is None:
            return False

        expected = 0
        for start, end, _ in group.fragments:
            if start != expected:
                return False
            expected = end
        return expected == group.payload_length

    def _build_datagram(self, group):
        header = bytearray(group.first_header)
        total_length = group.header_len + group.payload_length
        payload = bytearray(group.payload_length)

        for start, end, fragment_data in group.fragments:
            payload[start:end] = fragment_data

        struct.pack_into('>H', header, 2, total_length)
        flags_offset, = struct.unpack('>H', bytes(header[6:8]))
        flags_offset &= ~(IP_MF | IP_OFFMASK)
        struct.pack_into('>H', header, 6, flags_offset)
        header[10:12] = b'\x00\x00'
        struct.pack_into('>H', header, 10, dpkt.in_cksum(bytes(header)))

        return bytes(header) + bytes(payload)

    def _remove_group(self, group):
        if self.groups.get(group.key) is group:
            del self.groups[group.key]
            self.buffered_bytes -= group.buffered_bytes

    def _drop(self, group, key, reason, timestamp):
        if group is not None:
            buffered_bytes = group.buffered_bytes
            fragment_count = len(group.fragments)
            self._remove_group(group)
        else:
            buffered_bytes = 0
            fragment_count = 0

        report = DroppedIPDatagram(
            key, reason, timestamp, buffered_bytes, fragment_count
        )
        self.dropped.append(report)
        if self.on_drop is not None:
            self.on_drop(report)
        return report

    process = add
    defrag = add
    reassemble = add
    defragment = add
    push = add
    tick = expire
    advance_time = expire
    prune = expire


IPDefrag = IPReassembler


def _manual_udp_datagram(payload):
    src = b'\x0a\x00\x00\x01'
    dst = b'\x0a\x00\x00\x02'
    udp_len = 8 + len(payload)
    udp = struct.pack('>HHHH', 4000, 5000, udp_len, 0) + payload
    pseudo = src + dst + struct.pack('>BBH', 0, 17, udp_len)
    checksum = dpkt.in_cksum(pseudo + udp)
    udp = struct.pack('>HHHH', 4000, 5000, udp_len, checksum) + payload
    return src, dst, udp


def _manual_ip_fragment(src, dst, ident, offset, payload, mf, options=b''):
    header_len = IP_HDR_LEN + len(options)
    total_length = header_len + len(payload)
    flags_offset = (IP_MF if mf else 0) | (offset // 8)
    header = struct.pack(
        '>BBHHHBBH4s4s',
        (4 << 4) | (header_len // 4), 0, total_length, ident, flags_offset,
        64, 17, 0, src, dst
    ) + options
    checksum = dpkt.in_cksum(header)
    header = struct.pack(
        '>BBHHHBBH4s4s',
        (4 << 4) | (header_len // 4), 0, total_length, ident, flags_offset,
        64, 17, checksum, src, dst
    ) + options
    return header + payload


def _expected_datagram(src, dst, ident, options, transport):
    return _manual_ip_fragment(
        src, dst, ident, 0, transport, False, options=options
    )


def test_ip_reassembler_out_of_order_and_duplicate():
    payload = b'0123456789abcdef'
    src, dst, transport = _manual_udp_datagram(payload)
    options = b'\x01' * 4
    first = _manual_ip_fragment(src, dst, 0x1234, 0, transport[:16], True, options)
    last = _manual_ip_fragment(src, dst, 0x1234, 16, transport[16:], False)
    expected = _expected_datagram(src, dst, 0x1234, options, transport)

    reassembler = IPReassembler(timeout=10)
    assert reassembler.add(last, 1.0) is None
    assert reassembler.add(last, 1.5) is None
    assert reassembler.buffered_bytes == 8
    later_ip = IP(last)
    assert isinstance(later_ip.data, bytes)
    assert not hasattr(later_ip, 'udp')

    complete = reassembler.add(first, 2.0)
    assert complete == expected

    ip = IP(complete)
    assert ip.opts == options
    assert ip.len == 24 + len(transport)
    assert ip.mf == 0
    assert ip.offset == 0
    assert ip.udp.data == payload
    assert dpkt.in_cksum(complete[:24]) == 0
    assert reassembler.buffered_bytes == 0
    assert reassembler.pending_groups() == []


def test_ip_reassembler_missing_first_timeout_and_id_reuse():
    old_payload = b'old-data-payload'
    new_payload = b'new-data-payload!'
    src, dst, old_transport = _manual_udp_datagram(old_payload)
    _, _, new_transport = _manual_udp_datagram(new_payload)

    old_last = _manual_ip_fragment(src, dst, 0x4242, 16, old_transport[16:], False)
    new_first = _manual_ip_fragment(src, dst, 0x4242, 0, new_transport[:16], True)
    new_last = _manual_ip_fragment(src, dst, 0x4242, 16, new_transport[16:], False)
    expected = _expected_datagram(src, dst, 0x4242, b'', new_transport)

    reassembler = IPReassembler(timeout=5)
    assert reassembler.add(old_last, 0.0) is None
    dropped = reassembler.expire(5.0)
    assert len(dropped) == 1
    assert dropped[0].reason == DROP_REASON_TIMEOUT
    assert dropped[0].key.id == 0x4242
    assert dropped[0].buffered_bytes == 8
    assert reassembler.pending_groups() == []

    assert reassembler.add(new_last, 6.0) is None
    complete = reassembler.add(new_first, 7.0)
    assert complete == expected
    assert IP(complete).udp.data == new_payload


def test_ip_reassembler_missing_last_times_out():
    payload = b'0123456789abcdef'
    src, dst, transport = _manual_udp_datagram(payload)
    first = _manual_ip_fragment(src, dst, 0x1111, 0, transport[:16], True)

    reassembler = IPReassembler(timeout=3)
    assert reassembler.add(first, 0.0) is None
    assert reassembler.expire(2.9) == []
    dropped = reassembler.expire(3.0)
    assert len(dropped) == 1
    assert dropped[0].reason == DROP_REASON_TIMEOUT
    assert dropped[0].buffered_bytes == 36


def test_ip_reassembler_counts_first_header_and_options():
    payload = b'0123456789abcdef'
    src, dst, transport = _manual_udp_datagram(payload)
    options = b'\x01' * 4
    first = _manual_ip_fragment(src, dst, 0x7777, 0, transport[:16], True, options)

    reassembler = IPReassembler(timeout=10)
    assert reassembler.add(first, 0.0) is None
    assert reassembler.buffered_bytes == 16 + IP_HDR_LEN + len(options)


def test_ip_reassembler_conflicting_overlap_drops_group():
    payload = b'0123456789abcdef'
    src, dst, transport = _manual_udp_datagram(payload)
    first = _manual_ip_fragment(src, dst, 0x2222, 0, transport[:16], True)
    overlap = _manual_ip_fragment(src, dst, 0x2222, 8, b'X' * 8, True)

    reassembler = IPReassembler(timeout=10)
    assert reassembler.add(first, 0.0) is None
    assert reassembler.add(overlap, 1.0) is None

    assert len(reassembler.dropped) == 1
    assert reassembler.dropped[0].reason == DROP_REASON_OVERLAP
    assert reassembler.pending_groups() == []
    assert reassembler.buffered_bytes == 0


def test_ip_reassembler_rejects_fragment_extending_past_last():
    reassembler = IPReassembler(timeout=10)
    src = b'\x0a\x00\x00\x01'
    dst = b'\x0a\x00\x00\x02'
    tail = _manual_ip_fragment(src, dst, 0x3333, 24, b'past-end', True)
    last = _manual_ip_fragment(src, dst, 0x3333, 16, b'final!!!', False)

    assert reassembler.add(tail, 0.0) is None
    assert reassembler.add(last, 1.0) is None
    assert reassembler.dropped[0].reason == DROP_REASON_FRAGMENT_AFTER_END
    assert reassembler.pending_groups() == []

    last = _manual_ip_fragment(src, dst, 0x3434, 8, b'last!!!!', False)
    middle = _manual_ip_fragment(src, dst, 0x3434, 0, b'accepted', True)
    tail_after_end = _manual_ip_fragment(
        src, dst, 0x3434, 16, b'past-end', True
    )
    reassembler = IPReassembler(timeout=10)
    assert reassembler.add(middle, 0.0) is None
    assert reassembler.add(tail_after_end, 1.0) is None
    assert reassembler.add(last, 2.0) is None
    assert reassembler.dropped[-1].reason == DROP_REASON_FRAGMENT_AFTER_END


def test_ip_reassembler_accepts_identical_overlap():
    payload = b'0123456789abcdef'
    src, dst, transport = _manual_udp_datagram(payload)
    first = _manual_ip_fragment(src, dst, 0x6666, 0, transport[:16], True)
    overlapping = _manual_ip_fragment(
        src, dst, 0x6666, 8, transport[8:20], True
    )
    last = _manual_ip_fragment(src, dst, 0x6666, 16, transport[16:], False)
    expected = _expected_datagram(src, dst, 0x6666, b'', transport)

    reassembler = IPReassembler(timeout=10)
    assert reassembler.add(first, 0.0) is None
    assert reassembler.add(overlapping, 1.0) is None
    assert reassembler.buffered_bytes == 40
    assert reassembler.defragment(last, 2.0) == expected


def test_ip_reassembler_limits_groups():
    src = b'\x0a\x00\x00\x01'
    dst = b'\x0a\x00\x00\x02'
    first = _manual_ip_fragment(src, dst, 1, 0, b'A' * 16, True)
    second_group = _manual_ip_fragment(src, dst, 2, 0, b'B' * 8, True)
    third_group = _manual_ip_fragment(src, dst, 3, 0, b'C' * 8, True)

    reassembler = IPReassembler(timeout=10, max_groups=2)
    assert reassembler.group_count == 0
    assert reassembler.add(first, 0.0) is None
    assert reassembler.group_count == 1
    assert reassembler.add(second_group, 1.0) is None
    assert reassembler.group_count == 2
    assert reassembler.add(third_group, 2.0) is None
    assert reassembler.group_count == 2
    assert reassembler.dropped[-1].reason == DROP_REASON_MAX_GROUPS

    fourth_group = _manual_ip_fragment(src, dst, 4, 0, b'', True)
    assert reassembler.add(fourth_group, 3.0) is None
    assert reassembler.dropped[-1].reason == DROP_REASON_MAX_GROUPS
    assert reassembler.group_count == 2


def test_ip_reassembler_limits_buffered_bytes():
    src = b'\x0a\x00\x00\x01'
    dst = b'\x0a\x00\x00\x02'
    first = _manual_ip_fragment(src, dst, 1, 0, b'A' * 16, True)
    second_group = _manual_ip_fragment(src, dst, 2, 0, b'B' * 8, True)
    third_group = _manual_ip_fragment(src, dst, 3, 0, b'C' * 8, True)

    reassembler = IPReassembler(timeout=10, max_groups=4, max_buffered_bytes=20)
    assert reassembler.add(first, 0.0) is None
    assert reassembler.add(second_group, 1.0) is None
    assert reassembler.add(third_group, 2.0) is None
    assert reassembler.dropped[-1].reason == DROP_REASON_MAX_BUFFERED_BYTES
    assert reassembler.buffered_bytes == 0

    reassembler = IPReassembler(timeout=10, max_groups=4, max_buffered_bytes=36)
    assert reassembler.add(first, 0.0) is None
    assert reassembler.add(second_group, 1.0) is None
    assert reassembler.add(third_group, 2.0) is None
    assert reassembler.dropped[-1].reason == DROP_REASON_MAX_BUFFERED_BYTES
    assert reassembler.buffered_bytes == 36


def test_ip_reassembler_passes_unfragmented_packet_through():
    payload = b'0123456789abcdef'
    src, dst, transport = _manual_udp_datagram(payload)
    packet = _manual_ip_fragment(src, dst, 0x5555, 0, transport, False)

    reassembler = IPReassembler()
    assert reassembler.add(packet, 0.0) == packet
    assert reassembler.pending_groups() == []
    assert reassembler.buffered_bytes == 0
