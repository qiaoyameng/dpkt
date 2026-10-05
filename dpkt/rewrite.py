# -*- coding: utf-8 -*-
"""Rewrite IP addresses inside captured packets.

Sanitizes packets before a capture is handed to an external party:
addresses found in Ethernet / 802.1Q (VLAN) frames carrying IPv4 or IPv6
are replaced according to a caller supplied one-to-one mapping, including
the original IP headers quoted inside ICMP and ICMPv6 error messages.

Every checksum covering a rewritten field is brought back in sync:

* IPv4 header checksums are recomputed when the complete header was
  captured, and reported as unverifiable otherwise.
* TCP, UDP, ICMP and ICMPv6 checksums are recomputed when the complete
  checksummed region was captured.  When the packet, or the original
  datagram quoted inside an ICMP error, is truncated, the checksum is
  adjusted incrementally (RFC 1624) from the known address deltas and
  reported as adjusted, because it can no longer be independently
  verified.  Checksums are never simply zeroed out.
* An IPv4 UDP datagram with a zero checksum (checksum disabled,
  RFC 768) keeps its zero checksum.

The input buffer is never modified; :func:`rewrite_packet` returns the
rewritten packet together with a report describing, for every field,
what was done (:data:`REWRITTEN`, :data:`RECOMPUTED`, :data:`ADJUSTED`,
:data:`PRESERVED`) and what could not be proven valid
(:data:`UNVERIFIABLE`, :data:`SKIPPED`).
"""
from __future__ import absolute_import
from __future__ import print_function

import socket
import struct
from collections import namedtuple

from . import dpkt
from .compat import iteritems
from .utils import inet_to_str

__all__ = [
    'MappingError', 'Fix', 'normalize_mapping', 'rewrite_packet',
    'REWRITTEN', 'RECOMPUTED', 'ADJUSTED', 'PRESERVED', 'UNVERIFIABLE', 'SKIPPED',
]

# report statuses
REWRITTEN = 'rewritten'  # address field replaced according to the mapping
RECOMPUTED = 'recomputed'  # checksum recomputed over complete data
ADJUSTED = 'adjusted'  # checksum updated incrementally; cannot be independently verified
PRESERVED = 'preserved'  # semantics deliberately kept (zero IPv4 UDP checksum)
UNVERIFIABLE = 'unverifiable'  # left as captured; validity cannot be proven
SKIPPED = 'skipped'  # layer not handled by the rewriter

Fix = namedtuple('Fix', ('layer', 'field', 'status', 'detail'))

_ETH_TYPES_VLAN = frozenset((0x8100, 0x88a8, 0x9100, 0x9200))
_ETH_TYPE_IP = 0x0800
_ETH_TYPE_IP6 = 0x86dd

_IP_PROTO_ICMP = 1
_IP_PROTO_TCP = 6
_IP_PROTO_UDP = 17
_IP_PROTO_FRAGMENT = 44
_IP_PROTO_ICMP6 = 58
_IP6_EXT_HDRS = frozenset((0, 43, 60))  # hop-by-hop, routing, destination options

# ICMP error types quoting the original IP header + 8 bytes of payload
_ICMP_ERROR_TYPES = frozenset((3, 4, 5, 11, 12))  # unreach, source quench, redirect, time exceeded, param problem
_ICMP6_ERROR_TYPES = frozenset((1, 2, 3, 4))  # unreach, packet too big, time exceeded, param problem


class MappingError(ValueError):
    """Raised when the address mapping is not a usable one-to-one mapping."""


def _parse_addr(addr):
    if isinstance(addr, bytes):
        if len(addr) in (4, 16):
            return addr
        addr = addr.decode('ascii')
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return socket.inet_pton(family, addr)
        except (socket.error, TypeError):
            pass
    raise MappingError('cannot parse IP address: %r' % (addr,))


def normalize_mapping(mapping):
    """Validate and normalize a one-to-one address mapping.

    Accepts a dict or an iterable of (old, new) pairs; addresses may be
    text ('192.0.2.1', '2001:db8::1') or packed bytes.  Returns a dict of
    packed-address to packed-address.  Raises MappingError before any
    packet is processed when the mapping is not one-to-one (a source
    listed twice, or two sources mapping to the same target) or when a
    pair mixes address families.
    """
    if hasattr(mapping, 'items'):
        pairs = list(iteritems(mapping))
    else:
        pairs = list(mapping)
    normalized = {}
    for old, new in pairs:
        old_packed = _parse_addr(old)
        new_packed = _parse_addr(new)
        if len(old_packed) != len(new_packed):
            raise MappingError('address family mismatch: %r -> %r' % (old, new))
        if old_packed in normalized:
            raise MappingError('duplicate source address: %r' % (old,))
        normalized[old_packed] = new_packed
    targets = list(normalized.values())
    if len(set(targets)) != len(targets):
        raise MappingError('address collision: two source addresses map to the same target')
    return normalized


def _edit_delta(pos, old, new):
    """One's-complement delta of replacing old with new at offset pos."""
    delta = 0
    for i in range(len(old)):
        if (pos + i) & 1:
            delta += new[i] - old[i]
        else:
            delta += (new[i] - old[i]) << 8
    return delta


def _incr_adjust(old_sum, delta):
    """Incrementally update a one's-complement checksum (RFC 1624)."""
    s = ((~old_sum) & 0xffff) + delta
    s %= 0xffff
    return (~s) & 0xffff


class _Rewriter(object):
    """Byte-level packet rewriter; never mutates the caller's buffer."""

    def __init__(self, buf, mapping):
        self.buf = bytearray(buf)
        self.mapping = mapping
        self.edits = []  # (offset, old, new) of every byte range replaced so far
        self.report = []

    def _u16(self, off):
        return struct.unpack('>H', self.buf[off:off + 2])[0]

    @staticmethod
    def _addr_str(packed):
        family = socket.AF_INET if len(packed) == 4 else socket.AF_INET6
        return socket.inet_ntop(family, packed)

    def replace_addr(self, off, length, layer, field):
        old = bytes(self.buf[off:off + length])
        new = self.mapping.get(old)
        if new is None:
            return None
        self.buf[off:off + length] = new
        edit = (off, old, new)
        self.edits.append(edit)
        self.report.append(Fix(layer, field, REWRITTEN, '%s -> %s' % (self._addr_str(old), self._addr_str(new))))
        return edit

    def fix_cksum(self, sum_off, start, end, layer, field, pseudo=b'', pseudo_edits=(),
                  force_delta=False, reason='', zero_as_ones=False):
        """Bring the checksum at sum_off covering [start, end) back in sync.

        When the complete region was captured the checksum is recomputed.
        Otherwise it is adjusted incrementally (RFC 1624) from the edits
        known to lie inside the region plus the pseudo-header edits; the
        result then depends on bytes that were not captured and is
        reported as ADJUSTED rather than proven valid.
        """
        if sum_off + 2 > len(self.buf):
            self.report.append(Fix(layer, field, UNVERIFIABLE, 'checksum field not captured; left as captured'))
            return
        if not (start <= sum_off and sum_off + 2 <= end):
            self.report.append(Fix(layer, field, UNVERIFIABLE, 'checksum field outside the checksummed region; left as captured'))
            return
        old_sum = self._u16(sum_off)
        if end <= len(self.buf) and not force_delta:
            region = bytes(self.buf[start:sum_off]) + b'\x00\x00' + bytes(self.buf[sum_off + 2:end])
            new_sum = dpkt.in_cksum(pseudo + region)
            status = RECOMPUTED
            detail = 'recomputed over complete data'
        else:
            delta = 0
            plen = len(pseudo)
            for pos, old, new in pseudo_edits:
                delta += _edit_delta(pos, old, new)
            for eoff, eold, enew in self.edits:
                if start <= eoff and eoff + len(eold) <= end:
                    delta += _edit_delta(plen + eoff - start, eold, enew)
            new_sum = _incr_adjust(old_sum, delta)
            status = ADJUSTED
            detail = reason or 'adjusted incrementally; cannot be independently verified'
        if zero_as_ones and new_sum == 0:
            new_sum = 0xffff  # RFC 768: a computed zero checksum is transmitted as all ones
        if new_sum == old_sum:
            self.report.append(Fix(layer, field, status, detail + '; checksum already in sync'))
            return
        self.buf[sum_off:sum_off + 2] = struct.pack('>H', new_sum)
        self.edits.append((sum_off, struct.pack('>H', old_sum), struct.pack('>H', new_sum)))
        self.report.append(Fix(layer, field, status, detail))

    def fix_transport(self, layer, data_off, end, proto, pseudo, pseudo_edits, force_delta, reason, ip_version):
        if not pseudo_edits:
            return
        if proto == _IP_PROTO_UDP:
            sum_off = data_off + 6
            if sum_off + 2 <= len(self.buf) and self._u16(sum_off) == 0:
                if ip_version == 4:
                    self.report.append(Fix(layer, 'sum', PRESERVED, 'zero checksum (IPv4 UDP checksum disabled) preserved'))
                else:
                    self.report.append(Fix(layer, 'sum', UNVERIFIABLE, 'zero UDP checksum in IPv6; cannot be proven valid'))
                return
        else:
            sum_off = data_off + 16
        self.fix_cksum(sum_off, data_off, end, layer, 'sum', pseudo=pseudo, pseudo_edits=pseudo_edits,
                       force_delta=force_delta, reason=reason, zero_as_ones=(proto == _IP_PROTO_UDP))

    def rewrite_frame(self):
        if len(self.buf) < 14:
            self.report.append(Fix('eth', 'type', SKIPPED, 'frame shorter than an Ethernet header'))
            return
        eth_type = self._u16(12)
        off = 14
        while eth_type in _ETH_TYPES_VLAN:
            if off + 4 > len(self.buf):
                self.report.append(Fix('vlan', 'type', UNVERIFIABLE, 'truncated 802.1Q tag'))
                return
            eth_type = self._u16(off + 2)
            off += 4
        if eth_type == _ETH_TYPE_IP:
            self.rewrite_ip(off, len(self.buf), 'ip')
        elif eth_type == _ETH_TYPE_IP6:
            self.rewrite_ip6(off, len(self.buf), 'ip6')
        else:
            self.report.append(Fix('eth', 'type', SKIPPED, 'no address rewriting for ethertype 0x%04x' % eth_type))

    def rewrite_ip(self, off, limit, layer):
        limit = min(limit, len(self.buf))
        avail = limit - off
        if avail < 20:
            self.report.append(Fix(layer, 'hdr', UNVERIFIABLE, 'truncated IPv4 header (%d of 20+ bytes captured)' % max(avail, 0)))
            return
        ihl = (self.buf[off] & 0x0f) << 2
        if ihl < 20:
            self.report.append(Fix(layer, 'hdr', SKIPPED, 'invalid IPv4 header length %d' % ihl))
            return
        total_len = self._u16(off + 2)
        if total_len and total_len < ihl:
            self.report.append(Fix(layer, 'len', SKIPPED, 'invalid IPv4 total length %d' % total_len))
            return
        src_edit = self.replace_addr(off + 12, 4, layer, 'src')
        dst_edit = self.replace_addr(off + 16, 4, layer, 'dst')
        if avail < ihl:
            self.report.append(Fix(layer, 'sum', UNVERIFIABLE, 'IPv4 options truncated; header checksum left as captured'))
            return
        if src_edit or dst_edit:
            self.fix_cksum(off + 10, off, off + ihl, layer, 'sum')
        if total_len:
            wire_end = off + total_len
        else:  # zero length (e.g. TCP segmentation offload): use what was captured
            wire_end = limit
        end = min(wire_end, limit)
        force_delta = False
        reason = ''
        if wire_end > limit:
            force_delta = True
            reason = 'capture truncated; adjusted incrementally, cannot be independently verified'
        flags_off = self._u16(off + 6)
        if flags_off & 0x1fff:
            self.report.append(Fix(layer, 'data', SKIPPED, 'non-first fragment; transport header not present'))
            return
        if flags_off & 0x2000:
            force_delta = True
            reason = 'fragmented datagram; transport checksum spans data not in this fragment'
        proto = self.buf[off + 9]
        data_off = off + ihl
        pseudo_edits = []
        if src_edit:
            pseudo_edits.append((0, src_edit[1], src_edit[2]))
        if dst_edit:
            pseudo_edits.append((4, dst_edit[1], dst_edit[2]))
        if proto in (_IP_PROTO_TCP, _IP_PROTO_UDP):
            pseudo = bytes(self.buf[off + 12:off + 20]) + struct.pack('>xBH', proto, wire_end - data_off)
            name = 'tcp' if proto == _IP_PROTO_TCP else 'udp'
            self.fix_transport('%s.%s' % (layer, name), data_off, end, proto, pseudo, pseudo_edits, force_delta, reason, 4)
        elif proto == _IP_PROTO_ICMP:
            self.rewrite_icmp(data_off, end, layer + '.icmp', force_delta, reason)
        else:
            self.report.append(Fix(layer, 'data', SKIPPED, 'no checksum handling for IPv4 protocol %d' % proto))

    def rewrite_ip6(self, off, limit, layer):
        limit = min(limit, len(self.buf))
        avail = limit - off
        if avail < 40:
            self.report.append(Fix(layer, 'hdr', UNVERIFIABLE, 'truncated IPv6 header (%d of 40 bytes captured)' % max(avail, 0)))
            return
        plen = self._u16(off + 4)
        src_edit = self.replace_addr(off + 8, 16, layer, 'src')
        dst_edit = self.replace_addr(off + 24, 16, layer, 'dst')
        if plen:
            wire_end = off + 40 + plen
        else:  # jumbo payload or TSO: use what was captured
            wire_end = limit
        end = min(wire_end, limit)
        force_delta = False
        reason = ''
        if wire_end > limit:
            force_delta = True
            reason = 'capture truncated; adjusted incrementally, cannot be independently verified'
        pseudo_edits = []
        if src_edit:
            pseudo_edits.append((0, src_edit[1], src_edit[2]))
        if dst_edit:
            pseudo_edits.append((16, dst_edit[1], dst_edit[2]))
        nxt = self.buf[off + 6]
        hoff = off + 40
        while nxt in _IP6_EXT_HDRS or nxt == _IP_PROTO_FRAGMENT:
            if nxt == _IP_PROTO_FRAGMENT:
                if hoff + 8 > limit:
                    self.report.append(Fix(layer, 'data', UNVERIFIABLE, 'truncated IPv6 fragment header'))
                    return
                frag_off = self._u16(hoff + 2) >> 3
                nxt = self.buf[hoff]
                hoff += 8
                if frag_off:
                    self.report.append(Fix(layer, 'data', SKIPPED, 'non-first fragment; transport header not present'))
                    return
                force_delta = True
                reason = 'fragmented datagram; transport checksum spans data not in this fragment'
            else:
                if hoff + 2 > limit:
                    self.report.append(Fix(layer, 'data', UNVERIFIABLE, 'truncated IPv6 extension header'))
                    return
                hdr_len = (self.buf[hoff + 1] + 1) << 3
                nxt = self.buf[hoff]
                hoff += hdr_len
                if hoff > end:
                    self.report.append(Fix(layer, 'data', UNVERIFIABLE, 'IPv6 extension headers exceed the payload'))
                    return
        tlen = wire_end - hoff
        if tlen < 0:
            tlen = 0
        pseudo = bytes(self.buf[off + 8:off + 40]) + struct.pack('>I3xB', tlen, nxt)
        if nxt in (_IP_PROTO_TCP, _IP_PROTO_UDP):
            name = 'tcp' if nxt == _IP_PROTO_TCP else 'udp'
            self.fix_transport('%s.%s' % (layer, name), hoff, end, nxt, pseudo, pseudo_edits, force_delta, reason, 6)
        elif nxt == _IP_PROTO_ICMP6:
            self.rewrite_icmp6(hoff, end, layer + '.icmp6', pseudo, pseudo_edits, force_delta, reason)
        else:
            self.report.append(Fix(layer, 'data', SKIPPED, 'no checksum handling for IPv6 next header %d' % nxt))

    def rewrite_quoted(self, off, limit, layer):
        version = self.buf[off] >> 4
        if version == 4:
            self.rewrite_ip(off, limit, layer + '.ip')
        elif version == 6:
            self.rewrite_ip6(off, limit, layer + '.ip6')
        else:
            self.report.append(Fix(layer, 'version', SKIPPED, 'quoted packet is neither IPv4 nor IPv6'))

    def rewrite_icmp(self, off, end, layer, force_delta, reason):
        if off + 4 > len(self.buf):
            self.report.append(Fix(layer, 'hdr', UNVERIFIABLE, 'truncated ICMP header'))
            return
        edits_before = len(self.edits)
        if self.buf[off] in _ICMP_ERROR_TYPES:
            quote_off = off + 8  # ICMP header + 4 bytes of type-specific data
            if quote_off < end:
                self.rewrite_quoted(quote_off, end, layer + '.quote')
            else:
                self.report.append(Fix(layer, 'quote', UNVERIFIABLE, 'ICMP error quotes no original packet'))
        if len(self.edits) == edits_before:
            return
        self.fix_cksum(off + 2, off, end, layer, 'sum', force_delta=force_delta, reason=reason)

    def rewrite_icmp6(self, off, end, layer, pseudo, pseudo_edits, force_delta, reason):
        if off + 4 > len(self.buf):
            self.report.append(Fix(layer, 'hdr', UNVERIFIABLE, 'truncated ICMPv6 header'))
            return
        edits_before = len(self.edits)
        if self.buf[off] in _ICMP6_ERROR_TYPES:
            quote_off = off + 8  # ICMPv6 header + 4 bytes of type-specific data
            if quote_off < end:
                self.rewrite_quoted(quote_off, end, layer + '.quote')
            else:
                self.report.append(Fix(layer, 'quote', UNVERIFIABLE, 'ICMPv6 error quotes no original packet'))
        if len(self.edits) == edits_before and not pseudo_edits:
            return
        self.fix_cksum(off + 2, off, end, layer, 'sum', pseudo=pseudo, pseudo_edits=pseudo_edits,
                       force_delta=force_delta, reason=reason)


def rewrite_packet(buf, mapping):
    """Rewrite IP addresses in a single captured packet.

    Args:
        buf: bytes-like object holding one packet, starting at the
            Ethernet header.  Never modified.
        mapping: one-to-one mapping of addresses to replace; see
            :func:`normalize_mapping` for the accepted forms.

    Returns:
        tuple: (new packet bytes, report) where report is a list of
        :class:`Fix` records (layer, field, status, detail) describing
        every rewritten address and every checksum decision, including
        the fields that could not be proven valid.

    Raises:
        MappingError: the mapping is not a usable one-to-one mapping;
            raised before the packet is looked at.
    """
    normalized = normalize_mapping(mapping)
    rewriter = _Rewriter(buf, normalized)
    rewriter.rewrite_frame()
    return bytes(rewriter.buf), rewriter.report


def _pton(addr):
    family = socket.AF_INET6 if ':' in addr else socket.AF_INET
    return socket.inet_pton(family, addr)


def _make_udp_request(src, dst, udp_sum_zero=False):
    from .ip import IP
    from .udp import UDP
    payload = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x03www\x06google\x03com\x00\x00\x01\x00\x01')
    udp = UDP(sport=53120, dport=53, data=payload)
    udp.ulen = 8 + len(payload)
    ip = IP(src=_pton(src), dst=_pton(dst), p=17, data=udp)
    raw = bytearray(bytes(ip))  # valid IP and UDP checksums
    if udp_sum_zero:
        raw[20 + 6:20 + 8] = b'\x00\x00'  # RFC 768: checksum disabled
    return bytes(raw)


def _make_icmp_error_frame(inner_ip, outer_src, outer_dst, quote_len=None):
    from .icmp import ICMP
    from .ip import IP
    quote = inner_ip if quote_len is None else inner_ip[:quote_len]
    icmp = ICMP(type=3, code=3, data=ICMP.Unreach(mtu=1500, data=quote))
    ip = IP(src=_pton(outer_src), dst=_pton(outer_dst), p=1, data=icmp)
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + bytes(ip)


_MAPPING = {
    '10.0.0.1': '192.0.2.10',
    '10.0.0.2': '192.0.2.20',
    '172.16.0.1': '198.51.100.1',
    '172.16.0.2': '198.51.100.2',
}


def _cksum_ok(raw):
    """Independent checksum verification: a valid region sums to zero."""
    return dpkt.in_cksum(raw) == 0


def test_icmp_error_nested_udp_layer_by_layer():
    from .ethernet import Ethernet
    from .icmp import ICMP
    from .ip import IP
    from .udp import UDP
    inner = _make_udp_request('10.0.0.1', '10.0.0.2')
    frame = _make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2')
    new_frame, report = rewrite_packet(frame, _MAPPING)

    assert new_frame != frame
    # layer-by-layer mapping consistency
    eth = Ethernet(new_frame)
    ip = eth.data
    assert isinstance(ip, IP)
    assert inet_to_str(ip.src) == '198.51.100.1'
    assert inet_to_str(ip.dst) == '198.51.100.2'
    icmp = ip.data
    assert isinstance(icmp, ICMP)
    quoted_ip = icmp.unreach.ip
    assert inet_to_str(quoted_ip.src) == '192.0.2.10'
    assert inet_to_str(quoted_ip.dst) == '192.0.2.20'
    udp = quoted_ip.data
    assert isinstance(udp, UDP)
    assert (udp.sport, udp.dport) == (53120, 53)

    # independent checksum verification of every complete layer
    assert _cksum_ok(new_frame[14:34])  # outer IPv4 header
    assert _cksum_ok(new_frame[34:14 + ip.len])  # whole ICMP message
    q_off = 14 + 20 + 8
    assert _cksum_ok(new_frame[q_off:q_off + 20])  # quoted IPv4 header
    udp_raw = new_frame[q_off + 20:q_off + 20 + udp.ulen]
    pseudo = new_frame[q_off + 12:q_off + 20] + struct.pack('>xBH', 17, udp.ulen)
    assert _cksum_ok(pseudo + udp_raw)  # quoted UDP with pseudo-header

    statuses = dict(((f.layer, f.field), f.status) for f in report)
    assert statuses[('ip', 'src')] == REWRITTEN
    assert statuses[('ip', 'dst')] == REWRITTEN
    assert statuses[('ip', 'sum')] == RECOMPUTED
    assert statuses[('ip.icmp', 'sum')] == RECOMPUTED
    assert statuses[('ip.icmp.quote.ip', 'src')] == REWRITTEN
    assert statuses[('ip.icmp.quote.ip', 'dst')] == REWRITTEN
    assert statuses[('ip.icmp.quote.ip', 'sum')] == RECOMPUTED
    assert statuses[('ip.icmp.quote.ip.udp', 'sum')] == RECOMPUTED


def test_input_buffer_not_modified():
    inner = _make_udp_request('10.0.0.1', '10.0.0.2')
    frame = bytearray(_make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2'))
    snapshot = bytes(frame)
    new_frame, report = rewrite_packet(frame, _MAPPING)
    assert bytes(frame) == snapshot
    assert isinstance(new_frame, bytes)
    assert new_frame != snapshot


def test_mapping_collision_rejected_before_processing():
    import pytest
    assert issubclass(MappingError, ValueError)
    frame = _make_icmp_error_frame(_make_udp_request('10.0.0.1', '10.0.0.2'), '172.16.0.1', '172.16.0.2')
    # two sources mapping to the same target
    with pytest.raises(MappingError):
        rewrite_packet(frame, {'10.0.0.1': '192.0.2.1', '10.0.0.2': '192.0.2.1'})
    # duplicate source in a pair list
    with pytest.raises(MappingError):
        rewrite_packet(frame, [('10.0.0.1', '192.0.2.1'), ('10.0.0.1', '192.0.2.2')])
    # address family mismatch inside a pair
    with pytest.raises(MappingError):
        rewrite_packet(frame, {'10.0.0.1': '2001:db8::1'})
    # unparsable address
    with pytest.raises(MappingError):
        rewrite_packet(frame, {'not-an-ip': '192.0.2.1'})


def test_mapping_swap_is_allowed():
    from .ip import IP
    inner = _make_udp_request('10.0.0.1', '10.0.0.2')
    frame = _make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2')
    new_frame, report = rewrite_packet(frame, {'10.0.0.1': '10.0.0.2', '10.0.0.2': '10.0.0.1'})
    q_off = 14 + 20 + 8
    quoted_ip = IP(new_frame[q_off:])
    assert inet_to_str(quoted_ip.src) == '10.0.0.2'
    assert inet_to_str(quoted_ip.dst) == '10.0.0.1'
    assert _cksum_ok(new_frame[q_off:q_off + 20])


def test_ipv4_udp_zero_checksum_preserved():
    inner = _make_udp_request('10.0.0.1', '10.0.0.2', udp_sum_zero=True)
    frame = _make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2')
    new_frame, report = rewrite_packet(frame, _MAPPING)
    q_off = 14 + 20 + 8
    assert new_frame[q_off + 20 + 6:q_off + 20 + 8] == b'\x00\x00'
    statuses = dict(((f.layer, f.field), f.status) for f in report)
    assert statuses[('ip.icmp.quote.ip.udp', 'sum')] == PRESERVED
    # surrounding checksums are still fixed and valid
    assert _cksum_ok(new_frame[14:34])
    ip_len = struct.unpack('>H', new_frame[16:18])[0]
    assert _cksum_ok(new_frame[34:14 + ip_len])


def test_truncated_quote_udp_checksum_unverifiable():
    inner = _make_udp_request('10.0.0.1', '10.0.0.2')
    # quoted: full IPv4 header (20) + only 4 bytes of UDP; the UDP
    # checksum field (offset 26) is not part of the quote
    frame = _make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2', quote_len=24)
    new_frame, report = rewrite_packet(frame, _MAPPING)
    statuses = dict(((f.layer, f.field), f.status) for f in report)
    assert statuses[('ip.icmp.quote.ip', 'src')] == REWRITTEN
    assert statuses[('ip.icmp.quote.ip', 'sum')] == RECOMPUTED
    assert statuses[('ip.icmp.quote.ip.udp', 'sum')] == UNVERIFIABLE
    # nothing was zeroed out or invented: the frame length is unchanged
    assert len(new_frame) == len(frame)
    # the outer ICMP checksum was recomputed and is valid
    ip_len = struct.unpack('>H', new_frame[16:18])[0]
    assert _cksum_ok(new_frame[34:14 + ip_len])


def test_truncated_quote_udp_checksum_adjusted():
    inner = _make_udp_request('10.0.0.1', '10.0.0.2')
    full_new, _ = rewrite_packet(_make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2'), _MAPPING)
    # quoted: IPv4 header + UDP header + 5 payload bytes (of 32)
    frame = _make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2', quote_len=20 + 8 + 5)
    new_frame, report = rewrite_packet(frame, _MAPPING)
    statuses = dict(((f.layer, f.field), f.status) for f in report)
    assert statuses[('ip.icmp.quote.ip.udp', 'sum')] == ADJUSTED
    # incremental adjustment must agree with the full recomputation
    q_off = 14 + 20 + 8
    assert new_frame[q_off + 26:q_off + 28] == full_new[q_off + 26:q_off + 28]
    ip_len = struct.unpack('>H', new_frame[16:18])[0]
    assert _cksum_ok(new_frame[34:14 + ip_len])


def test_truncated_capture_reports_adjusted_checksums():
    inner = _make_udp_request('10.0.0.1', '10.0.0.2')
    frame = _make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2')
    full_new, _ = rewrite_packet(frame, _MAPPING)
    cut = frame[:-7]  # drop 7 payload bytes of the quoted UDP datagram
    new_frame, report = rewrite_packet(cut, _MAPPING)
    statuses = dict(((f.layer, f.field), f.status) for f in report)
    assert statuses[('ip', 'sum')] == RECOMPUTED
    assert statuses[('ip.icmp', 'sum')] == ADJUSTED
    assert statuses[('ip.icmp.quote.ip', 'sum')] == RECOMPUTED
    assert statuses[('ip.icmp.quote.ip.udp', 'sum')] == ADJUSTED
    # every edited field lies inside the captured part, so the
    # incrementally adjusted result must equal the full rewrite
    assert new_frame == full_new[:-7]


def test_ipv6_udp_rewrite():
    from .ip6 import IP6
    from .udp import UDP
    payload = b'\xde\xad\xbe\xef'
    udp = UDP(sport=1234, dport=4321, data=payload)
    udp.ulen = 8 + len(payload)
    ip6 = IP6(src=_pton('2001:db8::1'), dst=_pton('2001:db8::2'), nxt=17, plen=udp.ulen, data=udp)
    frame = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x86\xdd' + bytes(ip6)
    mapping = {'2001:db8::1': '2001:db8:ffff::1', '2001:db8::2': '2001:db8:ffff::2'}
    new_frame, report = rewrite_packet(frame, mapping)
    ip6_new = IP6(new_frame[14:])
    assert inet_to_str(ip6_new.src) == '2001:db8:ffff::1'
    assert inet_to_str(ip6_new.dst) == '2001:db8:ffff::2'
    udp_raw = new_frame[14 + 40:14 + 40 + udp.ulen]
    pseudo = new_frame[14 + 8:14 + 40] + struct.pack('>I3xB', udp.ulen, 17)
    assert _cksum_ok(pseudo + udp_raw)
    statuses = dict(((f.layer, f.field), f.status) for f in report)
    assert statuses[('ip6', 'src')] == REWRITTEN
    assert statuses[('ip6.udp', 'sum')] == RECOMPUTED


def test_icmp6_error_nested_udp():
    from .icmp6 import ICMP6
    from .ip6 import IP6
    from .udp import UDP
    payload = b'\x01\x02\x03\x04\x05'
    udp = UDP(sport=1000, dport=2000, data=payload)
    udp.ulen = 8 + len(payload)
    inner = IP6(src=_pton('2001:db8::1'), dst=_pton('2001:db8::2'), nxt=17, plen=udp.ulen, data=udp)
    icmp6 = ICMP6(type=3, code=0, data=ICMP6.TimeExceed(data=bytes(inner)))
    icmp6_raw = bytes(icmp6)
    outer = IP6(src=_pton('2001:db8:1::1'), dst=_pton('2001:db8:2::1'), nxt=58, plen=len(icmp6_raw), data=icmp6)
    frame = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x86\xdd' + bytes(outer)
    mapping = {
        '2001:db8::1': '2001:db8:ffff::1',
        '2001:db8::2': '2001:db8:ffff::2',
        '2001:db8:1::1': '2001:db8:ffff::3',
        '2001:db8:2::1': '2001:db8:ffff::4',
    }
    new_frame, report = rewrite_packet(frame, mapping)
    ip6_new = IP6(new_frame[14:])
    assert inet_to_str(ip6_new.src) == '2001:db8:ffff::3'
    assert inet_to_str(ip6_new.dst) == '2001:db8:ffff::4'
    quoted = ip6_new.data.data.ip6
    assert inet_to_str(quoted.src) == '2001:db8:ffff::1'
    assert inet_to_str(quoted.dst) == '2001:db8:ffff::2'
    # independent verification of the ICMPv6 checksum (pseudo-header + message)
    icmp6_len = struct.unpack('>H', new_frame[14 + 4:14 + 6])[0]
    icmp6_raw_new = new_frame[14 + 40:14 + 40 + icmp6_len]
    pseudo = new_frame[14 + 8:14 + 40] + struct.pack('>I3xB', icmp6_len, 58)
    assert _cksum_ok(pseudo + icmp6_raw_new)
    # and of the quoted UDP checksum
    q_off = 14 + 40 + 8
    udp_len = 8 + len(payload)
    udp_raw = new_frame[q_off + 40:q_off + 40 + udp_len]
    qpseudo = new_frame[q_off + 8:q_off + 40] + struct.pack('>I3xB', udp_len, 17)
    assert _cksum_ok(qpseudo + udp_raw)


def test_vlan_tagged_frame():
    from .ip import IP
    inner = _make_udp_request('10.0.0.1', '10.0.0.2')
    frame = (b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01'
             b'\x81\x00' b'\x00\x64' b'\x08\x00' + inner)  # 802.1Q, VLAN 100
    new_frame, report = rewrite_packet(frame, _MAPPING)
    assert new_frame[12:14] == b'\x81\x00'
    ip = IP(new_frame[18:])
    assert inet_to_str(ip.src) == '192.0.2.10'
    assert inet_to_str(ip.dst) == '192.0.2.20'
    assert _cksum_ok(new_frame[18:38])
    udp_raw = new_frame[18 + 20:18 + 20 + ip.data.ulen]
    pseudo = new_frame[18 + 12:18 + 20] + struct.pack('>xBH', 17, ip.data.ulen)
    assert _cksum_ok(pseudo + udp_raw)


def test_unmapped_packet_passes_through():
    inner = _make_udp_request('10.0.0.1', '10.0.0.2')
    frame = _make_icmp_error_frame(inner, '172.16.0.1', '172.16.0.2')
    new_frame, report = rewrite_packet(frame, {'203.0.113.1': '203.0.113.2'})
    assert new_frame == frame
    assert not any(f.status == REWRITTEN for f in report)
