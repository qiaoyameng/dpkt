# -*- coding: utf-8 -*-
"""IP address rewriting for captured packets.

Rewrites IPv4/IPv6 addresses in Ethernet frames (with or without VLAN
tags) according to a caller-supplied one-to-one mapping, including the
original datagram quoted inside ICMP/ICMPv6 error messages.  Every IP
and transport checksum affected by a substitution is fixed incrementally
(RFC 1624), so truncated captures and truncated ICMP quotes are handled
exactly: the report states which fields were fixed and which cannot be
proven valid, instead of zeroing checksums.  An IPv4 UDP checksum of 0
(checksum disabled, RFC 768) is preserved as 0.
"""
from __future__ import absolute_import

import socket
import struct

from .compat import compat_ord, isstr, iteritems
from .utils import inet_to_str

ETH_TYPE_IP = 0x0800
ETH_TYPE_IP6 = 0x86DD
# 802.1Q / 802.1ad / legacy QinQ ethertypes
_ETH_TYPES_VLAN = frozenset([0x8100, 0x88A8, 0x9100, 0x9200])

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMP6 = 58

_IP6_EXT_HDRS = frozenset([0, 43, 60])  # hop-by-hop, routing, destination options
_IP6_FRAGMENT = 44
_IP6_AH = 51

# ICMP types that quote the offending IP datagram
_ICMP_ERROR_TYPES = frozenset([3, 4, 5, 11, 12])
_ICMP6_ERROR_TYPES = frozenset([1, 2, 3, 4])


class MappingError(ValueError):
    """The address mapping is not a usable one-to-one mapping."""


class RewriteReport(object):
    """Outcome of :func:`rewrite_packet`.

    Attributes:
        fixed: (list of str): fields that were rewritten and checksums that
            were corrected accordingly.
        unresolved: (list of str): fields that could not be rewritten or
            corrected, or whose validity cannot be proven, e.g. because the
            capture or the ICMP quote is truncated.
        notes: (list of str): informational entries, e.g. a deliberately
            preserved disabled UDP checksum.
    """

    def __init__(self):
        self.fixed = []
        self.unresolved = []
        self.notes = []

    def __repr__(self):
        return 'RewriteReport(fixed=%r, unresolved=%r, notes=%r)' % (
            self.fixed, self.unresolved, self.notes)


def _addr_to_bytes(addr):
    if isinstance(addr, bytes):
        if len(addr) in (4, 16):
            return addr
        raise MappingError('address must be 4 or 16 bytes: %r' % (addr,))
    if isstr(addr):
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                return socket.inet_pton(family, addr)
            except (socket.error, TypeError):
                continue
    raise MappingError('cannot parse IP address: %r' % (addr,))


def normalize_mapping(mapping):
    """Validate a one-to-one address mapping.

    Accepts a dict or an iterable of (old, new) pairs; addresses may be
    strings or 4/16-byte values.  Returns {old_bytes: new_bytes}.

    Raises:
        MappingError: if a source appears twice, if two sources map to the
            same target (collision), or if a pair mixes address families.
            Raised before any packet is processed.
    """
    if hasattr(mapping, 'items'):
        pairs = list(iteritems(mapping))
    else:
        pairs = list(mapping)
    normalized = {}
    targets = {}
    for old, new in pairs:
        old_b = _addr_to_bytes(old)
        new_b = _addr_to_bytes(new)
        if len(old_b) != len(new_b):
            raise MappingError(
                'address family mismatch in pair %r -> %r' % (old, new))
        if old_b in normalized:
            raise MappingError(
                'duplicate source address %s' % inet_to_str(old_b))
        if new_b in targets:
            raise MappingError(
                'mapping collision: %s and %s both map to %s' % (
                    inet_to_str(targets[new_b]), inet_to_str(old_b),
                    inet_to_str(new_b)))
        normalized[old_b] = new_b
        targets[new_b] = old_b
    return normalized


def _cksum_adjust(sum_old, old, new):
    """Incrementally update an Internet checksum field (RFC 1624).

    sum_old is the checksum field value as stored in the packet; old and
    new are the replaced bytes (even length).  Returns the new field value.
    """
    s = (~sum_old) & 0xffff
    for i in range(0, len(old), 2):
        word_old = (compat_ord(old[i]) << 8) | compat_ord(old[i + 1])
        word_new = (compat_ord(new[i]) << 8) | compat_ord(new[i + 1])
        s += (~word_old & 0xffff) + word_new
        s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class _Rewriter(object):
    """Byte-level rewriter; never touches the caller's buffer."""

    def __init__(self, buf, mapping, report):
        self.buf = buf  # bytearray, our private copy
        self.mapping = mapping
        self.report = report

    def adjust_cksum(self, cksum_off, old, new, udp=False):
        """Fix the checksum field at cksum_off for replaced bytes old->new.

        Returns the (offset, old, new) change of the checksum field itself.
        """
        sum_old = struct.unpack('>H', self.buf[cksum_off:cksum_off + 2])[0]
        sum_new = _cksum_adjust(sum_old, old, new)
        if udp and sum_new == 0:
            # RFC 768: a computed zero checksum is transmitted as all ones;
            # an all-zero field means "no checksum generated".
            sum_new = 0xffff
        field_old = bytes(self.buf[cksum_off:cksum_off + 2])
        field_new = struct.pack('>H', sum_new)
        self.buf[cksum_off:cksum_off + 2] = field_new
        return (cksum_off, field_old, field_new)

    def map_addr(self, off, length, label):
        """Replace buf[off:off+length] if mapped. Returns (old, new) or None."""
        old = bytes(self.buf[off:off + length])
        new = self.mapping.get(old)
        if new is None:
            return None
        self.buf[off:off + length] = new
        self.report.fixed.append(
            '%s: %s -> %s' % (label, inet_to_str(old), inet_to_str(new)))
        return (old, new)

    def rewrite_ethernet(self):
        buf = self.buf
        if len(buf) < 14:
            self.report.unresolved.append(
                'ethernet: header truncated (%d of 14 bytes captured); '
                'nothing rewritten' % len(buf))
            return
        eth_type = struct.unpack('>H', buf[12:14])[0]
        off = 14
        n_tags = 0
        while eth_type in _ETH_TYPES_VLAN:
            if off + 4 > len(buf):
                self.report.unresolved.append(
                    'vlan: tag truncated; nothing rewritten')
                return
            eth_type = struct.unpack('>H', buf[off + 2:off + 4])[0]
            off += 4
            n_tags += 1
            if n_tags >= 4:
                self.report.unresolved.append(
                    'vlan: more than 4 nested tags; nothing rewritten')
                return
        if eth_type in (ETH_TYPE_IP, ETH_TYPE_IP6):
            self.rewrite_ip(off, len(buf) - off, quoted=False)
        else:
            self.report.notes.append(
                'ethernet: ethertype 0x%04x not IP/IPv6; nothing to rewrite'
                % eth_type)

    def rewrite_ip(self, off, avail, quoted):
        """Rewrite the IP packet at off. Returns [(off, old, new), ...]."""
        if avail < 1:
            return []
        version = compat_ord(self.buf[off]) >> 4
        if version == 4:
            return self.rewrite_ipv4(off, avail, quoted)
        if version == 6:
            return self.rewrite_ipv6(off, avail, quoted)
        self.report.unresolved.append(
            'ip: unknown version %d at offset %d; not rewritten'
            % (version, off))
        return []

    def rewrite_ipv4(self, off, avail, quoted):
        label = 'icmp quote ipv4' if quoted else 'ipv4'
        if avail < 20:
            self.report.unresolved.append(
                '%s: header truncated (%d of 20 bytes captured); '
                'cannot rewrite' % (label, avail))
            return []
        ihl = (compat_ord(self.buf[off]) & 0x0f) * 4
        if ihl < 20:
            self.report.unresolved.append(
                '%s: invalid header length %d; cannot rewrite' % (label, ihl))
            return []
        if ihl > avail:
            self.report.unresolved.append(
                '%s: header truncated (%d of %d bytes captured); '
                'cannot rewrite' % (label, avail, ihl))
            return []
        total_len = struct.unpack('>H', self.buf[off + 2:off + 4])[0]
        changes = []
        addr_changes = []
        for addr_off, name in ((off + 12, 'src'), (off + 16, 'dst')):
            subst = self.map_addr(addr_off, 4, '%s.%s' % (label, name))
            if subst:
                old, new = subst
                changes.append((addr_off, old, new))
                changes.append(self.adjust_cksum(off + 10, old, new))
                addr_changes.append((old, new))
                self.report.fixed.append(
                    '%s: header checksum updated' % label)
        if total_len < ihl:
            self.report.unresolved.append(
                '%s: invalid total length %d; payload not examined'
                % (label, total_len))
            return changes
        if total_len > avail:
            self.report.unresolved.append(
                '%s: capture truncated (%d of %d bytes present); checksums '
                'were fixed incrementally but cannot be re-validated '
                'end-to-end' % (label, avail, total_len))
        flags_off = struct.unpack('>H', self.buf[off + 6:off + 8])[0]
        if flags_off & 0x1fff:
            if addr_changes:
                self.report.unresolved.append(
                    '%s: non-first fragment; the transport checksum lives '
                    'in another fragment and cannot be fixed here' % label)
            return changes
        payload_avail = min(avail, total_len) - ihl
        if payload_avail <= 0:
            return changes
        proto = compat_ord(self.buf[off + 9])
        changes += self.rewrite_transport(
            off + ihl, payload_avail, proto, addr_changes, 4, label)
        return changes

    def rewrite_ipv6(self, off, avail, quoted):
        label = 'icmp quote ipv6' if quoted else 'ipv6'
        if avail < 40:
            self.report.unresolved.append(
                '%s: header truncated (%d of 40 bytes captured); '
                'cannot rewrite' % (label, avail))
            return []
        changes = []
        addr_changes = []
        for addr_off, name in ((off + 8, 'src'), (off + 24, 'dst')):
            subst = self.map_addr(addr_off, 16, '%s.%s' % (label, name))
            if subst:
                changes.append((addr_off,) + subst)
                addr_changes.append(subst)
        plen = struct.unpack('>H', self.buf[off + 4:off + 6])[0]
        if plen and plen + 40 > avail:
            self.report.unresolved.append(
                '%s: capture truncated (%d of %d bytes present); checksums '
                'were fixed incrementally but cannot be re-validated '
                'end-to-end' % (label, avail, plen + 40))
        payload_avail = min(avail - 40, plen) if plen else avail - 40
        nxt = compat_ord(self.buf[off + 6])
        ext_off = off + 40
        while nxt in _IP6_EXT_HDRS or nxt in (_IP6_FRAGMENT, _IP6_AH):
            if payload_avail < 2:
                self.report.unresolved.append(
                    '%s: extension header truncated; payload not examined'
                    % label)
                return changes
            nxt_hdr = compat_ord(self.buf[ext_off])
            if nxt == _IP6_FRAGMENT:
                if payload_avail < 8:
                    self.report.unresolved.append(
                        '%s: fragment header truncated; payload not examined'
                        % label)
                    return changes
                frag = struct.unpack(
                    '>H', self.buf[ext_off + 2:ext_off + 4])[0]
                if frag & 0xfff8:  # fragment offset != 0
                    if addr_changes:
                        self.report.unresolved.append(
                            '%s: non-first fragment; the transport checksum '
                            'lives in another fragment and cannot be fixed '
                            'here' % label)
                    return changes
                hdr_len = 8
            elif nxt == _IP6_AH:
                hdr_len = (compat_ord(self.buf[ext_off + 1]) + 2) * 4
            else:
                hdr_len = (compat_ord(self.buf[ext_off + 1]) + 1) * 8
            if hdr_len > payload_avail:
                self.report.unresolved.append(
                    '%s: extension header truncated; payload not examined'
                    % label)
                return changes
            ext_off += hdr_len
            payload_avail -= hdr_len
            nxt = nxt_hdr
        if payload_avail <= 0:
            return changes
        changes += self.rewrite_transport(
            ext_off, payload_avail, nxt, addr_changes, 6, label)
        return changes

    def rewrite_transport(self, off, avail, proto, addr_changes, ip_version,
                          ip_label):
        if proto == IP_PROTO_ICMP and ip_version == 4:
            return self.rewrite_icmp(off, avail, ip_label)
        if proto == IP_PROTO_ICMP6 and ip_version == 6:
            return self.rewrite_icmp6(off, avail, addr_changes, ip_label)
        if proto == IP_PROTO_TCP:
            cksum_off, need, name = off + 16, 18, 'tcp'
        elif proto == IP_PROTO_UDP:
            cksum_off, need, name = off + 6, 8, 'udp'
        else:
            return []
        if (proto == IP_PROTO_UDP and ip_version == 4 and avail >= 8 and
                struct.unpack('>H', self.buf[cksum_off:cksum_off + 2])[0] == 0):
            self.report.notes.append(
                '%s udp: checksum is 0 (checksum disabled); preserved as 0'
                % ip_label)
            return []
        if not addr_changes:
            return []
        if avail < need:
            self.report.unresolved.append(
                '%s %s: checksum field not captured (truncated); '
                'left unchanged' % (ip_label, name))
            return []
        changes = []
        for old, new in addr_changes:
            changes.append(self.adjust_cksum(
                cksum_off, old, new, udp=(proto == IP_PROTO_UDP)))
        self.report.fixed.append(
            '%s %s: checksum updated for pseudo-header change'
            % (ip_label, name))
        return changes

    def rewrite_icmp(self, off, avail, ip_label):
        label = '%s icmp' % ip_label
        if avail < 4:
            self.report.unresolved.append(
                '%s: header truncated; checksum cannot be maintained' % label)
            return []
        icmp_type = compat_ord(self.buf[off])
        if icmp_type not in _ICMP_ERROR_TYPES:
            return []
        if avail < 8:
            self.report.unresolved.append(
                '%s: error header truncated; quoted packet missing' % label)
            return []
        inner = self.rewrite_ip(off + 8, avail - 8, quoted=True)
        changes = []
        for _change_off, old, new in inner:
            changes.append(self.adjust_cksum(off + 2, old, new))
        if inner:
            self.report.fixed.append(
                '%s: checksum updated for changes in quoted packet' % label)
        changes += inner
        return changes

    def rewrite_icmp6(self, off, avail, addr_changes, ip_label):
        label = '%s icmp6' % ip_label
        if avail < 4:
            self.report.unresolved.append(
                '%s: header truncated; checksum cannot be maintained' % label)
            return []
        changes = []
        # the ICMPv6 checksum covers the IPv6 pseudo-header
        for old, new in addr_changes:
            changes.append(self.adjust_cksum(off + 2, old, new))
        if addr_changes:
            self.report.fixed.append(
                '%s: checksum updated for pseudo-header change' % label)
        icmp_type = compat_ord(self.buf[off])
        if icmp_type not in _ICMP6_ERROR_TYPES:
            return changes
        if avail < 8:
            self.report.unresolved.append(
                '%s: error header truncated; quoted packet missing' % label)
            return changes
        inner = self.rewrite_ip(off + 8, avail - 8, quoted=True)
        for _change_off, old, new in inner:
            changes.append(self.adjust_cksum(off + 2, old, new))
        if inner:
            self.report.fixed.append(
                '%s: checksum updated for changes in quoted packet' % label)
        changes += inner
        return changes


def rewrite_packet(data, mapping):
    """Rewrite IP addresses in a captured Ethernet frame.

    Args:
        data: frame bytes (bytes or bytearray); never modified.
        mapping: one-to-one address mapping, a dict or an iterable of
            (old, new) pairs; addresses as strings or 4/16-byte values.

    Returns:
        (new_bytes, RewriteReport): the rewritten frame, and a report
        listing every field fixed and every field left unresolved.

    Raises:
        MappingError: the mapping is not one-to-one (e.g. two sources map
            to the same target); raised before the packet is touched.
    """
    normalized = normalize_mapping(mapping)
    buf = bytearray(data)
    report = RewriteReport()
    if normalized:
        _Rewriter(buf, normalized, report).rewrite_ethernet()
    return bytes(buf), report


# --- tests -----------------------------------------------------------------

def _independent_cksum(data):
    """Reference Internet checksum (RFC 1071), independent of the rewriter."""
    if len(data) % 2:
        data += b'\x00'
    words = struct.unpack('>%dH' % (len(data) // 2), data)
    s = sum(words)
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _pton(addr):
    family = socket.AF_INET6 if ':' in addr else socket.AF_INET
    return socket.inet_pton(family, addr)


def _ipv4_header(src, dst, proto, payload_len, ttl=64):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + payload_len, 0x1234, 0,
                      ttl, proto, 0, _pton(src), _pton(dst))
    return hdr[:10] + struct.pack('>H', _independent_cksum(hdr)) + hdr[12:]


def _udp4_datagram(src, dst, sport, dport, payload, checksum=True):
    ulen = 8 + len(payload)
    udp = struct.pack('>HHHH', sport, dport, ulen, 0) + payload
    if checksum:
        pseudo = _pton(src) + _pton(dst) + struct.pack('>BBH', 0, 17, ulen)
        sum_ = _independent_cksum(pseudo + udp) or 0xffff
        udp = struct.pack('>HHHH', sport, dport, ulen, sum_) + payload
    return _ipv4_header(src, dst, 17, len(udp)) + udp


def _tcp4_datagram(src, dst, sport, dport, payload):
    tcp = struct.pack('>HHIIBBHHH', sport, dport, 1, 0, 5 << 4, 0x18,
                      1024, 0, 0) + payload
    pseudo = _pton(src) + _pton(dst) + struct.pack('>BBH', 0, 6, len(tcp))
    sum_ = _independent_cksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack('>H', sum_) + tcp[18:]
    return _ipv4_header(src, dst, 6, len(tcp)) + tcp


def _eth(eth_type, vlan_id=None):
    hdr = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02'
    if vlan_id is not None:
        hdr += struct.pack('>HH', 0x8100, vlan_id)
    return hdr + struct.pack('>H', eth_type)


def test_rewrite_icmp_error_quoting_udp():
    from . import ethernet as ethernet_mod
    from .utils import inet_to_str as _inet_to_str

    inner_src, inner_dst = '10.1.0.1', '10.2.0.2'
    new_inner_src, new_inner_dst = '198.51.100.1', '198.51.100.2'
    payload = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x03www\x06google\x03com\x00\x00\x01\x00\x01')
    inner_ip = _udp4_datagram(inner_src, inner_dst, 53210, 53, payload)
    quote = inner_ip[:28]  # IP header + 8 bytes of UDP, as ICMP errors carry
    icmp = struct.pack('>BBHI', 11, 0, 0, 0) + quote  # time exceeded
    icmp = icmp[:2] + struct.pack('>H', _independent_cksum(icmp)) + icmp[4:]
    outer_ip = _ipv4_header('192.0.2.254', inner_src, 1, len(icmp), ttl=255)
    frame = _eth(0x0800, vlan_id=100) + outer_ip + icmp

    buf = bytearray(frame)
    original = bytes(buf)
    mapping = {inner_src: new_inner_src, inner_dst: new_inner_dst}
    new_frame, report = rewrite_packet(buf, mapping)

    # the tool returns a new packet; the input bytes are unchanged
    assert bytes(buf) == original
    assert new_frame != original

    # layer-by-layer mapping consistency
    eth = ethernet_mod.Ethernet(new_frame)
    assert eth.vlan_tags[0].id == 100
    outer = eth.data
    assert _inet_to_str(outer.src) == '192.0.2.254'  # not in mapping
    assert _inet_to_str(outer.dst) == new_inner_src
    ic = outer.data
    assert ic.type == 11
    quoted_ip = ic.data.ip
    assert _inet_to_str(quoted_ip.src) == new_inner_src
    assert _inet_to_str(quoted_ip.dst) == new_inner_dst
    quoted_udp = quoted_ip.data
    assert quoted_udp.sport == 53210
    assert quoted_udp.dport == 53

    # independent checksum validation of the complete layers
    ip_off = 14 + 4  # ethernet + one vlan tag
    assert _independent_cksum(new_frame[ip_off:ip_off + 20]) == 0
    icmp_off = ip_off + 20
    assert _independent_cksum(new_frame[icmp_off:icmp_off + len(icmp)]) == 0
    quote_off = icmp_off + 8
    assert _independent_cksum(new_frame[quote_off:quote_off + 20]) == 0

    # the quoted UDP checksum must equal an independent checksum over the
    # fully rewritten inner datagram (the quote itself is truncated)
    mapped_inner = _udp4_datagram(new_inner_src, new_inner_dst, 53210, 53,
                                  payload)
    expected_sum = struct.unpack('>H', mapped_inner[26:28])[0]
    quoted_sum = struct.unpack(
        '>H', new_frame[quote_off + 26:quote_off + 28])[0]
    assert quoted_sum == expected_sum
    assert quoted_sum != 0

    # the quote is truncated by nature: fixed fields are listed, and the
    # missing tail of the quoted datagram is reported as unresolved
    assert any('10.1.0.1 -> 198.51.100.1' in e for e in report.fixed)
    assert any('10.2.0.2 -> 198.51.100.2' in e for e in report.fixed)
    assert any('truncated' in e for e in report.unresolved)


def test_mapping_collision_rejected():
    import pytest

    frame = _eth(0x0800) + _udp4_datagram('10.0.0.1', '10.0.0.2', 1, 2, b'x')
    original = bytes(frame)
    # two sources mapping to the same target
    with pytest.raises(MappingError):
        rewrite_packet(frame, {'10.0.0.1': '198.51.100.9',
                               '10.0.0.2': '198.51.100.9'})
    # duplicate source in a pair list
    with pytest.raises(MappingError):
        rewrite_packet(frame, [('10.0.0.1', '198.51.100.9'),
                               ('10.0.0.1', '198.51.100.10')])
    # mixed address families in one pair
    with pytest.raises(MappingError):
        rewrite_packet(frame, {'10.0.0.1': '2001:db8::1'})
    # unparseable address
    with pytest.raises(MappingError):
        rewrite_packet(frame, {'not-an-address': '198.51.100.9'})
    assert bytes(frame) == original


def test_udp_zero_checksum_preserved():
    frame = _eth(0x0800) + _udp4_datagram('10.1.0.1', '10.2.0.2', 1234, 53,
                                          b'abcd', checksum=False)
    new_frame, report = rewrite_packet(frame, {'10.1.0.1': '198.51.100.1'})
    udp_sum = struct.unpack('>H', new_frame[14 + 20 + 6:14 + 20 + 8])[0]
    assert udp_sum == 0  # disabled checksum stays disabled
    assert any('preserved' in e for e in report.notes)
    # the IP header checksum is still fixed for the new source address
    assert _independent_cksum(new_frame[14:34]) == 0


def test_truncated_quote_reports_unresolved():
    inner_ip = _udp4_datagram('10.1.0.1', '10.2.0.2', 53210, 53, b'payload')
    quote = inner_ip[:26]  # IP header + 6 bytes of UDP: no checksum field
    icmp = struct.pack('>BBHI', 3, 3, 0, 0) + quote  # port unreachable
    icmp = icmp[:2] + struct.pack('>H', _independent_cksum(icmp)) + icmp[4:]
    frame = _eth(0x0800) + _ipv4_header('192.0.2.254', '10.1.0.1', 1,
                                        len(icmp)) + icmp
    new_frame, report = rewrite_packet(
        frame, {'10.1.0.1': '198.51.100.1', '10.2.0.2': '198.51.100.2'})

    quote_off = 14 + 20 + 8
    # quoted addresses rewritten, quoted IP header checksum fixed
    assert new_frame[quote_off + 12:quote_off + 16] == _pton('198.51.100.1')
    assert new_frame[quote_off + 16:quote_off + 20] == _pton('198.51.100.2')
    assert _independent_cksum(new_frame[quote_off:quote_off + 20]) == 0
    # the missing UDP checksum field is reported, not zeroed or invented
    assert any('udp' in e and 'not captured' in e for e in report.unresolved)
    # the ICMP checksum still validates over the whole message
    icmp_off = 14 + 20
    assert _independent_cksum(new_frame[icmp_off:icmp_off + len(icmp)]) == 0


def test_rewrite_ipv4_tcp():
    src, dst = '172.16.0.10', '172.16.0.20'
    new_src, new_dst = '203.0.113.10', '203.0.113.20'
    payload = b'GET / HTTP/1.0\r\n\r\n'
    frame = _eth(0x0800) + _tcp4_datagram(src, dst, 49152, 80, payload)
    new_frame, report = rewrite_packet(frame, {src: new_src, dst: new_dst})
    ip_off = 14
    assert _independent_cksum(new_frame[ip_off:ip_off + 20]) == 0
    seg = new_frame[ip_off + 20:]
    pseudo = _pton(new_src) + _pton(new_dst) + struct.pack('>BBH', 0, 6,
                                                           len(seg))
    assert _independent_cksum(pseudo + seg) == 0
    assert report.unresolved == []


def test_rewrite_ipv6_icmp6_error():
    src6, dst6 = '2001:db8:1::1', '2001:db8:2::2'
    new_src6, new_dst6 = '2001:db8:aaaa::1', '2001:db8:bbbb::2'
    router6 = '2001:db8:ff::1'
    payload = b'hello-ipv6'
    udp = struct.pack('>HHHH', 40000, 9, 8 + len(payload), 0) + payload
    pseudo = _pton(src6) + _pton(dst6) + struct.pack('>I3xB', len(udp), 17)
    udp_sum = _independent_cksum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', udp_sum) + udp[8:]
    inner_ip6 = struct.pack('>IHBB16s16s', 0x60000000, len(udp), 17, 64,
                            _pton(src6), _pton(dst6)) + udp
    quote = inner_ip6[:48]  # IPv6 header + 8 bytes of UDP
    ic6 = struct.pack('>BBHI', 3, 0, 0, 0) + quote  # time exceeded
    pseudo = _pton(router6) + _pton(src6) + struct.pack('>I3xB', len(ic6), 58)
    ic6_sum = _independent_cksum(pseudo + ic6)
    ic6 = ic6[:2] + struct.pack('>H', ic6_sum) + ic6[4:]
    outer_ip6 = struct.pack('>IHBB16s16s', 0x60000000, len(ic6), 58, 255,
                            _pton(router6), _pton(src6)) + ic6
    frame = _eth(0x86DD) + outer_ip6

    new_frame, report = rewrite_packet(
        frame, {src6: new_src6, dst6: new_dst6})

    # outer header: dst mapped, router src untouched
    assert new_frame[14 + 8:14 + 24] == _pton(router6)
    assert new_frame[14 + 24:14 + 40] == _pton(new_src6)
    # quoted header: both addresses mapped
    quote_off = 14 + 40 + 8
    assert new_frame[quote_off + 8:quote_off + 24] == _pton(new_src6)
    assert new_frame[quote_off + 24:quote_off + 40] == _pton(new_dst6)

    # ICMPv6 checksum validates with the new pseudo-header
    ic6_off = 14 + 40
    seg = new_frame[ic6_off:ic6_off + len(ic6)]
    pseudo = _pton(router6) + _pton(new_src6) + struct.pack('>I3xB', len(seg),
                                                            58)
    assert _independent_cksum(pseudo + seg) == 0

    # quoted UDP checksum equals an independent full-datagram checksum
    udp_mapped = struct.pack('>HHHH', 40000, 9, 8 + len(payload), 0) + payload
    pseudo = _pton(new_src6) + _pton(new_dst6) + struct.pack(
        '>I3xB', len(udp_mapped), 17)
    expected_sum = _independent_cksum(pseudo + udp_mapped) or 0xffff
    quoted_sum = struct.unpack(
        '>H', new_frame[quote_off + 40 + 6:quote_off + 40 + 8])[0]
    assert quoted_sum == expected_sum


def test_non_ip_frame_unchanged():
    frame = _eth(0x0806) + b'\x00' * 28  # ARP
    new_frame, report = rewrite_packet(frame, {'10.0.0.1': '198.51.100.1'})
    assert new_frame == bytes(frame)
    assert report.fixed == []
    assert any('0x0806' in e for e in report.notes)
