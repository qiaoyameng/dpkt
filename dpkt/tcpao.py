# -*- coding: utf-8 -*-
"""TCP Authentication Option verification (RFC 5925/RFC 5926)."""
from __future__ import absolute_import

import binascii
import hashlib
import hmac
import struct

from . import dpkt
from . import tcp

TCP_OPT_AO = tcp.TCP_OPT_AO

AO_HMAC_SHA1_96 = 'HMAC-SHA-1-96'
AO_HMAC_SHA1_96_DIGEST_LEN = 12
AO_SHA1_KEY_LEN = 20
AO_SENDER_TO_RECEIVER = 0
AO_RECEIVER_TO_SENDER = 1

AO_VERIFIED = 'verified'
AO_FAILED = 'failed'
AO_UNVERIFIABLE = 'unverifiable'
AO_NO_OPTION = 'missing_tcp_ao_option'
AO_NO_KEY = 'no_matching_mkt'
AO_NEED_CONTEXT = 'insufficient_context'
AO_INVALID_PACKET = 'invalid_packet'
AO_INVALID_MKT = 'invalid_mkt'
AO_UNSUPPORTED_ALGORITHM = 'unsupported_algorithm'
AO_MAC_MISMATCH = 'mac_mismatch'

_DIRECTION_LABELS = (
    b'TCP-AO sender-to-receiver key\x00',
    b'TCP-AO receiver-to-sender key\x00',
)


class TCPAOError(dpkt.Error):
    pass


class MasterKey(object):
    """A Master Key Tuple and the per-connection keying parameters."""

    def __init__(self, key, keyid, algorithm=AO_HMAC_SHA1_96, maclen=None,
                 sender_isn=None, receiver_isn=None, include_options=True):
        self.key = key
        self.keyid = keyid
        self.algorithm = algorithm
        self.maclen = maclen if maclen is not None else AO_HMAC_SHA1_96_DIGEST_LEN
        self.sender_isn = sender_isn
        self.receiver_isn = receiver_isn
        self.include_options = include_options


class VerificationResult(object):
    __slots__ = ('status', 'reason', 'detail', 'keyid', 'rnext_keyid', 'sne', 'direction')

    def __init__(self, status, reason=None, detail=None, keyid=None,
                 rnext_keyid=None, sne=None, direction=None):
        self.status = status
        self.reason = reason
        self.detail = detail
        self.keyid = keyid
        self.rnext_keyid = rnext_keyid
        self.sne = sne
        self.direction = direction

    def __bool__(self):
        return self.status == AO_VERIFIED

    __nonzero__ = __bool__


def _u32(value):
    return value & 0xffffffff


def derive_traffic_key(master_key, context, direction=0):
    """Derive a traffic key with the RFC 5926 counter-mode KDF."""
    if not isinstance(master_key, (bytes, bytearray)):
        raise TCPAOError('master key must be a byte string')
    key = bytes(master_key)
    if not key or len(key) > 80:
        raise TCPAOError('master key length must be between 1 and 80 bytes')
    if direction not in (0, 1):
        raise TCPAOError('direction must be 0 or 1')
    output = bytearray()
    counter = 1
    while len(output) < len(key):
        msg = struct.pack('>I', counter) + _DIRECTION_LABELS[direction] + bytes(context)
        block = hmac.new(key, msg, hashlib.sha1).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:len(key)])


def make_key_context(src_ip, dst_ip, sport, dport, sender_isn, receiver_isn):
    if len(src_ip) not in (4, 16) or len(src_ip) != len(dst_ip):
        raise TCPAOError('IP addresses must both be IPv4 or IPv6')
    return (src_ip + dst_ip + struct.pack('>HHII', sport, dport,
                                          _u32(sender_isn), _u32(receiver_isn)))


def find_ao_option(tcp_packet):
    offset = 20
    data_offset = (tcp_packet[12] >> 4) * 4
    while offset + 1 < data_offset:
        kind = tcp_packet[offset]
        if kind == 0:
            break
        if kind == 1:
            offset += 1
            continue
        length = tcp_packet[offset + 1]
        if length < 2 or offset + length > data_offset:
            raise TCPAOError('malformed TCP option')
        if kind == TCP_OPT_AO:
            if length < 4 or length - 4 != AO_HMAC_SHA1_96_DIGEST_LEN:
                raise TCPAOError('unsupported TCP-AO option length')
            return offset, length
        offset += length
    return None


def _parse_ip_packet(packet):
    if len(packet) < 20:
        raise TCPAOError('IP packet is truncated')
    version = packet[0] >> 4
    if version == 4:
        ihl = (packet[0] & 0x0f) * 4
        if ihl < 20 or len(packet) < ihl:
            raise TCPAOError('invalid IPv4 header length')
        if packet[9] != 6 or (packet[6] & 0x20 or struct.unpack('>H', packet[6:8])[0] & 0x1fff):
            raise TCPAOError('TCP-AO verification requires an unfragmented TCP segment')
        total_length = struct.unpack('>H', packet[2:4])[0]
        if total_length and total_length < ihl:
            raise TCPAOError('invalid IPv4 total length')
        end = total_length or len(packet)
        if end > len(packet):
            raise TCPAOError('truncated IPv4 packet')
        return {
            'family': 4,
            'src': packet[12:16],
            'dst': packet[16:20],
            'options': packet[20:ihl],
            'tcp_offset': ihl,
            'tcp_packet': packet[ihl:end],
        }
    if version == 6:
        if len(packet) < 40:
            raise TCPAOError('IPv6 packet is truncated')
        payload_length = struct.unpack('>H', packet[4:6])[0]
        payload_end = 40 + payload_length if payload_length else len(packet)
        if payload_end > len(packet):
            raise TCPAOError('truncated IPv6 packet')
        next_header = packet[6]
        extension_offset = 40
        while next_header != 6:
            if next_header not in (0, 43, 60):
                raise TCPAOError('TCP-AO verification requires TCP after supported IPv6 extension headers')
            if extension_offset + 2 > payload_end:
                raise TCPAOError('unsupported IPv6 extension header')
            current_header = next_header
            extension_length = (packet[extension_offset + 1] + 1) * 8
            next_header = packet[extension_offset]
            if current_header in (0, 60) and extension_length > 8:
                raise TCPAOError('invalid IPv6 options header length')
            extension_offset += extension_length
            if extension_offset > payload_end:
                raise TCPAOError('truncated IPv6 extension header')
        end = payload_end
        if end > len(packet):
            raise TCPAOError('truncated IPv6 packet')
        return {
            'family': 6,
            'src': packet[8:24],
            'dst': packet[24:40],
            'options': b'',
            'tcp_offset': extension_offset,
            'tcp_packet': packet[extension_offset:end],
        }
    raise TCPAOError('unsupported IP version')


def _pseudoheader(parsed, tcp_length):
    if parsed['family'] == 4:
        return struct.pack('>4s4sxBH', parsed['src'], parsed['dst'], 6, tcp_length)
    return struct.pack('>16s16sxBH', parsed['src'], parsed['dst'], 6, tcp_length)


def build_mac_input(parsed, tcp_packet, sne, include_tcp_options=True):
    if len(tcp_packet) < 20:
        raise TCPAOError('TCP packet is truncated')
    data_offset = (tcp_packet[12] >> 4) * 4
    if data_offset < 20 or data_offset > len(tcp_packet):
        raise TCPAOError('invalid TCP data offset')
    location = find_ao_option(tcp_packet)
    if location is None:
        raise TCPAOError('packet does not contain TCP-AO')
    option_offset, option_length = location
    mac_offset = option_offset + 4
    mutable = bytearray(tcp_packet)
    for index in range(mac_offset, mac_offset + option_length - 4):
        mutable[index] = 0
    if not include_tcp_options:
        canonical = bytearray(mutable[:20])
        canonical[12] = (5 << 4) | (tcp_packet[12] & 0x0f)
        canonical.extend(mutable[data_offset:])
        mutable = canonical
    return struct.pack('>I', _u32(sne)) + _pseudoheader(parsed, len(tcp_packet)) + bytes(mutable)


def calculate_mac(traffic_key, mac_input, maclen=AO_HMAC_SHA1_96_DIGEST_LEN):
    if maclen != AO_HMAC_SHA1_96_DIGEST_LEN:
        raise TCPAOError('only HMAC-SHA-1-96 is supported')
    return hmac.new(traffic_key, mac_input, hashlib.sha1).digest()[:maclen]


def verify_packet(packet, mkt_or_provider, sender_isn=None, receiver_isn=None,
                  direction=0, sne=None, state=None):
    """Verify a raw IPv4/IPv6 TCP-AO packet without modifying the input."""
    try:
        parsed = _parse_ip_packet(packet)
        tcp_packet = parsed['tcp_packet']
        location = find_ao_option(tcp_packet)
    except TCPAOError as error:
        return VerificationResult(AO_FAILED, reason=AO_INVALID_PACKET, detail=str(error))

    if location is None:
        return VerificationResult(AO_FAILED, reason=AO_NO_OPTION)
    option_offset, option_length = location
    keyid = tcp_packet[option_offset + 2]
    rnext_keyid = tcp_packet[option_offset + 3]
    expected_mac = tcp_packet[option_offset + 4:option_offset + option_length]

    mkt = mkt_or_provider
    if callable(mkt_or_provider):
        try:
            mkt = mkt_or_provider(keyid, parsed['src'], parsed['dst'],
                                  struct.unpack('>H', tcp_packet[0:2])[0],
                                  struct.unpack('>H', tcp_packet[2:4])[0])
        except Exception:
            mkt = None
    elif getattr(mkt, 'keyid', None) != keyid:
        mkt = None

    if mkt is None:
        return VerificationResult(AO_UNVERIFIABLE, reason=AO_NO_KEY,
                                  keyid=keyid, rnext_keyid=rnext_keyid)
    if mkt.algorithm != AO_HMAC_SHA1_96 or mkt.maclen != len(expected_mac):
        return VerificationResult(AO_UNVERIFIABLE, reason=AO_UNSUPPORTED_ALGORITHM,
                                  keyid=keyid, rnext_keyid=rnext_keyid)
    if sender_isn is None:
        sender_isn = mkt.sender_isn
    if receiver_isn is None:
        receiver_isn = mkt.receiver_isn
    seq = struct.unpack('>I', tcp_packet[4:8])[0]
    flags = tcp_packet[13]
    if sender_isn is None and flags & 0x02:
        sender_isn = seq
    if receiver_isn is None and (flags & 0x12) == 0x12:
        receiver_isn = _u32(struct.unpack('>I', tcp_packet[8:12])[0] - 1)
    elif receiver_isn is None and (flags & 0x02) and not (flags & 0x10):
        receiver_isn = 0
    if sender_isn is None or receiver_isn is None:
        return VerificationResult(AO_UNVERIFIABLE, reason=AO_NEED_CONTEXT, detail='both endpoint ISNs are required',
                                  keyid=keyid, rnext_keyid=rnext_keyid)

    if sne is None and state is not None:
        sne = state.sequence_number(direction, sender_isn, seq)
    if isinstance(sne, int) and not 0 <= sne <= 0xffffffff:
        return VerificationResult(AO_FAILED, reason=AO_INVALID_MKT,
                                  keyid=keyid, rnext_keyid=rnext_keyid)
    if sne is None:
        return VerificationResult(AO_UNVERIFIABLE, reason=AO_NEED_CONTEXT, detail='SNE is unavailable',
                                  keyid=keyid, rnext_keyid=rnext_keyid)

    try:
        context = make_key_context(parsed['src'], parsed['dst'],
                                   struct.unpack('>H', tcp_packet[0:2])[0],
                                   struct.unpack('>H', tcp_packet[2:4])[0],
                                   sender_isn, receiver_isn)
        traffic_key = derive_traffic_key(mkt.key, context, direction)
        mac_input = build_mac_input(parsed, tcp_packet, sne, mkt.include_options)
        actual_mac = calculate_mac(traffic_key, mac_input, len(expected_mac))
    except (TCPAOError, TypeError, ValueError, struct.error):
        return VerificationResult(AO_FAILED, reason=AO_INVALID_MKT, keyid=keyid, rnext_keyid=rnext_keyid)

    result = VerificationResult(AO_VERIFIED, keyid=keyid, rnext_keyid=rnext_keyid,
                                sne=_u32(sne), direction=direction)
    valid = hmac.compare_digest(actual_mac, expected_mac)
    if valid and state is not None:
        state.observe(direction, sender_isn, seq, result.sne)
    elif not valid:
        result.status = AO_FAILED
        result.reason = AO_MAC_MISMATCH
    return result


class SNEState(object):
    """Per-direction extended sequence-number tracker."""

    def __init__(self):
        self._state = {}

    def sequence_number(self, direction, sender_isn, seq):
        key = (direction, _u32(sender_isn))
        if key not in self._state:
            return None
        _, sne, highest = self._state[key]
        current_ext = (sne << 32) + highest
        forward_delta = _u32(seq - highest)
        if forward_delta < 0x80000000:
            candidate_ext = current_ext + forward_delta
        else:
            candidate_ext = current_ext - (0x100000000 - forward_delta)
            if candidate_ext < _u32(sender_isn):
                return None
        return candidate_ext >> 32

    def observe(self, direction, sender_isn, seq, sne):
        key = (direction, _u32(sender_isn))
        if key in self._state:
            _, current_sne, highest = self._state[key]
            delta = _u32(seq - highest)
            if delta == 0 or delta >= 0x80000000:
                return
            sne = (((current_sne << 32) + highest + delta) >> 32)
        self._state[key] = (_u32(sender_isn), _u32(sne), _u32(seq))

    def reset(self, direction, sender_isn, seq, sne=0):
        self.observe(direction, sender_isn, seq, sne)


def _test_tcp_packet(seq, ack, sport, dport, src_ip, dst_ip, payload=b'hi'):
    opts = (bytes([8, 10]) + b'TS1TS2' + bytes([1, 1, TCP_OPT_AO, 16, 7, 9]) +
            b'\x00' * 12 + b'\x01\x01')
    data_offset = ((20 + len(opts) + 3) // 4) << 4
    tcp_packet = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, data_offset,
                             0x18, 65535, 0, 0) + opts + payload
    if len(src_ip) == 4:
        ip_header = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp_packet),
                                0, 0, 64, 6, 0, src_ip, dst_ip)
    else:
        ip_header = struct.pack('>IHBB16s16s', 0x60000000, len(tcp_packet),
                                6, 64, src_ip, dst_ip)
    return ip_header + tcp_packet


def _test_sign(packet, mkt, sender_isn, receiver_isn, direction, sne,
               include_options=True):
    parsed = _parse_ip_packet(packet)
    tcp_packet = parsed['tcp_packet']
    option_offset, option_length = find_ao_option(tcp_packet)
    context = make_key_context(parsed['src'], parsed['dst'],
                               struct.unpack('>H', tcp_packet[0:2])[0],
                               struct.unpack('>H', tcp_packet[2:4])[0],
                               sender_isn, receiver_isn)
    traffic_key = derive_traffic_key(mkt, context, direction)
    mac_input = build_mac_input(parsed, tcp_packet, sne, include_options)
    mac = calculate_mac(traffic_key, mac_input, option_length - 4)
    mac_offset = parsed['tcp_offset'] + option_offset + 4
    return packet[:mac_offset] + mac + packet[mac_offset + len(mac):]


def _test_mac(packet):
    parsed = _parse_ip_packet(packet)
    tcp_packet = parsed['tcp_packet']
    option_offset, _ = find_ao_option(tcp_packet)
    return tcp_packet[option_offset + 4:option_offset + 16]


def test_hmac_sha1_96_public_vector():
    digest = calculate_mac(b'\x0b' * 20, b'Hi There')
    assert digest == b'\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6'


def test_derive_directional_traffic_keys():
    master_key = b'A' * 20
    context = make_key_context(b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02',
                               12345, 443, 0xfffffff0, 0x11223344)
    assert derive_traffic_key(master_key, context, AO_SENDER_TO_RECEIVER) == (
        b'\x3a\x31\x67\x74\xac\x57\x0b\xee\x77\xcc\x9d\xfc\x91\xb4\xb1\x6d'
        b'\x2d\x75\xa1\xcd'
    )
    assert derive_traffic_key(master_key, context, AO_RECEIVER_TO_SENDER) == (
        b'\x5f\xd2\x2d\x6f\x60\x04\x4e\xa3\x29\x6b\x9a\xce\x87\x49\x62\x62'
        b'\x1e\x59\x9b\xda'
    )


def test_verify_ipv4_both_directions_and_sne_wrap():
    master_key = b'A' * 20
    isn_a = 0xfffffff0
    isn_b = 0x11223344
    src_a = b'\x0a\x00\x00\x01'
    src_b = b'\x0a\x00\x00\x02'
    forward = _test_tcp_packet((isn_a + 1000) & 0xffffffff, isn_b + 1,
                               12345, 443, src_a, src_b)
    forward = _test_sign(forward, master_key, isn_a, isn_b, 0, 0)
    assert _test_mac(forward) == binascii.unhexlify('fb94f670c952e1e275064fa8')
    result = verify_packet(forward, MasterKey(master_key, 7, sender_isn=isn_a,
                                             receiver_isn=isn_b), sne=0)
    assert result.status == AO_VERIFIED
    assert result.keyid == 7
    assert result.rnext_keyid == 9

    reverse = _test_tcp_packet(isn_b + 1001, (isn_a + 1002) & 0xffffffff,
                               443, 12345, src_b, src_a)
    reverse = _test_sign(reverse, master_key, isn_b, isn_a, 1, 0)
    assert _test_mac(reverse) == binascii.unhexlify('d63eb1f5611523e918fd9e07')
    result = verify_packet(reverse, MasterKey(master_key, 7, sender_isn=isn_b,
                                             receiver_isn=isn_a),
                           direction=AO_RECEIVER_TO_SENDER, sne=0)
    assert result.status == AO_VERIFIED

    before = _test_tcp_packet(0xffffffff, isn_b + 1, 12345, 443, src_a, src_b)
    before = _test_sign(before, master_key, isn_a, isn_b, 0, 0)
    assert _test_mac(before) == binascii.unhexlify('37f0c87a7b4bb74dff3bc0d0')
    after = _test_tcp_packet(0, isn_b + 1, 12345, 443, src_a, src_b)
    after = _test_sign(after, master_key, isn_a, isn_b, 0, 1)
    assert _test_mac(after) == binascii.unhexlify('8418e34bee62ded652bcfc17')
    assert verify_packet(after, MasterKey(master_key, 7, sender_isn=isn_a,
                                         receiver_isn=isn_b),
                         sne=1).status == AO_VERIFIED
    assert verify_packet(after, MasterKey(master_key, 7, sender_isn=isn_a,
                                         receiver_isn=isn_b),
                         sne=0).status == AO_FAILED

    state = SNEState()
    state.reset(0, isn_a, 0xffffffff, 0)
    assert verify_packet(before, MasterKey(master_key, 7, sender_isn=isn_a,
                                          receiver_isn=isn_b),
                         state=state).sne == 0
    assert verify_packet(after, MasterKey(master_key, 7, sender_isn=isn_a,
                                         receiver_isn=isn_b),
                         state=state).sne == 1
    assert verify_packet(after, MasterKey(master_key, 7, sender_isn=isn_a,
                                         receiver_isn=isn_b),
                         state=state).sne == 1
    assert verify_packet(before, MasterKey(master_key, 7, sender_isn=isn_a,
                                          receiver_isn=isn_b),
                         state=state).sne == 0
    assert verify_packet(after, MasterKey(master_key, 7)).status == AO_UNVERIFIABLE


def test_verify_ipv6_and_mkt_option_policy():
    master_key = b'A' * 20
    isn_a = 0xfffffff0
    isn_b = 0x11223344
    src = b'\x20\x01\x0d\xb8\x00' + b'\x00' * 11
    dst = b'\x20\x01\x0d\xb8\x00' + b'\x00' * 10 + b'\x00\x02'
    tcp_packet = _test_tcp_packet((isn_a + 10) & 0xffffffff, isn_b + 1,
                                  12345, 443, src, dst)
    extension = bytes([6, 0, 0, 0, 0, 0, 0, 0])
    packet_with_extension = (
        struct.pack('>IHBB16s16s', 0x60000000, len(extension) + len(tcp_packet) - 40,
                    0, 64, src, dst) + extension + tcp_packet[40:]
    )
    packet_with_extension = _test_sign(packet_with_extension, master_key,
                                       isn_a, isn_b, 0, 0)
    packet_without_extension = _test_sign(tcp_packet, master_key, isn_a, isn_b, 0, 0)
    assert _test_mac(packet_with_extension) == _test_mac(packet_without_extension)
    assert _test_mac(packet_with_extension) == binascii.unhexlify('5471713dd7c5d53b3ec19c58')
    result = verify_packet(packet_with_extension,
                           MasterKey(master_key, 7, sender_isn=isn_a,
                                     receiver_isn=isn_b), sne=0)
    assert result.status == AO_VERIFIED

    excluded = _test_sign(tcp_packet, master_key, isn_a, isn_b, 0, 0, False)
    assert _test_mac(excluded) == binascii.unhexlify('a298327f46bf2d6cfce8344d')
    mkt = MasterKey(master_key, 7, sender_isn=isn_a, receiver_isn=isn_b,
                    include_options=False)
    assert verify_packet(excluded, mkt, sne=0).status == AO_VERIFIED
    assert verify_packet(excluded, MasterKey(master_key, 7, sender_isn=isn_a,
                                             receiver_isn=isn_b),
                         sne=0).status == AO_FAILED


def test_key_lookup_and_immutable_packet():
    master_key = b'A' * 20
    isn_a = 0xfffffff0
    isn_b = 0x11223344
    src = b'\x0a\x00\x00\x01'
    dst = b'\x0a\x00\x00\x02'
    packet = _test_tcp_packet(isn_a + 1, isn_b + 1, 12345, 443, src, dst)
    packet = _test_sign(packet, master_key, isn_a, isn_b, 0, 0)
    original = bytearray(packet)

    def provider(keyid, source, destination, sport, dport):
        assert (keyid, source, destination, sport, dport) == (7, src, dst, 12345, 443)
        return MasterKey(master_key, keyid, sender_isn=isn_a, receiver_isn=isn_b)

    result = verify_packet(packet, provider, sne=0)
    assert result.status == AO_VERIFIED
    assert (result.keyid, result.rnext_keyid) == (7, 9)
    assert bytes(original) == packet

    tampered = bytearray(packet)
    tampered[-1] ^= 0x01
    assert verify_packet(bytes(tampered), provider, sne=0).status == AO_FAILED
    assert verify_packet(packet, lambda *args: None, sne=0).status == AO_UNVERIFIABLE
