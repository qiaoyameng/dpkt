# -*- coding: utf-8 -*-
"""TCP Authentication Option (TCP-AO) offline verification.

Implements offline segment verification for the TCP Authentication Option
as specified by RFC 5925 (TCP-AO) and RFC 5926 (cryptographic algorithms).
Only the HMAC-SHA-1-96 algorithm is supported in this version.

The verifier is stateful: it is fed captured segments in capture order,
learns the connection ISNs from the TCP handshake, tracks the per-direction
Sequence Number Extension (SNE) across sequence number wraparound, and
follows key rotation through the KeyID / RNextKeyID fields of the TCP-AO
option.  When the handshake (or any other required context) is missing,
segments are reported as UNVERIFIABLE; the verifier never guesses an SNE
or ISN in order to report success.

Master keys are supplied by the caller through a key source callback,
looked up by connection identity and KeyID.  Verification never modifies
the packet under inspection and never emits master or traffic key
material in diagnostic output.

Example:
    import dpkt
    from dpkt import tcpao

    mkt = tcpao.MasterKeyTuple(key_id=1, master_key=b"...")
    verifier = tcpao.AOVerifier(lambda conn_id, key_id: mkt if key_id == 1 else None)
    result = verifier.verify(pkt)  # dpkt.ip.IP / dpkt.ip6.IP6 / dpkt.ethernet.Ethernet
    assert result.status == tcpao.VERIFIED
"""
from __future__ import absolute_import
from __future__ import print_function

import binascii
import hashlib
import hmac
import struct

from . import dpkt
from . import ethernet
from . import ip
from . import ip6
from . import tcp
from .compat import compat_ord

TCP_OPT_AO = 29  # TCP Authentication Option, RFC 5925

# verification statuses
VERIFIED = 'verified'
FAILED = 'failed'
UNVERIFIABLE = 'unverifiable'

_IP_PROTO_TCP = 6
_HALF_SEQ_SPACE = 0x80000000


class HMAC_SHA1_96(object):
    """HMAC-SHA-1-96 algorithm as specified by RFC 5926, Section 3.1."""

    name = 'HMAC-SHA-1-96'
    mac_length = 12          # 96-bit truncated MAC
    traffic_key_length = 20  # 160-bit traffic key

    @staticmethod
    def kdf(master_key, context):
        """Key Derivation Function of RFC 5926, Section 3.1.1.

        KDF(master_key, context, outputlength) = T1 || T2 || ... where
        T(i) = MAC(master_key, i || context || outputlength), i is one
        octet and outputlength is two octets, the key length in bits.
        """
        output_length = HMAC_SHA1_96.traffic_key_length
        result = b''
        counter = 1
        while len(result) < output_length:
            data = struct.pack('B', counter) + context + struct.pack('!H', output_length * 8)
            result += hmac.new(master_key, data, hashlib.sha1).digest()
            counter += 1
        return result[:output_length]

    @staticmethod
    def mac(traffic_key, data):
        """HMAC-SHA-1 truncated to 96 bits (RFC 5926, Section 3.1)."""
        return hmac.new(traffic_key, data, hashlib.sha1).digest()[:HMAC_SHA1_96.mac_length]


class MasterKeyTuple(object):
    """Master Key Tuple (RFC 5925, Section 4.1), offline-verification subset.

    Attributes:
        key_id: KeyID selecting this MKT (0-255).
        master_key: master key bytes; never included in diagnostic output.
        algorithm: algorithm descriptor; only HMAC_SHA1_96 is supported.
        include_options: True when TCP options other than TCP-AO are covered
            by the MAC (the MKT "TCP option flag" of RFC 5925, Section 4.1).
    """

    def __init__(self, key_id, master_key, algorithm=HMAC_SHA1_96, include_options=True):
        if not 0 <= key_id <= 255:
            raise ValueError('key_id must be in range 0..255')
        self.key_id = key_id
        self.master_key = bytes(master_key)
        self.algorithm = algorithm
        self.include_options = bool(include_options)

    def __repr__(self):
        return 'MasterKeyTuple(key_id=%d, algorithm=%s, include_options=%r)' % (
            self.key_id, self.algorithm.name, self.include_options)


class AOOption(object):
    """Parsed TCP-AO option fields (offsets relative to the TCP segment)."""

    __slots__ = ('offset', 'length', 'key_id', 'rnext_key_id', 'mac')

    def __init__(self, offset, length, key_id, rnext_key_id, mac):
        self.offset = offset
        self.length = length
        self.key_id = key_id
        self.rnext_key_id = rnext_key_id
        self.mac = mac

    def __repr__(self):
        return 'AOOption(offset=%d, length=%d, key_id=%d, rnext_key_id=%d)' % (
            self.offset, self.length, self.key_id, self.rnext_key_id)


def parse_ao_option(tcp_bytes):
    """Locate and parse the TCP-AO option in a raw TCP segment.

    Returns an AOOption, or None if no well-formed TCP-AO option is present.
    """
    if len(tcp_bytes) < 20:
        return None
    hdr_len = (compat_ord(tcp_bytes[12]) >> 4) << 2
    if hdr_len < 20 or hdr_len > len(tcp_bytes):
        return None
    pos = 20
    while pos < hdr_len:
        kind = compat_ord(tcp_bytes[pos])
        if kind == tcp.TCP_OPT_EOL:
            break
        if kind == tcp.TCP_OPT_NOP:
            pos += 1
            continue
        if pos + 2 > hdr_len:
            break
        length = compat_ord(tcp_bytes[pos + 1])
        if length < 2 or pos + length > hdr_len:
            break
        if kind == TCP_OPT_AO:
            if length < 4:
                return None
            return AOOption(offset=pos, length=length,
                            key_id=compat_ord(tcp_bytes[pos + 2]),
                            rnext_key_id=compat_ord(tcp_bytes[pos + 3]),
                            mac=bytes(tcp_bytes[pos + 4:pos + length]))
        pos += length
    return None


def kdf_context(source_isn, dest_isn):
    """KDF context of RFC 5925, Section 6.2: sender ISN || receiver ISN.

    dest_isn is zero when the receiver ISN is not yet known (initial SYN).
    """
    return struct.pack('!II', source_isn & 0xffffffff, dest_isn & 0xffffffff)


def derive_traffic_key(master_key, context, algorithm=HMAC_SHA1_96):
    """Derive a traffic key from a master key (RFC 5926, Section 3.1.1)."""
    return algorithm.kdf(master_key, context)


def build_mac_input(ip_version, src, dst, sne, tcp_bytes, include_options,
                    algorithm=HMAC_SHA1_96):
    """Build the MAC input of RFC 5925, Section 5.1 for one segment.

    The input is the TCP-AO pseudoheader (which carries the SNE), the TCP
    header with the checksum zeroed, the TCP options with the TCP-AO MAC
    field zeroed (and all other options zeroed when the MKT excludes them),
    and the segment payload.  tcp_bytes is not modified.
    """
    if len(tcp_bytes) < 20:
        raise dpkt.UnpackError('truncated TCP header')
    hdr_len = (compat_ord(tcp_bytes[12]) >> 4) << 2
    if hdr_len < 20 or hdr_len > len(tcp_bytes):
        raise dpkt.UnpackError('invalid TCP data offset')
    header = bytearray(tcp_bytes[:hdr_len])
    # the TCP checksum is zeroed for the MAC computation
    header[16] = 0
    header[17] = 0
    ao = parse_ao_option(tcp_bytes)
    if not include_options:
        # zero every option byte, then restore the TCP-AO option itself
        for i in range(20, hdr_len):
            header[i] = 0
        if ao is not None:
            for i in range(ao.offset, ao.offset + ao.length):
                header[i] = compat_ord(tcp_bytes[i])
    if ao is not None:
        # the MAC field of the TCP-AO option is always zeroed
        for i in range(ao.offset + 4, ao.offset + ao.length):
            header[i] = 0
    tcp_len = len(tcp_bytes)
    if ip_version == 4:
        pseudoheader = bytes(src) + bytes(dst) + struct.pack('!IHBB', sne, tcp_len, 0, _IP_PROTO_TCP)
    elif ip_version == 6:
        pseudoheader = (bytes(src) + bytes(dst) + struct.pack('!II', sne, tcp_len) +
                        b'\x00' * 3 + struct.pack('!B', _IP_PROTO_TCP))
    else:
        raise dpkt.UnpackError('unsupported IP version')
    return pseudoheader + bytes(header) + bytes(tcp_bytes[hdr_len:])


class VerificationResult(object):
    """Outcome of verifying a single segment.

    Carries diagnostic context only; never any master or traffic key material.

    Attributes:
        status: VERIFIED, FAILED or UNVERIFIABLE.
        reason: human-readable explanation of the outcome.
        connection: normalized connection identifier
            (ip_version, (addr, port), (addr, port)) with sorted endpoints.
        direction: 0 or 1, relative to the sorted connection endpoints.
        key_id: KeyID of the segment's TCP-AO option, when present.
        rnext_key_id: RNextKeyID of the option (key rotation hint,
            RFC 5925, Section 7.1), when present.
        sne: Sequence Number Extension used for this segment.
    """

    __slots__ = ('status', 'reason', 'connection', 'direction',
                 'key_id', 'rnext_key_id', 'sne')

    def __init__(self, status, reason='', connection=None, direction=None,
                 key_id=None, rnext_key_id=None, sne=None):
        self.status = status
        self.reason = reason
        self.connection = connection
        self.direction = direction
        self.key_id = key_id
        self.rnext_key_id = rnext_key_id
        self.sne = sne

    @property
    def ok(self):
        return self.status == VERIFIED

    def __repr__(self):
        return ('VerificationResult(status=%r, direction=%r, key_id=%r, '
                'rnext_key_id=%r, sne=%r, reason=%r)' % (
                    self.status, self.direction, self.key_id,
                    self.rnext_key_id, self.sne, self.reason))


class _DirectionState(object):
    __slots__ = ('isn', 'sne', 'max_ext')

    def __init__(self):
        self.isn = None      # initial sequence number learned from a SYN
        self.sne = 0         # current sequence number extension
        self.max_ext = None  # highest extended sequence number observed


def _connection_id(ip_version, src, sport, dst, dport):
    """Direction-independent connection identity; returns (conn_id, direction)."""
    a = (bytes(src), sport)
    b = (bytes(dst), dport)
    if a <= b:
        return (ip_version, a, b), 0
    return (ip_version, b, a), 1


def _unwrap_tcp(pkt):
    """Extract (ip_version, src, dst, tcp.TCP) from a parsed packet."""
    if isinstance(pkt, ethernet.Ethernet):
        pkt = pkt.data
    if isinstance(pkt, ip.IP):
        if pkt.p != _IP_PROTO_TCP or not isinstance(pkt.data, tcp.TCP):
            raise dpkt.UnpackError('not a TCP/IPv4 packet')
        return 4, pkt.src, pkt.dst, pkt.data
    if isinstance(pkt, ip6.IP6):
        if pkt.nxt != _IP_PROTO_TCP or not isinstance(pkt.data, tcp.TCP):
            raise dpkt.UnpackError('not a TCP/IPv6 packet')
        return 6, pkt.src, pkt.dst, pkt.data
    raise dpkt.UnpackError('unsupported packet type')


class AOVerifier(object):
    """Stateful offline TCP-AO verifier.

    Segments are verified in capture order.  The handshake ISNs are learned
    from observed SYN segments; without them the traffic keys cannot be
    derived and segments are reported UNVERIFIABLE.

    key_source: callable(connection_id, key_id) -> MasterKeyTuple or None.
        connection_id is (ip_version, (addr, port), (addr, port)) with the
        two endpoints sorted, so both directions map to the same identity.
    """

    def __init__(self, key_source):
        self._key_source = key_source
        self._connections = {}

    def verify(self, pkt):
        """Verify one captured segment; returns a VerificationResult."""
        try:
            ip_version, src, dst, seg = _unwrap_tcp(pkt)
        except dpkt.UnpackError as exc:
            return VerificationResult(UNVERIFIABLE, reason=str(exc))

        conn_id, direction = _connection_id(ip_version, src, seg.sport, dst, seg.dport)
        state = self._connections.get(conn_id)
        if state is None:
            state = [_DirectionState(), _DirectionState()]
            self._connections[conn_id] = state
        send = state[direction]
        peer = state[1 - direction]
        seq = seg.seq
        flags = seg.flags

        if flags & tcp.TH_SYN:
            if send.isn is not None and send.isn != seq:
                # new incarnation of the connection; drop stale state
                state = [_DirectionState(), _DirectionState()]
                self._connections[conn_id] = state
                send = state[direction]
                peer = state[1 - direction]
            send.isn = seq
            send.sne = 0
            send.max_ext = seq
            seg_sne = 0
        else:
            seg_sne = send.sne
            if send.max_ext is not None:
                last_seq = send.max_ext & 0xffffffff
                diff = (seq - last_seq) & 0xffffffff
                if diff < _HALF_SEQ_SPACE:
                    # in-order segment; a numerically smaller sequence number
                    # means the 32-bit sequence space wrapped (RFC 5925, 6.1)
                    if seq < last_seq:
                        send.sne += 1
                        seg_sne = send.sne
                    send.max_ext = (send.sne << 32) | seq
                elif seq > last_seq and seg_sne > 0:
                    # old segment transmitted before the wrap
                    seg_sne = send.sne - 1

        seg_bytes = bytes(seg)
        ao = parse_ao_option(seg_bytes)
        if ao is None:
            return VerificationResult(UNVERIFIABLE, 'no TCP-AO option present',
                                      conn_id, direction, sne=seg_sne)
        mkt = self._key_source(conn_id, ao.key_id)
        if mkt is None:
            return VerificationResult(UNVERIFIABLE,
                                      'no MKT provisioned for KeyID %d' % ao.key_id,
                                      conn_id, direction, ao.key_id, ao.rnext_key_id, seg_sne)
        alg = mkt.algorithm
        if ao.length != 4 + alg.mac_length:
            return VerificationResult(UNVERIFIABLE,
                                      'AO option length %d does not match %s MAC length' % (
                                          ao.length, alg.name),
                                      conn_id, direction, ao.key_id, ao.rnext_key_id, seg_sne)
        if send.isn is None:
            return VerificationResult(UNVERIFIABLE,
                                      'sender ISN unknown (SYN not observed)',
                                      conn_id, direction, ao.key_id, ao.rnext_key_id, seg_sne)
        if peer.isn is None:
            if flags & tcp.TH_SYN and not flags & tcp.TH_ACK:
                # initial SYN: the peer ISN is not yet known, RFC 5925
                # Section 6.2 uses zero in the KDF context
                dest_isn = 0
            else:
                return VerificationResult(UNVERIFIABLE,
                                          'peer ISN unknown (handshake not observed)',
                                          conn_id, direction, ao.key_id, ao.rnext_key_id, seg_sne)
        else:
            dest_isn = peer.isn

        traffic_key = derive_traffic_key(mkt.master_key, kdf_context(send.isn, dest_isn), alg)
        try:
            mac_input = build_mac_input(ip_version, src, dst, seg_sne, seg_bytes,
                                        mkt.include_options, alg)
        except dpkt.UnpackError as exc:
            return VerificationResult(UNVERIFIABLE, str(exc),
                                      conn_id, direction, ao.key_id, ao.rnext_key_id, seg_sne)
        expected = alg.mac(traffic_key, mac_input)
        if hmac.compare_digest(expected, ao.mac):
            return VerificationResult(VERIFIED, 'MAC verified',
                                      conn_id, direction, ao.key_id, ao.rnext_key_id, seg_sne)
        return VerificationResult(FAILED, 'MAC mismatch',
                                  conn_id, direction, ao.key_id, ao.rnext_key_id, seg_sne)


# ---------------------------------------------------------------------------
# Tests
#
# The signer helpers below build TCP-AO segments with the module's public
# primitives (KDF, MAC input construction) so the verifier can be exercised
# end to end with fixed keys: public algorithm vectors, sequence number
# wraparound, both connection directions and key rotation.

_TEST_MASTER_KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14'
_TEST_MASTER_KEY_2 = b'\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3'

_A_ADDR = b'\x0a\x00\x00\x01'
_B_ADDR = b'\x0a\x00\x00\x02'
_A_PORT = 40000
_B_PORT = 179
_A_ISN = 1000
_B_ISN = 5000

_A_ADDR6 = binascii.unhexlify(b'20010db8000000000000000000000001')
_B_ADDR6 = binascii.unhexlify(b'20010db8000000000000000000000002')


def _ao_option_bytes(key_id, rnext_key_id, mac):
    return struct.pack('BBBB', TCP_OPT_AO, 4 + len(mac), key_id, rnext_key_id) + mac


def _build_segment(sport, dport, seq, ack, flags, key_id=5, rnext_key_id=5,
                   payload=b'', extra_opts=b'', mac=b'\x00' * 12):
    opts = extra_opts + _ao_option_bytes(key_id, rnext_key_id, mac)
    opts += b'\x01' * ((-len(opts)) % 4)  # NOP padding to a 4-byte boundary
    seg = tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, win=64240)
    seg.off = (tcp.TCP.__hdr_len__ + len(opts)) // 4
    seg.opts = opts
    seg.data = payload
    return seg


def _sign_segment(ip_version, src, dst, seg, mkt, source_isn, dest_isn, sne):
    seg_bytes = bytes(seg)
    ao = parse_ao_option(seg_bytes)
    assert ao is not None
    traffic_key = derive_traffic_key(mkt.master_key, kdf_context(source_isn, dest_isn),
                                     mkt.algorithm)
    mac_input = build_mac_input(ip_version, src, dst, sne, seg_bytes,
                                mkt.include_options, mkt.algorithm)
    mac = mkt.algorithm.mac(traffic_key, mac_input)
    signed = seg_bytes[:ao.offset + 4] + mac + seg_bytes[ao.offset + 4 + len(mac):]
    return tcp.TCP(signed)


def _ip4(src, dst, seg):
    return ip.IP(src=src, dst=dst, p=_IP_PROTO_TCP, data=seg)


def _ip6(src, dst, seg):
    return ip6.IP6(src=src, dst=dst, nxt=_IP_PROTO_TCP, hlim=64, data=seg)


def _key_source(mkts):
    def lookup(conn_id, key_id):
        return mkts.get(key_id)
    return lookup


def _signed_handshake(mkt, key_id=5, rnext_key_id=5, a_isn=_A_ISN, b_isn=_B_ISN):
    syn = _sign_segment(4, _A_ADDR, _B_ADDR,
                        _build_segment(_A_PORT, _B_PORT, a_isn, 0, tcp.TH_SYN,
                                       key_id=key_id, rnext_key_id=rnext_key_id),
                        mkt, a_isn, 0, 0)
    synack = _sign_segment(4, _B_ADDR, _A_ADDR,
                           _build_segment(_B_PORT, _A_PORT, b_isn, (a_isn + 1) & 0xffffffff,
                                          tcp.TH_SYN | tcp.TH_ACK,
                                          key_id=key_id, rnext_key_id=rnext_key_id),
                           mkt, b_isn, a_isn, 0)
    return syn, synack


def _feed_handshake(verifier, mkt, **kwargs):
    syn, synack = _signed_handshake(mkt, **kwargs)
    assert verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, syn)))).status == VERIFIED
    assert verifier.verify(ip.IP(bytes(_ip4(_B_ADDR, _A_ADDR, synack)))).status == VERIFIED


def test_hmac_sha1_96_public_vector():
    # RFC 2202 test case 1, the public vector anchoring the HMAC-SHA-1-96
    # MAC of RFC 5926: HMAC-SHA-1(0x0b * 20, "Hi There"), truncated to 96 bits.
    mac = HMAC_SHA1_96.mac(b'\x0b' * 20, b'Hi There')
    assert binascii.hexlify(mac) == b'b617318655057264e28bc0b6'


def test_kdf_construction():
    # RFC 5926, Section 3.1.1: T1 = HMAC-SHA-1(master_key, 0x01 || context || 160)
    context = kdf_context(_A_ISN, _B_ISN)
    assert context == struct.pack('!II', _A_ISN, _B_ISN)
    expected = hmac.new(_TEST_MASTER_KEY, b'\x01' + context + struct.pack('!H', 160),
                        hashlib.sha1).digest()
    traffic_key = derive_traffic_key(_TEST_MASTER_KEY, context)
    assert traffic_key == expected
    assert len(traffic_key) == HMAC_SHA1_96.traffic_key_length


def test_fixed_vector():
    # Frozen regression vector: fixed key, fixed connection, fixed segment.
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)
    seg = _build_segment(_A_PORT, _B_PORT, _A_ISN + 1, _B_ISN + 1,
                         tcp.TH_ACK | tcp.TH_PUSH, payload=b'hello tcp-ao')
    signed = _sign_segment(4, _A_ADDR, _B_ADDR, seg, mkt, _A_ISN, _B_ISN, 0)
    ao = parse_ao_option(bytes(signed))
    assert binascii.hexlify(ao.mac) == b'ec696c1e0723bfc8300b3b0f'

    # Independent reconstruction of the MAC input per RFC 5925, Section 5.1:
    # pseudoheader with SNE, checksum zeroed, TCP-AO MAC field zeroed.
    seg_bytes = bytes(seg)
    traffic_key = hmac.new(_TEST_MASTER_KEY,
                           b'\x01' + struct.pack('!II', _A_ISN, _B_ISN) + struct.pack('!H', 160),
                           hashlib.sha1).digest()
    hdr = bytearray(seg_bytes[:36])
    hdr[16] = hdr[17] = 0
    hdr[24:36] = b'\x00' * 12
    pseudoheader = _A_ADDR + _B_ADDR + struct.pack('!IHBB', 0, len(seg_bytes), 0, 6)
    expected = hmac.new(traffic_key, pseudoheader + bytes(hdr) + seg_bytes[36:],
                        hashlib.sha1).digest()[:12]
    assert ao.mac == expected


def test_ipv4_connection_both_directions():
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)
    verifier = AOVerifier(_key_source({5: mkt}))

    syn, synack = _signed_handshake(mkt)
    data_ab = _sign_segment(4, _A_ADDR, _B_ADDR,
                            _build_segment(_A_PORT, _B_PORT, _A_ISN + 1, _B_ISN + 1,
                                           tcp.TH_ACK | tcp.TH_PUSH, payload=b'hello tcp-ao'),
                            mkt, _A_ISN, _B_ISN, 0)
    data_ba = _sign_segment(4, _B_ADDR, _A_ADDR,
                            _build_segment(_B_PORT, _A_PORT, _B_ISN + 1, _A_ISN + 13,
                                           tcp.TH_ACK | tcp.TH_PUSH, payload=b'reply'),
                            mkt, _B_ISN, _A_ISN, 0)

    r_syn = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, syn))))
    assert r_syn.status == VERIFIED
    assert r_syn.direction == 0 and r_syn.key_id == 5 and r_syn.sne == 0

    r_synack = verifier.verify(ip.IP(bytes(_ip4(_B_ADDR, _A_ADDR, synack))))
    assert r_synack.status == VERIFIED and r_synack.direction == 1

    r_ab = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, data_ab))))
    assert r_ab.status == VERIFIED and r_ab.direction == 0 and r_ab.ok

    # also exercise the Ethernet unwrap path for the reverse direction
    eth = ethernet.Ethernet(src=b'\x00' * 6, dst=b'\x00' * 6,
                          type=ethernet.ETH_TYPE_IP,
                          data=ip.IP(bytes(_ip4(_B_ADDR, _A_ADDR, data_ba))))
    r_ba = verifier.verify(eth)
    assert r_ba.status == VERIFIED and r_ba.direction == 1


def test_ipv6_connection():
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)
    verifier = AOVerifier(_key_source({5: mkt}))

    syn = _sign_segment(6, _A_ADDR6, _B_ADDR6,
                        _build_segment(_A_PORT, _B_PORT, _A_ISN, 0, tcp.TH_SYN),
                        mkt, _A_ISN, 0, 0)
    synack = _sign_segment(6, _B_ADDR6, _A_ADDR6,
                           _build_segment(_B_PORT, _A_PORT, _B_ISN, _A_ISN + 1,
                                          tcp.TH_SYN | tcp.TH_ACK),
                           mkt, _B_ISN, _A_ISN, 0)
    data_ab = _sign_segment(6, _A_ADDR6, _B_ADDR6,
                            _build_segment(_A_PORT, _B_PORT, _A_ISN + 1, _B_ISN + 1,
                                           tcp.TH_ACK | tcp.TH_PUSH, payload=b'ipv6 ao'),
                            mkt, _A_ISN, _B_ISN, 0)
    data_ba = _sign_segment(6, _B_ADDR6, _A_ADDR6,
                            _build_segment(_B_PORT, _A_PORT, _B_ISN + 1, _A_ISN + 9,
                                           tcp.TH_ACK | tcp.TH_PUSH, payload=b'v6 reply'),
                            mkt, _B_ISN, _A_ISN, 0)

    assert verifier.verify(ip6.IP6(bytes(_ip6(_A_ADDR6, _B_ADDR6, syn)))).status == VERIFIED
    assert verifier.verify(ip6.IP6(bytes(_ip6(_B_ADDR6, _A_ADDR6, synack)))).status == VERIFIED
    assert verifier.verify(ip6.IP6(bytes(_ip6(_A_ADDR6, _B_ADDR6, data_ab)))).status == VERIFIED
    assert verifier.verify(ip6.IP6(bytes(_ip6(_B_ADDR6, _A_ADDR6, data_ba)))).status == VERIFIED


def test_sequence_number_wraparound():
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)
    verifier = AOVerifier(_key_source({5: mkt}))
    a_isn = 0xfffffff0
    b_isn = 7000

    syn, synack = _signed_handshake(mkt, a_isn=a_isn, b_isn=b_isn)
    # last segment before the wrap: seq 0xfffffff1, 32 bytes of payload
    pre = _sign_segment(4, _A_ADDR, _B_ADDR,
                        _build_segment(_A_PORT, _B_PORT, 0xfffffff1, b_isn + 1,
                                       tcp.TH_ACK | tcp.TH_PUSH, payload=b'x' * 32),
                        mkt, a_isn, b_isn, 0)
    # first segment after the wrap: seq (0xfffffff1 + 32) mod 2**32 = 0x11, SNE 1
    post = _sign_segment(4, _A_ADDR, _B_ADDR,
                         _build_segment(_A_PORT, _B_PORT, 0x11, b_isn + 1,
                                        tcp.TH_ACK | tcp.TH_PUSH, payload=b'after wrap'),
                         mkt, a_isn, b_isn, 1)
    # the same post-wrap segment signed with a wrong (guessed) SNE must fail
    bad_sne = _sign_segment(4, _A_ADDR, _B_ADDR,
                            _build_segment(_A_PORT, _B_PORT, 0x11, b_isn + 1,
                                           tcp.TH_ACK | tcp.TH_PUSH, payload=b'after wrap'),
                            mkt, a_isn, b_isn, 0)

    assert verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, syn)))).status == VERIFIED
    assert verifier.verify(ip.IP(bytes(_ip4(_B_ADDR, _A_ADDR, synack)))).status == VERIFIED
    r_pre = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, pre))))
    assert r_pre.status == VERIFIED and r_pre.sne == 0
    r_post = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, post))))
    assert r_post.status == VERIFIED and r_post.sne == 1
    r_bad = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, bad_sne))))
    assert r_bad.status == FAILED


def test_key_rotation_hint():
    mkt1 = MasterKeyTuple(key_id=1, master_key=_TEST_MASTER_KEY)
    mkt2 = MasterKeyTuple(key_id=2, master_key=_TEST_MASTER_KEY_2)
    verifier = AOVerifier(_key_source({1: mkt1, 2: mkt2}))

    syn, synack = _signed_handshake(mkt1, key_id=1, rnext_key_id=1)
    # A signals it wants B to switch to KeyID 2 (RNextKeyID rotation hint)
    data1 = _sign_segment(4, _A_ADDR, _B_ADDR,
                          _build_segment(_A_PORT, _B_PORT, _A_ISN + 1, _B_ISN + 1,
                                         tcp.TH_ACK, key_id=1, rnext_key_id=2),
                          mkt1, _A_ISN, _B_ISN, 0)
    # B rotated to the new key
    data2 = _sign_segment(4, _B_ADDR, _A_ADDR,
                          _build_segment(_B_PORT, _A_PORT, _B_ISN + 1, _A_ISN + 1,
                                         tcp.TH_ACK, key_id=2, rnext_key_id=2),
                          mkt2, _B_ISN, _A_ISN, 0)

    assert verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, syn)))).status == VERIFIED
    assert verifier.verify(ip.IP(bytes(_ip4(_B_ADDR, _A_ADDR, synack)))).status == VERIFIED
    r1 = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, data1))))
    assert r1.status == VERIFIED
    assert r1.key_id == 1 and r1.rnext_key_id == 2
    r2 = verifier.verify(ip.IP(bytes(_ip4(_B_ADDR, _A_ADDR, data2))))
    assert r2.status == VERIFIED and r2.key_id == 2


def test_missing_handshake_is_unverifiable():
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)

    # capture starts mid-connection: no SYN observed in either direction
    verifier = AOVerifier(_key_source({5: mkt}))
    data = _sign_segment(4, _A_ADDR, _B_ADDR,
                         _build_segment(_A_PORT, _B_PORT, _A_ISN + 1, _B_ISN + 1,
                                        tcp.TH_ACK | tcp.TH_PUSH, payload=b'mid-stream'),
                         mkt, _A_ISN, _B_ISN, 0)
    result = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, data))))
    assert result.status == UNVERIFIABLE
    assert not result.ok

    # SYN-ACK observed without the SYN: the peer ISN is unknown, so the
    # verifier must not guess context and report success
    verifier = AOVerifier(_key_source({5: mkt}))
    _, synack = _signed_handshake(mkt)
    result = verifier.verify(ip.IP(bytes(_ip4(_B_ADDR, _A_ADDR, synack))))
    assert result.status == UNVERIFIABLE

    # segment without a TCP-AO option
    verifier = AOVerifier(_key_source({5: mkt}))
    plain = tcp.TCP(sport=_A_PORT, dport=_B_PORT, seq=_A_ISN, flags=tcp.TH_SYN)
    result = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, plain))))
    assert result.status == UNVERIFIABLE


def test_unknown_key_id_is_unverifiable():
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)
    verifier = AOVerifier(_key_source({5: mkt}))
    syn = _sign_segment(4, _A_ADDR, _B_ADDR,
                        _build_segment(_A_PORT, _B_PORT, _A_ISN, 0, tcp.TH_SYN,
                                       key_id=9, rnext_key_id=9),
                        mkt, _A_ISN, 0, 0)
    result = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, syn))))
    assert result.status == UNVERIFIABLE
    assert result.key_id == 9


def test_tampered_segment_fails():
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)
    verifier = AOVerifier(_key_source({5: mkt}))
    _feed_handshake(verifier, mkt)

    data = _sign_segment(4, _A_ADDR, _B_ADDR,
                         _build_segment(_A_PORT, _B_PORT, _A_ISN + 1, _B_ISN + 1,
                                        tcp.TH_ACK | tcp.TH_PUSH, payload=b'authentic'),
                         mkt, _A_ISN, _B_ISN, 0)
    raw = bytearray(bytes(_ip4(_A_ADDR, _B_ADDR, data)))
    raw[-1] ^= 0xff  # flip the last payload byte
    result = verifier.verify(ip.IP(bytes(raw)))
    assert result.status == FAILED
    assert not result.ok


def test_option_inclusion_follows_mkt():
    ts_option = struct.pack('BB', tcp.TCP_OPT_TIMESTAMP, 10) + b'\x01\x02\x03\x04\x05\x06\x07\x08'
    mkt_inc = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY, include_options=True)
    mkt_exc = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY, include_options=False)

    # segment signed with options excluded from the MAC
    data = _sign_segment(4, _A_ADDR, _B_ADDR,
                         _build_segment(_A_PORT, _B_PORT, _A_ISN + 1, _B_ISN + 1,
                                        tcp.TH_ACK | tcp.TH_PUSH, payload=b'opts',
                                        extra_opts=ts_option),
                         mkt_exc, _A_ISN, _B_ISN, 0)
    raw = bytearray(bytes(data))
    raw[22] ^= 0xff  # flip a byte of the timestamp option value
    tampered = tcp.TCP(bytes(raw))

    # MKT excluding options: the tampered option is zeroed, MAC still verifies
    verifier = AOVerifier(_key_source({5: mkt_exc}))
    _feed_handshake(verifier, mkt_exc)
    assert verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, data)))).status == VERIFIED
    assert verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, tampered)))).status == VERIFIED

    # MKT including options: the same tampering breaks the MAC
    verifier = AOVerifier(_key_source({5: mkt_inc}))
    _feed_handshake(verifier, mkt_inc)
    assert verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, tampered)))).status == FAILED


def test_verify_does_not_modify_packet():
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)
    verifier = AOVerifier(_key_source({5: mkt}))
    syn, _ = _signed_handshake(mkt)
    pkt = ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, syn)))
    before = bytes(pkt)
    opts_before = pkt.tcp.opts
    verifier.verify(pkt)
    assert bytes(pkt) == before
    assert pkt.tcp.opts == opts_before


def test_no_key_material_in_diagnostics():
    mkt = MasterKeyTuple(key_id=5, master_key=_TEST_MASTER_KEY)
    verifier = AOVerifier(_key_source({5: mkt}))
    syn, _ = _signed_handshake(mkt)
    result = verifier.verify(ip.IP(bytes(_ip4(_A_ADDR, _B_ADDR, syn))))
    assert result.status == VERIFIED
    traffic_key = derive_traffic_key(mkt.master_key, kdf_context(_A_ISN, 0))
    for text in (repr(mkt), repr(result), str(result)):
        assert binascii.hexlify(_TEST_MASTER_KEY).decode() not in text
        assert binascii.hexlify(traffic_key).decode() not in text
