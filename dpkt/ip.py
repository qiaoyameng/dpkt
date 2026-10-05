# $Id: ip.py 87 2013-03-05 19:41:04Z andrewflnr@gmail.com $
# -*- coding: utf-8 -*-
"""Internet Protocol."""
from __future__ import print_function
from __future__ import absolute_import

from collections import namedtuple

from . import dpkt
from .compat import iteritems
from .utils import inet_to_str, deprecation_warning

_ip_proto_names = {}  # {1: 'ICMP', 6: 'TCP', 17: 'UDP', etc.}


def get_ip_proto_name(p):
    return _ip_proto_names.get(p, None)


class IP(dpkt.Packet):
    """Internet Protocol.

    The Internet Protocol (IP) is the network layer communications protocol in the Internet protocol suite
    for relaying datagrams across network boundaries. Its routing function enables internetworking, and
    essentially establishes the Internet.

    Attributes:
        __hdr__: Header fields of IP.
             _v_hl:
                v: (int): Version (4 bits) For IPv4, this is always equal to 4
                hl: (int): Internet Header Length (IHL) (4 bits)
            _flags_offset:
                rf: (int): Reserved bit (1 bit)
                df: (int): Don't fragment (1 bit)
                mf: (int): More fragments (1 bit)
                offset: (int): Fragment offset (13 bits)
            tos: (int): Type of service. (1 byte)
            len: (int): Total Length. Defines the entire packet size in bytes, including header and data.(2 bytes)
            id: (int): Identification. Uniquely identifying the group of fragments of a single IP datagram. (2 bytes)
            ttl: (int): Time to live (1 byte)
            p: (int): Protocol. This field defines the protocol used in the data portion of the IP datagram. (1 byte)
            sum: (int): Header checksum. (2 bytes)
            src: (int): Source address. This field is the IPv4 address of the sender of the packet. (4 bytes)
            dst: (int): Destination address. This field is the IPv4 address of the receiver of the packet. (4 bytes)
    """

    __hdr__ = (
        ('_v_hl', 'B', (4 << 4) | (20 >> 2)),
        ('tos', 'B', 0),
        ('len', 'H', 20),
        ('id', 'H', 0),
        ('_flags_offset', 'H', 0),  # XXX - previously ip.off
        ('ttl', 'B', 64),
        ('p', 'B', 0),
        ('sum', 'H', 0),
        ('src', '4s', b'\x00' * 4),
        ('dst', '4s', b'\x00' * 4)
    )
    __bit_fields__ = {
        '_v_hl': (
            ('v', 4),   # version, 4 bits
            ('hl', 4),  # header len, 4 bits
        ),
        '_flags_offset': (
            ('rf', 1),  # reserved bit
            ('df', 1),  # don't fragment
            ('mf', 1),  # more fragments
            ('offset', 13),  # fragment offset, 13 bits
        )
    }
    __pprint_funcs__ = {
        'dst': inet_to_str,
        'src': inet_to_str,
        'sum': hex,  # display checksum in hex
        'p': get_ip_proto_name
    }
    _protosw = {}
    opts = b''

    def __init__(self, *args, **kwargs):
        super(IP, self).__init__(*args, **kwargs)

        # If IP packet is not initialized by string and the len field has
        # been rewritten.
        if not args and 'len' not in kwargs:
            self.len = self.__len__()

    def __len__(self):
        return self.__hdr_len__ + len(self.opts) + len(self.data)

    def __bytes__(self):
        if self.sum == 0:
            self.len = self.__len__()
            self.sum = dpkt.in_cksum(self.pack_hdr() + bytes(self.opts))
            if (self.p == 6 or self.p == 17) and (self._flags_offset & (IP_MF | IP_OFFMASK)) == 0 and \
                    isinstance(self.data, dpkt.Packet) and self.data.sum == 0:
                # Set zeroed TCP and UDP checksums for non-fragments.
                p = bytes(self.data)
                s = dpkt.struct.pack('>4s4sxBH', self.src, self.dst, self.p, len(p))
                s = dpkt.in_cksum_add(0, s)
                s = dpkt.in_cksum_add(s, p)
                self.data.sum = dpkt.in_cksum_done(s)

                # RFC 768 (Fields):
                # If the computed checksum is zero, it is transmitted as all
                # ones (the equivalent in one's complement arithmetic). An all
                # zero transmitted checksum value means that the transmitter
                # generated no checksum (for debugging or for higher level
                # protocols that don't care).
                if self.p == 17 and self.data.sum == 0:
                    self.data.sum = 0xffff
                    # XXX - skip transports which don't need the pseudoheader
        return self.pack_hdr() + bytes(self.opts) + bytes(self.data)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        ol = ((self._v_hl & 0xf) << 2) - self.__hdr_len__
        if ol < 0:
            raise dpkt.UnpackError('invalid header length')
        self.opts = buf[self.__hdr_len__:self.__hdr_len__ + ol]
        if self.len:
            buf = buf[self.__hdr_len__ + ol:self.len]
        else:  # very likely due to TCP segmentation offload
            buf = buf[self.__hdr_len__ + ol:]
        try:
            self.data = self._protosw[self.p](buf) if self.offset == 0 else buf
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf

    @classmethod
    def set_proto(cls, p, pktclass):
        cls._protosw[p] = pktclass

    @classmethod
    def get_proto(cls, p):
        return cls._protosw[p]

    # XXX - compatibility; to be deprecated
    @property
    def off(self):
        deprecation_warning("IP.off is deprecated")
        return self._flags_offset

    @off.setter
    def off(self, val):
        deprecation_warning("IP.off is deprecated")
        self.offset = val


IP_REASSEMBLY_TIMEOUT = 30


class IPReassemblyError(dpkt.Error):
    """A fragment cannot be reassembled and its group was discarded."""


DroppedDatagram = namedtuple('DroppedDatagram', ['key', 'reason', 'timestamp', 'buffered_bytes'])


class _FragmentGroup(object):
    def __init__(self, key):
        self.key = key
        self.fragments = []
        self.first_header = None
        self.total_len = None
        self.first_seen = None
        self.last_seen = None

    @property
    def buffered_bytes(self):
        total = sum(len(chunk) for start, chunk in self.fragments)
        if self.first_header is not None:
            total += len(self.first_header)
        return total

    @staticmethod
    def merged(fragments):
        ordered = sorted(((start, bytearray(chunk)) for start, chunk in fragments if chunk),
                         key=lambda fragment: fragment[0])
        merged = []
        for start, chunk in ordered:
            end = start + len(chunk)
            if not merged or start > merged[-1][0] + len(merged[-1][1]):
                merged.append([start, chunk])
                continue

            previous_start, previous_chunk = merged[-1]
            previous_end = previous_start + len(previous_chunk)
            if start < previous_end:
                overlap_len = min(end, previous_end) - start
                if bytes(previous_chunk[start - previous_start:start - previous_start + overlap_len]) != \
                        bytes(chunk[:overlap_len]):
                    return None
            if end > previous_end:
                previous_chunk.extend(chunk[previous_end - start:])

            for index in range(len(merged) - 2, -1, -1):
                earlier_start, earlier_chunk = merged[index]
                earlier_end = earlier_start + len(earlier_chunk)
                current_start, current_chunk = merged[index + 1]
                if current_start > earlier_end:
                    break

                overlap_len = min(earlier_end, current_start + len(current_chunk)) - current_start
                if bytes(earlier_chunk[current_start - earlier_start:current_start - earlier_start + overlap_len]) != \
                        bytes(current_chunk[:overlap_len]):
                    return None

                if current_start + len(current_chunk) > earlier_end:
                    earlier_chunk.extend(current_chunk[overlap_len:])
                merged.pop(index + 1)

        return [(start, bytes(chunk)) for start, chunk in merged]

    def payload(self):
        if not self.fragments or self.fragments[0][0] != 0 or self.total_len is None:
            return None

        payload = bytearray()
        for start, chunk in self.fragments:
            if start != len(payload):
                return None
            payload.extend(chunk)

        if len(payload) != self.total_len:
            return None
        return bytes(payload)


class IPReassembler(object):
    """Reassemble IPv4 fragments without using a background timer.

    Groups are keyed by source address, destination address, protocol and
    identification.  Callers supply a timestamp with every fragment and call
    :meth:`expire` to discard incomplete groups once they are too old.
    """

    def __init__(self, timeout=IP_REASSEMBLY_TIMEOUT, max_groups=1024, max_buffered_bytes=1024 * 1024):
        if timeout is not None and timeout < 0:
            raise ValueError('timeout must be non-negative or None')
        if max_groups is not None and max_groups < 0:
            raise ValueError('max_groups must be non-negative or None')
        if max_buffered_bytes is not None and max_buffered_bytes < 0:
            raise ValueError('max_buffered_bytes must be non-negative or None')

        self.timeout = timeout
        self.max_groups = max_groups
        self.max_buffered_bytes = max_buffered_bytes
        self.groups = {}
        self.dropped = []

    @property
    def group_count(self):
        return len(self.groups)

    @property
    def buffered_bytes(self):
        return sum(group.buffered_bytes for group in self.groups.values())

    def __len__(self):
        return len(self.groups)

    def push(self, packet, timestamp):
        """Add a fragment and return the complete IP datagram, or ``None``."""
        if not isinstance(packet, IP):
            packet = IP(packet)

        self.expire(timestamp)

        key = (packet.src, packet.dst, packet.p, packet.id)
        if packet.mf == 0 and packet.offset == 0:
            return packet

        try:
            start, payload, header_len = self._fragment_info(packet)
        except IPReassemblyError:
            self._drop_existing(key, 'invalid_packet', timestamp)
            raise
        except Exception:
            self._drop_existing(key, 'invalid_packet', timestamp)
            raise IPReassemblyError('invalid IPv4 fragment')

        if start % 8:
            self._drop_existing(key, 'invalid_packet', timestamp)
            raise IPReassemblyError('fragment offset is not 8-byte aligned')
        if packet.mf == 1 and len(payload) % 8:
            self._drop_existing(key, 'invalid_packet', timestamp)
            raise IPReassemblyError('non-final fragment payload is not 8-byte aligned')

        end = start + len(payload)
        group = self.groups.get(key)
        is_new_group = group is None
        if is_new_group:
            if self.max_groups is not None and len(self.groups) >= self.max_groups:
                dropped = self._make_drop(key, 'max_groups', timestamp, 0)
                self.dropped.append(dropped)
                raise IPReassemblyError('maximum reassembly group count exceeded')
            group = _FragmentGroup(key)
            group.first_seen = timestamp
            group.last_seen = timestamp
            self.groups[key] = group

        if group.total_len is not None and end > group.total_len:
            return self._reject(group, 'fragment_past_end', timestamp)

        first_header = group.first_header
        if start == 0 and first_header is None:
            first_header = packet.pack_hdr() + packet.opts
            if group.total_len is not None and group.total_len > IP_LEN_MAX - len(first_header):
                return self._reject(group, 'datagram_too_large', timestamp)

        candidate = list(group.fragments)
        if payload:
            candidate.append((start, bytes(payload)))
        merged = _FragmentGroup.merged(candidate)
        if merged is None:
            return self._reject(group, 'overlap_conflict', timestamp)

        projected_payload = sum(len(chunk) for fragment_start, chunk in merged)
        projected = projected_payload
        if first_header is not None:
            projected += len(first_header)
        projected += self.buffered_bytes - group.buffered_bytes
        if self.max_buffered_bytes is not None and projected > self.max_buffered_bytes:
            return self._reject(group, 'max_buffered_bytes', timestamp)

        if packet.mf == 0:
            complete_header_len = len(first_header) if first_header is not None else header_len
            if end > IP_LEN_MAX - complete_header_len:
                return self._reject(group, 'datagram_too_large', timestamp)
            if group.total_len is not None and end != group.total_len:
                return self._reject(group, 'inconsistent_total_length', timestamp)
            if any(start + len(chunk) > end for start, chunk in group.fragments):
                return self._reject(group, 'fragment_past_end', timestamp)
            group.total_len = end

        group.fragments = merged
        if first_header is not None:
            group.first_header = first_header
        group.last_seen = timestamp

        payload = group.payload()
        if payload is None:
            return None

        return self._complete(group, payload)

    add = push
    process = push
    reassemble = push

    def expire(self, timestamp):
        """Expire incomplete groups and return newly recorded drops."""
        if self.timeout is None:
            return []

        expired = []
        for key in list(self.groups):
            group = self.groups[key]
            if timestamp - group.first_seen >= self.timeout:
                expired.append(self._make_drop(key, 'timeout', timestamp, group.buffered_bytes))
                del self.groups[key]
        self.dropped.extend(expired)
        return expired

    advance = expire
    flush_expired = expire

    @staticmethod
    def _fragment_info(packet):
        if packet.v != 4:
            raise IPReassemblyError('not an IPv4 packet')

        header_len = packet.__hdr_len__ + len(packet.opts)
        if packet.hl < 5 or header_len > IP_HDR_LEN_MAX or header_len != packet.hl * 4:
            raise IPReassemblyError('invalid IPv4 header length')

        if packet.len:
            if packet.len < header_len or packet.len > IP_LEN_MAX:
                raise IPReassemblyError('invalid IPv4 total length')
            payload_len = packet.len - header_len
            if len(packet.data) != payload_len:
                raise IPReassemblyError('truncated IPv4 fragment')
        else:
            payload_len = len(packet.data)

        start = packet.offset * 8
        if start > IP_LEN_MAX - header_len or start + payload_len > IP_LEN_MAX - header_len:
            raise IPReassemblyError('fragment payload exceeds IPv4 datagram bounds')

        return start, bytes(packet.data), header_len

    def _complete(self, group, payload):
        header = bytearray(group.first_header)
        header[0] = 0x40 | ((len(header) // 4) & 0x0f)
        total_len = len(header) + len(payload)
        header[2:4] = bytearray(((total_len >> 8) & 0xff, total_len & 0xff))
        header[6:8] = b'\x00\x00'
        header[10:12] = b'\x00\x00'
        checksum = dpkt.in_cksum(bytes(header))
        header[10:12] = bytearray(((checksum >> 8) & 0xff, checksum & 0xff))
        del self.groups[group.key]
        return IP(bytes(header) + payload)

    def _reject(self, group, reason, timestamp):
        dropped = self._make_drop(group.key, reason, timestamp, group.buffered_bytes)
        self.groups.pop(group.key, None)
        self.dropped.append(dropped)
        raise IPReassemblyError(reason)

    def _drop_existing(self, key, reason, timestamp):
        group = self.groups.pop(key, None)
        buffered_bytes = group.buffered_bytes if group is not None else 0
        if group is not None:
            self.dropped.append(self._make_drop(key, reason, timestamp, buffered_bytes))

    @staticmethod
    def _make_drop(key, reason, timestamp, buffered_bytes):
        return DroppedDatagram(key, reason, timestamp, buffered_bytes)


# IP Headers
IP_ADDR_LEN = 0x04
IP_ADDR_BITS = 0x20

IP_HDR_LEN = 0x14
IP_OPT_LEN = 0x02
IP_OPT_LEN_MAX = 0x28
IP_HDR_LEN_MAX = IP_HDR_LEN + IP_OPT_LEN_MAX

IP_LEN_MAX = 0xffff
IP_LEN_MIN = IP_HDR_LEN

# Reserved Addresses
IP_ADDR_ANY = "\x00\x00\x00\x00"    # 0.0.0.0
IP_ADDR_BROADCAST = "\xff\xff\xff\xff"    # 255.255.255.255
IP_ADDR_LOOPBACK = "\x7f\x00\x00\x01"    # 127.0.0.1
IP_ADDR_MCAST_ALL = "\xe0\x00\x00\x01"    # 224.0.0.1
IP_ADDR_MCAST_LOCAL = "\xe0\x00\x00\xff"    # 224.0.0.255

# Type of service (ip_tos), RFC 1349 ("obsoleted by RFC 2474")
IP_TOS_DEFAULT = 0x00  # default
IP_TOS_LOWDELAY = 0x10  # low delay
IP_TOS_THROUGHPUT = 0x08  # high throughput
IP_TOS_RELIABILITY = 0x04  # high reliability
IP_TOS_LOWCOST = 0x02  # low monetary cost - XXX
IP_TOS_ECT = 0x02  # ECN-capable transport
IP_TOS_CE = 0x01  # congestion experienced

# IP precedence (high 3 bits of ip_tos), hopefully unused
IP_TOS_PREC_ROUTINE = 0x00
IP_TOS_PREC_PRIORITY = 0x20
IP_TOS_PREC_IMMEDIATE = 0x40
IP_TOS_PREC_FLASH = 0x60
IP_TOS_PREC_FLASHOVERRIDE = 0x80
IP_TOS_PREC_CRITIC_ECP = 0xa0
IP_TOS_PREC_INTERNETCONTROL = 0xc0
IP_TOS_PREC_NETCONTROL = 0xe0

# Fragmentation flags (ip_off)
IP_RF = 0x8000  # reserved
IP_DF = 0x4000  # don't fragment
IP_MF = 0x2000  # more fragments (not last frag)
IP_OFFMASK = 0x1fff  # mask for fragment offset

# Time-to-live (ip_ttl), seconds
IP_TTL_DEFAULT = 64  # default ttl, RFC 1122, RFC 1340
IP_TTL_MAX = 255  # maximum ttl

# Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
IP_PROTO_IP = 0  # dummy for IP
IP_PROTO_HOPOPTS = IP_PROTO_IP  # IPv6 hop-by-hop options
IP_PROTO_ICMP = 1  # ICMP
IP_PROTO_IGMP = 2  # IGMP
IP_PROTO_GGP = 3  # gateway-gateway protocol
IP_PROTO_IPIP = 4  # IP in IP
IP_PROTO_ST = 5  # ST datagram mode
IP_PROTO_TCP = 6  # TCP
IP_PROTO_CBT = 7  # CBT
IP_PROTO_EGP = 8  # exterior gateway protocol
IP_PROTO_IGP = 9  # interior gateway protocol
IP_PROTO_BBNRCC = 10  # BBN RCC monitoring
IP_PROTO_NVP = 11  # Network Voice Protocol
IP_PROTO_PUP = 12  # PARC universal packet
IP_PROTO_ARGUS = 13  # ARGUS
IP_PROTO_EMCON = 14  # EMCON
IP_PROTO_XNET = 15  # Cross Net Debugger
IP_PROTO_CHAOS = 16  # Chaos
IP_PROTO_UDP = 17  # UDP
IP_PROTO_MUX = 18  # multiplexing
IP_PROTO_DCNMEAS = 19  # DCN measurement
IP_PROTO_HMP = 20  # Host Monitoring Protocol
IP_PROTO_PRM = 21  # Packet Radio Measurement
IP_PROTO_IDP = 22  # Xerox NS IDP
IP_PROTO_TRUNK1 = 23  # Trunk-1
IP_PROTO_TRUNK2 = 24  # Trunk-2
IP_PROTO_LEAF1 = 25  # Leaf-1
IP_PROTO_LEAF2 = 26  # Leaf-2
IP_PROTO_RDP = 27  # "Reliable Datagram" proto
IP_PROTO_IRTP = 28  # Inet Reliable Transaction
IP_PROTO_TP = 29  # ISO TP class 4
IP_PROTO_NETBLT = 30  # Bulk Data Transfer
IP_PROTO_MFPNSP = 31  # MFE Network Services
IP_PROTO_MERITINP = 32  # Merit Internodal Protocol
IP_PROTO_SEP = 33  # Sequential Exchange proto
IP_PROTO_3PC = 34  # Third Party Connect proto
IP_PROTO_IDPR = 35  # Interdomain Policy Route
IP_PROTO_XTP = 36  # Xpress Transfer Protocol
IP_PROTO_DDP = 37  # Datagram Delivery Proto
IP_PROTO_CMTP = 38  # IDPR Ctrl Message Trans
IP_PROTO_TPPP = 39  # TP++ Transport Protocol
IP_PROTO_IL = 40  # IL Transport Protocol
IP_PROTO_IP6 = 41  # IPv6
IP_PROTO_SDRP = 42  # Source Demand Routing
IP_PROTO_ROUTING = 43  # IPv6 routing header
IP_PROTO_FRAGMENT = 44  # IPv6 fragmentation header
IP_PROTO_RSVP = 46  # Reservation protocol
IP_PROTO_GRE = 47  # General Routing Encap
IP_PROTO_MHRP = 48  # Mobile Host Routing
IP_PROTO_ENA = 49  # ENA
IP_PROTO_ESP = 50  # Encap Security Payload
IP_PROTO_AH = 51  # Authentication Header
IP_PROTO_INLSP = 52  # Integated Net Layer Sec
IP_PROTO_SWIPE = 53  # SWIPE
IP_PROTO_NARP = 54  # NBMA Address Resolution
IP_PROTO_MOBILE = 55  # Mobile IP, RFC 2004
IP_PROTO_TLSP = 56  # Transport Layer Security
IP_PROTO_SKIP = 57  # SKIP
IP_PROTO_ICMP6 = 58  # ICMP for IPv6
IP_PROTO_NONE = 59  # IPv6 no next header
IP_PROTO_DSTOPTS = 60  # IPv6 destination options
IP_PROTO_ANYHOST = 61  # any host internal proto
IP_PROTO_CFTP = 62  # CFTP
IP_PROTO_ANYNET = 63  # any local network
IP_PROTO_EXPAK = 64  # SATNET and Backroom EXPAK
IP_PROTO_KRYPTOLAN = 65  # Kryptolan
IP_PROTO_RVD = 66  # MIT Remote Virtual Disk
IP_PROTO_IPPC = 67  # Inet Pluribus Packet Core
IP_PROTO_DISTFS = 68  # any distributed fs
IP_PROTO_SATMON = 69  # SATNET Monitoring
IP_PROTO_VISA = 70  # VISA Protocol
IP_PROTO_IPCV = 71  # Inet Packet Core Utility
IP_PROTO_CPNX = 72  # Comp Proto Net Executive
IP_PROTO_CPHB = 73  # Comp Protocol Heart Beat
IP_PROTO_WSN = 74  # Wang Span Network
IP_PROTO_PVP = 75  # Packet Video Protocol
IP_PROTO_BRSATMON = 76  # Backroom SATNET Monitor
IP_PROTO_SUNND = 77  # SUN ND Protocol
IP_PROTO_WBMON = 78  # WIDEBAND Monitoring
IP_PROTO_WBEXPAK = 79  # WIDEBAND EXPAK
IP_PROTO_EON = 80  # ISO CNLP
IP_PROTO_VMTP = 81  # Versatile Msg Transport
IP_PROTO_SVMTP = 82  # Secure VMTP
IP_PROTO_VINES = 83  # VINES
IP_PROTO_TTP = 84  # TTP
IP_PROTO_NSFIGP = 85  # NSFNET-IGP
IP_PROTO_DGP = 86  # Dissimilar Gateway Proto
IP_PROTO_TCF = 87  # TCF
IP_PROTO_EIGRP = 88  # EIGRP
IP_PROTO_OSPF = 89  # Open Shortest Path First
IP_PROTO_SPRITERPC = 90  # Sprite RPC Protocol
IP_PROTO_LARP = 91  # Locus Address Resolution
IP_PROTO_MTP = 92  # Multicast Transport Proto
IP_PROTO_AX25 = 93  # AX.25 Frames
IP_PROTO_IPIPENCAP = 94  # yet-another IP encap
IP_PROTO_MICP = 95  # Mobile Internet Ctrl
IP_PROTO_SCCSP = 96  # Semaphore Comm Sec Proto
IP_PROTO_ETHERIP = 97  # Ethernet in IPv4
IP_PROTO_ENCAP = 98  # encapsulation header
IP_PROTO_ANYENC = 99  # private encryption scheme
IP_PROTO_GMTP = 100  # GMTP
IP_PROTO_IFMP = 101  # Ipsilon Flow Mgmt Proto
IP_PROTO_PNNI = 102  # PNNI over IP
IP_PROTO_PIM = 103  # Protocol Indep Multicast
IP_PROTO_ARIS = 104  # ARIS
IP_PROTO_SCPS = 105  # SCPS
IP_PROTO_QNX = 106  # QNX
IP_PROTO_AN = 107  # Active Networks
IP_PROTO_IPCOMP = 108  # IP Payload Compression
IP_PROTO_SNP = 109  # Sitara Networks Protocol
IP_PROTO_COMPAQPEER = 110  # Compaq Peer Protocol
IP_PROTO_IPXIP = 111  # IPX in IP
IP_PROTO_VRRP = 112  # Virtual Router Redundancy
IP_PROTO_PGM = 113  # PGM Reliable Transport
IP_PROTO_ANY0HOP = 114  # 0-hop protocol
IP_PROTO_L2TP = 115  # Layer 2 Tunneling Proto
IP_PROTO_DDX = 116  # D-II Data Exchange (DDX)
IP_PROTO_IATP = 117  # Interactive Agent Xfer
IP_PROTO_STP = 118  # Schedule Transfer Proto
IP_PROTO_SRP = 119  # SpectraLink Radio Proto
IP_PROTO_UTI = 120  # UTI
IP_PROTO_SMP = 121  # Simple Message Protocol
IP_PROTO_SM = 122  # SM
IP_PROTO_PTP = 123  # Performance Transparency
IP_PROTO_ISIS = 124  # ISIS over IPv4
IP_PROTO_FIRE = 125  # FIRE
IP_PROTO_CRTP = 126  # Combat Radio Transport
IP_PROTO_CRUDP = 127  # Combat Radio UDP
IP_PROTO_SSCOPMCE = 128  # SSCOPMCE
IP_PROTO_IPLT = 129  # IPLT
IP_PROTO_SPS = 130  # Secure Packet Shield
IP_PROTO_PIPE = 131  # Private IP Encap in IP
IP_PROTO_SCTP = 132  # Stream Ctrl Transmission
IP_PROTO_FC = 133  # Fibre Channel
IP_PROTO_RSVPIGN = 134  # RSVP-E2E-IGNORE
IP_PROTO_RAW = 255  # Raw IP packets
IP_PROTO_RESERVED = IP_PROTO_RAW  # Reserved
IP_PROTO_MAX = 255

# XXX - auto-load IP dispatch table from IP_PROTO_* definitions


def __load_protos():
    g = globals()
    for k, v in iteritems(g):
        if k.startswith('IP_PROTO_'):
            name = k[9:]
            _ip_proto_names[v] = name
            try:
                mod = __import__(name.lower(), g, level=1)
                IP.set_proto(v, getattr(mod, name))
            except (ImportError, AttributeError):
                continue


def _mod_init():
    """Post-initialization called when all dpkt modules are fully loaded"""
    if not IP._protosw:
        __load_protos()


def test_ip():
    from . import udp

    s = b'E\x00\x00"\x00\x00\x00\x00@\x11r\xc0\x01\x02\x03\x04\x01\x02\x03\x04\x00o\x00\xde\x00\x0e\xbf5foobar'
    ip = IP(id=0, src=b'\x01\x02\x03\x04', dst=b'\x01\x02\x03\x04', p=17)
    u = udp.UDP(sport=111, dport=222)
    u.data = b'foobar'
    u.ulen += len(u.data)
    ip.data = u
    ip.len += len(u)
    assert (bytes(ip) == s)
    assert (ip.v == 4)
    assert (ip.hl == 5)

    ip = IP(s)
    assert (bytes(ip) == s)
    assert (ip.udp.sport == 111)
    assert (ip.udp.data == b'foobar')


def test_dict():
    ip = IP(id=0, src=b'\x01\x02\x03\x04', dst=b'\x01\x02\x03\x04', p=17)
    d = dict(ip)

    assert (d['src'] == b'\x01\x02\x03\x04')
    assert (d['dst'] == b'\x01\x02\x03\x04')
    assert (d['id'] == 0)
    assert (d['p'] == 17)


def test_hl():  # Todo check this test method
    s = (b'BB\x03\x00\x00\x00\x00\x00\x00\x00\xd0\x00\xec\xbc\xa5\x00\x00\x00\x03\x80\x00\x00\xd0'
         b'\x01\xf2\xac\xa5"0\x01\x00\x14\x00\x02\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    try:
        IP(s)
    except dpkt.UnpackError:
        pass


def test_opt():
    s = (b'\x4f\x00\x00\x3c\xae\x08\x00\x00\x40\x06\x18\x10\xc0\xa8\x0a\x26\xc0\xa8\x0a\x01\x07\x27'
         b'\x08\x01\x02\x03\x04\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    ip = IP(s)
    ip.sum = 0
    assert (bytes(ip) == s)


def test_iplen():
    # ensure the ip.len is not affected by serialization
    # https://github.com/kbandla/dpkt/issues/279 , https://github.com/kbandla/dpkt/issues/625
    s = (b'\x45\x00\x00\xa3\xb6\x7a\x00\x00\x80\x11\x5e\x6f\xc0\xa8\x03\x02\x97\x47\xca\x6e\xc7\x38'
         b'\x64\xdf\x00\x8f\x4a\xfa\x26\xd8\x15\xbe\xd9\x42\xae\x66\xe1\xce\x14\x5f\x06\x79\x4b\x13'
         b'\x02\xad\xa4\x8b\x69\x1c\x7a\xf6\xd5\x3d\x45\xaa\xba\xcd\x24\x77\xc2\xe7\x5f\x6a\xcc\xb5'
         b'\x1f\x21\xfa\x62\xf0\xf3\x32\xe1\xe4\xf0\x20\x1f\x47\x61\xec\xbc\xb1\x0e\x6c\xf0\xb8\x6d'
         b'\x7f\x96\x9b\x35\x03\xa1\x79\x05\xc5\xfd\x2a\xf7\xfa\x35\xe3\x0e\x04\xd0\xc7\x4e\x94\x72'
         b'\x3d\x07\x5a\xa8\x53\x2a\x5d\x03\xf7\x04\xc4\xa8\xb8\xa1')

    ip_len1 = IP(s).len  # original len
    assert (IP(bytes(IP(s))).len == ip_len1)


def test_zerolen():
    from . import tcp
    d = b'X' * 2048
    s = (b'\x45\x00\x00\x00\x34\xce\x40\x00\x80\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01\xcc\x4e'
         b'\x0c\x38\x60\xff\xc6\x4e\x5f\x8a\x12\x98\x50\x18\x40\x29\x3a\xa3\x00\x00') + d
    ip = IP(s)
    assert (isinstance(ip.data, tcp.TCP))
    assert (ip.tcp.data == d)


def test_constuctor():
    ip1 = IP(data=b"Hello world!")
    ip2 = IP(data=b"Hello world!", len=0)
    ip3 = IP(bytes(ip1))
    ip4 = IP(bytes(ip2))
    assert (bytes(ip1) == bytes(ip3))
    assert (bytes(ip1) == b'E\x00\x00 \x00\x00\x00\x00@\x00z\xdf\x00\x00\x00\x00\x00\x00\x00\x00Hello world!')
    assert (bytes(ip2) == bytes(ip4))
    assert (bytes(ip2) == b'E\x00\x00 \x00\x00\x00\x00@\x00z\xdf\x00\x00\x00\x00\x00\x00\x00\x00Hello world!')


def test_frag():
    from . import ethernet
    s = (b'\x00\x23\x20\xd4\x2a\x8c\x00\x23\x20\xd4\x2a\x8c\x08\x00\x45\x00\x00\x54\x00\x00\x40\x00'
         b'\x40\x01\x25\x8d\x0a\x00\x00\x8f\x0a\x00\x00\x8e\x08\x00\x2e\xa0\x01\xff\x23\x73\x20\x48'
         b'\x4a\x4d\x00\x00\x00\x00\x78\x85\x02\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17'
         b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d'
         b'\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37')
    ip = ethernet.Ethernet(s).ip
    assert (ip.rf == 0)
    assert (ip.df == 1)
    assert (ip.mf == 0)
    assert (ip.offset == 0)

    # test setters of fragmentation related attributes.
    ip.rf = 1
    ip.df = 0
    ip.mf = 1
    ip.offset = 1480
    assert (ip.rf == 1)
    assert (ip.df == 0)
    assert (ip.mf == 1)
    assert (ip.offset == 1480)


def test_property_setters():
    ip = IP()
    assert ip.v == 4
    ip.v = 6
    assert ip.v == 6
    # test property delete
    del ip.v
    assert ip.v == 4  # back to default

    assert ip.hl == 5
    ip.hl = 7
    assert ip.hl == 7
    del ip.hl
    assert ip.hl == 5

    # coverage
    ip.off = 10
    assert ip.off == 10


def test_default_udp_checksum():
    from dpkt.udp import UDP

    udp = UDP(sport=1, dport=0xffdb)
    ip = IP(src=b'\x00\x00\x00\x01', dst=b'\x00\x00\x00\x01', p=17, data=udp)
    assert ip.p == 17
    assert ip.data.sum == 0

    # this forces recalculation of the data layer checksum
    bytes(ip)

    # during calculation the checksum was evaluated to 0x0000
    # this was then conditionally set to 0xffff per RFC768
    assert ip.data.sum == 0xffff


def test_get_proto_name():
    assert get_ip_proto_name(6) == 'TCP'
    assert get_ip_proto_name(999) is None


def _test_fragment(payload_chunks, ident=0x1234, opts=b'', p=17):
    header_len = IP_HDR_LEN + len(opts)
    fragments = []
    offset = 0

    for index, chunk in enumerate(payload_chunks):
        is_last = index == len(payload_chunks) - 1
        fragment = IP(id=ident, src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                      p=p, opts=opts, data=chunk, offset=offset // 8, mf=0 if is_last else 1)
        fragment.hl = header_len // 4
        fragments.append(bytes(fragment))
        offset += len(chunk)

    return fragments


def _test_payload():
    return b'\x04\xd2\x00\x35\x00\x1c\x00\x00' + bytes(bytearray(range(20)))


def test_ip_reassembly_out_of_order_duplicate():
    import pytest
    from . import udp

    fragments = _test_fragment([_test_payload()[i:i + 8] for i in range(0, 28, 8)])
    reassembler = IPReassembler(timeout=10)

    assert isinstance(IP(fragments[1]).data, bytes)
    assert reassembler.push(fragments[3], 1) is None
    assert reassembler.push(fragments[0], 2) is None
    assert reassembler.push(fragments[3], 3) is None
    assert reassembler.push(fragments[1], 4) is None
    assert reassembler.dropped == []

    datagram = reassembler.push(fragments[2], 5)
    assert isinstance(datagram, IP)
    assert datagram.offset == 0
    assert datagram.mf == 0
    assert datagram.df == 0
    assert datagram.len == IP_HDR_LEN + 28
    assert bytes(datagram.data) == _test_payload()
    assert dpkt.in_cksum(datagram.pack_hdr()) == 0

    reparsed = IP(bytes(datagram))
    assert isinstance(reparsed.data, udp.UDP)
    assert reparsed.udp.data == bytes(bytearray(range(20)))
    assert reassembler.group_count == 0
    assert reassembler.buffered_bytes == 0


def test_ip_reassembly_preserves_first_fragment_options():
    opts = b'\x01\x01\x01\x00'
    payload = bytes(bytearray(range(20)))
    fragments = _test_fragment([payload[:8], payload[8:16], payload[16:]], opts=opts, p=1)
    reassembler = IPReassembler()

    reassembler.push(fragments[1], 1)
    reassembler.push(fragments[0], 2)
    datagram = reassembler.push(fragments[2], 3)

    assert datagram.hl == 6
    assert datagram.opts == opts
    assert datagram.len == IP_HDR_LEN + len(opts) + len(payload)
    assert bytes(datagram.data) == payload
    assert dpkt.in_cksum(datagram.pack_hdr() + datagram.opts) == 0
    assert bytes(IP(bytes(datagram)).data) == payload


def test_ip_reassembly_missing_first_and_last_expire():
    payload = _test_payload()
    fragments = _test_fragment([payload[:8], payload[8:16], payload[16:24], payload[24:]])

    missing_first = IPReassembler(timeout=10)
    missing_first.push(fragments[1], 1)
    missing_first.push(fragments[2], 2)
    assert missing_first.push(fragments[3], 3) is None
    drops = missing_first.expire(13)
    assert len(drops) == 1
    assert drops[0].reason == 'timeout'
    assert missing_first.group_count == 0

    missing_last = IPReassembler(timeout=10)
    missing_last.push(fragments[0], 1)
    missing_last.push(fragments[1], 2)
    assert missing_last.push(fragments[2], 3) is None
    drops = missing_last.expire(20)
    assert [drop.reason for drop in drops] == ['timeout']
    assert missing_last.group_count == 0


def test_ip_reassembly_duplicate_identification_reuse_after_expiry():
    payload = _test_payload()
    fragments = _test_fragment([payload[:8], payload[8:16], payload[16:24], payload[24:]])
    reassembler = IPReassembler(timeout=10)

    reassembler.push(fragments[0], 0)
    assert reassembler.push(fragments[1], 1) is None
    assert reassembler.expire(11)[0].reason == 'timeout'

    datagram = None
    for timestamp, fragment in enumerate(fragments, start=12):
        datagram = reassembler.push(fragment, timestamp)

    assert datagram is not None
    assert bytes(datagram.data) == payload
    assert [drop.reason for drop in reassembler.dropped] == ['timeout']


def test_ip_reassembly_overlap_conflict():
    import pytest

    fragments = _test_fragment([_test_payload()[:8], _test_payload()[8:16], _test_payload()[16:]])
    conflicting = bytearray(fragments[1])
    conflicting[IP_HDR_LEN] ^= 0xff
    reassembler = IPReassembler()

    reassembler.push(fragments[0], 1)
    reassembler.push(bytes(conflicting), 2)
    with pytest.raises(IPReassemblyError):
        reassembler.push(fragments[1], 3)

    assert reassembler.group_count == 0
    assert reassembler.dropped[-1].reason == 'overlap_conflict'


def test_ip_reassembly_rejects_fragment_past_known_end():
    import pytest

    payload = _test_payload()
    fragments = _test_fragment([payload[:8], payload[8:16], payload[16:24], payload[24:]])
    last_early = IP(id=0x1234, src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                    p=17, data=payload[8:16], offset=1, mf=0)
    last_early.sum = 0
    last_early = bytes(last_early)

    reassembler = IPReassembler()
    reassembler.push(fragments[0], 1)
    reassembler.push(fragments[1], 2)
    reassembler.push(fragments[2], 3)

    with pytest.raises(IPReassemblyError):
        reassembler.push(last_early, 4)
    assert reassembler.dropped[-1].reason == 'fragment_past_end'
    assert reassembler.group_count == 0


def test_ip_reassembler_limits():
    import pytest

    payload = _test_payload()
    fragments = _test_fragment([payload[:8], payload[8:16], payload[16:24], payload[24:]])

    max_groups = IPReassembler(max_groups=1, max_buffered_bytes=None)
    max_groups.push(fragments[0], 1)
    other = IP(id=0x5678, src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
               p=17, data=b'abcdefgh', offset=0, mf=1)
    other.sum = 0
    other = bytes(other)
    with pytest.raises(IPReassemblyError):
        max_groups.push(other, 2)
    assert max_groups.dropped[-1].reason == 'max_groups'

    max_bytes = IPReassembler(max_groups=None, max_buffered_bytes=25)
    with pytest.raises(IPReassemblyError):
        max_bytes.push(fragments[0], 1)
    assert max_bytes.dropped[-1].reason == 'max_buffered_bytes'
    assert max_bytes.group_count == 0

    cross_group = IPReassembler(max_groups=None, max_buffered_bytes=59)
    cross_group.push(fragments[0], 1)
    other = IP(id=0x5678, src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
               p=17, data=b'Y' * 32, offset=1, mf=1)
    other.sum = 0
    with pytest.raises(IPReassemblyError):
        cross_group.push(bytes(other), 2)
    assert cross_group.dropped[-1].reason == 'max_buffered_bytes'
    assert cross_group.group_count == 1
