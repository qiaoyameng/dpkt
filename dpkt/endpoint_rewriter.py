# -*- coding: utf-8 -*-
"""Endpoint rewriting for complete Ethernet, IPv4/IPv6, TCP and UDP packets."""
from __future__ import absolute_import

import copy
import socket
import struct

from . import dpkt
from . import ethernet
from . import ip
from . import ip6
from . import tcp
from . import udp

POLICY_ERROR = 'error'
POLICY_MARK_UNHANDLED = 'mark_unhandled'

STATUS_REWRITTEN = 'rewritten'
STATUS_UNHANDLED = 'unhandled'


class EndpointRewriteError(dpkt.Error):
    """The requested endpoint rewrite cannot be performed safely."""


class UnhandledPacket(EndpointRewriteError):
    """The packet cannot be rewritten under the selected handling policy."""


class Endpoint(object):
    """An IP address and transport-layer port."""

    __slots__ = ('family', 'address', 'port')

    def __init__(self, family, address, port):
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise EndpointRewriteError('invalid address family')
        address = self._address_bytes(family, address)
        if not isinstance(port, int) or not 0 <= port <= 65535:
            raise EndpointRewriteError('invalid port')
        self.family = family
        self.address = address
        self.port = port

    @staticmethod
    def _address_bytes(family, address):
        if isinstance(address, str):
            try:
                return socket.inet_pton(family, address)
            except (OSError, ValueError):
                raise EndpointRewriteError('invalid address')
        if isinstance(address, bytes) and len(address) == (4 if family == socket.AF_INET else 16):
            try:
                socket.inet_ntop(family, address)
            except (OSError, ValueError):
                raise EndpointRewriteError('invalid address')
            return address
        raise EndpointRewriteError('invalid address')

    def key(self):
        return self.family, self.address, self.port

    def __eq__(self, other):
        return isinstance(other, Endpoint) and self.key() == other.key()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.key())

    def __repr__(self):
        return 'Endpoint(%r, %r, %r)' % (self.family, self.address, self.port)


class EndpointMapping(object):
    """The source and destination endpoints to use for a rewritten flow."""

    __slots__ = ('source', 'destination')

    def __init__(self, source, destination):
        if source.family != destination.family:
            raise EndpointRewriteError('source and destination address families differ')
        self.source = source
        self.destination = destination


class RewriteResult(object):
    """The result of one packet rewrite attempt."""

    __slots__ = ('status', 'packet', 'bytes', 'reason', 'caplen_before', 'caplen_after',
                 'wirelen_before', 'wirelen_after')

    def __init__(self, status, packet=None, packet_bytes=None, reason=None,
                 caplen_before=None, caplen_after=None, wirelen_before=None, wirelen_after=None):
        self.status = status
        self.packet = packet
        self.bytes = packet_bytes
        self.reason = reason
        self.caplen_before = caplen_before
        self.caplen_after = caplen_after
        self.wirelen_before = wirelen_before
        self.wirelen_after = wirelen_after

    @property
    def caplen_delta(self):
        if self.caplen_before is None or self.caplen_after is None:
            return None
        return self.caplen_after - self.caplen_before

    @property
    def wirelen_delta(self):
        if self.wirelen_before is None or self.wirelen_after is None:
            return None
        return self.wirelen_after - self.wirelen_before


class EndpointRewriter(object):
    """Rewrite endpoints while preserving packet payloads and checksums."""

    def __init__(self, mapper, policy=POLICY_ERROR):
        if policy not in (POLICY_ERROR, POLICY_MARK_UNHANDLED):
            raise EndpointRewriteError('invalid policy')
        self.mapper = mapper
        self.policy = policy
        self._mappings = {}
        self._reverse = {}
        self._flows = set()

    def rewrite_frame(self, frame, caplen=None, wirelen=None):
        if type(frame) is not bytes:
            raise EndpointRewriteError('frame must be bytes')
        original_len = len(frame)
        if caplen is None:
            caplen = original_len
        if wirelen is None:
            wirelen = original_len
        if caplen != original_len or wirelen < caplen:
            return self._unhandled_frame(frame, 'truncated frame', caplen, wirelen, caplen)
        try:
            eth = ethernet.Ethernet(frame)
            if not isinstance(eth.data, (ip.IP, ip6.IP6)):
                raise UnhandledPacket('unsupported Ethernet payload')
            result = self.rewrite_packet(eth, caplen=caplen, wirelen=wirelen)
            result.caplen_after = len(result.bytes)
            if result.status == STATUS_REWRITTEN:
                result.wirelen_after = len(result.bytes)
            return result
        except (UnhandledPacket, dpkt.UnpackError, dpkt.PackError, struct.error) as exc:
            return self._unhandled_frame(frame, str(exc), caplen, wirelen, caplen)

    def rewrite_packet(self, packet, caplen=None, wirelen=None):
        original = copy.deepcopy(packet)
        try:
            eth, network = self._parse_packet(original)
            original_bytes = self._packet_bytes(eth, network)
        except (UnhandledPacket, dpkt.UnpackError, dpkt.PackError, struct.error) as exc:
            if caplen is None or wirelen is None:
                raise
            return self._unhandled(original, str(exc), caplen, wirelen, caplen, wirelen)
        if caplen is None:
            caplen = len(original_bytes)
        if wirelen is None:
            wirelen = len(original_bytes)
        if caplen != len(original_bytes) or wirelen < caplen:
            return self._unhandled(original, 'truncated packet', caplen, wirelen,
                                   len(original_bytes), wirelen)
        try:
            self._validate_packet(eth, network)
            mapping = self._mapping_for(network)
            self._apply_mapping(network, mapping)
            rewritten = self._packet_bytes(eth, network)
            result = RewriteResult(
                STATUS_REWRITTEN,
                packet=eth if eth is not None else network,
                packet_bytes=rewritten,
                caplen_before=caplen,
                caplen_after=len(rewritten),
                wirelen_before=wirelen,
                wirelen_after=wirelen + len(rewritten) - len(original_bytes)
            )
            return result
        except (UnhandledPacket, dpkt.UnpackError, dpkt.PackError, struct.error) as exc:
            return self._unhandled(original, str(exc), caplen, wirelen, caplen, wirelen)

    def _unhandled(self, packet, reason, caplen_before, wirelen_before, caplen_after, wirelen_after):
        if self.policy == POLICY_ERROR:
            raise UnhandledPacket(reason)
        packet_bytes = None
        if packet is not None:
            try:
                packet_bytes = self._packet_bytes(packet, packet.data) if isinstance(packet, ethernet.Ethernet) else bytes(packet)
            except dpkt.Error:
                packet_bytes = None
        return RewriteResult(
            STATUS_UNHANDLED,
            packet=packet,
            packet_bytes=packet_bytes,
            reason=reason,
            caplen_before=caplen_before,
            caplen_after=caplen_after,
            wirelen_before=wirelen_before,
            wirelen_after=wirelen_after
        )

    def _unhandled_frame(self, frame, reason, caplen, wirelen, frame_len=None):
        if self.policy == POLICY_ERROR:
            raise UnhandledPacket(reason)
        if frame_len is None:
            frame_len = len(frame)
        return RewriteResult(
            STATUS_UNHANDLED,
            packet=None,
            packet_bytes=frame,
            reason=reason,
            caplen_before=caplen,
            caplen_after=frame_len,
            wirelen_before=wirelen,
            wirelen_after=wirelen
        )

    @staticmethod
    def _parse_packet(packet):
        if isinstance(packet, (ip.IP, ip6.IP6)):
            return None, packet
        if isinstance(packet, ethernet.Ethernet):
            vlan_tags = getattr(packet, 'vlan_tags', None)
            if vlan_tags and not all(isinstance(tag, ethernet.VLANtag8021Q) for tag in vlan_tags):
                raise UnhandledPacket('unsupported VLAN encapsulation')
            if not isinstance(packet.data, (ip.IP, ip6.IP6)):
                raise UnhandledPacket('unsupported Ethernet payload')
            return packet, packet.data
        raise EndpointRewriteError('unsupported packet type')

    def _validate_packet(self, eth, network):
        if isinstance(network, ip.IP):
            self._validate_ipv4(network)
        else:
            self._validate_ipv6(network)
        if eth is not None:
            self._validate_ethernet(eth, network)

    @staticmethod
    def _validate_ethernet(eth, network):
        raw = EndpointRewriter._packet_bytes(eth, network)
        parsed = ethernet.Ethernet(raw)
        if not isinstance(parsed.data, type(network)):
            raise UnhandledPacket('malformed Ethernet packet')
        for name in ('fcs', 'padding', 'trailer'):
            if hasattr(eth, name):
                raise UnhandledPacket('Ethernet trailer data is not supported')

    def _validate_ipv4(self, network):
        if network.v != 4:
            raise UnhandledPacket('invalid IPv4 version')
        header_len = network.hl * 4
        network_bytes = self._network_bytes(network)
        if header_len < 20 or header_len > len(network_bytes):
            raise UnhandledPacket('truncated IPv4 header')
        if network.len == 0:
            raise UnhandledPacket('zero IPv4 total length')
        if network.len < header_len:
            raise UnhandledPacket('invalid IPv4 total length')
        if network.len > len(network_bytes):
            raise UnhandledPacket('truncated IPv4 packet')
        if network.len != len(network_bytes):
            raise UnhandledPacket('invalid IPv4 total length')
        if network.mf or network.offset:
            raise UnhandledPacket('IPv4 fragments are not supported')
        header = bytes(network.pack_hdr()) + network.opts
        if dpkt.in_cksum(header) != 0:
            raise UnhandledPacket('invalid IPv4 header checksum')
        self._validate_transport(network, socket.AF_INET)

    def _validate_ipv6(self, network):
        if network.v != 6:
            raise UnhandledPacket('invalid IPv6 version')
        if network.plen == 0:
            raise UnhandledPacket('zero IPv6 payload length')
        network_bytes = self._network_bytes(network)
        if len(network_bytes) < 40 + network.plen:
            raise UnhandledPacket('truncated IPv6 packet')
        if len(network_bytes) != 40 + network.plen:
            raise UnhandledPacket('invalid IPv6 payload length')
        if getattr(network, 'all_extension_headers', None):
            raise UnhandledPacket('IPv6 extension headers are not supported')
        if network.nxt not in (ip.IP_PROTO_TCP, ip.IP_PROTO_UDP):
            raise UnhandledPacket('unsupported IPv6 transport protocol')
        self._validate_transport(network, socket.AF_INET6)

    def _validate_transport(self, network, family):
        transport = network.data
        ip_bytes = self._network_bytes(network)
        header_len = network.hl * 4 if family == socket.AF_INET else 40
        transport_bytes = bytes(transport)
        if isinstance(transport, tcp.TCP):
            transport_header_len = transport.off * 4
            if transport_header_len < 20 or transport_header_len > len(ip_bytes) - header_len:
                raise UnhandledPacket('truncated TCP header')
            if transport_header_len + len(transport.data) != len(ip_bytes) - header_len:
                raise UnhandledPacket('invalid TCP data offset')
            if transport.sum == 0:
                raise UnhandledPacket('missing TCP checksum')
        elif isinstance(transport, udp.UDP):
            transport_len = len(bytes(transport))
            if transport.ulen < 8 or transport.ulen > transport_len:
                raise UnhandledPacket('truncated UDP packet')
            if transport.ulen != transport_len:
                raise UnhandledPacket('invalid UDP length')
            if family == socket.AF_INET6 and transport.sum == 0:
                raise UnhandledPacket('missing IPv6 UDP checksum')
        else:
            raise UnhandledPacket('unsupported transport protocol')
        if transport.sum != 0:
            if self._raw_transport_checksum(network, transport_bytes) != 0:
                raise UnhandledPacket('invalid transport checksum')

    def _mapping_for(self, network):
        family = socket.AF_INET if isinstance(network, ip.IP) else socket.AF_INET6
        source = Endpoint(family, network.src, network.data.sport)
        destination = Endpoint(family, network.dst, network.data.dport)
        reverse = self._reverse.get(destination.key())
        if reverse == source.key():
            return self._mappings[source.key()]
        if reverse is not None:
            raise EndpointRewriteError('endpoint mapping collision')
        if source.key() in self._mappings:
            raise EndpointRewriteError('endpoint mapping collision')
        if source.key() in self._reverse:
            raise EndpointRewriteError('endpoint mapping collision')
        mapping = self.mapper(source, destination)
        if not isinstance(mapping, EndpointMapping):
            raise EndpointRewriteError('mapper must return EndpointMapping')
        if mapping.source.family != family or mapping.destination.family != family:
            raise EndpointRewriteError('mapper returned an invalid address family')
        flow = frozenset((source.key(), destination.key()))
        reverse_flow = frozenset((mapping.source.key(), mapping.destination.key()))
        if flow in self._flows or reverse_flow in self._flows:
            raise EndpointRewriteError('endpoint mapping collision')
        if mapping.source.key() in self._mappings or mapping.destination.key() in self._mappings:
            raise EndpointRewriteError('endpoint mapping collision')
        if mapping.source.key() in self._reverse or mapping.destination.key() in self._reverse:
            raise EndpointRewriteError('endpoint mapping collision')
        self._mappings[source.key()] = mapping
        self._mappings[destination.key()] = EndpointMapping(mapping.destination, mapping.source)
        self._flows.add(flow)
        self._flows.add(reverse_flow)
        self._reverse[destination.key()] = source.key()
        self._reverse[mapping.destination.key()] = mapping.source.key()
        self._reverse[source.key()] = destination.key()
        self._reverse[mapping.source.key()] = mapping.destination.key()
        return mapping

    def _apply_mapping(self, network, mapping):
        transport = network.data
        network.src = mapping.source.address
        network.dst = mapping.destination.address
        transport.sport = mapping.source.port
        transport.dport = mapping.destination.port
        self._refresh_lengths(network)
        if isinstance(network, ip.IP):
            network.sum = 0
            network.sum = dpkt.in_cksum(network.pack_hdr() + network.opts)
        if isinstance(transport, udp.UDP):
            if transport.sum == 0:
                return
        transport.sum = 0
        updated_transport = bytes(transport)
        transport.sum = self._calculate_transport_checksum(network, updated_transport)

    @staticmethod
    def _refresh_lengths(network):
        transport = network.data
        if isinstance(network, ip.IP):
            network.len = len(network.pack_hdr()) + len(network.opts) + len(bytes(transport))
        else:
            network.plen = len(bytes(transport))
        if isinstance(transport, udp.UDP):
            transport.ulen = len(bytes(transport))

    @staticmethod
    def _network_bytes(network):
        transport_bytes = bytes(network.data)
        if isinstance(network, ip.IP):
            return network.pack_hdr() + network.opts + transport_bytes
        return network.pack_hdr() + transport_bytes

    @classmethod
    def _packet_bytes(cls, eth, network):
        network_bytes = cls._network_bytes(network)
        if eth is None:
            return network_bytes
        return eth.pack_hdr() + network_bytes

    @classmethod
    def _calculate_transport_checksum(cls, network, transport_bytes):
        checksum = cls._raw_transport_checksum(network, transport_bytes)
        if checksum == 0:
            return 0xffff
        return checksum

    @staticmethod
    def _raw_transport_checksum(network, transport_bytes):
        if isinstance(network, ip.IP):
            pseudo = struct.pack('>4s4sxBH', network.src, network.dst, network.p, len(transport_bytes))
        else:
            pseudo = struct.pack('>16s16sxBH', network.src, network.dst, network.p, len(transport_bytes))
        checksum = dpkt.in_cksum_add(0, pseudo)
        checksum = dpkt.in_cksum_add(checksum, transport_bytes)
        return dpkt.in_cksum_done(checksum)
