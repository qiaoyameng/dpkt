# -*- coding: utf-8 -*-
from __future__ import absolute_import

import copy
import socket
import struct

import pytest

from . import endpoint_rewriter as rewriter
from . import ethernet
from . import ip
from . import ip6
from . import tcp
from . import udp


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while total > 0xffff:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def transport_checksum(src, dst, protocol, packet):
    if len(src) == 4:
        pseudo = struct.pack('>4s4sxBH', src, dst, protocol, len(packet))
    else:
        pseudo = struct.pack('>16s16sxBH', src, dst, protocol, len(packet))
    value = checksum(pseudo + packet)
    return value if value else 0xffff


def build_tcp(sport, dport, payload, options=b''):
    header = struct.pack('>HHIIHHHH', sport, dport, 100, 200, (5 + len(options) // 4) << 12,
                         8192, 0, 0) + options
    return header + payload


def build_udp(sport, dport, payload, checksum_value=0):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), checksum_value) + payload


def build_network(family, src, dst, protocol, transport):
    src = socket.inet_pton(family, src)
    dst = socket.inet_pton(family, dst)
    if family == socket.AF_INET:
        packet = ip.IP(src=src, dst=dst, p=protocol, data=transport)
        packet.len = 20 + len(transport)
        packet.sum = checksum(packet.pack_hdr())
        return packet
    packet = ip6.IP6(src=src, dst=dst, nxt=protocol, data=transport)
    packet.plen = len(transport)
    return packet


def build_frame(network, vlan=False):
    eth_type = ethernet.ETH_TYPE_IP6 if len(network.src) == 16 else ethernet.ETH_TYPE_IP
    frame = ethernet.Ethernet(dst=b'\x01\x02\x03\x04\x05\x06', src=b'\x0a\x0b\x0c\x0d\x0e\x0f')
    if vlan:
        frame.type = ethernet.ETH_TYPE_8021Q
        frame.vlan_tags = [ethernet.VLANtag8021Q(id=42, type=eth_type)]
    frame.data = network
    return bytes(frame)


def build_packet(family, transport_name, vlan=False, zero_udp_checksum=False, reverse=False):
    if family == socket.AF_INET:
        src = '10.1.1.10' if not reverse else '10.1.1.20'
        dst = '10.1.1.20' if not reverse else '10.1.1.10'
    else:
        src = '2001:db8::10' if not reverse else '2001:db8::20'
        dst = '2001:db8::20' if not reverse else '2001:db8::10'
    sport = 4000 if not reverse else 5000
    dport = 5000 if not reverse else 4000
    payload = b'endpoint-rewrite'
    protocol = ip.IP_PROTO_TCP if transport_name == 'tcp' else ip.IP_PROTO_UDP
    if transport_name == 'tcp':
        transport_bytes = build_tcp(sport, dport, payload, b'\x01\x01\x01\x01')
        transport = tcp.TCP(transport_bytes)
    else:
        transport_bytes = build_udp(sport, dport, payload)
        transport = udp.UDP(transport_bytes)
    network = build_network(family, src, dst, protocol, transport)
    if transport_name == 'tcp' or not zero_udp_checksum:
        transport.sum = transport_checksum(network.src, network.dst, protocol, transport_bytes)
    return build_frame(network, vlan=vlan)


def mapper(source, destination):
    if source.family == socket.AF_INET:
        return rewriter.EndpointMapping(
            rewriter.Endpoint(socket.AF_INET, '192.0.2.100', 6000),
            rewriter.Endpoint(socket.AF_INET, '198.51.100.200', 7000)
        )
    return rewriter.EndpointMapping(
        rewriter.Endpoint(socket.AF_INET6, '2001:db8:1::100', 6000),
        rewriter.Endpoint(socket.AF_INET6, '2001:db8:2::200', 7000)
    )


@pytest.mark.parametrize('family', [socket.AF_INET, socket.AF_INET6])
@pytest.mark.parametrize('transport_name', ['tcp', 'udp'])
@pytest.mark.parametrize('vlan', [False, True])
def test_rewrite_bidirectional_frames(family, transport_name, vlan):
    forward = build_packet(family, transport_name, vlan=vlan)
    reverse = build_packet(family, transport_name, vlan=vlan, reverse=True)
    calls = []

    def counting_mapper(source, destination):
        calls.append((source, destination))
        return mapper(source, destination)

    state = rewriter.EndpointRewriter(counting_mapper)
    forward_result = state.rewrite_frame(forward)
    reverse_result = state.rewrite_frame(reverse)
    repeat_result = state.rewrite_frame(forward)

    assert forward_result.status == rewriter.STATUS_REWRITTEN
    assert reverse_result.status == rewriter.STATUS_REWRITTEN
    assert repeat_result.bytes == forward_result.bytes
    assert len(calls) == 1

    parsed_forward = ethernet.Ethernet(forward_result.bytes)
    parsed_reverse = ethernet.Ethernet(reverse_result.bytes)
    if vlan:
        assert len(parsed_forward.vlan_tags) == 1
        assert parsed_forward.vlan_tags[0].id == 42

    assert parsed_forward.data.src == socket.inet_pton(family, '192.0.2.100' if family == socket.AF_INET else '2001:db8:1::100')
    assert parsed_forward.data.dst == socket.inet_pton(family, '198.51.100.200' if family == socket.AF_INET else '2001:db8:2::200')
    assert parsed_forward.data.data.sport == 6000
    assert parsed_forward.data.data.dport == 7000
    assert parsed_forward.data.data.data == b'endpoint-rewrite'

    assert parsed_reverse.data.src == parsed_forward.data.dst
    assert parsed_reverse.data.dst == parsed_forward.data.src
    assert parsed_reverse.data.data.sport == 7000
    assert parsed_reverse.data.data.dport == 6000
    assert parsed_reverse.data.data.data == b'endpoint-rewrite'


def test_rewrite_verifies_wire_checksums_and_preserves_input():
    frame = build_packet(socket.AF_INET, 'tcp')
    parsed = ethernet.Ethernet(frame)
    state = rewriter.EndpointRewriter(mapper)

    result = state.rewrite_packet(parsed)
    output = result.bytes
    rewritten = ethernet.Ethernet(output)

    assert bytes(parsed) == frame
    assert result.caplen_before == result.caplen_after == len(frame)
    assert result.wirelen_before == result.wirelen_after == len(frame)
    assert result.caplen_delta == 0
    assert result.wirelen_delta == 0
    assert checksum(rewritten.ip.pack_hdr()) == 0
    transport = bytes(rewritten.ip.data)
    zeroed_transport = transport[:16] + b'\x00\x00' + transport[18:]
    assert zeroed_transport[16:18] == b'\x00\x00'
    assert checksum(
        struct.pack('>4s4sxBH', rewritten.ip.src, rewritten.ip.dst, ip.IP_PROTO_TCP, len(transport)) + transport
    ) == 0
    assert len(zeroed_transport) == len(transport)
    expected = transport_checksum(rewritten.ip.src, rewritten.ip.dst, ip.IP_PROTO_TCP,
                                  zeroed_transport)
    assert rewritten.ip.data.sum == expected


def test_ipv4_udp_zero_checksum_is_preserved():
    frame = build_packet(socket.AF_INET, 'udp', zero_udp_checksum=True)
    result = rewriter.EndpointRewriter(mapper).rewrite_frame(frame)
    rewritten = ethernet.Ethernet(result.bytes)

    assert rewritten.ip.data.sum == 0
    assert rewritten.ip.data.data == b'endpoint-rewrite'


def test_ipv6_udp_zero_checksum_is_rejected():
    transport = build_udp(4000, 5000, b'endpoint-rewrite', 0)
    src = socket.inet_pton(socket.AF_INET6, '2001:db8::10')
    dst = socket.inet_pton(socket.AF_INET6, '2001:db8::20')
    network = struct.pack('>IHBB16s16s', 0x60000000, len(transport), ip.IP_PROTO_UDP, 64, src, dst)
    eth_header = b'\x01\x02\x03\x04\x05\x06\x0a\x0b\x0c\x0d\x0e\x0f' + struct.pack('>H', ethernet.ETH_TYPE_IP6)
    frame = eth_header + network + transport

    with pytest.raises(rewriter.UnhandledPacket):
        rewriter.EndpointRewriter(mapper).rewrite_frame(frame)

    marked = rewriter.EndpointRewriter(mapper, policy=rewriter.POLICY_MARK_UNHANDLED).rewrite_frame(frame)
    assert marked.status == rewriter.STATUS_UNHANDLED
    assert marked.bytes == frame
    assert marked.reason


def test_fragment_and_extension_headers_are_unhandled():
    fragment = build_packet(socket.AF_INET, 'udp')
    fragmented = ethernet.Ethernet(fragment)
    fragmented.ip.mf = 1

    extension = build_packet(socket.AF_INET6, 'udp')
    extended = ethernet.Ethernet(extension)

    class FakeExtension(object):
        nxt = ip.IP_PROTO_UDP
        length = 8

        def __bytes__(self):
            return b'\x11\x00' + b'\x00' * 6

    extended.ip6.all_extension_headers = [FakeExtension()]

    state = rewriter.EndpointRewriter(mapper, policy=rewriter.POLICY_MARK_UNHANDLED)
    fragment_result = state.rewrite_packet(fragmented)
    extension_result = state.rewrite_packet(extended)

    assert fragment_result.status == rewriter.STATUS_UNHANDLED
    assert extension_result.status == rewriter.STATUS_UNHANDLED


def test_qinq_vlan_is_preserved_and_short_frames_are_unhandled():
    packet = ethernet.Ethernet(build_packet(socket.AF_INET, 'tcp', vlan=True))
    packet.vlan_tags = [
        packet.vlan_tags[0],
        ethernet.VLANtag8021Q(id=7, type=ethernet.ETH_TYPE_IP)
    ]
    result = rewriter.EndpointRewriter(mapper).rewrite_packet(packet)
    rewritten = ethernet.Ethernet(result.bytes)

    assert result.status == rewriter.STATUS_REWRITTEN
    assert [tag.id for tag in rewritten.vlan_tags] == [42, 7]
    assert rewritten.ip.data.sport == 6000

    frame = build_packet(socket.AF_INET, 'tcp')
    marked = rewriter.EndpointRewriter(mapper, policy=rewriter.POLICY_MARK_UNHANDLED)
    short_result = marked.rewrite_frame(frame[:13], caplen=13, wirelen=len(frame))

    assert short_result.status == rewriter.STATUS_UNHANDLED
    assert short_result.bytes == frame[:13]
    assert short_result.caplen_before == 13
    assert short_result.caplen_after == 13
    assert short_result.wirelen_before == len(frame)
    assert short_result.wirelen_after == len(frame)

    with pytest.raises(rewriter.UnhandledPacket):
        rewriter.EndpointRewriter(mapper).rewrite_frame(frame[:13], caplen=13, wirelen=len(frame))


def test_truncated_and_offload_packets_are_unhandled():
    frame = build_packet(socket.AF_INET, 'tcp')
    truncated = frame[:-1]
    zero_len = ethernet.Ethernet(frame)
    zero_len.ip.len = 0

    state = rewriter.EndpointRewriter(mapper, policy=rewriter.POLICY_MARK_UNHANDLED)
    truncated_result = state.rewrite_frame(truncated, caplen=len(truncated), wirelen=len(frame))
    zero_len_result = state.rewrite_packet(zero_len)

    assert truncated_result.status == rewriter.STATUS_UNHANDLED
    assert truncated_result.bytes == truncated
    assert truncated_result.caplen_before == len(truncated)
    assert truncated_result.wirelen_before == len(frame)
    assert truncated_result.caplen_after == len(truncated)
    assert truncated_result.wirelen_after == len(frame)
    assert zero_len_result.status == rewriter.STATUS_UNHANDLED


def test_mapping_collision_and_invalid_address_raise_before_delivery():
    frame = build_packet(socket.AF_INET, 'tcp')
    state = rewriter.EndpointRewriter(mapper)
    state.rewrite_frame(frame)

    def colliding(source, destination):
        return rewriter.EndpointMapping(
            rewriter.Endpoint(socket.AF_INET, '192.0.2.100', 6000),
            rewriter.Endpoint(socket.AF_INET, '203.0.113.9', 9000)
        )

    colliding_packet = ethernet.Ethernet(build_packet(socket.AF_INET, 'tcp'))
    colliding_packet.ip.src = socket.inet_pton(socket.AF_INET, '10.2.2.2')
    colliding_packet.ip.sum = 0
    colliding_packet.ip.sum = checksum(colliding_packet.ip.pack_hdr())
    colliding_packet.ip.data.sum = transport_checksum(
        colliding_packet.ip.src, colliding_packet.ip.dst, ip.IP_PROTO_TCP,
        bytes(colliding_packet.ip.data)[:16] + b'\x00\x00' + bytes(colliding_packet.ip.data)[18:]
    )
    with pytest.raises(rewriter.EndpointRewriteError):
        state.rewrite_packet(colliding_packet)

    def invalid(source, destination):
        return rewriter.EndpointMapping(
            rewriter.Endpoint(socket.AF_INET, b'\x01\x02\x03', 6000),
            rewriter.Endpoint(socket.AF_INET, '198.51.100.200', 7000)
        )

    with pytest.raises(rewriter.EndpointRewriteError):
        rewriter.EndpointRewriter(invalid).rewrite_frame(frame)


def test_failed_mapping_keeps_input_and_session_state_unchanged():
    frame = build_packet(socket.AF_INET, 'tcp')
    packet = ethernet.Ethernet(frame)
    snapshot = copy.deepcopy(packet)
    state = rewriter.EndpointRewriter(mapper)
    state.rewrite_frame(frame)
    mapping_count = len(state._mappings)

    colliding_packet = ethernet.Ethernet(build_packet(socket.AF_INET, 'tcp'))
    colliding_packet.ip.src = socket.inet_pton(socket.AF_INET, '10.9.9.9')
    colliding_packet.ip.sum = 0
    colliding_packet.ip.sum = checksum(colliding_packet.ip.pack_hdr())
    transport = bytes(colliding_packet.ip.data)
    colliding_packet.ip.data.sum = transport_checksum(
        colliding_packet.ip.src, colliding_packet.ip.dst, ip.IP_PROTO_TCP,
        transport[:16] + b'\x00\x00' + transport[18:]
    )

    with pytest.raises(rewriter.EndpointRewriteError):
        state.rewrite_packet(colliding_packet)

    assert bytes(packet) == bytes(snapshot) == frame
    assert len(state._mappings) == mapping_count


def test_truncated_transport_headers_and_string_endpoints_are_handled():
    tcp_packet = ethernet.Ethernet(build_packet(socket.AF_INET, 'tcp'))
    tcp_packet.ip.data.off = 4
    udp_packet = ethernet.Ethernet(build_packet(socket.AF_INET, 'udp'))
    udp_packet.ip.data.ulen = 7

    state = rewriter.EndpointRewriter(mapper, policy=rewriter.POLICY_MARK_UNHANDLED)
    tcp_result = state.rewrite_packet(tcp_packet)
    udp_result = state.rewrite_packet(udp_packet)

    assert tcp_result.status == rewriter.STATUS_UNHANDLED
    assert udp_result.status == rewriter.STATUS_UNHANDLED

    def string_mapper(source, destination):
        return rewriter.EndpointMapping(
            rewriter.Endpoint(socket.AF_INET, '192.0.2.100', 6000),
            rewriter.Endpoint(socket.AF_INET, '198.51.100.200', 7000)
        )

    result = rewriter.EndpointRewriter(string_mapper).rewrite_frame(build_packet(socket.AF_INET, 'udp'))
    rewritten = ethernet.Ethernet(result.bytes)
    assert rewritten.ip.src == socket.inet_pton(socket.AF_INET, '192.0.2.100')


def test_bad_checksum_is_not_rewritten():
    frame = bytearray(build_packet(socket.AF_INET, 'tcp'))
    frame[40] ^= 0xff

    with pytest.raises(rewriter.EndpointRewriteError):
        rewriter.EndpointRewriter(mapper).rewrite_frame(bytearray(build_packet(socket.AF_INET, 'tcp')))

    with pytest.raises(rewriter.UnhandledPacket):
        rewriter.EndpointRewriter(mapper).rewrite_frame(bytes(frame))

    result = rewriter.EndpointRewriter(mapper, policy=rewriter.POLICY_MARK_UNHANDLED).rewrite_frame(bytes(frame))
    assert result.status == rewriter.STATUS_UNHANDLED
    assert result.bytes == bytes(frame)
