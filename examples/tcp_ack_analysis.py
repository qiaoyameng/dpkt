# -*- coding: utf-8 -*-
"""Offline TCP acknowledgment analysis demo (no real connection needed).

Feeds hand-built :class:`dpkt.tcpack.Packet` records of one connection
in capture order and prints the per-step in-flight ranges, SACK state,
statistic deltas and the RTT samples that survive Karn's rule.

Scenarios:
  1. 32 bit sequence wrap-around
  2. overlapping retransmission + RTT ambiguity
  3. out-of-order / duplicate / SACK ACKs
  4. short capture with the handshake missing
"""
from __future__ import print_function

from dpkt import tcpack


def banner(title):
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)


def scenario_wraparound():
    banner('场景 1：序号 32 位回绕')
    isn = 0xFFFFFFF0
    packets = [
        tcpack.Packet(0, 0.000, isn, flags='S'),
        tcpack.Packet(1, 0.001, 100, ack=tcpack.to_u32(isn + 1), flags='SA'),
        tcpack.Packet(0, 0.002, tcpack.to_u32(isn + 1), ack=101, flags='A'),
        # 20 data bytes straddle the wrap boundary
        tcpack.Packet(0, 0.003, tcpack.to_u32(isn + 1),
                      flags='PA', length=20),
        # receiver SACKs the post-wrap tail, ACK edge stays pre-wrap
        tcpack.Packet(1, 0.004, 101,
                      ack=tcpack.to_u32(isn + 6),
                      flags='A',
                      sacks=[(0x00000000, 0x00000005)]),
        tcpack.Packet(1, 0.005, 101,
                      ack=tcpack.to_u32(isn + 21), flags='A'),
    ]
    return tcpack.analyze(packets, labels=('客户端', '服务器'))


def scenario_overlapping_retransmit():
    banner('场景 2：重叠重传与 RTT 歧义（Karn）')
    packets = [
        tcpack.Packet(0, 0.000, 1000, flags='S'),
        tcpack.Packet(1, 0.001, 2000, ack=1001, flags='SA'),
        tcpack.Packet(0, 0.002, 1001, ack=2001, flags='A'),
        tcpack.Packet(0, 0.003, 1001, flags='PA', length=100),
        tcpack.Packet(1, 0.004, 2001, ack=1051, flags='A'),
        # 30-byte tail gap is lost and retransmitted after a timeout
        tcpack.Packet(0, 0.020, 1071, flags='PA', length=30),
        # SACK tells the sender the retransmitted data actually arrived
        tcpack.Packet(1, 0.021, 2001, ack=1051, flags='A',
                      sacks=[(1071, 1101)]),
        # cumulative ACK covers a window containing a retransmitted byte
        tcpack.Packet(1, 0.022, 2001, ack=1101, flags='A'),
    ]
    return tcpack.analyze(packets)


def scenario_reordered_acks():
    banner('场景 3：乱序 ACK、重复 ACK 与新 SACK')
    packets = [
        tcpack.Packet(0, 0.000, 100, flags='S'),
        tcpack.Packet(1, 0.001, 50, ack=101, flags='SA'),
        tcpack.Packet(0, 0.002, 101, ack=51, flags='A'),
        tcpack.Packet(0, 0.003, 101, flags='PA', length=100),
        tcpack.Packet(1, 0.004, 51, ack=111, flags='A'),
        tcpack.Packet(1, 0.006, 51, ack=111, flags='A'),
        tcpack.Packet(1, 0.007, 51, ack=111, flags='A',
                      sacks=[(121, 151)]),
        # an old ACK delivered out of capture/network order
        tcpack.Packet(1, 0.008, 51, ack=101, flags='A'),
        tcpack.Packet(1, 0.009, 51, ack=151, flags='A'),
    ]
    return tcpack.analyze(packets)


def scenario_missing_handshake():
    banner('场景 4：缺少握手的短序列')
    packets = [
        # capture started mid-connection; first observed packet has data
        tcpack.Packet(0, 0.000, 5000, flags='PA', length=10),
        # ACK covers 5 bytes sent before the capture window
        tcpack.Packet(1, 0.001, 9000, ack=5005, flags='A'),
        # ACK then jumps beyond anything we observed
        tcpack.Packet(1, 0.002, 9000, ack=7000, flags='A'),
        tcpack.Packet(0, 0.003, 5010, flags='PA', length=5),
    ]
    return tcpack.analyze(packets)


def main():
    for builder in (scenario_wraparound,
                    scenario_overlapping_retransmit,
                    scenario_reordered_acks,
                    scenario_missing_handshake):
        analyzer = builder()
        print(tcpack.render_steps(analyzer.steps))
        print(tcpack.render_rtt(analyzer))


if __name__ == '__main__':
    main()
