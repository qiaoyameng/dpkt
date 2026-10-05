"""Offline TCP acknowledgement / in-flight analysis demo.

Runs a synthetic, capture-ordered connection through
``dpkt.tcpack.TcpAckAnalyzer`` and prints, after every segment, the in-flight
sequence ranges and the running counters.  The trace exercises sequence
number wrap-around, an overlapping retransmission (Karn-ambiguous RTT),
duplicate ACKs with SACK, SACK reneging and a handshake-truncated short
sequence -- all without opening a real TCP socket.

Pass a pcap/pcap-ng filename to analyse real traffic instead::

    python tcp_inflight_analysis.py [capture.pcap]
"""
from __future__ import absolute_import, print_function

import sys

import dpkt
from dpkt import tcp as _tcp
from dpkt import tcpack


def synthetic_trace():
    """Build the analyzer feed for a hand-crafted connection."""
    an = tcpack.TcpAckAnalyzer()

    # ISN close to 2**32 so the first data segment wraps.
    isn = (1 << 32) - 4

    an.feed(0.000, side=0, seq=isn, flags=_tcp.TH_SYN)
    an.feed(0.010, side=1, seq=7000, ack=(isn + 1) & 0xffffffff,
            flags=_tcp.TH_SYN | _tcp.TH_ACK)
    an.feed(0.020, side=0, seq=(isn + 1) & 0xffffffff, ack=7001,
            flags=_tcp.TH_ACK)

    # 10 payload bytes straddle the wrap boundary: 0xfffffffc..0 then 0..6.
    an.feed(0.030, side=0, seq=(isn + 1) & 0xffffffff, ack=7001,
            flags=_tcp.TH_ACK | _tcp.TH_PUSH, payload=b'0123456789')
    an.feed(0.040, side=0, seq=10, ack=7001,
            flags=_tcp.TH_ACK | _tcp.TH_PUSH, payload=b'abcdefghij')

    # First segment is lost on the wire: dup ACK + SACK of [10,20).
    sack = (10).to_bytes(4, 'big') + (20).to_bytes(4, 'big')
    opts = bytes([_tcp.TCP_OPT_SACK, 2 + len(sack)]) + sack
    an.feed(0.060, side=1, seq=7001, ack=6, flags=_tcp.TH_ACK, opts=opts)
    an.feed(0.070, side=1, seq=7001, ack=6, flags=_tcp.TH_ACK)

    # Retransmit the first (wrapped) segment at 0.080: its RTT must never be
    # sampled because the send time is now ambiguous.
    an.feed(0.080, side=0, seq=(isn + 1) & 0xffffffff, ack=7001,
            flags=_tcp.TH_ACK, payload=b'0123456789')

    # Cumulative ACK of everything retires the scoreboard and the data.
    an.feed(0.120, side=1, seq=7001, ack=20, flags=_tcp.TH_ACK)
    return an


def main(argv):
    if len(argv) > 1:
        an = tcpack.analyze_pcap(argv[1])
    else:
        an = synthetic_trace()
    print(an.render_all())
    print('\nFinal statistics:')
    for side, stats in enumerate(an.stats()):
        if stats is None:
            continue
        print('  side%d: sent=%d retrans=%d acked=%d dup_acks=%d '
              'backward_acks=%d sack_reneges=%d rtt=%s uncertain=%s' % (
                  side, stats['data_bytes_sent'],
                  stats['data_bytes_retrans'],
                  stats['bytes_acknowledged'],
                  stats['acks_duplicate'], stats['acks_backward'],
                  stats['sack_reneges'],
                  ['%.3f' % r for r in stats['rtt_samples']],
                  stats['uncertain']))


def test_synthetic_trace():
    an = synthetic_trace()
    stats = an.stats(0)
    assert stats['inflight_bytes'] == 0
    assert stats['data_bytes_retrans'] == 10
    # Two data RTTs are legal: the tail of the first segment and the second
    # segment were acknowledged at 0.060, before the 0.080 retransmission.
    # The final ACK at 0.120 adds no RTT for the retransmitted bytes
    # (Karn's rule); the two SYN RTTs are control samples.
    data_rtts = [s for st in an.steps if st['ack_event']
                 for s in st['ack_event']['new_rtt_samples']
                 if s['kind'] in ('cumulative', 'sack')]
    assert len(data_rtts) == 2
    assert not [s for s in an.steps[-1]['ack_event']['new_rtt_samples']
                if s['kind'] == 'cumulative']


if __name__ == '__main__':
    main(sys.argv)
