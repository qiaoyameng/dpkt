# $Id: rtp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Real-Time Transport Protocol."""
from __future__ import absolute_import

from .dpkt import Packet
from . import rtcp

# version 1100 0000 0000 0000 ! 0xC000  14
# p       0010 0000 0000 0000 ! 0x2000  13
# x       0001 0000 0000 0000 ! 0x1000  12
# cc      0000 1111 0000 0000 ! 0x0F00   8
# m       0000 0000 1000 0000 ! 0x0080   7
# pt      0000 0000 0111 1111 ! 0x007F   0
#

_VERSION_MASK = 0xC000
_P_MASK = 0x2000
_X_MASK = 0x1000
_CC_MASK = 0x0F00
_M_MASK = 0x0080
_PT_MASK = 0x007F
_VERSION_SHIFT = 14
_P_SHIFT = 13
_X_SHIFT = 12
_CC_SHIFT = 8
_M_SHIFT = 7
_PT_SHIFT = 0

VERSION = 2


class RTP(Packet):
    """Real-Time Transport Protocol.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of RTP.
        TODO.
    """

    __hdr__ = (
        ('_type', 'H', 0x8000),
        ('seq', 'H', 0),
        ('ts', 'I', 0),
        ('ssrc', 'I', 0),
    )
    csrc = b''

    @property
    def version(self):
        return (self._type & _VERSION_MASK) >> _VERSION_SHIFT

    @version.setter
    def version(self, ver):
        self._type = (ver << _VERSION_SHIFT) | (self._type & ~_VERSION_MASK)

    @property
    def p(self):
        return (self._type & _P_MASK) >> _P_SHIFT

    @p.setter
    def p(self, p):
        self._type = (p << _P_SHIFT) | (self._type & ~_P_MASK)

    @property
    def x(self):
        return (self._type & _X_MASK) >> _X_SHIFT

    @x.setter
    def x(self, x):
        self._type = (x << _X_SHIFT) | (self._type & ~_X_MASK)

    @property
    def cc(self):
        return (self._type & _CC_MASK) >> _CC_SHIFT

    @cc.setter
    def cc(self, cc):
        self._type = (cc << _CC_SHIFT) | (self._type & ~_CC_MASK)

    @property
    def m(self):
        return (self._type & _M_MASK) >> _M_SHIFT

    @m.setter
    def m(self, m):
        self._type = (m << _M_SHIFT) | (self._type & ~_M_MASK)

    @property
    def pt(self):
        return (self._type & _PT_MASK) >> _PT_SHIFT

    @pt.setter
    def pt(self, m):
        self._type = (m << _PT_SHIFT) | (self._type & ~_PT_MASK)

    def __len__(self):
        return self.__hdr_len__ + len(self.csrc) + len(self.data)

    def __bytes__(self):
        return self.pack_hdr() + self.csrc + bytes(self.data)

    def unpack(self, buf):
        super(RTP, self).unpack(buf)
        self.csrc = buf[self.__hdr_len__:self.__hdr_len__ + self.cc * 4]
        self.data = buf[self.__hdr_len__ + self.cc * 4:]


# RFC 3550 receiver-side sequence number validation (appendix A.3).
SEQ_MOD = 1 << 16
MAX_DROPOUT = 3000
MAX_MISORDER = 100
MIN_SEQUENTIAL = 2


class RxState(object):
    """Per-SSRC RTP reception statistics (RFC 3550 sec. 6.4.1).

    Tracks everything needed to fill in an RTCP receiver report block for
    one synchronization source: cumulative and fractional packet loss, the
    extended highest sequence number received, interarrival jitter
    (RFC 3550 appendix A.8) and LSR/DLSR from sender reports. Sequence
    number validation follows RFC 3550 appendix A.3, including the initial
    probation phase, 16-bit wraparound, large jumps and source restarts;
    duplicate or late packets are not counted as new in-order packets.

    All timing is driven by the caller: packet arrival times are passed to
    process() as monotonic timestamps in seconds and converted to RTP
    timestamp units using the clock rate given at construction.
    """

    def __init__(self, ssrc, clock_rate):
        self.ssrc = ssrc
        self.clock_rate = clock_rate
        self.probation = 0
        self.started = False
        self.base_seq = 0
        self.max_seq = 0
        self.bad_seq = SEQ_MOD + 1
        self.cycles = 0
        self.received = 0
        self.received_prior = 0
        self.expected_prior = 0
        self._jitter = 0.0
        self._transit = None
        self.lsr = 0
        self._last_sr_ntp = None

    def _init_seq(self, seq):
        self.base_seq = seq
        self.max_seq = seq
        self.bad_seq = SEQ_MOD + 1  # so seq == bad_seq is false
        self.cycles = 0
        self.received = 0
        self.received_prior = 0
        self.expected_prior = 0

    def _update_seq(self, seq):
        """RFC 3550 appendix A.3; True if the packet counts as received."""
        udelta = (seq - self.max_seq) & 0xFFFF
        if self.probation:
            # probation phase: only sequential packets are accepted
            if seq == (self.max_seq + 1) & 0xFFFF:
                self.probation -= 1
                self.max_seq = seq
                if self.probation == 0:
                    self._init_seq(seq)
                    self.received += 1
                    return True
            else:
                self.probation = MIN_SEQUENTIAL - 1
                self.max_seq = seq
            return False
        elif udelta == 0:
            # exact duplicate of the highest sequence number seen
            return False
        elif udelta < MAX_DROPOUT:
            # in order, with permissible gap
            if seq < self.max_seq:
                # sequence number wrapped - count another 64K cycle
                self.cycles += SEQ_MOD
            self.max_seq = seq
        elif udelta <= SEQ_MOD - MAX_MISORDER:
            # the sequence number made a very large jump
            if seq == self.bad_seq:
                # two sequential packets -- assume the other side restarted
                self._init_seq(seq)
            else:
                self.bad_seq = (seq + 1) & 0xFFFF
                return False
        else:
            # duplicate or reordered packet
            return False
        self.received += 1
        return True

    def process(self, packet, arrival):
        """Update statistics for one received RTP packet.

        packet must expose seq/ts/ssrc attributes (e.g. dpkt.rtp.RTP);
        arrival is a monotonic timestamp in seconds. Returns True if the
        packet was accepted as a new in-order packet.
        """
        if not self.started:
            self.started = True
            self._init_seq(packet.seq)
            self.probation = MIN_SEQUENTIAL
            return False
        if not self._update_seq(packet.seq):
            return False
        # interarrival jitter, RFC 3550 appendix A.8
        transit = int(arrival * self.clock_rate) - packet.ts
        if self._transit is not None:
            d = transit - self._transit
            if d < 0:
                d = -d
            self._jitter += (d - self._jitter) / 16.0
        self._transit = transit
        return True

    @property
    def extended_max_seq(self):
        return self.cycles + self.max_seq

    @property
    def expected(self):
        return self.extended_max_seq - self.base_seq + 1

    @property
    def lost(self):
        return self.expected - self.received

    @property
    def jitter(self):
        return int(self._jitter)

    def note_sender_report(self, ntp_msw, ntp_lsw, arrival_ntp):
        """Record the NTP timestamp of the most recent RTCP sender report.

        ntp_msw/ntp_lsw are the two halves of the 64-bit NTP timestamp from
        the SR sender info; arrival_ntp is the local time at which the SR
        was received, as a 64-bit NTP fixed-point timestamp. Both feed the
        LSR/DLSR fields of the next report block.
        """
        self.lsr = ((ntp_msw & 0xFFFF) << 16) | (ntp_lsw >> 16)
        self._last_sr_ntp = arrival_ntp

    def report_block(self, now_ntp=None):
        """Build an rtcp.Report block from the current statistics.

        now_ntp is the current local time as a 64-bit NTP fixed-point
        timestamp, used to compute DLSR; it may be omitted when no sender
        report has been seen. Fraction lost is computed over the interval
        since the previous call, per RFC 3550 sec. 6.4.1.
        """
        expected = self.expected
        expected_interval = expected - self.expected_prior
        self.expected_prior = expected
        received_interval = self.received - self.received_prior
        self.received_prior = self.received
        lost_interval = expected_interval - received_interval
        if expected_interval == 0 or lost_interval <= 0:
            fraction = 0
        else:
            fraction = (lost_interval << 8) // expected_interval
            if fraction > 0xFF:
                # total interval loss (e.g. still in probation) does not
                # fit the 8-bit fixed-point field; clamp to 255/256
                fraction = 0xFF
        lost = self.lost
        if lost < 0:
            lost = 0
        elif lost > 0xFFFFFF:
            lost = 0xFFFFFF
        if self._last_sr_ntp is None or now_ntp is None:
            dlsr = 0
        else:
            dlsr = (now_ntp - self._last_sr_ntp) >> 16
        return rtcp.Report(
            ssrc=self.ssrc,
            lossfrac=fraction,
            losscumm=lost,
            seq=self.extended_max_seq,
            jitter=int(self._jitter),
            lsr=self.lsr,
            dlsr=dlsr,
        )


class RxTable(object):
    """RTP reception statistics for multiple sources, keyed by SSRC."""

    def __init__(self, clock_rate):
        self.clock_rate = clock_rate
        self.sources = {}

    def process(self, packet, arrival):
        state = self.sources.get(packet.ssrc)
        if state is None:
            state = self.sources[packet.ssrc] = RxState(packet.ssrc, self.clock_rate)
        return state.process(packet, arrival)

    def report_blocks(self, now_ntp=None):
        return [state.report_block(now_ntp) for state in self.sources.values()]


def test_rtp():
    rtp = RTP(
        b'\x80\x08\x4d\x01\x00\x01\x00\xe0\x34\x3f\xfa\x34\x53\x53\x53\x56\x53\x5d\x56\x57\xd5\xd6'
        b'\xd1\xde\xdf\xd3\xd9\xda\xdf\xdc\xdf\xd8\xdd\xd4\xdd\xd9\xd1\xd6\xdc\xda\xde\xdd\xc7\xc1'
        b'\xdf\xdf\xda\xdb\xdd\xdd\xc4\xd9\x55\x57\xd4\x50\x44\x44\x5b\x44\x4f\x4c\x47\x40\x4c\x47'
        b'\x59\x5b\x58\x5d\x56\x56\x53\x56\xd5\xd5\x54\x55\xd6\xd6\xd4\xd1\xd1\xd0\xd1\xd5\xdd\xd6'
        b'\x55\xd4\xd6\xd1\xd4\xd6\xd7\xd7\xd5\xd4\xd0\xd7\xd1\xd4\xd2\xdc\xd6\xdc\xdf\xdc\xdd\xd2'
        b'\xde\xdc\xd0\xdd\xdc\xd0\xd6\xd6\xd6\x55\x54\x55\x57\x57\x56\x50\x50\x5c\x5c\x52\x5d\x5d'
        b'\x5f\x5e\x5d\x5e\x52\x50\x52\x56\x54\x57\x55\x55\xd4\xd7\x55\xd5\x55\x55\x55\x55\x55\x54'
        b'\x57\x54\x55\x55\xd5\xd5\xd7\xd6\xd7\xd1\xd1\xd3\xd2\xd3\xd2\xd2\xd3\xd3'
    )
    assert (rtp.version == 2)
    assert (rtp.p == 0)
    assert (rtp.x == 0)
    assert (rtp.cc == 0)
    assert (rtp.m == 0)
    assert (rtp.pt == 8)
    assert (rtp.seq == 19713)
    assert (rtp.ts == 65760)
    assert (rtp.ssrc == 0x343ffa34)
    assert (len(rtp) == 172)
    assert (bytes(rtp) == (
        b'\x80\x08\x4d\x01\x00\x01\x00\xe0\x34\x3f\xfa\x34\x53\x53\x53\x56\x53\x5d\x56\x57\xd5\xd6'
        b'\xd1\xde\xdf\xd3\xd9\xda\xdf\xdc\xdf\xd8\xdd\xd4\xdd\xd9\xd1\xd6\xdc\xda\xde\xdd\xc7\xc1'
        b'\xdf\xdf\xda\xdb\xdd\xdd\xc4\xd9\x55\x57\xd4\x50\x44\x44\x5b\x44\x4f\x4c\x47\x40\x4c\x47'
        b'\x59\x5b\x58\x5d\x56\x56\x53\x56\xd5\xd5\x54\x55\xd6\xd6\xd4\xd1\xd1\xd0\xd1\xd5\xdd\xd6'
        b'\x55\xd4\xd6\xd1\xd4\xd6\xd7\xd7\xd5\xd4\xd0\xd7\xd1\xd4\xd2\xdc\xd6\xdc\xdf\xdc\xdd\xd2'
        b'\xde\xdc\xd0\xdd\xdc\xd0\xd6\xd6\xd6\x55\x54\x55\x57\x57\x56\x50\x50\x5c\x5c\x52\x5d\x5d'
        b'\x5f\x5e\x5d\x5e\x52\x50\x52\x56\x54\x57\x55\x55\xd4\xd7\x55\xd5\x55\x55\x55\x55\x55\x54'
        b'\x57\x54\x55\x55\xd5\xd5\xd7\xd6\xd7\xd1\xd1\xd3\xd2\xd3\xd2\xd2\xd3\xd3'
    ))

    # the following tests RTP header setters
    rtp = RTP()
    rtp.m = 1
    rtp.pt = 3
    rtp.seq = 1234
    rtp.ts = 5678
    rtp.ssrc = 0xabcdef01
    assert (rtp.m == 1)
    assert (rtp.pt == 3)
    assert (rtp.seq == 1234)
    assert (rtp.ts == 5678)
    assert (rtp.ssrc == 0xabcdef01)


def test_rtp_properties():
    from .compat import compat_izip

    rtp = RTP()
    properties = ['version', 'p', 'x', 'cc', 'm', 'pt']
    defaults = [2, 0, 0, 0, 0, 0]
    for prop, default in compat_izip(properties, defaults):
        assert hasattr(rtp, prop)
        assert getattr(rtp, prop) == default
        setattr(rtp, prop, 1)
        assert getattr(rtp, prop) == 1


def _rx_packet(seq, ts, ssrc=0x01020304):
    return RTP(seq=seq, ts=ts, ssrc=ssrc)


def test_rxstate_probation():
    st = RxState(0x01020304, 8000)
    # the first packet only starts the probation phase
    assert st.process(_rx_packet(100, 0), 0.0) is False
    assert st.probation == MIN_SEQUENTIAL
    # one sequential packet is not enough yet
    assert st.process(_rx_packet(101, 160), 0.02) is False
    # the second sequential packet completes probation and is counted
    assert st.process(_rx_packet(102, 320), 0.04) is True
    assert st.probation == 0
    assert st.received == 1
    assert st.base_seq == 102
    assert st.process(_rx_packet(103, 480), 0.06) is True
    assert st.process(_rx_packet(104, 640), 0.08) is True
    rb = st.report_block()
    assert rb.ssrc == 0x01020304
    assert rb.seq == 104
    assert rb.lossfrac == 0
    assert rb.losscumm == 0
    assert rb.jitter == 0

    # a non-sequential packet during probation restarts the phase
    st = RxState(0x01020304, 8000)
    assert st.process(_rx_packet(100, 0), 0.0) is False
    assert st.process(_rx_packet(105, 160), 0.02) is False
    assert st.probation == MIN_SEQUENTIAL - 1
    assert st.max_seq == 105
    assert st.process(_rx_packet(106, 320), 0.04) is True
    assert st.base_seq == 106
    assert st.received == 1


def test_rxstate_loss_and_fraction():
    st = RxState(0x01020304, 8000)
    for seq in range(1000, 1010):
        st.process(_rx_packet(seq, (seq - 1000) * 160), (seq - 1000) * 0.02)
    rb = st.report_block()
    assert rb.seq == 1009
    assert rb.losscumm == 0
    assert rb.lossfrac == 0
    # packets 1010 and 1011 never arrive
    for seq in range(1012, 1020):
        st.process(_rx_packet(seq, (seq - 1000) * 160), (seq - 1000) * 0.02)
    rb = st.report_block()
    assert rb.seq == 1019
    assert rb.losscumm == 2
    # 2 of the 10 packets expected in this interval were lost
    assert rb.lossfrac == (2 << 8) // 10  # 51
    assert bytes(rb) == (
        b'\x01\x02\x03\x04\x33\x00\x00\x02\x00\x00\x03\xfb'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    )
    # no new packets: interval fraction drops to 0, cumulative stays
    rb = st.report_block()
    assert rb.lossfrac == 0
    assert rb.losscumm == 2


def test_rxstate_wraparound():
    st = RxState(0x01020304, 8000)
    for i, seq in enumerate([65533, 65534, 65535, 0, 1, 2]):
        st.process(_rx_packet(seq, i * 160), i * 0.02)
    # probation completed at 65535; the wrap to 0 counts one 64K cycle
    assert st.cycles == SEQ_MOD
    assert st.max_seq == 2
    assert st.received == 4
    rb = st.report_block()
    assert rb.seq == SEQ_MOD + 2  # extended highest sequence number
    assert rb.losscumm == 0
    assert rb.lossfrac == 0


def test_rxstate_large_jump_and_restart():
    st = RxState(0x01020304, 8000)
    for i, seq in enumerate([100, 101, 102, 103, 104]):
        st.process(_rx_packet(seq, i * 160), i * 0.02)
    assert st.received == 3
    # a jump smaller than MAX_DROPOUT is an in-order gap: packets are lost
    assert st.process(_rx_packet(2000, 5 * 160), 5 * 0.02) is True
    assert st.max_seq == 2000
    assert st.lost == 2000 - 102 + 1 - 4  # 1895
    # a jump larger than MAX_DROPOUT only arms the restart detector
    assert st.process(_rx_packet(6000, 6 * 160), 6 * 0.02) is False
    assert st.max_seq == 2000
    assert st.received == 4
    # a second, sequential packet confirms a restart and reinitializes
    assert st.process(_rx_packet(6001, 7 * 160), 7 * 0.02) is True
    assert st.base_seq == 6001
    assert st.max_seq == 6001
    assert st.received == 1
    rb = st.report_block()
    assert rb.seq == 6001
    assert rb.losscumm == 0


def test_rxstate_duplicate_and_late():
    st = RxState(0x01020304, 8000)
    for i, seq in enumerate([100, 101, 102, 103, 104]):
        st.process(_rx_packet(seq, i * 160), i * 0.02)
    assert st.received == 3
    # a late packet, older than max_seq - MAX_MISORDER, is ignored
    assert st.process(_rx_packet(50, 8 * 160), 8 * 0.02) is False
    # a duplicate of a recent packet is ignored as well
    assert st.process(_rx_packet(103, 9 * 160), 9 * 0.02) is False
    # and so is an exact retransmission of the highest sequence number
    assert st.process(_rx_packet(104, 10 * 160), 10 * 0.02) is False
    assert st.received == 3
    assert st.max_seq == 104
    rb = st.report_block()
    assert rb.seq == 104
    assert rb.losscumm == 0
    assert rb.lossfrac == 0


def test_rxstate_jitter():
    st = RxState(0x01020304, 8000)
    st.process(_rx_packet(10, 0), 0.0)
    st.process(_rx_packet(11, 160), 0.02)
    st.process(_rx_packet(12, 320), 0.04)  # first counted packet, transit 0
    assert st.jitter == 0
    # arrives 10 ms late: transit = 0.07 * 8000 - 480 = 80, d = 80
    st.process(_rx_packet(13, 480), 0.07)
    assert st.jitter == 5  # 0 + (80 - 0) / 16
    # same 10 ms delay again: d = 0, jitter = 5 + (0 - 5) / 16 = 4.6875
    st.process(_rx_packet(14, 640), 0.09)
    assert st.jitter == 4
    rb = st.report_block()
    assert rb.jitter == 4


def test_rxstate_lsr_dlsr():
    st = RxState(0x01020304, 8000)
    st.process(_rx_packet(10, 0), 0.0)
    st.process(_rx_packet(11, 160), 0.02)
    st.process(_rx_packet(12, 320), 0.04)
    # no sender report seen yet
    rb = st.report_block()
    assert rb.lsr == 0
    assert rb.dlsr == 0
    ntp = (0xE6A25FA9 << 32) | 0x2903D32F
    st.note_sender_report(0xE6A25FA9, 0x2903D32F, ntp)
    # LSR is the middle 32 bits of the SR's NTP timestamp
    assert st.lsr == 0x5FA92903
    # report generated 5.5 seconds after the SR arrived
    now = ntp + (5 << 32) + (1 << 31)
    rb = st.report_block(now)
    assert rb.lsr == 0x5FA92903
    assert rb.dlsr == 5 * 65536 + 32768  # 360448, in units of 1/65536 s


def test_rxtable_per_ssrc():
    table = RxTable(8000)
    table.process(_rx_packet(100, 0, ssrc=0xAAAA0001), 0.0)
    table.process(_rx_packet(500, 0, ssrc=0xBBBB0002), 0.0)
    table.process(_rx_packet(101, 160, ssrc=0xAAAA0001), 0.02)
    table.process(_rx_packet(501, 160, ssrc=0xBBBB0002), 0.02)
    assert table.process(_rx_packet(102, 320, ssrc=0xAAAA0001), 0.04) is True
    blocks = table.report_blocks()
    assert len(blocks) == 2
    by_ssrc = dict((b.ssrc, b) for b in blocks)
    # first source completed probation at seq 102
    assert by_ssrc[0xAAAA0001].seq == 102
    assert by_ssrc[0xAAAA0001].losscumm == 0
    # second source is still in probation at seq 501
    assert by_ssrc[0xBBBB0002].seq == 501
