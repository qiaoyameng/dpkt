# -*- coding: utf-8 -*-
"""RTP receiver report statistics (RFC 3550).

Per-SSRC reception state that consumes parsed RTP packets together with a
monotonic arrival time and produces the data carried in an RTCP Receiver
Report (RR) report block (RFC 3550 section 6.4), following the algorithms
of Appendix A.1 (sequence number handling, source validation and restart)
and Appendix A.8 (packet loss, extended highest sequence number and
interarrival jitter).

Everything here is deterministic and purely time driven: no sleep and no
wall clock are used.  The caller supplies the RTP clock rate (Hz) used to
scale jitter and the arrival instant of every packet.

Arrival times are seconds expressed as a number; ``fractions.Fraction`` is
exact and ``float`` is converted exactly, so jitter and DLSR can be unit
tested against fixed expected values.  NTP sender reports update the
LSR/DLSR fields through :meth:`ReceptionTable.on_sender_report`.
"""
from __future__ import absolute_import

from fractions import Fraction

from . import rtcp

# RFC 3550 Appendix A.1 constants.
MIN_SEQUENTIAL = 2          # consecutive packets that validate a source
MAX_DROPOUT = 3000          # max forward jump accepted as one loss burst
MAX_MISORDER = 100          # max backward span accepted as late/reordered
SEQ_MOD = 1 << 16           # 16-bit sequence modulus
SEQ_HALF = 1 << 15

NTP_FRAC_PER_SEC = 1 << 16  # DLSR unit: 1/65536 of a second
LOSS_MASK = 0xFFFFFF        # cumulative number lost is 24 bits
FRACTION_MASK = 0xFF        # fraction lost is 8 bits


def _signed_delta(max_seq, seq):
    """Signed 16-bit distance from raw ``max_seq`` to raw ``seq``.

    A raw number just past the wrap boundary reads as a small forward step;
    one just before it reads as a small backward step.
    """
    delta = seq - max_seq
    if delta >= SEQ_HALF:
        delta -= SEQ_MOD
    elif delta < -SEQ_HALF:
        delta += SEQ_MOD
    return delta


def _trunc_div(value, divisor):
    """Integer division truncated toward zero (RFC 3550 uses C '/' rules)."""
    quotient = abs(value) // abs(divisor)
    if (value < 0) != (divisor < 0):
        quotient = -quotient
    return quotient


class ReceptionTable(object):
    """Reception statistics for one synchronization source (SSRC)."""

    def __init__(self, clock_rate):
        if clock_rate <= 0:
            raise ValueError("clock_rate must be positive")
        self.clock_rate = clock_rate
        # No anchor until the first observed sequence number.
        self.base_seq = 0
        self.max_seq = 0
        self.cycles = 0
        self.bad_seq = None
        self.probation = MIN_SEQUENTIAL - 1
        self._anchored = False
        self.received_pkts = 0
        self.expected_prior = 0
        self.received_prior = 0
        self.jitter = 0
        self._transit = None
        self.duplicates = 0
        self.late = 0
        self._seen = set()
        self.lsr = 0
        self._last_sr_arrival = None

    # ------------------------------------------------------------------
    # Sequence handling (RFC 3550 Appendix A.1)
    # ------------------------------------------------------------------
    def init_seq(self, seq):
        """Anchor a new source at raw ``seq``.

        The first observed packet anchors the sequence space and is counted
        as received; one further consecutive packet must confirm the source
        before later statistics are trusted (RFC 3550 source validation).
        """
        self.base_seq = seq & 0xFFFF
        self.max_seq = seq & 0xFFFF
        self.cycles = 0
        self.bad_seq = None
        self.probation = MIN_SEQUENTIAL - 1
        self._anchored = True

        # Appendix A.8 counters.
        self.received_pkts = 1
        self.expected_prior = 0
        self.received_prior = 0

        # Appendix A.8.3 jitter (RTP timestamp units).
        self.jitter = 0
        self._transit = None

        self._seen = {self.base_seq}

        # Diagnostics that are not part of the RR block.
        self.duplicates = 0
        self.late = 0

        # LSR / DLSR (section 6.4.1 / A.6.4).
        self.lsr = 0
        self._last_sr_arrival = None

    def _restart(self, seq):
        """Accept a restarted source at raw ``seq`` (A.1 restart branch)."""
        self.init_seq(seq)

    def update_seq(self, seq):
        """Process one raw 16-bit sequence number.

        Returns ``True`` for new, in-order data (eligible to advance the
        highest sequence, loss and jitter) and ``False`` otherwise
        (probation, duplicate or late/reordered packet).
        """
        seq &= 0xFFFF

        if self.probation:
            return self._update_probation(seq)

        delta = _signed_delta(self.max_seq, seq)

        if 0 < delta < MAX_DROPOUT:
            # In order (a small positive delta also covers 16-bit wrap).
            if seq < self.max_seq:
                self.cycles += SEQ_MOD
            self.max_seq = seq
            self.received_pkts += 1
            self._seen.add(self.extended_max)
            self.bad_seq = None
            return True

        if delta >= MAX_DROPOUT or delta <= -MAX_MISORDER:
            # Large discontinuity: either a restarted source or a packet far
            # out of range.  Only a packet immediately following the first
            # far-ahead packet confirms a restart (Appendix A.1).
            if self.bad_seq is not None and seq == (self.bad_seq + 1) & 0xFFFF:
                self._restart(seq)
                return True
            if delta >= MAX_DROPOUT:
                self.bad_seq = seq
            return False

        # Within the misorder window: duplicate or a genuinely late packet.
        extended = self._extend(seq)
        if extended in self._seen:
            self.duplicates += 1
            return False
        self.late += 1
        self._seen.add(extended)
        # A never-before-seen late packet counts as received (A.1 increments
        # "received" on the duplicate/late path) but never raises the
        # highest sequence number.
        self.received_pkts += 1
        return False

    def _update_probation(self, seq):
        if seq == (self.max_seq + 1) & 0xFFFF:
            if self.max_seq == 0xFFFF:
                self.cycles += SEQ_MOD
            self.max_seq = seq
            self.probation -= 1
            if self.probation == 0:
                self.received_pkts += 1
                self._seen.add(self.extended_max)
                return True
            return False
        # Not consecutive: re-anchor the source at this packet and keep
        # waiting for one sequential confirmation (no phantom loss is ever
        # booked for the unvalidated probation interval).
        self.init_seq(seq)
        return False

    def _extend(self, seq):
        """Extend a raw sequence number using the current cycle count."""
        cycles = self.cycles - SEQ_MOD if seq > self.max_seq else self.cycles
        return cycles + seq

    # ------------------------------------------------------------------
    # RFC 3550 Appendix A.8 derived values
    # ------------------------------------------------------------------
    @property
    def extended_max(self):
        """Extended highest sequence number received (Appendix A.8.2)."""
        return self.cycles + self.max_seq

    @property
    def expected(self):
        """Packets expected since the source was (re)initialised (A.8)."""
        return self.extended_max - self.base_seq + 1

    @property
    def lost_cumulative(self):
        """Cumulative packets lost; never negative when encoded (A.3/A.8)."""
        lost = self.expected - self.received_pkts
        return lost if lost > 0 else 0

    def fraction_lost(self):
        """8-bit fraction lost since the last report (A.3).

        Computing the value snapshots and resets the interval priors, as a
        real sender does when emitting each RR.
        """
        expected = self.expected
        expected_interval = expected - self.expected_prior
        received_interval = self.received_pkts - self.received_prior
        self.expected_prior = expected
        self.received_prior = self.received_pkts
        if expected_interval <= 0 or received_interval >= expected_interval:
            return 0
        lost_interval = expected_interval - received_interval
        return (lost_interval * 256 // expected_interval) & FRACTION_MASK

    # ------------------------------------------------------------------
    # Interarrival jitter (RFC 3550 Appendix A.8.3)
    # ------------------------------------------------------------------
    def _update_jitter(self, rtp_ts, arrival):
        arrival_rtp = Fraction(arrival) * self.clock_rate
        transit = arrival_rtp - rtp_ts
        if self._transit is None:
            # The first accepted packet anchors the transit estimate, so the
            # average starts from the first real interarrival sample.
            self._transit = transit
            return
        difference = int(abs(transit - self._transit))
        self.jitter += _trunc_div(difference - self.jitter, 16)
        self._transit = transit

    # ------------------------------------------------------------------
    # Packet / sender report entry points
    # ------------------------------------------------------------------
    def update(self, seq, rtp_ts, arrival):
        """Process one received packet; ``True`` if it is new in-order data."""
        if not self._anchored:
            # First packet: anchor the sequence space and validate jitter.
            self.init_seq(seq)
            self._update_jitter(rtp_ts, arrival)
            return True
        accepted = self.update_seq(seq)
        if accepted:
            self._update_jitter(rtp_ts, arrival)
        return accepted

    def on_sender_report(self, ntp_msw, ntp_lsw, arrival):
        """Record an RTCP SR (section 6.4.1 LSR/DLSR bookkeeping).

        LSR is the compact 32-bit middle of the sender's 64-bit NTP stamp;
        ``arrival`` (monotonic seconds) is retained for the later DLSR.
        """
        self.lsr = ((ntp_msw & 0xFFFF) << 16) | ((ntp_lsw >> 16) & 0xFFFF)
        self._last_sr_arrival = Fraction(arrival)

    def dlsr(self, now):
        """Delay since the last SR in 1/65536 s (0 before any SR arrives)."""
        if self._last_sr_arrival is None:
            return 0
        delay = Fraction(now) - self._last_sr_arrival
        if delay < 0:
            return 0
        return int(delay * NTP_FRAC_PER_SEC)

    # ------------------------------------------------------------------
    # Report block output
    # ------------------------------------------------------------------
    def snapshot(self, ssrc, now=None):
        """Return report-block fields (and reset the fraction-lost interval)."""
        return {
            'ssrc': ssrc,
            'lossfrac': self.fraction_lost(),
            'losscumm': self.lost_cumulative & LOSS_MASK,
            'seq': self.extended_max & 0xFFFFFFFF,
            'jitter': int(self.jitter) & 0xFFFFFFFF,
            'lsr': self.lsr,
            'dlsr': 0 if now is None else self.dlsr(now),
        }

    def report_block(self, ssrc, now=None):
        """Build an :class:`dpkt.rtcp.Report` block for this source."""
        fields = self.snapshot(ssrc, now)
        return rtcp.Report(
            ssrc=fields['ssrc'],
            lossfrac=fields['lossfrac'],
            losscumm=fields['losscumm'],
            seq=fields['seq'],
            jitter=fields['jitter'],
            lsr=fields['lsr'],
            dlsr=fields['dlsr'],
        )


class RtpReception(object):
    """Keep one :class:`ReceptionTable` per sender SSRC."""

    def __init__(self, clock_rate):
        if clock_rate <= 0:
            raise ValueError("clock_rate must be positive")
        self.clock_rate = clock_rate
        self._tables = {}

    def get(self, ssrc):
        """Return the table for ``ssrc``, creating it on first use."""
        table = self._tables.get(ssrc)
        if table is None:
            table = ReceptionTable(self.clock_rate)
            self._tables[ssrc] = table
        return table

    def __contains__(self, ssrc):
        return ssrc in self._tables

    def __len__(self):
        return len(self._tables)

    def ssrcs(self):
        return list(self._tables.keys())

    def update_packet(self, packet, arrival):
        """Feed a parsed RTP packet (exposes ``ssrc``, ``seq`` and ``ts``)."""
        table = self.get(packet.ssrc)
        return table.update(packet.seq, packet.ts, arrival)

    def update(self, ssrc, seq, rtp_ts, arrival):
        """Feed explicit fields for one received packet."""
        return self.get(ssrc).update(seq, rtp_ts, arrival)

    def on_sender_report(self, ssrc, ntp_msw, ntp_lsw, arrival):
        self.get(ssrc).on_sender_report(ntp_msw, ntp_lsw, arrival)

    def snapshot(self, ssrc, now=None):
        return self.get(ssrc).snapshot(ssrc, now)

    def report_block(self, ssrc, now=None):
        return self.get(ssrc).report_block(ssrc, now)

    def report_blocks(self, now=None):
        """One :class:`dpkt.rtcp.Report` per tracked source (reset interval)."""
        return [table.report_block(ssrc, now)
                for ssrc, table in self._tables.items()]

    def receiver_report(self, sender_ssrc, now=None):
        """Build a complete RTCP RR packet carrying one block per source."""
        packet = rtcp.RTCP(pt=rtcp.PT_RR)
        packet.addInfo(rtcp.RRInfo(ssrc=sender_ssrc))
        for ssrc in sorted(self._tables):
            packet.addReport(self._tables[ssrc].report_block(ssrc, now))
        return packet


# ----------------------------------------------------------------------
# Deterministic tests.  All timing is fixed (Fraction seconds); no sleep.
# ----------------------------------------------------------------------
def _table(clock_rate=8000):
    return ReceptionTable(clock_rate)


def _anchor(table, seq=1000):
    # First observed packet anchors the source and is accepted.
    assert table.update(seq, 0, 0) is True
    return table


def _validated(clock_rate=8000, seq=1000):
    # Anchor plus one consecutive packet: source is validated (probation 0).
    table = _table(clock_rate)
    table.update(seq, 0, 0)
    table.update((seq + 1) & 0xFFFF, 160, Fraction(1, 40))
    assert table.probation == 0
    return table


def test_probation_requires_consecutive_packet():
    table = _table()
    assert table.update(1000, 0, 0) is True       # anchor, counted
    # A non-consecutive packet while validating is rejected and re-anchors.
    assert table.update(1005, 800, 1) is False
    assert table.received_pkts == 1
    assert table.max_seq == 1005
    assert table.base_seq == 1005
    # One consecutive packet confirms the source; no phantom loss is booked.
    assert table.update(1006, 960, 2) is True
    assert table.probation == 0
    assert table.received_pkts == 2
    snap = table.snapshot(0x1)
    assert snap['seq'] == 1006
    assert snap['losscumm'] == 0
    assert snap['lossfrac'] == 0
    # Once validated, a later gap is measured normally.
    table.update(1008, 1280, 3)
    snap = table.snapshot(0x1)
    assert snap['seq'] == 1008
    assert snap['losscumm'] == 1


def test_steady_order_no_loss():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))
    snap = table.snapshot(0xABCD)
    assert snap['ssrc'] == 0xABCD
    assert snap['seq'] == 1001
    assert snap['losscumm'] == 0
    assert snap['lossfrac'] == 0
    assert snap['jitter'] == 2                     # |D|=32 -> 32/16


def test_sixteen_bit_wraparound():
    table = _table()
    table.update(65534, 0, 0)
    table.update(65535, 160, Fraction(1, 40))
    table.update(0, 320, Fraction(1, 20))
    table.update(1, 480, Fraction(3, 40))
    assert table.cycles == SEQ_MOD
    assert table.extended_max == 65536 + 1
    assert table.max_seq == 1
    assert table.expected == 4
    assert table.received_pkts == 4
    assert table.lost_cumulative == 0
    # jitter: 32/16=2, +(32-2)/16=4, +(32-4)/16=6
    assert table.jitter == 6

    # A packet from the previous cycle arriving after the wrap is late.
    assert table.update(65535, 160, 1) is False
    assert table.duplicates == 1
    assert table.update(65530, 0, 1) is False
    assert table.late == 1
    assert table.extended_max == 65537


def test_backward_step_is_late_not_new_cycle():
    table = _table()
    table.update(65534, 0, 0)                      # anchor
    table.update(65535, 160, Fraction(1, 40))      # confirms, wraps toward 0
    # 65533 is two behind the highest; it is a late, never-seen packet.
    assert table.update(65533, 0, 1) is False
    assert table.late == 1
    assert table.cycles == 0
    assert table.extended_max == 65535
    # 65534 was the anchor; repeating it is a duplicate, not late.
    assert table.update(65534, 0, 2) is False
    assert table.duplicates == 1


def test_cumulative_and_fraction_lost_between_two_reports():
    table = _anchor(_table())
    # 1001 arrives; 1002 and 1003 are lost; 1004 arrives.
    table.update(1001, 160, Fraction(1, 40))
    table.update(1004, 640, Fraction(1, 10))
    first = table.snapshot(0x1, Fraction(1))
    assert first['seq'] == 1004
    assert first['losscumm'] == 2
    # interval expected = 5 (1000..1004), received = 3, lost = 2
    # -> 2*256//5 = 102.
    assert first['lossfrac'] == 102

    # Second interval: a duplicate (no effect), a late fill of 1002, then a
    # burst forward to 1007 (1005 and 1006 missing) followed by late 1005.
    assert table.update(1004, 640, 1) is False
    assert table.duplicates == 1
    assert table.update(1002, 320, Fraction(7, 40)) is False
    assert table.late == 1
    table.update(1007, 1120, Fraction(2, 10))
    assert table.update(1005, 800, Fraction(17, 80)) is False
    assert table.late == 2
    second = table.snapshot(0x1, Fraction(2))
    # New interval expected 3 (1005..1007); received: 1007 new plus late 1005
    # = 2, but the late 1002 also increments received, so received = 3 and
    # net interval loss is 0.
    assert second['lossfrac'] == 0
    # Cumulative: expected 8, received 7 (anchor+1001+1004+1007 + three late
    # /duplicate-accounted... ) leaving the never-recovered 1003 and 1006.
    assert second['losscumm'] == 2

    # A report with no new packets reports zero fraction loss.
    third = table.snapshot(0x1, Fraction(3))
    assert third['lossfrac'] == 0
    assert third['losscumm'] == 2
    assert third['seq'] == 1007


def test_late_packet_recovers_loss():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))      # confirm source
    table.update(1003, 480, Fraction(3, 40))      # 1002 missing
    assert table.lost_cumulative == 1
    # The missing 1002 then arrives within the misorder window: a late fill.
    assert table.update(1002, 320, 1) is False
    assert table.late == 1
    assert table.duplicates == 0
    assert table.lost_cumulative == 0
    # Repeating it is now a duplicate and changes nothing.
    assert table.update(1002, 320, 2) is False
    assert table.duplicates == 1
    assert table.lost_cumulative == 0


def test_large_forward_jump_then_restart():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))
    # Jump far beyond MAX_DROPOUT: not accepted yet.
    assert table.update(5000, 0, 2) is False
    assert table.bad_seq == 5000
    assert table.extended_max == 1001
    # A second, sequential packet confirms a restarted source (5000 anchors).
    assert table.update(5001, 160, 3) is True
    assert table.base_seq == 5001
    assert table.extended_max == 5001
    assert table.received_pkts == 1
    # Restart is still validating; the next sequential packet is normal.
    assert table.update(5002, 320, 4) is True
    assert table.extended_max == 5002
    assert table.received_pkts == 2


def test_large_jump_requires_sequential_confirmation():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))
    table.update(5000, 0, 2)
    # A non-consecutive second packet must not confirm the restart.
    assert table.update(5003, 0, 3) is False
    assert table.extended_max == 1001
    assert table.received_pkts == 2


def test_dropout_within_window_counts_loss():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))      # confirm source
    # A forward jump smaller than MAX_DROPOUT is one loss burst.
    table.update(3998, 0, 2)
    assert table.extended_max == 3998
    assert table.lost_cumulative == 2996


def test_far_backward_packet_is_ignored():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))
    old = (1001 - (MAX_MISORDER + 50)) % SEQ_MOD
    assert table.update(old, 0, 2) is False
    assert table.duplicates == 0
    assert table.late == 0
    assert table.extended_max == 1001


def test_dropout_boundary_values():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))      # confirm, highest = 1001
    # delta == MAX_DROPOUT is already beyond the in-order window.
    assert table.update((1001 + MAX_DROPOUT) % SEQ_MOD, 0, 1) is False
    assert table.extended_max == 1001
    # The immediately following packet confirms a restart.
    assert table.update((1002 + MAX_DROPOUT) % SEQ_MOD, 0, 2) is True
    assert table.base_seq == (1002 + MAX_DROPOUT) % SEQ_MOD

    # The largest accepted in-order gap has delta MAX_DROPOUT - 1.
    other = _validated(seq=2000)
    target = (2001 + MAX_DROPOUT - 1) % SEQ_MOD
    assert other.update(target, 0, 2) is True
    assert other.extended_max == 2001 + MAX_DROPOUT - 1  # 5000


def test_more_late_fills_than_gaps_clamps_at_zero():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))      # confirm source
    assert table.lost_cumulative == 0
    # Two never-seen packets arrive late with no forward gap at all.
    assert table.update(999, 0, 1) is False
    assert table.late == 1
    assert table.update(998, 0, 2) is False
    assert table.late == 2
    # Loss never goes negative and the highest sequence is unchanged.
    assert table.lost_cumulative == 0
    assert table.extended_max == 1001


def test_interarrival_jitter_fixed_values():
    table = _table(1000)
    # Equal sender spacing (100 ms) and arrival spacing -> zero jitter.
    table.update(0, 0, 0)
    table.update(1, 100, Fraction(1, 10))
    table.update(2, 200, Fraction(2, 10))
    assert table.jitter == 0
    # Packet 3 arrives 50 ms late relative to the sender: D = 50 units.
    table.update(3, 300, Fraction(35, 100))
    assert table.jitter == 50 // 16                  # 3
    # Packet 4 is another 50 ms later still, so D = 50 again.
    table.update(4, 400, Fraction(50, 100))
    assert table.jitter == 3 + _trunc_div(50 - 3, 16)  # 5


def test_clock_rate_scales_jitter():
    slow = _table(100)
    slow.update(0, 0, 0)
    slow.update(1, 10, Fraction(1, 10))
    slow.update(2, 20, Fraction(15, 100))
    # arrival drift = 50 ms * 100 Hz = 5 clock units.
    assert slow.jitter == 5 // 16


def test_lsr_and_dlsr():
    table = _anchor(_table())
    assert table.lsr == 0
    assert table.dlsr(10) == 0
    # SR with NTP msw 0xE6A25FAA / lsw 0x2903D32F -> compact middle 32 bits.
    table.on_sender_report(0xE6A25FAA, 0x2903D32F, 1)
    assert table.lsr == 0x5FAA2903
    # DLSR is measured in 1/65536 s; exactly 2 seconds.
    assert table.dlsr(3) == 2 * 65536
    # Fractional delay floors to the 1/65536 grid.
    assert table.dlsr(Fraction(3) + Fraction(1, 65536 * 2)) == 2 * 65536
    assert table.dlsr(Fraction(3) + Fraction(1, 65536)) == 2 * 65536 + 1
    # A report block carries both fields.
    block = table.report_block(0x99, Fraction(4))
    assert block.lsr == 0x5FAA2903
    assert block.dlsr == 3 * 65536


def test_report_block_roundtrip():
    table = _anchor(_table())
    table.update(1001, 160, Fraction(1, 40))     # confirm source
    table.update(1004, 0, 1)                     # two lost (1002, 1003)
    table.on_sender_report(0x11223344, 0x55667788, 0)
    block = table.report_block(0xAABBCCDD, 1)
    assert block.ssrc == 0xAABBCCDD
    assert block.seq == 1004
    assert block.losscumm == 2
    assert block.lsr == 0x33445566
    raw = bytes(block)
    from .rtcp import Report
    parsed = Report(raw)
    assert parsed.ssrc == 0xAABBCCDD
    assert parsed.seq == 1004
    assert parsed.losscumm == 2
    assert parsed.lsr == 0x33445566


def test_manager_isolates_ssrcs_and_builds_rr():
    from .rtp import RTP
    reception = RtpReception(8000)

    def packet(ssrc, seq, ts):
        rtp = RTP()
        rtp.ssrc = ssrc
        rtp.seq = seq
        rtp.ts = ts
        return rtp

    s1, s2 = 0x11111111, 0x22222222
    reception.update_packet(packet(s1, 100, 0), 0)
    reception.update_packet(packet(s1, 101, 160), Fraction(1, 40))
    reception.update_packet(packet(s2, 500, 0), 0)
    reception.update_packet(packet(s2, 501, 160), Fraction(1, 40))
    reception.update_packet(packet(s2, 504, 640), Fraction(1, 10))
    assert s1 in reception and s2 in reception
    assert len(reception) == 2

    reception.on_sender_report(s1, 0xE6A25FAA, 0x2903D32F, 1)
    rr = reception.receiver_report(0xDEADBEEF, 3)
    assert rr.pt == 201
    assert rr.info.ssrc == 0xDEADBEEF
    assert rr.cc == 2
    by_ssrc = {block.ssrc: block for block in rr.reports}
    assert by_ssrc[s1].seq == 101
    assert by_ssrc[s1].losscumm == 0
    assert by_ssrc[s1].lsr == 0x5FAA2903
    assert by_ssrc[s1].dlsr == 2 * 65536
    assert by_ssrc[s2].seq == 504
    assert by_ssrc[s2].losscumm == 2
    assert by_ssrc[s2].lsr == 0
    assert by_ssrc[s2].dlsr == 0

    # The generated RR parses back as a valid RTCP packet.
    from .rtcp import RTCP
    reparsed = RTCP(bytes(rr))
    assert reparsed.cc == 2
    assert reparsed.reports[0].ssrc == s1
    assert reparsed.reports[0].dlsr == 2 * 65536
