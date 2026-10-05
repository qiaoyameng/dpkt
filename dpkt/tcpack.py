# -*- coding: utf-8 -*-
"""Offline TCP acknowledgement / in-flight data analyzer.

Given the segments of *one* TCP connection, captured in capture order and
covering both directions, this module classifies every send and every
acknowledgement, tracks cumulative ACK and SACK scoreboard state and reports
the ranges of sequence space that are still in flight after each packet.

Design notes
------------
* All arithmetic happens in an unwrapped 64 bit sequence space per
  direction (:class:`_Unwrapper`) so wrap-around at ``2**32`` is handled
  transparently.  Output ranges are rendered back in the 32 bit space.
* SYN and FIN each consume one sequence number but are tracked separately
  from payload data; every reported byte count and range covers payload only.
* Records are never dropped just because a SACK block covered them.  The
  cumulative ACK is the only thing allowed to retire outstanding data;
  SACK state is kept as a separate (replaceable) scoreboard and is even
  checked for reneging.
* RTT samples follow Karn's algorithm and, more strongly, are only taken
  when the ambiguity of retransmissions can be eliminated: each sampled
  stretch must map to exactly one (and only one) transmission of exactly
  one recorded segment ("unambiguous samples").

The module works from :class:`dpkt.tcp.TCP` objects but does not require a
live connection: feed synthetic or pcap-derived segments in capture order.
"""
from __future__ import absolute_import, print_function

import struct

from . import tcp as _tcp

MOD = 1 << 32
HALF = 1 << 31


def _signed_delta(a, b):
    """Return ``a - b`` as a signed 32 bit modular offset."""
    d = (a - b) & 0xffffffff
    if d >= HALF:
        d -= MOD
    return d


class _Unwrapper(object):
    """Map 32 bit sequence numbers onto a monotonically increasing axis.

    The anchor is fixed at the first value seen; no attempt is made to
    re-anchor later values, otherwise genuine retransmissions landing near
    the anchor could be "re-wrapped".  A capture containing more than
    2**31 bytes of data in one direction cannot be disambiguated offline
    anyway (and is practically impossible for a real trace).
    """

    __slots__ = ('anchor',)

    def __init__(self):
        self.anchor = None

    def unwrap(self, val):
        val &= 0xffffffff
        if self.anchor is None:
            self.anchor = val
            return val
        return self.anchor + _signed_delta(val, self.anchor)


def _merge(intervals):
    """Merge an iterable of half-open ``[lo, hi)`` intervals."""
    out = []
    for lo, hi in sorted(intervals):
        if hi <= lo:
            continue
        if out and lo <= out[-1][1]:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


def _subtract(intervals, lo, hi):
    """Subtract ``[lo, hi)`` from a sorted list of disjoint intervals."""
    out = []
    for a, b in intervals:
        if hi <= a or lo >= b:
            out.append((a, b))
            continue
        if lo > a:
            out.append((a, lo))
        if hi < b:
            out.append((hi, b))
    return out


def _intersect(intervals, lo, hi):
    """Intersect a sorted interval list with ``[lo, hi)``."""
    out = []
    for a, b in intervals:
        if b <= lo:
            continue
        if a >= hi:
            break
        out.append((max(a, lo), min(b, hi)))
    return out


def to_seq32_ranges(intervals):
    """Split unwrapped ``[lo, hi)`` intervals at 32 bit space boundaries.

    Returns a list of ``(seq_lo, seq_hi)`` tuples that never straddle a
    wrap boundary, with both ends taken modulo ``2**32``.  A range that
    wraps is returned as two tuples, high one first in capture order
    (e.g. ``[(0xfffffff0, 0), (0, 10)]``).
    """
    out = []
    for lo, hi in intervals:
        if hi <= lo:
            continue
        pos = lo
        while pos < hi:
            boundary = ((pos >> 32) + 1) << 32
            nxt = min(hi, boundary)
            out.append((pos & 0xffffffff, nxt & 0xffffffff))
            pos = nxt
    return out


def format_seq_ranges(intervals):
    """Render unwrapped intervals as compact 32 bit ``[lo-hi)`` strings."""
    return ', '.join('0x%08x-0x%08x' % (lo, hi)
                     for lo, hi in to_seq32_ranges(intervals)) or '-'


def parse_sack_blocks(opts):
    """Extract SACK blocks from a raw TCP options buffer.

    Returns a list of ``(left_edge, right_edge)`` 32 bit sequence pairs in
    the order advertised, an empty list if a SACK option is present but
    carries no usable block, or ``None`` when no SACK option is present.
    Malformed option data is skipped.
    """
    blocks = []
    present = False
    for opt in _tcp.parse_opts(opts):
        if not opt or opt[0] != _tcp.TCP_OPT_SACK:
            continue
        present = True
        data = opt[1]
        n = (len(data) // 8) * 8
        for i in range(0, n, 8):
            left = struct.unpack('>I', data[i:i + 4])[0]
            right = struct.unpack('>I', data[i + 4:i + 8])[0]
            if right > left:
                blocks.append((left, right))
    return blocks if present else None


class TxRecord(object):
    """One transmitted payload segment.

    A later segment covering the same bytes creates a new entry in
    ``transmissions`` instead of overwriting the first send; that history is
    exactly what lets us reject RTT samples whose sending instant would be
    ambiguous.
    """

    __slots__ = ('lo', 'hi', 'transmissions', 'sampled', 'sacked')

    def __init__(self, lo, hi, ts):
        self.lo = lo
        self.hi = hi
        self.transmissions = [ts]
        self.sampled = False
        self.sacked = False

    @property
    def retransmitted(self):
        return len(self.transmissions) > 1

    def covers(self, lo, hi):
        return self.lo <= lo and self.hi >= hi


class DirectionState(object):
    """Send/ack state for one direction of a connection.

    All sequence numbers inside the instance are unwrapped integers.  SYN
    and FIN are represented by scalar control slots rather than data ranges
    so they can consume sequence space without polluting payload stats.
    """

    def __init__(self, label):
        self.label = label
        self.unwrap = _Unwrapper()
        # send side
        self.records = []
        self.sent_union = []       # union of every payload range ever sent
        self.snd_max = None        # highest payload end ever observed
        self.syn_tx = None
        self.fin_tx = None
        # ack side
        self.snd_una = None        # cumulative ACK (absolute, data-oriented)
        self.sack = []             # current SACK scoreboard, unwrapped
        self.ever_sacked = []      # union of everything ever advertised
        self.ever_acked = []       # payload ranges retired by cumulative ACK
        self.syn_acked = False
        self.fin_acked = False
        # counters
        self.segments_new = 0
        self.segments_retrans = 0
        self.segments_partial_retrans = 0
        self.dup_segments = 0
        self.data_bytes_sent = 0
        self.data_bytes_retrans = 0
        self.acks_new = 0
        self.acks_duplicate = 0
        self.acks_backward = 0
        self.bytes_acknowledged = 0
        self.bytes_sacked = 0
        self.sack_reneges = 0
        self.rtt_samples = []
        self.uncertain = set()

    # ------------------------------------------------------------------ sends
    def register_send(self, ts, seq, payload_len, syn, fin, rst):
        """Process a segment travelling in this direction.

        Returns an event dict describing the send classification.
        """
        abs_seq = self.unwrap.unwrap(seq)
        event = {
            'kind': 'send',
            'ts': ts,
            'seq32': seq & 0xffffffff,
            'payload_bytes': payload_len,
            'syn': bool(syn),
            'fin': bool(fin),
            'rst': bool(rst),
            'new_bytes': 0,
            'retrans_bytes': 0,
            'classification': None,
            'uncertain': False,
        }

        if syn:
            if self.syn_tx is None:
                self.syn_tx = {'ts': ts, 'seq': abs_seq,
                               'retransmissions': 0}
                event['classification'] = 'syn'
                # A SYN pins the cumulative-ACK base to the ISN.
                if self.snd_una is None:
                    self.snd_una = abs_seq
            else:
                self.syn_tx['retransmissions'] += 1
                event['classification'] = 'syn-retransmission'

        lo, hi = abs_seq, abs_seq + payload_len
        if payload_len:
            event['end32'] = hi & 0xffffffff
            retrans_parts = _merge(
                (max(lo, a), min(hi, b)) for a, b in self.sent_union
                if min(hi, b) > max(lo, a))
            new_parts = [(lo, hi)]
            for a, b in retrans_parts:
                new_parts = _subtract(new_parts, a, b)
            new_bytes = sum(b - a for a, b in new_parts)
            retrans_bytes = sum(b - a for a, b in retrans_parts)
            event['new_bytes'] = new_bytes
            event['retrans_bytes'] = retrans_bytes

            self.sent_union = _merge(self.sent_union + [(lo, hi)])
            self.data_bytes_sent += new_bytes
            self.data_bytes_retrans += retrans_bytes
            self._record_transmission(lo, hi, ts)

            exact_dup = any(r.lo == lo and r.hi == hi and
                            len(r.transmissions) > 1 for r in self.records)
            if new_bytes == 0:
                event['classification'] = (
                    'duplicate-send' if exact_dup else 'retransmission')
                self.segments_retrans += 1
                if exact_dup:
                    self.dup_segments += 1
            elif retrans_bytes:
                event['classification'] = 'partial-retransmission'
                self.segments_partial_retrans += 1
            else:
                event['classification'] = 'new-data'
                self.segments_new += 1

            if self.snd_max is None or hi > self.snd_max:
                self.snd_max = hi

            if self.syn_tx is None:
                # No handshake seen: bytes before this segment are unknown,
                # and a "new" segment could really be filling a captured gap.
                self.uncertain.add('missing-handshake')
                event['uncertain'] = True

        elif not syn and not fin and not rst:
            event['classification'] = 'pure-ack'

        if fin:
            # FIN consumes the sequence number after the payload.
            fin_seq = abs_seq + payload_len
            if self.fin_tx is None:
                self.fin_tx = {'ts': ts, 'seq': fin_seq,
                               'retransmissions': 0}
                if event['classification'] in (None, 'pure-ack'):
                    event['classification'] = 'fin'
            else:
                self.fin_tx['retransmissions'] += 1
                if event['classification'] in (None, 'pure-ack'):
                    event['classification'] = 'fin-retransmission'

        if rst and event['classification'] is None:
            event['classification'] = 'rst'

        return event

    def _record_transmission(self, lo, hi, ts):
        # Records are keyed by the byte range they cover.  An exact
        # retransmission adds a second send instant to the existing record;
        # an overlapping/partial retransmission creates its own record,
        # leaving both send histories visible to the RTT sweep.
        for rec in self.records:
            if (lo, hi) == (rec.lo, rec.hi):
                rec.transmissions.append(ts)
                return
        self.records.append(TxRecord(lo, hi, ts))

    # ------------------------------------------------------------------ acks
    def apply_ack(self, ts, ack32, blocks32):
        """Process an ACK sent by the peer (acknowledging this direction).

        Returns an event dict.  ``blocks32`` is the parsed SACK block list.
        """
        event = {
            'kind': 'ack',
            'ts': ts,
            'ack32': ack32 & 0xffffffff,
            'classification': None,
            'adv_bytes': 0,
            'new_rtt_samples': [],
            'sack_blocks': ([(l & 0xffffffff, r & 0xffffffff)
                             for l, r in blocks32]
                            if blocks32 else []),
            'sack_reneged_bytes': 0,
            'syn_acked': False,
            'fin_acked': False,
            'uncertain': False,
        }

        if self.snd_una is None:
            # No SYN/data anchor for this direction yet.  This ACK becomes
            # the cumulative-ACK base; everything before it is unknowable.
            self.snd_una = self.unwrap.unwrap(ack32)
            self.uncertain.add('missing-handshake')
            event['uncertain'] = True
            event['classification'] = 'bootstrap-ack'
            self._apply_sack(ts, blocks32, event)
            return event

        ack = self.unwrap.unwrap(ack32)

        if ack < self.snd_una:
            event['classification'] = 'backward-ack'
            self.acks_backward += 1
            # An old duplicate may still carry the same SACK blocks, but an
            # ACK that moved backwards must never replace the scoreboard.
            return event

        duplicate = (ack == self.snd_una)
        if duplicate:
            self.acks_duplicate += 1
            event['classification'] = 'duplicate-ack'
            # Duplicate ACKs still advertise fresh SACK information.
            self._apply_sack(ts, blocks32, event)
            return event

        # Advancing cumulative ACK.  Work out which control numbers it
        # crosses so SYN/FIN do not get counted as payload.
        old_una = self.snd_una
        syn_crossed = (not self.syn_acked and self.syn_tx is not None
                       and self.syn_tx['seq'] < ack)
        fin_crossed = (not self.fin_acked and self.fin_tx is not None
                       and self.fin_tx['seq'] < ack)
        data_lo = old_una + (1 if syn_crossed and old_una
                             == self.syn_tx['seq'] else 0)
        data_hi = ack - (1 if fin_crossed else 0)

        if syn_crossed:
            self.syn_acked = True
            event['syn_acked'] = True
            if self.syn_tx['retransmissions'] == 0:
                sm = self._control_rtt('syn', self.syn_tx, ts)
                event['new_rtt_samples'].append(sm)
                self.rtt_samples.append(sm)

        data_adv = max(0, data_hi - data_lo)
        unobserved = 0
        if data_adv > 0:
            observed_len = sum(
                b - a for a, b in _intersect(self.sent_union,
                                             data_lo, data_hi))
            unobserved = data_adv - observed_len
            self.ever_acked = _merge(
                self.ever_acked + [(data_lo, data_hi)])
            self.bytes_acknowledged += observed_len
            for sm in self._rtt_sweep(data_lo, data_hi, ts, 'cumulative'):
                event['new_rtt_samples'].append(sm)

        event['adv_bytes'] = data_adv
        if data_adv:
            event['adv_range32'] = (data_lo & 0xffffffff,
                                    data_hi & 0xffffffff)
        if unobserved > 0:
            self.uncertain.add('acks-unobserved-data')
            event['uncertain'] = True
            event['unobserved_bytes'] = unobserved

        self.snd_una = ack
        self.acks_new += 1
        event['classification'] = 'new-ack'

        # Cumulative ACK retires the SACK scoreboard prefix wholesale; the
        # send records themselves are retained for disambiguation/history.
        self.sack = [(a, b) for a, b in
                     ((max(a, ack), b) for a, b in self.sack) if b > a]
        self._apply_sack(ts, blocks32, event)

        if fin_crossed:
            self.fin_acked = True
            event['fin_acked'] = True
            if self.fin_tx['retransmissions'] == 0:
                sm = self._control_rtt('fin', self.fin_tx, ts)
                event['new_rtt_samples'].append(sm)
                self.rtt_samples.append(sm)

        return event

    @staticmethod
    def _control_rtt(kind, ctrl, ts):
        sm = {
            'rtt': ts - ctrl['ts'],
            'kind': kind,
            'seq32': ctrl['seq'] & 0xffffffff,
            'end32': (ctrl['seq'] + 1) & 0xffffffff,
            'ts_send': ctrl['ts'],
            'ts_ack': ts,
        }
        return sm

    def _apply_sack(self, ts, blocks32, event):
        """Merge a new SACK scoreboard, detect reneging and take RTT samples.

        SACK blocks are advisory: they update the outstanding picture but
        never retire records, and a previously advertised block that shrinks
        away is counted as a renege instead of silently disappearing.
        """
        if blocks32 is None:
            # Segment carried no SACK option: the scoreboard is unchanged.
            return
        incoming = _merge(
            (self.unwrap.unwrap(l), self.unwrap.unwrap(r))
            for l, r in (blocks32 or []))
        # Clamp blocks into live window: below snd.una are stale, above
        # snd_max advertise data we never sent (broken peer).
        cap_hi = self.snd_max if self.snd_max is not None else None
        clamped = []
        for a, b in incoming:
            if self.snd_una is not None and b <= self.snd_una:
                continue
            a2 = max(a, self.snd_una if self.snd_una is not None else a)
            b2 = b if cap_hi is None else min(b, cap_hi)
            if b2 > a2:
                clamped.append((a2, b2))
        incoming = _merge(clamped)

        # Reneging: bytes that were sacked before and are no longer covered.
        reneged = self.sack
        for a, b in incoming:
            reneged = _subtract(reneged, a, b)
        reneged_len = sum(b - a for a, b in reneged)
        if reneged_len:
            self.sack_reneges += 1
            self.uncertain.add('sack-reneging')
            event['sack_reneged_bytes'] = reneged_len
            event['uncertain'] = True

        # RTT samples only from newly advertised, never-before-sacked bytes.
        fresh = incoming
        for a, b in self.ever_sacked:
            fresh = _subtract(fresh, a, b)
        for a, b in fresh:
            for sm in self._rtt_sweep(a, b, ts, 'sack'):
                event['new_rtt_samples'].append(sm)

        self.ever_sacked = _merge(self.ever_sacked + incoming)
        self.bytes_sacked = sum(b - a for a, b in incoming)
        self.sack = incoming

    def _rtt_sweep(self, lo, hi, ts, kind):
        """Yield unambiguous RTT samples for bytes in ``[lo, hi)``.

        A stretch qualifies only when it is covered by exactly one recorded
        segment, that segment was transmitted exactly once and has not
        contributed a sample before.  Bytes of an exact retransmission
        belong to a record with two send times and bytes of an overlapping
        or partial retransmission are covered by two records; both are
        ambiguous (Karn's rule).
        """
        # Split the target range at every record boundary/coverage edge.
        edges = {lo, hi}
        for rec in self.records:
            if rec.hi > lo and rec.lo < hi:
                edges.add(max(lo, rec.lo))
                edges.add(min(hi, rec.hi))
        edges = sorted(edges)
        samples = []
        used_records = set()
        for a, b in zip(edges, edges[1:]):
            if b <= a:
                continue
            # A piece is unambiguous only when a single recorded segment
            # contains it in full.
            owners = [r for r in self.records if r.lo <= a and r.hi >= b]
            if len(owners) != 1:
                continue
            rec = owners[0]
            if rec.sampled or rec.retransmitted:
                continue
            if id(rec) in used_records:
                continue
            used_records.add(id(rec))
            # Record-level eligibility: this piece must be the unique-cover
            # region for the record; adjacent pieces for the same record are
            # merged by the one-sample-per-record rule above.
            rec.sampled = True
            samples.append({
                'rtt': ts - rec.transmissions[0],
                'kind': kind,
                'seq32': rec.lo & 0xffffffff,
                'end32': rec.hi & 0xffffffff,
                'matched_lo32': a & 0xffffffff,
                'matched_hi32': b & 0xffffffff,
                'ts_send': rec.transmissions[0],
                'ts_ack': ts,
            })
            self.rtt_samples.append(samples[-1])
        return samples

    # --------------------------------------------------------------- reporting
    def outstanding_ranges(self):
        """Payload sent but not yet retired by the cumulative ACK.

        Result excludes the SYN/FIN control sequence numbers.
        """
        base = self.snd_una if self.snd_una is not None else (
            self.sent_union[0][0] if self.sent_union else 0)
        ranges = list(self.sent_union)
        ranges = _subtract(ranges, -(1 << 62), base)
        return ranges

    def inflight_ranges(self):
        """Outstanding payload that is *not* currently covered by SACK."""
        ranges = self.outstanding_ranges()
        for a, b in self.sack:
            ranges = _subtract(ranges, a, b)
        return ranges

    def snapshot(self):
        """Return a plain-dict, 32-bit-view state snapshot."""
        outstanding = self.outstanding_ranges()
        inflight = self.inflight_ranges()
        sacked_live = [
            (a, b) for a, b in
            _intersect(self.sack,
                       self.snd_una if self.snd_una is not None
                       else -(1 << 62),
                       self.snd_max if self.snd_max is not None
                       else 1 << 62)
        ]
        rtts = [s['rtt'] for s in self.rtt_samples]
        return {
            'snd_una32': (None if self.snd_una is None
                          else self.snd_una & 0xffffffff),
            'snd_max32': (None if self.snd_max is None
                          else self.snd_max & 0xffffffff),
            'outstanding_ranges': to_seq32_ranges(outstanding),
            'inflight_ranges': to_seq32_ranges(inflight),
            'sack_blocks': to_seq32_ranges(sacked_live),
            'outstanding_bytes': sum(b - a for a, b in outstanding),
            'inflight_bytes': sum(b - a for a, b in inflight),
            'sacked_bytes': sum(b - a for a, b in sacked_live),
            'segments_new': self.segments_new,
            'segments_retrans': self.segments_retrans,
            'segments_partial_retrans': self.segments_partial_retrans,
            'dup_segments': self.dup_segments,
            'data_bytes_sent': self.data_bytes_sent,
            'data_bytes_retrans': self.data_bytes_retrans,
            'acks_new': self.acks_new,
            'acks_duplicate': self.acks_duplicate,
            'acks_backward': self.acks_backward,
            'bytes_acknowledged': self.bytes_acknowledged,
            'sack_reneges': self.sack_reneges,
            'rtt_samples': rtts,
            'rtt_min': min(rtts) if rtts else None,
            'rtt_max': max(rtts) if rtts else None,
            'rtt_mean': (sum(rtts) / len(rtts)) if rtts else None,
            'syn_acked': self.syn_acked,
            'fin_acked': self.fin_acked,
            'uncertain': sorted(self.uncertain),
        }


class TcpAckAnalyzer(object):
    """Offline analyzer for one TCP connection fed in capture order.

    Feed every captured segment (both directions) via :meth:`feed` in the
    order it was captured.  After each call the analyzer returns a step
    dict; all steps are also kept in ``self.steps``.  Each step contains
    the per-direction in-flight ranges and the running statistics, so the
    evolution of outstanding/sacked bytes can be inspected at every point.

    The two endpoint tuples ``(ip, port)`` decide direction.  When ``tcp``
    objects carry no IP information (synthetic segments) pass ``side``
    explicitly (``0`` = initiator/client, ``1`` = responder/server).
    """

    def __init__(self):
        self.sides = [None, None]
        self.endpoints = {}          # (ip, port) -> 0/1
        self.steps = []
        self._initiator_seen = False

    # ------------------------------------------------------------- feeding
    def feed(self, ts, tcp=None, src=None, dst=None, side=None,
             seq=None, ack=None, flags=None, payload=b'', opts=b''):
        """Process one captured segment.

        Args:
            ts: capture timestamp (any numeric type, e.g. seconds).
            tcp: a :class:`dpkt.tcp.TCP` instance, or ``None`` when the
                remaining keyword arguments describe the segment.
            src, dst: ``(ip_bytes, port)`` endpoint tuples (optional).
            side: force the direction (``0``/``1``); useful for synthetic
                segments that have no IP layer.
            seq, ack, flags, payload: segment fields when ``tcp`` is None.
        """
        if tcp is not None:
            seq = tcp.seq
            ack = tcp.ack
            flags = tcp.flags
            payload = bytes(tcp.data)
            opts = tcp.opts
        elif opts is None:
            opts = b''
        if payload is None:
            payload = b''

        syn = bool(flags & _tcp.TH_SYN)
        fin = bool(flags & _tcp.TH_FIN)
        ack_set = bool(flags & _tcp.TH_ACK)
        rst = bool(flags & _tcp.TH_RST)
        blocks32 = parse_sack_blocks(opts) if opts else None

        idx, peer = self._direction(src, dst, side, syn, ack_set)

        step = {
            'index': len(self.steps),
            'ts': ts,
            'side': idx,
            'src': self._ep(src),
            'dst': self._ep(dst),
            'seq32': seq & 0xffffffff if seq is not None else None,
            'ack32': ack & 0xffffffff if ack is not None else None,
            'flags': _tcp.tcp_flags_to_str(flags) if flags is not None else '',
            'send_event': None,
            'ack_event': None,
            'sides': {},
        }

        sender = self.sides[idx]
        send_event = sender.register_send(
            ts, seq, len(payload), syn, fin, rst)
        step['send_event'] = send_event

        if ack_set and ack is not None:
            receiver = self.sides[peer]
            ack_event = receiver.apply_ack(ts, ack, blocks32)
            step['ack_event'] = ack_event

        for i, st in enumerate(self.sides):
            if st is not None:
                step['sides'][i] = st.snapshot()

        self.steps.append(step)
        return step

    # ------------------------------------------------------------ internals
    @staticmethod
    def _ep(ep):
        if ep is None:
            return None
        return (ep[0], ep[1])

    def _direction(self, src, dst, side, syn, ack_set):
        if side is not None:
            idx = int(side) & 1
        elif src is not None and src in self.endpoints:
            idx = self.endpoints[src]
        elif dst is not None and dst in self.endpoints:
            idx = self.endpoints[dst] ^ 1
        elif self._initiator_seen:
            # Initiator known from its first SYN; an unmapped endpoint can
            # only be the responder (synthetic test traffic without src/dst).
            idx = 1
        else:
            # The bare SYN (no ACK) marks the initiator; everything seen
            # before that is only possible in handshake-truncated captures,
            # where the first observed endpoint is arbitrarily side 0.
            idx = 0
        if syn and not ack_set and not self._initiator_seen:
            idx = 0
            self._initiator_seen = True
        if self.sides[idx] is None:
            self.sides[idx] = DirectionState('side%d' % idx)
        if src is not None and src not in self.endpoints:
            self.endpoints[src] = idx
        if dst is not None and dst not in self.endpoints:
            self.endpoints[dst] = idx ^ 1
        if self.sides[idx ^ 1] is None:
            self.sides[idx ^ 1] = DirectionState('side%d' % (idx ^ 1))
        return idx, idx ^ 1

    # ------------------------------------------------------------- results
    def stats(self, side=None):
        """Final statistics snapshot for one side, or ``[side0, side1]``."""
        snaps = [s.snapshot() if s is not None else None
                 for s in self.sides]
        if side is not None:
            return snaps[int(side)]
        return snaps

    def render_step(self, step):
        """Return a human-readable multi-line description of one step."""
        lines = []
        se = step['send_event']
        ae = step['ack_event']
        head = '#%d t=%s side%d %s seq=0x%08x' % (
            step['index'], step['ts'], step['side'], step['flags'] or '-',
            step['seq32'] if step['seq32'] is not None else 0)
        if step['ack32'] is not None:
            head += ' ack=0x%08x' % step['ack32']
        lines.append(head)
        if se is not None:
            lines.append('  send: %s payload=%d new=%d retrans=%d%s' % (
                se['classification'], se['payload_bytes'],
                se['new_bytes'], se['retrans_bytes'],
                ' [UNCERTAIN]' if se['uncertain'] else ''))
        if ae is not None:
            lines.append('  ack : %s adv=%d dup/sack rtt=%d%s%s' % (
                ae['classification'], ae['adv_bytes'],
                len(ae['new_rtt_samples']),
                (' reneged=%d' % ae['sack_reneged_bytes'])
                if ae['sack_reneged_bytes'] else '',
                ' [UNCERTAIN]' if ae['uncertain'] else ''))
            for sm in ae['new_rtt_samples']:
                lines.append('        rtt %.6f (%s)' % (sm['rtt'],
                                                        sm['kind']))
        for i, snap in step['sides'].items():
            lines.append(
                '  side%d una=0x%s outstanding=%d sack=%d inflight=%d'
                % (i,
                   '%08x' % snap['snd_una32']
                   if snap['snd_una32'] is not None else '--------',
                   snap['outstanding_bytes'], snap['sacked_bytes'],
                   snap['inflight_bytes']))
            lines.append('        inflight: %s'
                         % format_seq_ranges(snap['inflight_ranges']))
            if snap['uncertain']:
                lines.append('        uncertain: %s'
                             % ', '.join(snap['uncertain']))
        return '\n'.join(lines)

    def render_all(self):
        """Render every captured step as a single trace string."""
        return '\n'.join(self.render_step(s) for s in self.steps)


def _iter_pcap_tcp(path_or_file):
    """Yield ``(ts, src, dst, tcp)`` tuples from a pcap/pcap-ng file.

    Ethernet, Linux cooked capture (SLL/SLL2) and raw IP link layers are
    understood.  Non-IP and non-TCP frames are skipped, as are IPv4
    fragments other than the first.
    """
    from . import ethernet
    from . import ip as ipmod
    from . import ip6 as ip6mod
    from . import pcap
    from . import pcapng
    from . import sll
    from . import sll2

    close = False
    if hasattr(path_or_file, 'read'):
        fh = path_or_file
    else:
        fh = open(path_or_file, 'rb')
        close = True

    try:
        magic = fh.read(4)
        fh.seek(0)
        if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                     b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
            reader = pcap.Reader(fh)
        else:
            reader = pcapng.Reader(fh)

        for ts, buf in reader:
            eth = None
            try:
                # Link type is exposed by both readers on .linktype when
                # available; default to Ethernet and fall back.
                linktype = getattr(reader, 'linktype', 1)
            except Exception:
                linktype = 1
            try:
                if linktype == 113:
                    frame = sll.SLL(buf)
                    ip_pkt = frame.data
                elif linktype in (276,):
                    frame = sll2.SLL2(buf)
                    ip_pkt = frame.data
                elif linktype in (101, 228):
                    ip_pkt = ipmod.IP(buf)
                else:
                    frame = ethernet.Ethernet(buf)
                    ip_pkt = frame.data
                    if not isinstance(ip_pkt, (ipmod.IP, ip6mod.IP6)):
                        continue
            except Exception:
                continue

            if isinstance(ip_pkt, ipmod.IP):
                # Skip non-first IPv4 fragments: the TCP header is absent.
                if ip_pkt.mf and ip_pkt.offset != 0:
                    continue
                src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
            elif isinstance(ip_pkt, ip6mod.IP6):
                src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
            else:
                continue

            t = ip_pkt.data
            if not isinstance(t, _tcp.TCP):
                continue
            yield (ts, (src_ip, t.sport), (dst_ip, t.dport), t)
    finally:
        if close:
            fh.close()


def analyze_pcap(path, endpoints=None):
    """Analyze one TCP connection from a capture file.

    Args:
        path: pcap/pcap-ng filename or open binary file.
        endpoints: optional pair of endpoint tuples
            ``((ip, port), (ip, port))`` or a list of ports selecting the
            connection to analyze.  With ``None`` the first TCP connection
            found in the capture is used.

    Returns the populated :class:`TcpAckAnalyzer`.
    """
    analyzer = TcpAckAnalyzer()
    wanted_eps = None
    wanted_ports = None
    if endpoints is not None:
        wanted_eps = [e for e in endpoints if isinstance(e, tuple)
                      and len(e) == 2 and not isinstance(e[0], int)]
        wanted_ports = [e for e in endpoints
                        if isinstance(e, int) or
                        (isinstance(e, tuple) and e and
                         isinstance(e[0], int))]

    # A capture file may hold many connections.  Group on the full 4-tuple
    # first (endpoint *port* alone is not unique: server port 80 serves
    # many clients), then pick the requested or the first flow.
    chosen = None
    packets = []
    for ts, src, dst, t in _iter_pcap_tcp(path):
        flow = tuple(sorted((src, dst)))
        if chosen is None:
            if wanted_eps and not (src in wanted_eps or dst in wanted_eps):
                continue
            if wanted_ports and not (
                    src[1] in wanted_ports or dst[1] in wanted_ports):
                continue
            chosen = flow
        if flow != chosen:
            continue
        packets.append((ts, src, dst, t))

    for ts, src, dst, t in packets:
        analyzer.feed(ts, t, src=src, dst=dst)
    return analyzer


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

def _syn(a, t, side, seq, **kw):
    return a.feed(t, side=side, seq=seq, flags=_tcp.TH_SYN, **kw)


def _synack(a, t, side, seq, ack, **kw):
    return a.feed(t, side=side, seq=seq, ack=ack,
                  flags=_tcp.TH_SYN | _tcp.TH_ACK, **kw)


def _data(a, t, side, seq, data, fin=False, ack=None):
    flags = _tcp.TH_ACK | (_tcp.TH_FIN if fin else 0)
    return a.feed(t, side=side, seq=seq, ack=ack, flags=flags,
                  payload=data)


def _ack(a, t, side, ack, seq=1000, blocks=None):
    opts = b''
    if blocks is not None:
        body = b''.join(l.to_bytes(4, 'big') + r.to_bytes(4, 'big')
                        for l, r in blocks)
        opts = bytes([_tcp.TCP_OPT_SACK, 2 + len(body)]) + body
    return a.feed(t, side=side, seq=seq, ack=ack, flags=_tcp.TH_ACK,
                  payload=b'', opts=opts)


def _handshake(a, isn_c=1000, isn_s=5000):
    _syn(a, 0.000, 0, isn_c)
    _synack(a, 0.010, 1, isn_s, isn_c + 1)
    _ack(a, 0.020, 0, isn_s + 1, seq=isn_c + 1)


def test_seq_helpers():
    assert _signed_delta(5, MOD - 2) == 7
    assert _signed_delta(MOD - 2, 5) == -7
    uw = _Unwrapper()
    assert uw.unwrap(0xfffffff0) == 0xfffffff0
    assert uw.unwrap(0x00000010) == 0x100000010
    assert uw.unwrap(0xfffffff0) == 0xfffffff0  # retrans stays unwrapped
    assert to_seq32_ranges([(0xfffffff0, 0x10000000a)]) == [
        (0xfffffff0, 0x00000000), (0x00000000, 0x0000000a)]
    assert to_seq32_ranges([(0x100000000, 0x100000005)]) == [
        (0x00000000, 0x00000005)]
    assert _subtract([(0, 10)], 5, 8) == [(0, 5), (8, 10)]
    assert _subtract([(0, 10)], 0, 10) == []


def test_basic_send_and_ack():
    a = TcpAckAnalyzer()
    _handshake(a)
    _data(a, 0.030, 0, 1001, b'abcdefghij')
    snap = a.stats(0)
    assert snap['inflight_bytes'] == 10
    assert snap['inflight_ranges'] == [(1001, 1011)]
    _ack(a, 0.100, 1, 1011, seq=5001)
    snap = a.stats(0)
    assert snap['outstanding_bytes'] == 0
    assert snap['bytes_acknowledged'] == 10
    assert snap['rtt_samples'] == [0.01, 0.07]  # SYN rtt + data rtt


def test_wraparound():
    a = TcpAckAnalyzer()
    isn = MOD - 4
    _handshake(a, isn_c=isn, isn_s=100)
    # 10 payload bytes straddle the 2**32 boundary.
    _data(a, 0.030, 0, (isn + 1) & 0xffffffff, b'0123456789')
    snap = a.stats(0)
    assert snap['inflight_ranges'] == [
        (0xfffffffD & 0xffffffff, 0x00000000),
        (0x00000000, 0x00000007)]
    assert snap['inflight_bytes'] == 10
    # ACK number also wraps.
    _ack(a, 0.090, 1, 7, seq=101)
    snap = a.stats(0)
    assert snap['snd_una32'] == 7
    assert snap['inflight_bytes'] == 0
    assert snap['bytes_acknowledged'] == 10
    assert snap['rtt_samples'][-1] == 0.06


def test_overlapping_retransmission_rtt():
    a = TcpAckAnalyzer()
    _handshake(a)
    _data(a, 0.030, 0, 1001, b'0123456789')        # [1001,1011)
    # Exact retransmission of the whole segment at 0.050.
    _data(a, 0.050, 0, 1001, b'0123456789')
    # Partial retransmission: covers bytes [1006,1011) plus fresh data.
    _data(a, 0.060, 0, 1006, b'56789ABCDEFGHI')     # [1006,1020)
    _ack(a, 0.100, 1, 1020, seq=5001)
    snap = a.stats(0)
    assert snap['segments_retrans'] == 1
    assert snap['dup_segments'] == 1
    assert snap['segments_partial_retrans'] == 1
    # [1011,1020) is the only stretch with a single, once-sent owner.
    data_rtts = [s for s in a.steps[-1]['ack_event']['new_rtt_samples']
                 if s['kind'] == 'cumulative']
    assert len(data_rtts) == 1
    assert data_rtts[0]['matched_lo32'] == 1011
    assert data_rtts[0]['matched_hi32'] == 1020
    assert abs(data_rtts[0]['rtt'] - 0.04) < 1e-9
    assert snap['inflight_bytes'] == 0


def test_retransmission_acked_piecemeal_no_ambiguous_rtt():
    a = TcpAckAnalyzer()
    _handshake(a)
    _data(a, 0.030, 0, 1001, b'01234')
    _data(a, 0.050, 0, 1001, b'01234')   # exact retransmit
    _ack(a, 0.090, 1, 1006, seq=5001)
    ack_ev = a.steps[-1]['ack_event']
    assert [s for s in ack_ev['new_rtt_samples']
            if s['kind'] == 'cumulative'] == []


def test_duplicate_acks_and_sack():
    a = TcpAckAnalyzer()
    _handshake(a)
    _data(a, 0.030, 0, 1001, b'0123456789')   # [1001,1011)
    _data(a, 0.040, 0, 1011, b'abcdefghij')   # [1011,1021)
    _data(a, 0.050, 0, 1021, b'XYZ')          # [1021,1024)
    # First segment lost at receiver: three dup ACKs with growing SACKs.
    _ack(a, 0.060, 1, 1001, seq=5001, blocks=[(1011, 1024)])
    _ack(a, 0.070, 1, 1001, seq=5001)
    _ack(a, 0.080, 1, 1001, seq=5001, blocks=[(1011, 1024)])
    snap = a.stats(0)
    assert snap['acks_duplicate'] == 3
    assert snap['sacked_bytes'] == 13
    assert snap['inflight_bytes'] == 10
    assert snap['outstanding_bytes'] == 23
    assert snap['inflight_ranges'] == [(1001, 1011)]
    # SACK gives unambiguous RTT for the segments it uniquely covered.
    sack_samples = [s for st in a.steps if st['ack_event']
                    for s in st['ack_event']['new_rtt_samples']
                    if s['kind'] == 'sack']
    kinds = {(s['matched_lo32'], s['matched_hi32'])
             for s in sack_samples}
    assert (1011, 1021) in kinds
    assert (1021, 1024) in kinds
    # Cumulative ACK finally covers the lost-and-re-sent first segment:
    # the SACKed records must still exist (no premature dropping).
    _ack(a, 0.120, 1, 1024, seq=5001)
    snap = a.stats(0)
    assert snap['snd_una32'] == 1024
    assert snap['inflight_bytes'] == 0
    assert snap['sacked_bytes'] == 0


def test_sack_reneging_keeps_inflight():
    a = TcpAckAnalyzer()
    _handshake(a)
    _data(a, 0.030, 0, 1001, b'0123456789')
    _data(a, 0.040, 0, 1011, b'abcdefghij')
    _ack(a, 0.060, 1, 1001, seq=5001, blocks=[(1011, 1021)])
    assert a.stats(0)['sacked_bytes'] == 10
    # Peer reneges: a SACK option advertising no blocks puts the bytes back
    # in flight.
    ev = _ack(a, 0.080, 1, 1001, seq=5001, blocks=[])['ack_event']
    assert ev['sack_reneged_bytes'] == 10
    snap = a.stats(0)
    assert snap['sacked_bytes'] == 0
    assert snap['inflight_bytes'] == 20
    assert snap['sack_reneges'] == 1
    assert 'sack-reneging' in snap['uncertain']


def test_backward_ack_is_classified():
    a = TcpAckAnalyzer()
    _handshake(a)
    _data(a, 0.030, 0, 1001, b'0123456789')
    _ack(a, 0.060, 1, 1011, seq=5001)
    ev = _ack(a, 0.070, 1, 1005, seq=5001)['ack_event']
    assert ev['classification'] == 'backward-ack'
    snap = a.stats(0)
    assert snap['acks_backward'] == 1
    assert snap['snd_una32'] == 1011  # never moved backwards


def test_out_of_order_hole_filler_is_new_data():
    a = TcpAckAnalyzer()
    _handshake(a)
    # Receiver-side reordering mirrored into capture: later seq first.
    _data(a, 0.030, 0, 1011, b'abcdefghij')
    _data(a, 0.040, 0, 1001, b'0123456789')
    snap = a.stats(0)
    assert snap['segments_new'] == 2
    assert snap['segments_retrans'] == 0
    assert snap['inflight_ranges'] == [(1001, 1021)]


def test_captured_ack_reordering():
    a = TcpAckAnalyzer()
    _handshake(a)
    _data(a, 0.030, 0, 1001, b'0123456789')
    _ack(a, 0.060, 1, 1011, seq=5001)
    _ack(a, 0.070, 1, 1005, seq=5001)   # captured late: moves backwards
    _ack(a, 0.080, 1, 1011, seq=5001)   # duplicate relative to live una
    snap = a.stats(0)
    assert snap['acks_backward'] == 1
    assert snap['acks_duplicate'] == 1
    assert snap['snd_una32'] == 1011


def test_missing_handshake_short_sequence():
    a = TcpAckAnalyzer()
    # Capture begins mid-connection with a data burst and cumulative ACK.
    _data(a, 0.000, 0, 9000, b'hello')
    _data(a, 0.010, 0, 9005, b'world')
    snap = a.stats(0)
    assert 'missing-handshake' in snap['uncertain']
    assert snap['inflight_bytes'] == 10
    _ack(a, 0.050, 1, 9010, seq=50)
    snap = a.stats(0)
    assert snap['snd_una32'] == 9010
    assert snap['inflight_bytes'] == 0
    # First observed segment is classified from observed history alone.
    assert a.steps[0]['send_event']['classification'] == 'new-data'
    assert a.steps[0]['send_event']['uncertain'] is True


def test_missing_handshake_ack_advances_past_unobserved():
    a = TcpAckAnalyzer()
    _data(a, 0.000, 0, 9010, b'xy')
    # ACK also covers 8 bytes sent before capture began.
    ev = _ack(a, 0.050, 1, 9012, seq=1)['ack_event']
    snap = a.stats(0)
    assert ev['classification'] == 'bootstrap-ack'
    assert snap['snd_una32'] == 9012
    assert snap['inflight_bytes'] == 0
    assert 'missing-handshake' in snap['uncertain']


def test_syn_fin_consume_seq_but_not_payload():
    a = TcpAckAnalyzer()
    _handshake(a)
    _data(a, 0.030, 0, 1001, b'data', fin=True)  # data + FIN
    snap = a.stats(0)
    assert snap['inflight_bytes'] == 4
    _ack(a, 0.100, 1, 1006, seq=5001)            # acks data and FIN
    snap = a.stats(0)
    assert snap['fin_acked'] is True
    assert snap['bytes_acknowledged'] == 4       # FIN not counted as data
    assert snap['inflight_bytes'] == 0


def test_pure_fin_and_rst():
    a = TcpAckAnalyzer()
    _handshake(a)
    ev = a.feed(0.030, side=0, seq=1001, ack=5001,
                flags=_tcp.TH_ACK | _tcp.TH_FIN)['send_event']
    assert ev['classification'] == 'fin'
    ev = a.feed(0.100, seq=5001, ack=1002, flags=_tcp.TH_ACK,
                side=1)['ack_event']
    assert ev['fin_acked']
    assert ev['adv_bytes'] == 0
    assert a.stats(0)['bytes_acknowledged'] == 0

    b = TcpAckAnalyzer()
    ev = b.feed(0.0, side=0, seq=1001, flags=_tcp.TH_RST)['send_event']
    assert ev['classification'] == 'rst'


def test_wraparound_exact_retransmit_no_rtt():
    a = TcpAckAnalyzer()
    isn = MOD - 4
    _handshake(a, isn_c=isn, isn_s=8000)
    seq = (isn + 1) & 0xffffffff
    _data(a, 0.030, 0, seq, b'0123456789')
    _data(a, 0.080, 0, seq, b'0123456789')   # exact retransmit
    _ack(a, 0.120, 1, 7, seq=8001)
    ev = a.steps[-1]['ack_event']
    # Every acked byte was sent twice -> no data RTT may be reported.
    assert [s for s in ev['new_rtt_samples']
            if s['kind'] == 'cumulative'] == []
    snap = a.stats(0)
    assert snap['dup_segments'] == 1
    assert snap['data_bytes_retrans'] == 10
    assert snap['inflight_bytes'] == 0


def test_sack_blocks_parsed_from_tcp_options():
    body = b''.join(x.to_bytes(4, 'big') for x in
                    (100, 200, 300, 400))
    opts = bytes([_tcp.TCP_OPT_NOP]) + \
        bytes([_tcp.TCP_OPT_SACK, 2 + len(body)]) + body
    assert parse_sack_blocks(opts) == [(100, 200), (300, 400)]
    # malformed trailing block must not raise
    assert parse_sack_blocks(
        bytes([_tcp.TCP_OPT_SACK, 7]) + b'\x00' * 5) == []


def test_parse_sack_blocks_absent_vs_empty():
    assert parse_sack_blocks(b'') is None  # no SACK option
    assert parse_sack_blocks(
        bytes([_tcp.TCP_OPT_NOP, _tcp.TCP_OPT_NOP])) is None
    assert parse_sack_blocks(
        bytes([_tcp.TCP_OPT_SACK, 2])) == []  # present but empty


def test_analyze_pcap_real_trace():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, '..', 'examples', 'data', 'http.pcap')
    a = analyze_pcap(path)
    assert a.steps
    s0, s1 = a.stats()
    assert s0['inflight_bytes'] == 0
    assert s1['inflight_bytes'] == 0
    assert s0['data_bytes_sent'] == s0['bytes_acknowledged']
    assert s1['data_bytes_sent'] == s1['bytes_acknowledged']
    assert s0['uncertain'] == [] and s1['uncertain'] == []
    # The capture holds two connections; port selection must isolate them.
    other = analyze_pcap(path, endpoints=[3371])
    assert len(other.steps) < len(a.steps)
