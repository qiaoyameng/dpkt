# -*- coding: utf-8 -*-
"""Offline TCP acknowledgment / in-flight analyzer.

The caller feeds the packets of one TCP connection, in capture order,
tagged with their direction.  The analyzer tracks, per direction:

* the intervals that were ever sent (payload plus the SYN/FIN control
  bytes, which consume sequence space but are not payload);
* the cumulative ACK edge and the SACK blocks seen so far;
* first transmissions versus retransmissions (including byte-wise
  overlaps and wrap-around of the 32 bit sequence space);
* first acknowledgement, duplicate ACK, stale/out-of-order ACK and
  "uncertain" states caused by an incomplete capture;
* RTT samples that are unambiguous under Karn's rule.

SACK information only marks records as selectively acknowledged; the
records are retained until the cumulative ACK actually covers them, so a
later cumulative ACK cannot make a retransmitted segment look like a
clean RTT sample.

All sequence work is done on unwrapped monotonically increasing integers
relative to the direction's anchor sequence; values are mapped back to
32 bit numbers only for display.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

SEQ_MOD = 1 << 32
SEQ_HALF = 1 << 31

# control flags (mirrors dpkt/tcp.py constants)
TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20
TH_ECE = 0x40
TH_CWR = 0x80

_FLAG_CHARS = {
    'F': TH_FIN, 'S': TH_SYN, 'R': TH_RST, 'P': TH_PUSH,
    'A': TH_ACK, 'U': TH_URG, 'E': TH_ECE, 'C': TH_CWR,
}
_FLAG_NAMES = {
    'FIN': TH_FIN, 'SYN': TH_SYN, 'RST': TH_RST, 'PUSH': TH_PUSH,
    'ACK': TH_ACK, 'URG': TH_URG, 'ECE': TH_ECE, 'CWR': TH_CWR,
}

Interval = Tuple[int, int]


# ---------------------------------------------------------------------------
# sequence space helpers
# ---------------------------------------------------------------------------

def seq_sub(left: int, right: int) -> int:
    """Signed-free modular distance: (left - right) mod 2**32 in [0, 2**32)."""
    return (left - right) & (SEQ_MOD - 1)


def seq_lt(left: int, right: int) -> bool:
    """Modulo comparison of two raw 32 bit sequence numbers."""
    d = seq_sub(left, right)
    return 0 < d < SEQ_HALF


def seq_le(left: int, right: int) -> bool:
    return left == right or seq_lt(left, right)


def _nearest(value: int, hint: int) -> int:
    """Pick ``value + k*2**32`` (k in -1..1) nearest to ``hint``."""
    base = (hint // SEQ_MOD) * SEQ_MOD
    candidates = (base + value - SEQ_MOD, base + value, base + value + SEQ_MOD)
    return min(candidates, key=lambda candidate: abs(candidate - hint))


def unwrap_relative(raw: int, anchor: int, hint: int) -> int:
    """Unwrap a raw seq relative to the anchored ISN, near ``hint``."""
    return _nearest(seq_sub(raw, anchor), hint)


def to_u32(value: int) -> int:
    return value & (SEQ_MOD - 1)


def normalize_flags(flags) -> int:
    """Accept a bit mask, an iterable of names, or a shorthand string.

    Shorthand characters follow tcpdump: S SYN, F FIN, R RST, P PUSH,
    A ACK, U URG, E ECE, C CWR.
    """
    if flags is None:
        return 0
    if isinstance(flags, int):
        return flags & 0x1FF
    if isinstance(flags, str):
        upper = flags.upper()
        if all(ch in _FLAG_NAMES for ch in upper.split(',')):
            mask = 0
            for name in upper.split(','):
                mask |= _FLAG_NAMES[name]
            return mask
        mask = 0
        for ch in upper:
            if ch not in _FLAG_CHARS:
                raise ValueError('unknown flag shorthand: %r' % ch)
            mask |= _FLAG_CHARS[ch]
        return mask
    mask = 0
    for name in flags:
        name = str(name).upper()
        if name not in _FLAG_NAMES:
            raise ValueError('unknown flag name: %r' % name)
        mask |= _FLAG_NAMES[name]
    return mask


# ---------------------------------------------------------------------------
# interval helpers (half-open [lo, hi), unwrapped coordinates)
# ---------------------------------------------------------------------------

def merge_intervals(intervals: Iterable[Interval]) -> List[Interval]:
    """Union of half-open intervals; adjacent intervals are joined."""
    ordered = sorted((lo, hi) for lo, hi in intervals if hi > lo)
    merged: List[Interval] = []
    for lo, hi in ordered:
        if merged and lo <= merged[-1][1]:
            if hi > merged[-1][1]:
                merged[-1] = (merged[-1][0], hi)
        else:
            merged.append((lo, hi))
    return merged


def interval_length(intervals: Sequence[Interval]) -> int:
    return sum(hi - lo for lo, hi in intervals)


def intersect_length(intervals: Sequence[Interval], lo: int, hi: int) -> int:
    total = 0
    for iv_lo, iv_hi in intervals:
        overlap = min(hi, iv_hi) - max(lo, iv_lo)
        if overlap > 0:
            total += overlap
    return total


def cut_prefix(intervals: Sequence[Interval], edge: int) -> List[Interval]:
    """Drop every byte < edge (the cumulative ACK prefix)."""
    result = []
    for lo, hi in intervals:
        if hi <= edge:
            continue
        result.append((max(lo, edge), hi))
    return result


def subtract_intervals(intervals: Sequence[Interval],
                       removed: Sequence[Interval]) -> List[Interval]:
    result: List[Interval] = []
    for lo, hi in intervals:
        pieces: List[Interval] = [(lo, hi)]
        for rm_lo, rm_hi in removed:
            next_pieces: List[Interval] = []
            for p_lo, p_hi in pieces:
                if rm_hi <= p_lo or rm_lo >= p_hi:
                    next_pieces.append((p_lo, p_hi))
                else:
                    if p_lo < rm_lo:
                        next_pieces.append((p_lo, rm_lo))
                    if p_hi > rm_hi:
                        next_pieces.append((rm_hi, p_hi))
            pieces = next_pieces
        result.extend(pieces)
    return merge_intervals(result)


# ---------------------------------------------------------------------------
# input packet and result types
# ---------------------------------------------------------------------------

@dataclass
class Packet:
    """One captured TCP segment handed in by the caller.

    Attributes:
        direction - 0 or 1 (c2s / s2c or caller defined)
        time      - capture timestamp, seconds (any monotonic epoch)
        seq       - raw 32 bit TCP sequence number
        ack       - raw 32 bit acknowledgment number, or None
        flags     - TCP flags (mask, name list or shorthand string)
        length    - payload length in bytes
        sacks     - iterable of (start_seq, end_seq) raw 32 bit SACK blocks
    """
    direction: int
    time: float
    seq: int
    ack: Optional[int] = None
    flags: object = 0
    length: int = 0
    sacks: Sequence[Interval] = ()

    def __post_init__(self):
        if self.direction not in (0, 1):
            raise ValueError('direction must be 0 or 1')
        self.flags = normalize_flags(self.flags)
        self.seq &= SEQ_MOD - 1
        if self.ack is not None:
            self.ack &= SEQ_MOD - 1
        if self.length < 0:
            raise ValueError('length must be non-negative')
        blocks = []
        for start, end in self.sacks:
            blocks.append((start & (SEQ_MOD - 1), end & (SEQ_MOD - 1)))
        self.sacks = blocks

    @property
    def has_ack(self) -> bool:
        return bool(self.flags & TH_ACK) and self.ack is not None

    @classmethod
    def from_tcp(cls, tcp, direction: int, time: float,
                 length: Optional[int] = None,
                 sacks: Optional[Sequence[Interval]] = None) -> 'Packet':
        """Build a Packet from a parsed :class:`dpkt.tcp.TCP` object.

        ``length`` defaults to ``len(tcp.data)``.  SACK blocks are not
        auto-parsed; use :func:`extract_sacks` and pass them in.
        """
        if length is None:
            length = len(getattr(tcp, 'data', b'') or b'')
        return cls(
            direction=direction, time=time, seq=tcp.seq, ack=tcp.ack,
            flags=tcp.flags, length=length,
            sacks=sacks or (),
        )


def extract_sacks(tcp) -> Tuple[Interval, ...]:
    """Extract (start, end) raw 32 bit blocks from a parsed TCP SACK option."""
    from . import tcp as tcp_mod
    blocks: List[Interval] = []
    try:
        opts = tcp_mod.parse_opts(tcp.opts)
    except Exception:
        return ()
    for opt in opts:
        if opt and opt[0] == tcp_mod.TCP_OPT_SACK:
            data = opt[1]
            end = len(data) - len(data) % 8
            for off in range(0, end, 8):
                start = int.from_bytes(data[off:off + 4], 'big')
                finish = int.from_bytes(data[off + 4:off + 8], 'big')
                if start != finish:
                    blocks.append((start, finish))
    return tuple(blocks)


@dataclass
class RttSample:
    time: float          # capture time of the acknowledging packet
    rtt: float           # seconds
    start: int           # relative start of the acknowledged region
    end: int             # relative cumulative ACK edge after advance
    kind: str            # 'DATA' / 'SYN' / 'FIN' / 'MIXED'


@dataclass
class DirView:
    """Per-direction snapshot after a step (all seq numbers raw u32)."""
    label: str
    anchored: bool
    uncertain: bool
    syn_seen: bool
    fin_seen: bool
    snd_nxt: Optional[int] = None          # next seq after highest sent byte
    una: Optional[int] = None              # cumulative ACK edge
    inflight: List[Interval] = field(default_factory=list)   # raw u32 ranges
    sacked: List[Interval] = field(default_factory=list)     # raw u32 ranges
    range_origin: int = 0        # first raw seq of the outstanding window
    inflight_bytes: int = 0
    sacked_bytes: int = 0
    stats: dict = field(default_factory=dict)


@dataclass
class Step:
    """Result of processing one captured packet."""
    index: int
    time: float
    direction: int
    label: str
    summary: str
    events: List[str] = field(default_factory=list)
    views: Tuple[Optional[DirView], Optional[DirView]] = (None, None)
    stats_delta: Tuple[dict, dict] = ({}, {})


# ---------------------------------------------------------------------------
# per-direction state
# ---------------------------------------------------------------------------

@dataclass
class _Record:
    """A single logical send: the SYN byte, FIN byte, or one payload chunk."""
    start: int          # relative half-open interval
    end: int
    kind: str           # 'SYN', 'FIN', 'DATA'
    first_time: float
    retrans: bool = False
    sacked: bool = False


@dataclass
class _DirState:
    label: str
    # 32 bit space anchor and how it was learned
    anchor: Optional[int] = None
    anchored_by_send: bool = False
    syn_seen: bool = False
    fin_seen: bool = False
    uncertain: bool = False
    # relative monotonic coordinates
    snd_hi: int = 0                 # max end ever sent (relative)
    una: Optional[int] = None      # cumulative ACK edge (relative)
    last_ack_raw: Optional[int] = None
    records: List[_Record] = field(default_factory=list)
    sent: List[Interval] = field(default_factory=list)     # union incl. ctrl
    payload_sent: List[Interval] = field(default_factory=list)
    retrans: List[Interval] = field(default_factory=list)  # dup byte union
    sacked: List[Interval] = field(default_factory=list)   # relative union
    rtts: List[RttSample] = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {
        'data_segments_first': 0,
        'segments_retrans': 0,
        'payload_bytes_sent': 0,
        'payload_bytes_dup': 0,
        'ctrl_syn': 0,
        'ctrl_syn_retrans': 0,
        'ctrl_fin': 0,
        'ctrl_fin_retrans': 0,
        'acks_processed': 0,
        'first_acks': 0,
        'new_acks': 0,
        'duplicate_acks': 0,
        'duplicate_acks_sack': 0,
        'stale_acks': 0,
        'sack_blocks': 0,
        'sack_blocks_stale': 0,
        'payload_bytes_acked': 0,
        'payload_bytes_sacked_new': 0,
        'bytes_acked_unseen': 0,
        'rtt_samples': 0,
        'uncertain_events': 0,
    })

    # -- helpers ------------------------------------------------------------

    def payload_bytes_total(self) -> int:
        return interval_length(self.payload_sent)

    # -- anchoring ----------------------------------------------------------

    def anchor_for_send(self, raw: int, syn: bool):
        if self.anchor is None:
            self.anchor = raw
            self.anchored_by_send = True
            if not syn:
                # capture starts mid-stream: the opening SYN is missing
                self.uncertain = True
                self.stats['uncertain_events'] += 1

    def unwrap(self, raw: int, hint: int) -> int:
        return unwrap_relative(raw, self.anchor, hint)

    # -- sending side -------------------------------------------------------

    def send_piece(self, piece: _Record, events: List[str]):
        old_sent = self.sent
        dup = intersect_length(old_sent, piece.start, piece.end)
        if piece.end > self.snd_hi:
            self.snd_hi = piece.end
        if dup:
            piece.retrans = True
            self.retrans = merge_intervals(
                self.retrans + [(piece.start, piece.end)])
            if piece.kind == 'DATA':
                self.stats['payload_bytes_dup'] += dup
            if piece.kind == 'SYN':
                self.stats['ctrl_syn_retrans'] += 1
                events.append('retransmit:SYN')
            elif piece.kind == 'FIN':
                self.stats['ctrl_fin_retrans'] += 1
                events.append('retransmit:FIN')
            else:
                events.append('retransmit:overlap')
            self.stats['segments_retrans'] += 1
        else:
            if piece.kind == 'DATA':
                self.stats['data_segments_first'] += 1
            tag = {'SYN': 'send:SYN', 'FIN': 'send:FIN',
                   'DATA': 'send:data'}[piece.kind]
            events.append(tag)
        self.sent = merge_intervals(self.sent + [(piece.start, piece.end)])
        if piece.kind == 'DATA':
            self.payload_sent = merge_intervals(
                self.payload_sent + [(piece.start, piece.end)])
            self.stats['payload_bytes_sent'] += piece.end - piece.start
        elif piece.kind == 'SYN':
            self.stats['ctrl_syn'] += 1
        else:
            self.stats['ctrl_fin'] += 1
        self.records.append(piece)

    def handle_send(self, pkt: Packet) -> List[str]:
        events: List[str] = []
        flags = pkt.flags
        syn = bool(flags & TH_SYN)
        fin = bool(flags & TH_FIN)
        self.anchor_for_send(pkt.seq, syn)
        self.syn_seen = self.syn_seen or syn
        self.fin_seen = self.fin_seen or fin

        cursor = self.unwrap(pkt.seq, self.snd_hi)
        pieces: List[Tuple[str, int, int]] = []
        if syn:
            pieces.append(('SYN', cursor, cursor + 1))
            cursor += 1
        if pkt.length:
            pieces.append(('DATA', cursor, cursor + pkt.length))
            cursor += pkt.length
        if fin:
            pieces.append(('FIN', cursor, cursor + 1))

        if not pieces:
            events.append('send:pure-ack')
        for kind, lo, hi in pieces:
            self.send_piece(_Record(lo, hi, kind, pkt.time), events)
        return events

    # -- ACK / SACK side ----------------------------------------------------

    def handle_ack(self, pkt: Packet) -> List[str]:
        events: List[str] = []
        raw_ack = pkt.ack
        self.stats['acks_processed'] += 1

        if self.anchor is None:
            # we have never seen this direction send anything; the ACK
            # arrives before the captured sender data. Anchor the sender's
            # space at the ACK value so later data lines up, but the
            # capture is necessarily incomplete.
            self.anchor = raw_ack
            self.anchored_by_send = False
            self.uncertain = True
            self.stats['uncertain_events'] += 1
            events.append('uncertain:peer-before-send')

        hint = self.una if self.una is not None else 0
        ack_rel = self.unwrap(raw_ack, hint)

        if self.una is None:
            # First ACK seen in the capture. With the SYN observed the
            # baseline is 0 (the SYN byte); without a handshake the ACK
            # itself is the baseline. If the ACK lags behind captured
            # data, anything below it must have been acknowledged before
            # the capture started, so treat it as one bulk advance.
            self.last_ack_raw = raw_ack
            if self.syn_seen:
                base = 0
            else:
                base = min(ack_rel, self.snd_hi)
            self.una = base
            if base == ack_rel:
                self.stats['first_acks'] += 1
                events.append('ack:first')
                if not self.syn_seen:
                    events.append('uncertain:no-syn')
            else:
                self._advance_una(base, ack_rel, pkt, events)
            self._prune_sacks(self.una, events)
            self._apply_sacks(pkt, self.una, events)
            return events

        if ack_rel < self.una:
            self.stats['stale_acks'] += 1
            events.append('ack:stale')
            self._apply_sacks(pkt, self.una, events)
            return events

        is_dup = (raw_ack == self.last_ack_raw)
        if is_dup:
            self.stats['duplicate_acks'] += 1
            sacked_before = interval_length(self.sacked)
            self._apply_sacks(pkt, self.una, events)
            if interval_length(self.sacked) > sacked_before:
                self.stats['duplicate_acks_sack'] += 1
                events.append('ack:duplicate-sack')
            else:
                events.append('ack:duplicate')
            return events

        # the ACK edge advances (first acknowledgement of new data)
        self._advance_una(self.una, ack_rel, pkt, events)
        self._apply_sacks(pkt, self.una, events)
        return events

    def _advance_una(self, old_una: int, new_una: int,
                     pkt: Packet, events: List[str]):
        if new_una > self.snd_hi:
            self.uncertain = True
            self.stats['uncertain_events'] += 1
            events.append('uncertain:acks-unseen')
        self.stats['new_acks'] += 1
        self.stats['bytes_acked_unseen'] += max(
            0, new_una - max(self.snd_hi, old_una))
        self.stats['payload_bytes_acked'] += intersect_length(
            self.payload_sent, old_una, new_una)
        events.append('ack:new')
        self._maybe_rtt(old_una, new_una, pkt, events)
        self.una = new_una
        self.last_ack_raw = pkt.ack
        self._prune_sacks(new_una, events)

    def _maybe_rtt(self, old_una: int, new_una: int,
                   pkt: Packet, events: List[str]):
        window = (old_una, new_una)
        window_len = new_una - old_una
        if window_len <= 0:
            return
        # Karn's rule: the whole freshly-acknowledged window must map to
        # non-retransmitted records, and every byte that was actually sent
        # must be covered exactly once by them.
        covered = 0
        send_time = None
        for rec in self.records:
            overlap = min(rec.end, new_una) - max(rec.start, old_una)
            if overlap <= 0:
                continue
            # Karn: any retransmitted byte inside the window makes the
            # sample ambiguous, even when the same record also covers
            # bytes outside the window.
            retrans_overlap = intersect_length(self.retrans, max(
                rec.start, old_una), min(rec.end, new_una))
            if rec.retrans and retrans_overlap > 0:
                events.append('rtt:skip-retransmit-ambiguous')
                return
            covered += overlap
            if send_time is None or rec.first_time < send_time:
                send_time = rec.first_time
        if covered != window_len:
            events.append('rtt:skip-incomplete-capture')
            return
        rtt = pkt.time - send_time
        if rtt < 0:
            events.append('rtt:skip-negative')
            return
        kinds = {rec.kind for rec in self.records
                 if rec.end > old_una and rec.start < new_una}
        if kinds == {'DATA'}:
            kind = 'DATA'
        elif kinds == {'SYN'}:
            kind = 'SYN'
        elif kinds == {'FIN'}:
            kind = 'FIN'
        else:
            kind = 'MIXED'
        sample = RttSample(pkt.time, rtt, old_una, new_una, kind)
        self.rtts.append(sample)
        self.stats['rtt_samples'] += 1
        events.append('rtt:sample')

    def _prune_sacks(self, una_rel: int, events: List[str]):
        pruned = self.sacked
        kept = cut_prefix(pruned, una_rel)
        if interval_length(pruned) != interval_length(kept):
            events.append('sack:cumulative-overtake')
        self.sacked = kept

    def _apply_sacks(self, pkt: Packet, una_rel: int,
                     events: List[str]) -> None:
        """Process SACK blocks carried by ``pkt``.

        Records are only flagged ``sacked`` — the cumulative ACK edge
        alone decides when a record can leave the in-flight picture, so
        SACK can never discard records permanently.
        """
        una_raw = self.anchor + una_rel
        for start_raw, end_raw in pkt.sacks:
            self.stats['sack_blocks'] += 1
            length_mod = seq_sub(end_raw, start_raw)
            if length_mod == 0 or length_mod >= SEQ_HALF:
                self.stats['sack_blocks_stale'] += 1
                events.append('sack:stale')
                continue
            # Pick the forward-nearest copy of the raw block start
            # within half a sequence space of the cumulative edge, then
            # express it in relative coordinates.
            forward = seq_sub(start_raw, una_raw)
            if forward >= SEQ_HALF:
                forward -= SEQ_MOD
            start = una_rel + forward
            end = start + length_mod
            if end <= una_rel:
                self.stats['sack_blocks_stale'] += 1
                events.append('sack:stale')
                continue
            if end > self.snd_hi:
                self.uncertain = True
                self.stats['uncertain_events'] += 1
                events.append('uncertain:sack-unseen')
            fresh = subtract_intervals([(start, end)], self.sacked)
            self.stats['payload_bytes_sacked_new'] += sum(
                intersect_length(self.payload_sent, lo, hi)
                for lo, hi in fresh)
            self.sacked = merge_intervals(self.sacked + [(start, end)])
            for rec in self.records:
                if rec.end > start and rec.start < end and not rec.sacked:
                    rec.sacked = True
            events.append('sack:block')


# ---------------------------------------------------------------------------
# analyzer
# ---------------------------------------------------------------------------

class TcpAckAnalyzer(object):
    """Feed capture-ordered packets of one connection, both directions.

    Usage::

        an = TcpAckAnalyzer()
        for pkt in packets:
            an.feed(pkt)         # returns a :class:`Step`
        print(render_steps(an.steps))
    """

    LABELS = ('A->B', 'B->A')

    def __init__(self, labels: Optional[Sequence[str]] = None):
        names = list(labels) if labels else list(self.LABELS)
        if len(names) != 2:
            raise ValueError('labels must contain exactly two names')
        self.dirs: Tuple[_DirState, _DirState] = (
            _DirState(names[0]), _DirState(names[1]))
        self.steps: List[Step] = []
        self._last_snap: Tuple[dict, dict] = ({}, {})

    def feed(self, pkt: Packet) -> Step:
        idx = len(self.steps) + 1
        sender = self.dirs[pkt.direction]
        peer = self.dirs[1 - pkt.direction]
        events: List[str] = []

        before = (dict(self.dirs[0].stats), dict(self.dirs[1].stats))

        flags = pkt.flags
        syn = bool(flags & TH_SYN)
        fin = bool(flags & TH_FIN)
        consumes = syn or fin or pkt.length > 0
        if consumes:
            events.extend(sender.handle_send(pkt))
        else:
            # A pure ACK still carries a sequence number; anchor the
            # sender's space on it when the capture started mid-stream.
            sender.anchor_for_send(pkt.seq, syn=False)
            events.append('send:pure-ack')

        if pkt.has_ack:
            events.extend(peer.handle_ack(pkt))
        if flags & TH_RST:
            events.append('ctrl:rst')

        views = (self._view(0), self._view(1))
        after = (dict(views[0].stats), dict(views[1].stats))
        delta = tuple(_dict_diff(before[i], after[i]) for i in (0, 1))
        summary = _summarize(pkt, self.dirs[pkt.direction], events)
        step = Step(
            index=idx, time=pkt.time, direction=pkt.direction,
            label=sender.label, summary=summary, events=events,
            views=views, stats_delta=delta)
        self.steps.append(step)
        return step

    def run(self, packets: Iterable[Packet]) -> List[Step]:
        for pkt in packets:
            self.feed(pkt)
        return self.steps

    # -- views --------------------------------------------------------------

    def _view(self, direction: int) -> DirView:
        st = self.dirs[direction]
        inflight_raw: List[Interval] = []
        sacked_raw: List[Interval] = []
        snd_nxt = None
        una = None
        inflight_bytes = 0
        sacked_bytes = 0
        una_rel = st.una if st.una is not None else 0
        if st.anchor is not None:
            outstanding = cut_prefix(st.sent, una_rel)
            sacked_rel = cut_prefix(st.sacked, una_rel)
            sacked_here = intersect_with(outstanding, sacked_rel)
            inflight_only = subtract_intervals(outstanding, sacked_rel)
            inflight_raw = _order_from(
                _to_u32_intervals(inflight_only, st.anchor),
                to_u32(st.anchor + una_rel))
            sacked_raw = _order_from(
                _to_u32_intervals(sacked_here, st.anchor),
                to_u32(st.anchor + una_rel))
            snd_nxt = to_u32(st.anchor + st.snd_hi)
            una = to_u32(st.anchor + una_rel)
            inflight_bytes = interval_length(inflight_only)
            sacked_bytes = interval_length(sacked_here)
        return DirView(
            label=st.label, anchored=st.anchor is not None,
            uncertain=st.uncertain, syn_seen=st.syn_seen,
            fin_seen=st.fin_seen, snd_nxt=snd_nxt, una=una,
            inflight=inflight_raw, sacked=sacked_raw,
            inflight_bytes=inflight_bytes, sacked_bytes=sacked_bytes,
            range_origin=to_u32(st.anchor + una_rel) if st.anchor is not None else 0,
            stats=dict(st.stats))

    @property
    def rtt_samples(self) -> Tuple[List[RttSample], List[RttSample]]:
        return (self.dirs[0].rtts, self.dirs[1].rtts)


def analyze(packets: Iterable[Packet],
            labels: Optional[Sequence[str]] = None) -> TcpAckAnalyzer:
    """Convenience: process all packets and return the analyzer."""
    an = TcpAckAnalyzer(labels=labels)
    an.run(packets)
    return an


# ---------------------------------------------------------------------------
# view helpers
# ---------------------------------------------------------------------------

def intersect_with(intervals: Sequence[Interval],
                   other: Sequence[Interval]) -> List[Interval]:
    """Intersection of two interval unions in relative coordinates."""
    result: List[Interval] = []
    for lo, hi in intervals:
        for ol, oh in other:
            il, ih = max(lo, ol), min(hi, oh)
            if il < ih:
                result.append((il, ih))
    return merge_intervals(result)


def _dict_diff(before: dict, after: dict) -> dict:
    return {key: after[key] - before.get(key, 0)
            for key in after
            if after[key] - before.get(key, 0) != 0}


def _to_u32_intervals(intervals: Sequence[Interval],
                      anchor: int) -> List[Interval]:
    """Map relative half-open intervals back to raw 32 bit ranges.

    Relative coordinates are unwrapped (can be negative or larger than
    2**32).  Each relative interval is chopped wherever
    ``anchor + coordinate`` crosses a multiple of 2**32; a chunk ending
    exactly at a boundary is reported with an exclusive end of 0 (i.e.
    "...through FFFFFFFF"), which keeps wrap-around visible instead of
    merging with the next chunk.
    """
    raw_pairs: List[Tuple[int, int]] = []
    for lo, hi in intervals:
        cur = lo
        while cur < hi:
            raw_lo = to_u32(anchor + cur)
            # distance from the current raw position to the next wrap
            span = SEQ_MOD - raw_lo
            length = hi - cur
            if length < span:
                raw_pairs.append((raw_lo, to_u32(raw_lo + length)))
                cur = hi
            else:
                raw_pairs.append((raw_lo, 0))
                cur += span
    # sort/merge overlapping pairs while preserving end-at-boundary pairs
    ordered = sorted(
        ((lo, SEQ_MOD if hi == 0 else hi) for lo, hi in raw_pairs),
        key=lambda pair: pair[0])
    merged = merge_intervals(ordered)
    return [(lo, 0 if hi == SEQ_MOD else hi) for lo, hi in merged]


def _order_from(pairs: List[Interval], start: int) -> List[Interval]:
    """Rotate u32 pairs so the interval containing ``start`` is first.

    Keeps wrap-around windows readable (FFFF... ranges before 0000...).
    """
    def begins(pair):
        lo, hi = pair
        if hi == 0:
            hi = SEQ_MOD
        return lo

    def contains(pair):
        lo, hi = pair
        hi = SEQ_MOD if hi == 0 else hi
        if lo < hi:
            return lo <= start < hi
        return lo <= start or start < hi

    for idx, pair in enumerate(pairs):
        if contains(pair):
            return pairs[idx:] + pairs[:idx]
    # fall back: sort by forward modular distance from start
    return sorted(pairs, key=lambda pair: seq_sub(begins(pair), start))


def _summarize(pkt: Packet, sender: _DirState,
               events: List[str]) -> str:
    flags = pkt.flags
    names = []
    for bit, nm in ((TH_SYN, 'SYN'), (TH_FIN, 'FIN'), (TH_RST, 'RST'),
                    (TH_ACK, 'ACK'), (TH_PUSH, 'PSH')):
        if flags & bit:
            names.append(nm)
    flag_str = '.'.join(names) if names else 'NONE'
    parts = ['seq=%08X' % pkt.seq]
    if pkt.length:
        parts.append('len=%u' % pkt.length)
    if pkt.ack is not None and flags & TH_ACK:
        parts.append('ack=%08X' % pkt.ack)
    if pkt.sacks:
        parts.append('SACKx%u' % len(pkt.sacks))
    return '%s %s' % (flag_str, ' '.join(parts))


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

_EVENT_CN = {
    'send:SYN': '发送 SYN（占用序号）',
    'send:FIN': '发送 FIN（占用序号）',
    'send:data': '发送数据',
    'send:pure-ack': '纯 ACK（无正文）',
    'retransmit:SYN': 'SYN 重传',
    'retransmit:FIN': 'FIN 重传',
    'retransmit:overlap': '重传/重叠发送',
    'ack:first': '首个累计 ACK（建立基线）',
    'ack:new': '累计确认推进',
    'ack:duplicate': '重复 ACK',
    'ack:duplicate-sack': '重复 ACK（携带新 SACK）',
    'ack:stale': '乱序/陈旧 ACK（回退），忽略',
    'sack:block': 'SACK 块到达',
    'sack:stale': 'SACK 块陈旧，忽略',
    'sack:cumulative-overtake': '累计 ACK 越过 SACK 区域',
    'rtt:sample': '采纳无歧义 RTT 样本',
    'rtt:skip-retransmit-ambiguous': '拒绝 RTT：重传歧义（Karn）',
    'rtt:skip-incomplete-capture': '拒绝 RTT：捕获不完整',
    'rtt:skip-negative': '拒绝 RTT：时间戳为负',
    'uncertain:peer-before-send': '不确定：ACK 先于所观测发送',
    'uncertain:no-syn': '不确定：缺少握手',
    'uncertain:acks-unseen': '不确定：ACK 越过已观测数据',
    'uncertain:sack-unseen': '不确定：SACK 越过已观测数据',
    'ctrl:rst': 'RST',
}

_STAT_CN = [
    ('data_segments_first', '数据报文首传数'),
    ('segments_retrans', '重传报文数'),
    ('payload_bytes_sent', '正文累计发送字节'),
    ('payload_bytes_dup', '重复/重叠发送字节'),
    ('ctrl_syn', 'SYN 次数'),
    ('ctrl_syn_retrans', 'SYN 重传次数'),
    ('ctrl_fin', 'FIN 次数'),
    ('ctrl_fin_retrans', 'FIN 重传次数'),
    ('acks_processed', '处理 ACK 数'),
    ('first_acks', '首个 ACK 数'),
    ('new_acks', '推进 ACK 数'),
    ('duplicate_acks', '重复 ACK 数'),
    ('duplicate_acks_sack', '带新 SACK 的重复 ACK'),
    ('stale_acks', '乱序/陈旧 ACK 数'),
    ('sack_blocks', 'SACK 块数'),
    ('sack_blocks_stale', '陈旧 SACK 块数'),
    ('payload_bytes_acked', '累计确认正文字节'),
    ('payload_bytes_sacked_new', '新 SACK 正文字节'),
    ('bytes_acked_unseen', '确认未观测数据字节'),
    ('rtt_samples', '采纳 RTT 样本数'),
    ('uncertain_events', '不确定事件数'),
]


def _fmt_ranges(ranges: Sequence[Interval]) -> str:
    if not ranges:
        return '—'
    return ', '.join('%08X-%08X' % (lo, hi) for lo, hi in ranges)


def render_step(step: Step) -> str:
    lines = []
    lines.append('[%03d] t=%.6f  %s  %s' % (
        step.index, step.time, step.label, step.summary))
    for event in step.events:
        lines.append('      · %s' % _EVENT_CN.get(event, event))
    for direction in (0, 1):
        view = step.views[direction]
        if view is None or not view.anchored:
            continue
        delta = step.stats_delta[direction]
        flag_bits = []
        if view.uncertain:
            flag_bits.append('不确定')
        if not view.syn_seen:
            flag_bits.append('未见 SYN')
        flags = (' [%s]' % '，'.join(flag_bits)) if flag_bits else ''
        lines.append('      [%s]%s 在途=%s（%u 字节） SACK=%s（%u 字节）'
                     ' SND.NXT=%08X UNA=%08X' % (
                         view.label, flags,
                         _fmt_ranges(view.inflight), view.inflight_bytes,
                         _fmt_ranges(view.sacked), view.sacked_bytes,
                         view.snd_nxt or 0, view.una or 0))
        for key, name in _STAT_CN:
            if key in delta and delta[key] != 0:
                sign = '+' if delta[key] > 0 else ''
                lines.append('          统计 %s: %s%s（累计 %s）' % (
                    name, sign, delta[key], view.stats[key]))
    return '\n'.join(lines)


def render_steps(steps: Sequence[Step]) -> str:
    return '\n'.join(render_step(step) for step in steps)


def render_rtt(analyzer: TcpAckAnalyzer) -> str:
    blocks = []
    for direction in (0, 1):
        st = analyzer.dirs[direction]
        blocks.append('[%s] RTT 样本 %u 个:' % (st.label, len(st.rtts)))
        for sample in st.rtts:
            blocks.append('    t=%.6f  rtt=%.6fs  %s  确认区间 %08X-%08X' % (
                sample.time, sample.rtt, sample.kind,
                to_u32(st.anchor + sample.start),
                to_u32(st.anchor + sample.end)))
    return '\n'.join(blocks)


# ---------------------------------------------------------------------------
# tests (inline, following the repository convention)
# ---------------------------------------------------------------------------

def test_normalize_flags():
    assert normalize_flags('SA') == TH_SYN | TH_ACK
    assert normalize_flags('fa') == TH_FIN | TH_ACK
    assert normalize_flags(['SYN', 'ACK']) == TH_SYN | TH_ACK
    assert normalize_flags(0x12) == TH_SYN | TH_ACK
    assert normalize_flags('SYN,ACK') == TH_SYN | TH_ACK


def test_seq_helpers():
    assert seq_sub(10, 0xFFFFFFF0) == 26
    assert seq_lt(5, 0xFFFFFFFF)
    assert not seq_lt(0xFFFFFFFF, 5)
    assert seq_lt(0x80000001, 1) is False
    assert seq_lt(0x7FFFFFFF, 0)
    # unwrap near a hint keeps monotonic coordinates
    assert unwrap_relative(0xFFFFFFF0, 0xFFFFFFF0, 0) == 0
    assert unwrap_relative(0x00000010, 0xFFFFFFF0, 0) == 32


def test_intervals():
    assert merge_intervals([(1, 3), (3, 5), (10, 12)]) == [(1, 5), (10, 12)]
    assert interval_length(merge_intervals([(0, 5), (4, 10)])) == 10
    assert intersect_length([(0, 10)], 8, 20) == 2
    assert cut_prefix([(0, 2), (3, 8)], 4) == [(4, 8)]
    assert subtract_intervals([(0, 10)], [(2, 4), (6, 8)]) == [
        (0, 2), (4, 6), (8, 10)]
    assert intersect_with([(0, 10)], [(2, 4), (8, 12)]) == [(2, 4), (8, 10)]


def test_wraparound():
    """序号跨越 32 位回绕边界，在途范围仍按真实区间跟踪。"""
    isn = 0xFFFFFFF0
    an = TcpAckAnalyzer()
    an.feed(Packet(0, 0.0, isn, flags='S'))
    an.feed(Packet(1, 0.001, 100, ack=to_u32(isn + 1), flags='SA'))
    an.feed(Packet(0, 0.002, to_u32(isn + 1), ack=101, flags='A'))
    # 20 data bytes straddle the wrap boundary: FFFFFFF1..FFFFFFFF, 00000000..0000000B
    an.feed(Packet(0, 0.003, to_u32(isn + 1), flags='PA', length=20))
    step = an.feed(Packet(1, 0.005, 101,
                          ack=to_u32(isn + 1 + 20), flags='A'))
    d0 = an.dirs[0]
    assert d0.payload_bytes_total() == 20
    # the 20 bytes are fully acknowledged across the wrap
    assert step.views[0].inflight_bytes == 0
    assert len(an.rtt_samples[0]) == 2  # SYN RTT and data RTT
    data_rtt = an.rtt_samples[0][-1]
    assert data_rtt.kind == 'DATA' and abs(data_rtt.rtt - 0.002) < 1e-9

    # partial ACK landing exactly on the boundary: first 15 bytes acked
    an2 = TcpAckAnalyzer()
    an2.feed(Packet(0, 0.0, isn, flags='S'))
    an2.feed(Packet(1, 0.001, 100, ack=to_u32(isn + 1), flags='SA'))
    an2.feed(Packet(0, 0.002, to_u32(isn + 1), ack=101, flags='A'))
    an2.feed(Packet(0, 0.003, to_u32(isn + 1), flags='PA', length=20))
    st = an2.feed(Packet(1, 0.004, 101,
                         ack=to_u32(isn + 1 + 15), flags='A'))
    assert st.views[0].inflight == [(0x00000000, 0x00000005)]
    assert st.views[0].inflight_bytes == 5


def test_overlapping_retransmit_and_karn():
    """重叠重传被识别；含重传的 ACK 窗口不产出 RTT。"""
    an = TcpAckAnalyzer()
    an.feed(Packet(0, 0.0, 1000, flags='S'))
    an.feed(Packet(1, 0.001, 2000, ack=1001, flags='SA'))
    an.feed(Packet(0, 0.002, 1001, ack=2001, flags='A'))
    an.feed(Packet(0, 0.003, 1001, flags='PA', length=100))   # 1001..1101
    # clean ACK of the first 50 bytes -> valid RTT from t=0.003
    an.feed(Packet(1, 0.004, 2001, ack=1051, flags='A'))
    # loss + retransmit: bytes 1051..1080 sent again (plus a tail overlap)
    an.feed(Packet(0, 0.020, 1051, flags='PA', length=30))
    dup_step = an.feed(Packet(1, 0.021, 2001, ack=1051,
                              flags='A', sacks=[(1051, 1081)]))
    d0 = an.dirs[0]
    assert d0.stats['segments_retrans'] == 1
    assert d0.stats['payload_bytes_dup'] == 30
    assert dup_step.views[0].sacked == [(1051, 1081)]
    assert dup_step.views[0].inflight == [(1081, 1101)]
    # cumulative ACK covering the retransmitted window: Karn ambiguity
    step = an.feed(Packet(1, 0.022, 2001, ack=1081, flags='A'))
    assert 'rtt:skip-retransmit-ambiguous' in step.events
    assert d0.stats['rtt_samples'] == 2  # SYN + first clean 50 bytes
    # tail bytes were sent once; their ACK is unambiguous
    last = an.feed(Packet(1, 0.023, 2001, ack=1101, flags='A'))
    assert 'rtt:sample' in last.events
    assert d0.stats['rtt_samples'] == 3
    assert an.rtt_samples[0][-1].rtt == 0.020

    # byte-level partial overlap must also count as retransmission
    an2 = TcpAckAnalyzer()
    an2.feed(Packet(0, 0.0, 1, flags='S'))
    an2.feed(Packet(1, 0.001, 9, ack=2, flags='SA'))
    an2.feed(Packet(0, 0.002, 2, ack=10, flags='A'))
    an2.feed(Packet(0, 0.003, 2, flags='PA', length=100))   # 2..102
    an2.feed(Packet(0, 0.010, 90, flags='PA', length=30))    # 90..120
    st2 = an2.dirs[0]
    assert st2.stats['payload_bytes_dup'] == 12
    assert st2.stats['payload_bytes_sent'] == 130


def test_reorder_and_duplicate_acks():
    """乱序到达的 ACK：陈旧 ACK 忽略，重复 ACK 计数，新 SACK 单列。"""
    an = TcpAckAnalyzer()
    an.feed(Packet(0, 0.0, 100, flags='S'))
    an.feed(Packet(1, 0.001, 50, ack=101, flags='SA'))
    an.feed(Packet(0, 0.002, 101, ack=51, flags='A'))
    an.feed(Packet(0, 0.003, 101, flags='PA', length=100))
    an.feed(Packet(1, 0.004, 51, ack=111, flags='A'))    # UNA 111
    # two duplicate ACKs without SACK
    dup1 = an.feed(Packet(1, 0.005, 51, ack=111, flags='A'))
    dup2 = an.feed(Packet(1, 0.006, 51, ack=111, flags='A'))
    assert 'ack:duplicate' in dup1.events
    assert 'ack:duplicate' in dup2.events
    # duplicate ACK carrying fresh SACK info
    d3 = an.feed(Packet(1, 0.007, 51, ack=111, flags='A',
                        sacks=[(121, 151)]))
    assert 'ack:duplicate-sack' in d3.events
    # stale/out-of-order ACK: sequence 101 already passed
    stale = an.feed(Packet(1, 0.008, 51, ack=101, flags='A'))
    assert 'ack:stale' in stale.events
    # fresh cumulative advance reuses raw ACK 111? no -> advances normally
    adv = an.feed(Packet(1, 0.009, 51, ack=151, flags='A'))
    assert 'ack:new' in adv.events
    d0 = an.dirs[0]
    assert d0.stats['duplicate_acks'] == 3
    assert d0.stats['duplicate_acks_sack'] == 1
    assert d0.stats['stale_acks'] == 1
    assert d0.stats['new_acks'] >= 2


def test_missing_handshake_short_capture():
    """捕获从中途开始：缺少 SYN，状态标记为不确定但仍能跟踪。"""
    an = TcpAckAnalyzer()
    # capture starts mid-stream: data without SYN
    s1 = an.feed(Packet(0, 0.0, 5000, flags='PA', length=10))
    assert s1.views[0].uncertain and not s1.views[0].syn_seen
    # ACK for bytes before the capture window
    s2 = an.feed(Packet(1, 0.001, 9000, ack=5005, flags='A'))
    assert 'ack:first' in s2.events and 'uncertain:no-syn' in s2.events
    # the first 5 bytes are treated as acknowledged pre-capture
    assert s2.views[0].inflight == [(5005, 5010)]
    # ACK jumping past everything we observed -> unseen data
    s3 = an.feed(Packet(1, 0.002, 9000, ack=7000, flags='A'))
    assert 'uncertain:acks-unseen' in s3.events
    assert an.dirs[0].stats['bytes_acked_unseen'] == 7000 - 5010
    # no RTT sample can be claimed for the pre-capture first ACK window
    assert an.dirs[0].stats['rtt_samples'] == 0

    # ACK arriving before any observed send in that direction
    an2 = TcpAckAnalyzer()
    z = an2.feed(Packet(0, 0.0, 1, flags='A', ack=8888))
    assert z.views[1].uncertain


def test_sack_does_not_discard_records():
    """SACK 只标记在途记录，不能永久丢弃；之后的累计确认仍可判重传歧义。"""
    an = TcpAckAnalyzer()
    an.feed(Packet(0, 0.0, 100, flags='S'))
    an.feed(Packet(1, 0.001, 50, ack=101, flags='SA'))
    an.feed(Packet(0, 0.002, 101, ack=51, flags='A'))
    an.feed(Packet(0, 0.003, 101, flags='PA', length=100))  # 101..201
    # 101..131 cumulatively acked; 131..161 received but only SACKed
    an.feed(Packet(1, 0.004, 51, ack=131, flags='A',
                   sacks=[(131, 161)]))
    view = an.steps[-1].views[0]
    assert view.sacked == [(131, 161)]
    assert view.inflight == [(161, 201)]
    assert view.inflight_bytes == 40
    # retransmission of an already-SACKed region (spurious-looking dup)
    an.feed(Packet(0, 0.010, 131, flags='PA', length=30))
    # cumulative ACK now overtakes the previously SACKed space. Records
    # for 131..161 must still exist and the retransmit must be detected:
    # Karn ambiguity forbids an RTT sample for this window.
    step = an.feed(Packet(1, 0.011, 51, ack=161, flags='A'))
    assert 'rtt:skip-retransmit-ambiguous' in step.events
    # SACK region became cumulative: overtaken notice, sacked display empty
    assert 'sack:cumulative-overtake' in step.events
    assert step.views[0].sacked == []
    assert step.views[0].inflight == [(161, 201)]


def test_from_tcp_and_extract_sacks():
    """Packet.from_tcp / extract_sacks integrate with dpkt.tcp.TCP."""
    from . import tcp as tcp_mod
    sack_data = b'\x05\x0a' + b'\x00\x00\x00\x05' + b'\x00\x00\x00\x0a'
    opts = sack_data + b'\x01'  # SACK option + NOP padding
    # 20 byte base header + 12 bytes options -> data offset 8
    off_flags = (8 << 12) | tcp_mod.TH_ACK
    tcp = tcp_mod.TCP(
        sport=1234, dport=80, seq=0xFFFFFFF0, ack=0x00000010,
        off=8, flags=tcp_mod.TH_ACK, win=100, opts=opts,
        data=b'hello')
    tcp._off_flags = off_flags
    blocks = extract_sacks(tcp)
    assert blocks == ((5, 10),)
    pkt = Packet.from_tcp(tcp, direction=1, time=1.5, sacks=blocks)
    assert pkt.length == 5 and pkt.seq == 0xFFFFFFF0 and pkt.ack == 0x10
    assert pkt.flags == tcp_mod.TH_ACK


def test_render_smoke():
    an = TcpAckAnalyzer()
    for pkt in [
        Packet(0, 0.0, 1000, flags='S'),
        Packet(1, 0.001, 5000, ack=1001, flags='SA'),
        Packet(0, 0.002, 1001, ack=5001, flags='A'),
    ]:
        an.feed(pkt)
    text = render_steps(an.steps)
    assert '在途=' in text and '采纳无歧义 RTT 样本' in text
    assert 'RTT 样本' in render_rtt(an)


def test_fin_consumes_sequence_and_rtt():
    """FIN 占用一个序号、不算正文；其 ACK 可产生独立 FIN RTT。"""
    an = TcpAckAnalyzer()
    an.feed(Packet(0, 0.0, 100, flags='S'))
    an.feed(Packet(1, 0.001, 50, ack=101, flags='SA'))
    an.feed(Packet(0, 0.002, 101, ack=51, flags='A'))
    an.feed(Packet(0, 0.003, 101, flags='FA', length=4))   # data + FIN
    d0 = an.dirs[0]
    assert d0.stats['payload_bytes_sent'] == 4
    assert d0.stats['ctrl_fin'] == 1
    assert d0.fin_seen
    step = an.steps[-1].views[0]
    assert step.inflight == [(101, 106)]   # 4 data + 1 FIN byte
    assert step.inflight_bytes == 5
    # ACK all data but not yet the FIN
    an.feed(Packet(1, 0.004, 51, ack=105, flags='A'))
    assert an.steps[-1].views[0].inflight == [(105, 106)]
    # FIN acknowledged -> own kind of RTT sample
    fin = an.feed(Packet(1, 0.005, 51, ack=106, flags='A'))
    assert 'rtt:sample' in fin.events
    assert an.rtt_samples[0][-1].kind == 'FIN'
    assert an.rtt_samples[0][-1].rtt == 0.002
