# Merging captures into pcapng

`dpkt.pcapmerge.merge` combines several time-ordered pcap or pcapng captures
into one pcapng stream without losing interface identity or timestamp
precision.

```python
from io import BytesIO
from dpkt import pcapng, pcapmerge

destination = BytesIO()
report = pcapmerge.merge([
    open('capture-a.pcapng', 'rb'),
    open('capture-b.pcap', 'rb'),
], destination)

# convenience entry point with the same signature:
pcapng.merge(sources, destination)
```

## Guarantees

* every input interface becomes its own Interface Description Block, and each
  packet's interface id is remapped; packets are never collapsed onto the
  first interface;
* timestamps are carried as exact rational numbers built from the on-disk
  integer ticks and the per-interface `if_tsresol` scale. No `float` is used,
  so nanosecond and binary (power-of-two) resolutions survive unchanged;
* link type, snap length and interface/packet options are preserved, with
  option fields re-encoded when source and output endianness differ;
* each source streams with at most one packet buffered ahead, so memory stays
  bounded regardless of capture size (sources must be seekable).

## Policies

Each source is assumed to be sorted by packet time. The `on_*` arguments
handle deviations; passing `None` makes that condition raise instead of
dropping.

* `on_no_timestamp`: Simple Packet Blocks (no timestamp), default skip;
* `on_backwards`: a packet older than the previous one, default skip;
* `on_unknown_block`: non-packet blocks (NRB, statistics, custom, ...),
  default report and drop; the event carries the raw block bytes so a
  callback can archive them;
* `on_truncated`: truncated blocks/captures, default raise; a callback merges
  everything preceding the cut and reports the truncation once.

The returned `MergeReport` counts packets per source and lists every skipped
or reported record.
