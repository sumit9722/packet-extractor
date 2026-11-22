"""Packet -> bidirectional flow extractor producing the 8 compact-model features.

This plays the role nProbe played when the NF-UNSW-NB15 CSV was made. The
conventions below follow the FPGA handoff spec (../readme.md, section 1) and
what that spec measured on the training CSV:

* Orientation: the first packet seen defines src -> dst. IN = src -> dst,
  OUT = dst -> src. A reverse packet updates the same flow.
* IN_BYTES / OUT_BYTES: sum of the IPv4 Total Length field per direction.
* FLOW_DURATION_MILLISECONDS: floor((last - first) / 1 ms), computed from
  microsecond timestamps.
* MIN_TTL: minimum TTL of the src -> dst packets, but 0 for single-packet
  flows. The handoff spec says "across the flow", but the dataset disagrees:
  benign rows have MIN_TTL 31 while their reply packets carry TTL 29/30, so
  nProbe only used the forward direction. Pass ``ttl_both_directions=True``
  for the other rule.
* Duplicate packets are counted. The UNSW-NB15 PCAPs were captured on a router's
  Linux "any" interface, so every forwarded packet appears twice (in and out,
  TTL one lower). nProbe counted both copies: dataset byte counts are almost
  always even, e.g. a DNS flow with IN_BYTES 130 = 2 x 65.
* MAX_IP_PKT_LEN: maximum Total Length across both directions.
* MIN_IP_PKT_LEN: minimum Total Length across both directions, but 0 when
  there are no reverse packets.
* TCP_WIN_MAX_IN / OUT: maximum raw (unscaled) TCP window field per direction,
  0 for non-TCP flows and for a direction with no packets.

Expiry, as in nProbe: a flow is exported when it has been idle for
``idle_timeout`` seconds, when it has lasted longer than ``active_timeout``
(the next packet then starts a new flow), or shortly after TCP teardown
(RST, or FIN seen in both directions). All of these are settings, because the
exact nProbe options used for the dataset are unknown. Validate them against
the dataset CSV with ``python3 -m svdd_ps compare``.
"""
import socket
from collections import OrderedDict, deque, namedtuple

from .pcap import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, ip_offset, parse_ipv4

FEATURES = (
    "IN_BYTES",
    "OUT_BYTES",
    "FLOW_DURATION_MILLISECONDS",
    "MIN_TTL",
    "MAX_IP_PKT_LEN",
    "MIN_IP_PKT_LEN",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
)

# Column names match NF-UNSW-NB15-v3 where an equivalent column exists.
FlowRecord = namedtuple("FlowRecord", (
    "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS",
    "IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL",
    "IN_PKTS", "OUT_PKTS",
) + FEATURES + ("END_REASON",))

FEATURE_SLICE = slice(9, 17)  # FlowRecord fields that form the model input
UINT32_MAX = 0xFFFFFFFF


def raw_features(record):
    """The 8 raw words in model order, saturated to uint32 like the hardware record."""
    return [v if v <= UINT32_MAX else UINT32_MAX for v in record[FEATURE_SLICE]]


class _Flow:
    __slots__ = ("key", "first", "last", "in_pkts", "out_pkts", "in_bytes", "out_bytes",
                 "min_ttl", "max_len", "min_len", "win_in", "win_out",
                 "fin_in", "fin_out", "closing")

    def __init__(self, key, ts):
        self.key = key
        self.first = self.last = ts
        self.in_pkts = self.out_pkts = 0
        self.in_bytes = self.out_bytes = 0
        self.min_ttl = 255
        self.max_len = 0
        self.min_len = 0xFFFF
        self.win_in = self.win_out = 0
        self.fin_in = self.fin_out = False
        self.closing = False


class FlowExtractor:
    """Keep a flow table and emit a :class:`FlowRecord` for every finished flow.

    Feed it decoded packets in capture order with :meth:`packet` (or raw frames
    with :meth:`frame`), collect finished flows with :meth:`drain`, and call
    :meth:`flush` at the end of the capture to export what is still open.
    """

    def __init__(self, idle_timeout=30.0, active_timeout=120.0,
                 tcp_close_timeout=1.0, close_on_fin_rst=True, ttl_both_directions=False):
        self.idle_us = int(idle_timeout * 1_000_000)
        self.active_us = int(active_timeout * 1_000_000)
        self.close_us = int(tcp_close_timeout * 1_000_000)
        self.close_on_fin_rst = close_on_fin_rst
        self.ttl_both = ttl_both_directions
        self.table = OrderedDict()   # key -> _Flow, least recently active first
        self.closing = OrderedDict() # key -> _Flow, torn-down TCP flows, least recently active first
        self.ready = deque()
        self.stats = dict(frames=0, ipv4=0, non_ipv4=0, malformed=0, flows=0, peak_flows=0)

    # ------------------------------------------------------------------ input
    def frame(self, ts, linktype, data):
        """Process one captured frame. ``ts`` is in microseconds."""
        self.stats["frames"] += 1
        off = ip_offset(linktype, data)
        if off < 0:
            self.stats["non_ipv4"] += 1
            self.expire(ts)
            return
        pkt = parse_ipv4(data, off)
        if pkt is None:
            self.stats["malformed"] += 1
            self.expire(ts)
            return
        self.stats["ipv4"] += 1
        self.packet(ts, pkt)

    def packet(self, ts, pkt):
        """Process one decoded packet from :func:`svdd_ps.pcap.parse_ipv4`."""
        src, dst, proto, sport, dport, ttl, length, win, flags = pkt
        table = self.table
        key = (src, dst, sport, dport, proto)
        flow = table.get(key)
        forward = True
        if flow is None:
            rkey = (dst, src, dport, sport, proto)
            flow = table.get(rkey)
            if flow is not None:
                key = rkey
                forward = False

        if flow is not None:
            reason = None
            if ts - flow.last > self.idle_us:
                reason = "idle"
            elif ts - flow.first > self.active_us:
                reason = "active"
            elif flow.closing and flags & TCP_SYN and not flags & TCP_ACK:
                reason = "closed"  # new connection reusing the same 5-tuple
            if reason is None:
                table.move_to_end(key)
                if flow.closing:
                    self.closing.move_to_end(key)
            else:
                self._export(flow, reason)
                flow = None
                key = (src, dst, sport, dport, proto)
                forward = True

        if flow is None:
            flow = _Flow(key, ts)
            table[key] = flow
            if len(table) > self.stats["peak_flows"]:
                self.stats["peak_flows"] = len(table)

        if ts > flow.last:
            flow.last = ts
        if forward:
            flow.in_pkts += 1
            flow.in_bytes += length
            if win > flow.win_in:
                flow.win_in = win
            if ttl < flow.min_ttl:
                flow.min_ttl = ttl
        else:
            flow.out_pkts += 1
            flow.out_bytes += length
            if win > flow.win_out:
                flow.win_out = win
            if self.ttl_both and ttl < flow.min_ttl:
                flow.min_ttl = ttl
        if length > flow.max_len:
            flow.max_len = length
        if length < flow.min_len:
            flow.min_len = length

        if proto == 6 and flags & (TCP_FIN | TCP_RST) and self.close_on_fin_rst:
            if flags & TCP_FIN:
                if forward:
                    flow.fin_in = True
                else:
                    flow.fin_out = True
            if not flow.closing and (flags & TCP_RST or (flow.fin_in and flow.fin_out)):
                flow.closing = True
                self.closing[key] = flow

        self.expire(ts)

    # ----------------------------------------------------------------- expiry
    def expire(self, now):
        """Export flows that are idle (or torn down) as of time ``now`` (microseconds)."""
        table = self.table
        limit = now - self.idle_us
        while table:
            flow = next(iter(table.values()))
            if flow.last >= limit:
                break
            self._export(flow, "idle")
        closing = self.closing
        limit = now - self.close_us
        while closing:
            flow = next(iter(closing.values()))
            if flow.last >= limit:
                break
            self._export(flow, "tcp_close")

    def flush(self):
        """Export every open flow (end of capture)."""
        for flow in list(self.table.values()):
            self._export(flow, "end")

    def drain(self):
        """Yield and remove the flows finished so far."""
        ready = self.ready
        while ready:
            yield ready.popleft()

    def process(self, source):
        """Run a whole packet source through the table and yield every flow record."""
        frame = self.frame
        expire = self.expire
        for ts, linktype, data in source:
            if data is None:          # LiveCapture tick with no packet
                expire(ts)
            else:
                frame(ts, linktype, data)
            if self.ready:
                yield from self.drain()
        self.flush()
        yield from self.drain()

    # ----------------------------------------------------------------- output
    def _export(self, flow, reason):
        del self.table[flow.key]
        self.closing.pop(flow.key, None)
        self.stats["flows"] += 1
        src, dst, sport, dport, proto = flow.key
        packets = flow.in_pkts + flow.out_pkts
        self.ready.append(FlowRecord(
            flow.first // 1000, flow.last // 1000,
            socket.inet_ntoa(src), sport, socket.inet_ntoa(dst), dport, proto,
            flow.in_pkts, flow.out_pkts,
            flow.in_bytes,
            flow.out_bytes,
            (flow.last - flow.first) // 1000,
            0 if packets == 1 else flow.min_ttl,
            flow.max_len,
            0 if flow.out_pkts == 0 else flow.min_len,
            flow.win_in,
            flow.win_out,
            reason,
        ))
