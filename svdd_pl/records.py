"""PL -> PS output: 128-byte flow and marker records (layout in hls/svdd_pl.hpp)."""
import socket
import struct

import numpy as np

from svdd_ps.flows import FEATURES, FlowRecord

REC_WORDS = 16
REC_BYTES = 8 * REC_WORDS
REC_FLOW = 0xF1
REC_MARKER = 0xA5
REASONS = {1: "idle", 2: "active", 3: "tcp_close", 4: "closed", 5: "end", 6: "evict"}
CHUNK_ERRORS = {1: "bad chunk header", 2: "chunk shorter than declared", 4: "chunk longer than declared"}

# Columns of the CSV files written by "run", "decode" and "reference": the svdd_ps
# flow record, then the PL's input codes and score.
CODE_FIELDS = tuple("CODE_%d" % i for i in range(8))
SCORE_FIELDS = ("SCORE_CODE", "SCORE", "ANOMALY", "ANOMALY_RECAL")
CSV_FIELDS = FlowRecord._fields + CODE_FIELDS + SCORE_FIELDS

MARKER_FIELDS = ("chunks", "frames", "ipv4", "non_ipv4", "malformed", "flows", "evicted",
                 "open_flows", "peak_flows", "deep_headers")


def _ip(v):
    return socket.inet_ntoa(struct.pack(">I", int(v)))


def split(words):
    """uint64 words (N*16) -> (flow rows as uint64 array (n, 16), list of marker dicts)."""
    w = np.asarray(words, np.uint64).reshape(-1, REC_WORDS)
    kind = w[:, 0] & np.uint64(0xFF)
    bad = ~np.isin(kind, [REC_FLOW, REC_MARKER])
    if bad.any():
        raise ValueError("unknown record type 0x%02x" % int(kind[bad][0]))
    markers = [marker_dict(row) for row in w[kind == REC_MARKER]]
    return w[kind == REC_FLOW], markers


def marker_dict(row):
    d = {name: int(row[1 + i]) for i, name in enumerate(MARKER_FIELDS)}
    err = int(row[0] >> np.uint64(8)) & 0xFF
    d["errors"] = [text for bit, text in sorted(CHUNK_ERRORS.items()) if err & bit]
    return d


def flow_rows(flows):
    """Decoded flow records as tuples in CSV_FIELDS order."""
    out = []
    for r in flows:
        r = [int(x) for x in r]
        codes = []
        for i in range(4):
            lo, hi = r[10 + i] & 0xFFFFFFFF, r[10 + i] >> 32
            codes += [lo - (1 << 32) if lo >> 31 else lo, hi - (1 << 32) if hi >> 31 else hi]
        score = r[14]
        out.append((
            r[1] // 1000, r[2] // 1000,
            _ip(r[3] & 0xFFFFFFFF), (r[0] >> 32) & 0xFFFF, _ip(r[3] >> 32), r[0] >> 48, (r[0] >> 16) & 0xFF,
            r[4] & 0xFFFFFFFF, r[4] >> 32,
            r[5], r[6], r[7],
            r[8] & 0xFFFF, (r[8] >> 16) & 0xFFFF, (r[8] >> 32) & 0xFFFF,
            r[9] & 0xFFFF, (r[9] >> 16) & 0xFFFF,
            REASONS.get((r[0] >> 8) & 0xFF, "?"),
        ) + tuple(codes) + (score, "%.9g" % (score / float(1 << 32)), (r[0] >> 24) & 1, (r[0] >> 25) & 1))
    return out


def raw_features_of(row):
    """The 8 raw features of a CSV_FIELDS row, in model order."""
    i = FlowRecord._fields.index(FEATURES[0])
    return list(row[i:i + len(FEATURES)])
