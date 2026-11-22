"""Software reference and comparison.

The reference is svdd_ps, the Python extractor + preprocessing + bit-exact model
from pynq-ps. The PL design must give the same flows, codes and scores.
"""
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from svdd_ps import FlowExtractor, PcapReader, Preprocessor, Q24Model
from svdd_ps.flows import FlowRecord, raw_features

from .records import CSV_FIELDS

ASSETS = Path(__file__).resolve().parent.parent / "assets"
REASON = FlowRecord._fields.index("END_REASON")


def _pcap_frames(paths):
    for path in paths:
        with PcapReader(path) as reader:
            for item in reader:
                yield item


def reference_rows(paths, settings, assets=ASSETS, batch=4096):
    """Run svdd_ps on the pcaps. Returns (rows in CSV_FIELDS order, extractor stats)."""
    ex = FlowExtractor(idle_timeout=settings.idle, active_timeout=settings.active,
                       tcp_close_timeout=settings.tcp_close, close_on_fin_rst=settings.close_on_fin_rst,
                       ttl_both_directions=settings.ttl_both)
    pre = Preprocessor(Path(assets) / "preprocessing.json")
    model = Q24Model(Path(assets) / "model_parameters.h")
    rows, pending = [], []

    def score():
        codes = pre.codes([raw_features(r) for r in pending])
        scores = model.score(codes)
        anomaly = model.is_anomaly(scores)
        recal = model.is_anomaly(scores, recalibrated=True)
        for r, c, s, a, b in zip(pending, codes.tolist(), scores.tolist(), anomaly, recal):
            rows.append(tuple(r) + tuple(c) + (int(s), "%.9g" % (s / float(1 << 32)), int(a), int(b)))
        del pending[:]

    for rec in ex.process(_pcap_frames(paths)):
        pending.append(rec)
        if len(pending) >= batch:
            score()
    if pending:
        score()
    return rows, ex.stats


def compare(pl_rows, sw_rows):
    """Match PL rows to reference rows as multisets of every column except END_REASON.

    Returns a dict with counts and up to 5 examples of each kind of difference.
    """
    def key(r):
        return tuple(str(x) for i, x in enumerate(r) if i != REASON)

    pl, sw = Counter(map(key, pl_rows)), Counter(map(key, sw_rows))
    same = pl & sw
    only_pl, only_sw = pl - sw, sw - pl

    reasons_pl, reasons_sw = defaultdict(Counter), defaultdict(Counter)
    for r in pl_rows:
        reasons_pl[key(r)][str(r[REASON])] += 1
    for r in sw_rows:
        reasons_sw[key(r)][str(r[REASON])] += 1
    reason_diff = []
    for k in same:
        if reasons_pl[k] != reasons_sw[k]:
            reason_diff.append((k, dict(reasons_pl[k]), dict(reasons_sw[k])))

    # For rows that did not match, find the same flow (start, 5-tuple) on the other
    # side and list which columns differ.
    def flow_id(k):
        return k[:7]

    sw_by_id = defaultdict(list)
    for k in only_sw:
        sw_by_id[flow_id(k)].append(k)
    field_diff = Counter()
    examples = []
    names = [f for i, f in enumerate(CSV_FIELDS) if i != REASON]
    for k in only_pl:
        cands = sw_by_id.get(flow_id(k))
        if not cands:
            continue
        diff = [names[i] for i, (a, b) in enumerate(zip(k, cands[0])) if a != b]
        field_diff.update(diff)
        if len(examples) < 5:
            examples.append({"flow": k[:7], "differs": {n: (k[names.index(n)], cands[0][names.index(n)])
                                                        for n in diff}})
    return {
        "pl_flows": sum(pl.values()),
        "sw_flows": sum(sw.values()),
        "identical": sum(same.values()),
        "only_pl": sum(only_pl.values()),
        "only_sw": sum(only_sw.values()),
        "reason_differs": len(reason_diff),
        "field_differences": dict(field_diff),
        "examples": examples,
        "only_pl_examples": [k[:7] for k in list(only_pl)[:5]],
        "only_sw_examples": [k[:7] for k in list(only_sw)[:5]],
        "reason_examples": reason_diff[:5],
    }


def print_compare(res, out):
    w = out.write
    w("PL flows %d, reference flows %d\n" % (res["pl_flows"], res["sw_flows"]))
    w("identical in every column (except END_REASON): %d\n" % res["identical"])
    w("only in PL output: %d   only in reference: %d\n" % (res["only_pl"], res["only_sw"]))
    w("END_REASON differs on matched flows: %d\n" % res["reason_differs"])
    if res["field_differences"]:
        w("columns that differ on the same flow: %s\n" % res["field_differences"])
    for e in res["examples"]:
        w("  e.g. %s %s\n" % (e["flow"], e["differs"]))
    for name in ("only_pl_examples", "only_sw_examples"):
        for k in res[name]:
            w("  %s: %s\n" % (name.replace("_examples", ""), k))
    for k, a, b in res["reason_examples"]:
        w("  reason: PL %s vs reference %s for %s\n" % (a, b, k[:7]))
    ok = res["only_pl"] == 0 and res["only_sw"] == 0
    w("RESULT: %s\n" % ("MATCH" if ok else "DIFFERENT"))
    return ok


def rows_to_codes_scores(rows):
    i = CSV_FIELDS.index("CODE_0")
    codes = np.array([r[i:i + 8] for r in rows], np.int64)
    scores = np.array([int(r[CSV_FIELDS.index("SCORE_CODE")]) for r in rows], np.uint64)
    return codes, scores
