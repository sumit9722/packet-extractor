"""Check extracted flows against the NF-UNSW-NB15-v3 CSV (the nProbe reference).

Rows are matched on the 5-tuple plus FLOW_START_MILLISECONDS within a small
tolerance. Only dataset rows whose start falls inside the time range of the
extracted capture count. A dataset row that only matches with src/dst swapped
is counted separately, because that means the two exporters disagree on
orientation (IN and OUT are swapped).
"""
import csv
from collections import defaultdict

from .flows import FEATURES

_KEY = ("IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL")


def _key(row, reverse=False):
    src, sport, dst, dport, proto = (row[k] for k in _KEY)
    proto = int(float(proto))
    if proto == 1:  # exporters put ICMP type/code in the ports differently; match on addresses
        sport = dport = 0
    else:
        sport, dport = int(float(sport)), int(float(dport))
    return (dst, dport, src, sport, proto) if reverse else (src, sport, dst, dport, proto)


def compare(ours_path, dataset_path, tolerance_ms=2, labels_path=None, examples=5):
    ours = defaultdict(list)
    rows = []
    t_lo, t_hi = float("inf"), float("-inf")
    with open(ours_path, newline="") as f:
        for row in csv.DictReader(f):
            row["_start"] = int(row["FLOW_START_MILLISECONDS"])
            row["_used"] = False
            t_lo = min(t_lo, row["_start"])
            t_hi = max(t_hi, int(row["FLOW_END_MILLISECONDS"]))
            ours[_key(row)].append(row)
            rows.append(row)
    if not rows:
        raise ValueError(f"{ours_path} has no flows")

    stats = dict(dataset_rows_in_window=0, matched=0, matched_reversed=0, unmatched=0)
    exact = dict.fromkeys(FEATURES, 0)
    abs_err = dict.fromkeys(FEATURES, 0.0)
    worst = {f: [] for f in FEATURES}

    def find(key, start):
        best = None
        for cand in ours.get(key, ()):
            d = abs(cand["_start"] - start)
            if not cand["_used"] and d <= tolerance_ms and (best is None or d < best[0]):
                best = (d, cand)
        return best[1] if best else None

    with open(dataset_path, newline="") as f:
        for ref in csv.DictReader(f):
            start = int(float(ref["FLOW_START_MILLISECONDS"]))
            if start < t_lo - tolerance_ms or start > t_hi:
                continue
            stats["dataset_rows_in_window"] += 1
            mine = find(_key(ref), start)
            if mine is None:
                if find(_key(ref, reverse=True), start) is not None:
                    stats["matched_reversed"] += 1
                else:
                    stats["unmatched"] += 1
                continue
            mine["_used"] = True
            stats["matched"] += 1
            for name in ("Label", "Attack"):
                if name in ref:
                    mine[name] = ref[name]
            for feat in FEATURES:
                a, b = int(mine[feat]), int(float(ref[feat]))
                if a == b:
                    exact[feat] += 1
                else:
                    abs_err[feat] += abs(a - b)
                    if len(worst[feat]) < examples:
                        worst[feat].append((_key(ref), start, a, b))

    stats["extracted_flows"] = len(rows)
    stats["extracted_unmatched"] = sum(not r["_used"] for r in rows)
    n = max(stats["matched"], 1)
    per_feature = {f: dict(exact_fraction=exact[f] / n,
                           mean_abs_error_when_different=abs_err[f] / max(n - exact[f], 1),
                           examples=worst[f]) for f in FEATURES}

    if labels_path:
        fields = [k for k in rows[0] if not k.startswith("_")]
        fields += [k for k in ("Label", "Attack") if k not in fields]
        with open(labels_path, "w", newline="") as f:
            w = csv.DictWriter(f, fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                if r["_used"]:
                    w.writerow(r)
    return stats, per_feature


def print_report(stats, per_feature):
    total = max(stats["dataset_rows_in_window"], 1)
    print(f"dataset rows inside the capture window : {stats['dataset_rows_in_window']}")
    print(f"  matched (same orientation)           : {stats['matched']} ({stats['matched'] / total:.1%})")
    print(f"  matched only with src/dst swapped    : {stats['matched_reversed']}")
    print(f"  not found in extracted flows         : {stats['unmatched']}")
    print(f"extracted flows with no dataset row    : {stats['extracted_unmatched']} of {stats['extracted_flows']}")
    print()
    print(f"{'feature':28s} {'exact':>8s} {'mean |diff| when different':>28s}")
    for feat, r in per_feature.items():
        print(f"{feat:28s} {r['exact_fraction']:8.1%} {r['mean_abs_error_when_different']:28.1f}")
    for feat, r in per_feature.items():
        if r["examples"]:
            print(f"\n{feat} mismatches (key, start_ms, ours, dataset):")
            for ex in r["examples"]:
                print("   ", ex)
