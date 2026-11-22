"""Command line: python3 -m svdd_ps <command> ...

  extract  PCAP... -o flows.csv          packets -> flow records (8 raw features)
  score    flows.csv -o scored.csv       flow records -> anomaly scores
  run      PCAP... -o scored.csv         extract + score in one pass
  live     --iface eth0                  capture from a network port and score
  selftest                               golden vectors through the model / FPGA
  slice    IN.pcap OUT.pcap --packets N  cut a smaller pcap (e.g. for the board)
  compare  flows.csv NF-UNSW-NB15-v3.csv check extracted flows against nProbe

Add --backend fpga to score on the PL (on the ZedBoard, as root), and --check
to also run the software model and count any score that differs. --driver
picks how the PL is reached: pynq (PYNQ image) or devmem (any Xilinx Linux,
no PYNQ); the default auto uses pynq when it is installed.
"""
import argparse
import csv
import sys
import time
from pathlib import Path

import numpy as np

from .flows import FEATURES, FlowExtractor, FlowRecord, raw_features
from .model import Q24Model
from .pcap import LiveCapture, PcapReader, write_pcap_slice
from .preprocess import Preprocessor

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
DEFAULT_OVERLAY = ROOT / "overlay" / "svdd.bit"
SCORE_FIELDS = ("SCORE_CODE", "SCORE", "ANOMALY")


# ----------------------------------------------------------------- scoring
class Scorer:
    """Raw flow records -> (score codes, anomaly flags) on the software model or the FPGA."""

    def __init__(self, backend="sw", overlay=DEFAULT_OVERLAY, check=False, assets=ASSETS,
                 driver="auto", buf_addr=None):
        self.pre = Preprocessor(Path(assets) / "preprocessing.json")
        self.model = Q24Model(Path(assets) / "model_parameters.h")
        self.backend = backend
        self.check = check and backend == "fpga"
        self.checked = self.mismatches = 0
        self.fpga = None
        if backend == "fpga":
            from .fpga import DEFAULT_BUF_ADDR, FpgaScorer
            self.fpga = FpgaScorer(overlay, driver=driver,
                                   buf_addr=DEFAULT_BUF_ADDR if buf_addr is None else buf_addr)
            print(self.fpga.info, file=sys.stderr)

    def score_raw(self, raw):
        codes = self.pre.codes(np.asarray(raw, np.float64).reshape(-1, len(FEATURES)))
        return self.score_codes(codes)

    def score_codes(self, codes):
        if self.fpga is None:
            scores = self.model.score(codes)
        else:
            scores = self.fpga.score(codes)
            if self.check:
                self.checked += len(codes)
                self.mismatches += int(np.count_nonzero(self.model.score(codes) != scores))
        return scores, self.model.is_anomaly(scores)


def _score_stream(records, scorer, writer, batch, on_anomaly=None):
    """Score records in batches, write them out, and return (flows, anomalies)."""
    pending, n, bad = [], 0, 0

    def emit():
        nonlocal n, bad
        scores, flags = scorer.score_raw([raw_features(r) for r in pending])
        values = Q24Model.score_value(scores)
        for r, s, v, a in zip(pending, scores, values, flags):
            if writer is not None:
                writer.writerow(tuple(r) + (int(s), f"{v:.9g}", int(a)))
            if a and on_anomaly is not None:
                on_anomaly(r, int(s), v)
        n += len(pending)
        bad += int(flags.sum())
        pending.clear()

    for r in records:
        pending.append(r)
        if len(pending) >= batch:
            emit()
    if pending:
        emit()
    return n, bad


# ----------------------------------------------------------------- sources
def _pcap_frames(paths, max_packets=None, progress=None):
    """Frames from several pcap files read back to back as one capture."""
    n = 0
    for path in paths:
        with PcapReader(path) as reader:
            for item in reader:
                if max_packets is not None and n >= max_packets:
                    return
                n += 1
                if progress is not None and n % 200_000 == 0:
                    progress(n)
                yield item


def _scorer(args, check=None):
    return Scorer(args.backend, args.overlay, args.check if check is None else check,
                  driver=args.driver, buf_addr=args.buf_addr)


def _extractor(args):
    return FlowExtractor(idle_timeout=args.idle, active_timeout=args.active,
                         tcp_close_timeout=args.tcp_close, close_on_fin_rst=not args.no_fin_rst,
                         ttl_both_directions=args.ttl_both_directions)


def _progress(t0):
    def report(n):
        dt = time.monotonic() - t0
        print(f"  {n:,} packets, {n / dt:,.0f} packets/s", file=sys.stderr)
    return report


def _summary(ex, t0, flows, anomalies=None):
    dt = time.monotonic() - t0
    s = ex.stats
    print(f"{s['frames']:,} frames ({s['ipv4']:,} IPv4, {s['non_ipv4']:,} other, {s['malformed']:,} malformed) "
          f"-> {flows:,} flows in {dt:.1f}s ({s['frames'] / max(dt, 1e-9):,.0f} packets/s, "
          f"peak {s['peak_flows']:,} open flows)", file=sys.stderr)
    if anomalies is not None:
        print(f"anomalies: {anomalies:,} of {flows:,} flows ({anomalies / max(flows, 1):.2%})", file=sys.stderr)


def _open_out(path):
    if path in (None, "-"):
        return sys.stdout, False
    return open(path, "w", newline=""), True


# ----------------------------------------------------------------- commands
def cmd_extract(args):
    ex = _extractor(args)
    t0 = time.monotonic()
    out, close = _open_out(args.output)
    w = csv.writer(out)
    w.writerow(FlowRecord._fields)
    n = 0
    for r in ex.process(_pcap_frames(args.pcap, args.max_packets, _progress(t0))):
        w.writerow(r)
        n += 1
    if close:
        out.close()
    _summary(ex, t0, n)


def cmd_score(args):
    scorer = _scorer(args)
    with open(args.flows, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        if tuple(header[:len(FlowRecord._fields)]) != FlowRecord._fields:
            raise SystemExit(f"{args.flows}: not a flow CSV from 'extract'")
        records = (FlowRecord(*row[:len(FlowRecord._fields)]) for row in reader)
        records = (r._replace(**{k: int(getattr(r, k)) for k in FEATURES}) for r in records)
        out, close = _open_out(args.output)
        w = csv.writer(out)
        w.writerow(FlowRecord._fields + SCORE_FIELDS)
        t0 = time.monotonic()
        n, bad = _score_stream(records, scorer, w, args.batch)
        if close:
            out.close()
    print(f"scored {n:,} flows in {time.monotonic() - t0:.1f}s on {args.backend}; "
          f"anomalies {bad:,} ({bad / max(n, 1):.2%})", file=sys.stderr)
    _report_check(scorer)


def cmd_run(args):
    scorer = _scorer(args)
    ex = _extractor(args)
    t0 = time.monotonic()
    out, close = _open_out(args.output)
    w = csv.writer(out)
    w.writerow(FlowRecord._fields + SCORE_FIELDS)
    records = ex.process(_pcap_frames(args.pcap, args.max_packets, _progress(t0)))
    n, bad = _score_stream(records, scorer, w, args.batch)
    if close:
        out.close()
    _summary(ex, t0, n, bad)
    _report_check(scorer)


def cmd_live(args):
    scorer = _scorer(args)
    ex = _extractor(args)
    cap = LiveCapture(args.iface)
    out, close = _open_out(args.output) if args.output else (None, False)
    w = csv.writer(out) if out else None
    if w:
        w.writerow(FlowRecord._fields + SCORE_FIELDS)
    deadline = time.monotonic() + args.seconds if args.seconds else None

    def frames():
        for item in cap:
            if deadline is not None and time.monotonic() > deadline:
                return
            yield item

    def alert(r, code, value):
        print(f"ANOMALY {r.IPV4_SRC_ADDR}:{r.L4_SRC_PORT} -> {r.IPV4_DST_ADDR}:{r.L4_DST_PORT} "
              f"proto {r.PROTOCOL} score {value:.6f} ({r.END_REASON})", flush=True)

    print(f"capturing on {args.iface}, scoring on {args.backend}; Ctrl-C to stop", file=sys.stderr)
    t0 = time.monotonic()
    n = bad = 0
    try:
        n, bad = _score_stream(ex.process(frames()), scorer, w, 1, alert)
    except KeyboardInterrupt:
        pass
    finally:
        cap.close()
        if close:
            out.close()
    _summary(ex, t0, n, bad)
    _report_check(scorer)


def cmd_selftest(args):
    scorer = _scorer(args, check=False)
    ok = True
    codes = np.loadtxt(ASSETS / "golden_inputs.csv", delimiter=",", dtype=np.int64)
    golden = np.loadtxt(ASSETS / "golden_outputs.csv", delimiter=",", dtype=np.int64)
    t0 = time.monotonic()
    scores, flags = scorer.score_codes(codes)
    dt = time.monotonic() - t0
    same = scores.astype(np.int64) == golden[:, -3]
    ok &= bool(same.all())
    print(f"golden vectors on {args.backend}: {int(same.sum())}/{len(same)} scores exact "
          f"({len(codes) / dt:,.0f} flows/s)")
    same_flags = flags.astype(np.int64) == golden[:, -2]
    ok &= bool(same_flags.all())
    print(f"anomaly decisions: {int(same_flags.sum())}/{len(same_flags)} match")

    raw = [1817, 2512, 1552, 31, 106, 52, 20272, 17376]
    want = [41347, 36297, 46490, 65536, 1516, 42598, 20389, 17476]
    got = scorer.pre.codes(raw).tolist()
    s, a = scorer.score_codes(np.array([got]))
    good = got == want and int(s[0]) == 51193 and not a[0]
    ok &= good
    print(f"bring-up vector raw -> codes -> score: {'ok' if good else 'FAILED'} "
          f"(codes {got}, score {int(s[0])}, anomaly {int(a[0])})")
    print("SELFTEST PASSED" if ok else "SELFTEST FAILED")
    return 0 if ok else 1


def cmd_slice(args):
    if args.packets is None and args.seconds is None:
        raise SystemExit("give --packets and/or --seconds")
    n = write_pcap_slice(args.input, args.output, args.packets, args.seconds)
    print(f"wrote {n:,} packets to {args.output}", file=sys.stderr)


def cmd_compare(args):
    from .compare import compare, print_report
    stats, per_feature = compare(args.flows, args.dataset, args.tolerance_ms, args.labels)
    print_report(stats, per_feature)


def _report_check(scorer):
    if scorer.check:
        state = "all identical" if scorer.mismatches == 0 else f"{scorer.mismatches:,} DIFFERENT"
        print(f"FPGA vs software model: {scorer.checked:,} scores compared, {state}", file=sys.stderr)


# ----------------------------------------------------------------- parser
def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m svdd_ps", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command")
    sub.required = True  # add_subparsers(required=...) needs Python 3.7

    def flow_opts(sp):
        g = sp.add_argument_group("flow expiry (nProbe-style; verify with 'compare')")
        g.add_argument("--idle", type=float, default=30.0, help="idle timeout, seconds (default 30)")
        g.add_argument("--active", type=float, default=120.0, help="active/lifetime timeout, seconds (default 120)")
        g.add_argument("--tcp-close", type=float, default=1.0,
                       help="export a TCP flow this long after RST or FIN in both directions (default 1)")
        g.add_argument("--no-fin-rst", action="store_true", help="ignore FIN/RST; only use the timeouts")
        g.add_argument("--ttl-both-directions", action="store_true",
                       help="MIN_TTL over both directions (default: src->dst only, which matches the dataset)")

    def score_opts(sp):
        sp.add_argument("--backend", choices=("sw", "fpga"), default="sw",
                        help="sw = bit-exact NumPy model, fpga = deep_svdd_axis over DMA (ZedBoard only)")
        sp.add_argument("--overlay", default=str(DEFAULT_OVERLAY), help="path to svdd.bit (svdd.hwh next to it)")
        sp.add_argument("--check", action="store_true", help="with --backend fpga, also run the software model and compare")
        sp.add_argument("--batch", type=int, default=4096, help="flows per scoring batch")
        sp.add_argument("--driver", choices=("auto", "pynq", "devmem"), default="auto",
                        help="how to reach the PL: pynq (PYNQ image), devmem (FPGA manager + /dev/mem, "
                             "no PYNQ); auto = pynq if installed")
        sp.add_argument("--buf-addr", type=lambda s: int(s, 0), default=None,
                        help="devmem: physical address of a free DDR page for the DMA buffers "
                             "(default 0x1FF00000, free when Linux boots with mem=504M)")

    sp = sub.add_parser("extract", help="pcap -> flow CSV")
    sp.add_argument("pcap", nargs="+", help="pcap files, read in order as one capture")
    sp.add_argument("-o", "--output", default="-")
    sp.add_argument("--max-packets", type=int)
    flow_opts(sp)
    sp.set_defaults(func=cmd_extract)

    sp = sub.add_parser("score", help="flow CSV -> scored CSV")
    sp.add_argument("flows")
    sp.add_argument("-o", "--output", default="-")
    score_opts(sp)
    sp.set_defaults(func=cmd_score)

    sp = sub.add_parser("run", help="pcap -> scored CSV in one pass")
    sp.add_argument("pcap", nargs="+")
    sp.add_argument("-o", "--output", default="-")
    sp.add_argument("--max-packets", type=int)
    flow_opts(sp)
    score_opts(sp)
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("live", help="capture from an interface and score (needs root)")
    sp.add_argument("--iface", default="eth0")
    sp.add_argument("-o", "--output", help="also write every scored flow to this CSV")
    sp.add_argument("--seconds", type=float, help="stop after this many seconds")
    flow_opts(sp)
    score_opts(sp)
    sp.set_defaults(func=cmd_live)

    sp = sub.add_parser("selftest", help="check the model (and FPGA) against the golden vectors")
    score_opts(sp)
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("slice", help="copy the first packets of a pcap into a smaller file")
    sp.add_argument("input")
    sp.add_argument("output")
    sp.add_argument("--packets", type=int)
    sp.add_argument("--seconds", type=float)
    sp.set_defaults(func=cmd_slice)

    sp = sub.add_parser("compare", help="match extracted flows to NF-UNSW-NB15-v3 rows and compare features")
    sp.add_argument("flows", help="CSV from 'extract'")
    sp.add_argument("dataset", help="NF-UNSW-NB15-v3.csv")
    sp.add_argument("--tolerance-ms", type=int, default=2, help="allowed FLOW_START_MILLISECONDS difference")
    sp.add_argument("--labels", help="write matched flows with the dataset's Label/Attack columns here")
    sp.set_defaults(func=cmd_compare)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
