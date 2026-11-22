"""Command line: python3 -m svdd_pl <command> ...   (run from the pynq-pl folder)

On the board (needs root, the PL does the extraction):
  run      PCAP... -o scored.csv     stream pcap files through the PL
  live     --iface eth0              stream live traffic through the PL
  selftest                           sample pcap through the PL and through svdd_ps; must match

On the PC (checking the HLS design in C simulation):
  pack       PCAP... -o stream.bin   chunks exactly as "run" sends them, for the testbench
  decode     out.bin -o flows.csv    testbench output -> CSV
  reference  PCAP... -o ref.csv      the svdd_ps software pipeline, same CSV columns
  compare    a.csv b.csv             PL output vs reference, column by column
"""
import argparse
import csv
import sys
import time
from pathlib import Path

import numpy as np

from .records import CSV_FIELDS, flow_rows, split
from .stream import DEFAULT_CHUNK, Settings, pcap_chunks, write_stream_file

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "unsw_sample.pcap"


def _settings(args):
    return Settings(args.idle, args.active, args.tcp_close, not args.no_fin_rst, args.ttl_both_directions)


def _write_csv(path, rows):
    out = sys.stdout if path in (None, "-") else open(path, "w", newline="")
    w = csv.writer(out)
    w.writerow(CSV_FIELDS)
    w.writerows(rows)
    if out is not sys.stdout:
        out.close()


def _read_csv(path):
    with open(path, newline="") as f:
        r = csv.reader(f)
        header = tuple(next(r))
        if header != CSV_FIELDS:
            raise SystemExit("%s: not a CSV from svdd_pl (columns differ)" % path)
        return [tuple(row) for row in r]


def _print_markers(markers, out=sys.stderr):
    if not markers:
        return
    m = markers[-1]
    out.write("PL counters: %d chunks, %d frames (%d IPv4, %d other, %d malformed), %d flows, "
              "%d evicted, peak %d open flows\n" % (m["chunks"], m["frames"], m["ipv4"], m["non_ipv4"],
                                                     m["malformed"], m["flows"], m["evicted"], m["peak_flows"]))
    errs = sorted({e for mk in markers for e in mk["errors"]})
    if errs:
        out.write("PL chunk errors: %s\n" % ", ".join(errs))
    if m["deep_headers"]:
        out.write("frames with headers deeper than 128 bytes (counted as malformed): %d\n" % m["deep_headers"])


# ----------------------------------------------------------------- PC commands
def cmd_pack(args):
    n = write_stream_file(pcap_chunks(args.pcap, _settings(args), args.chunk_bytes), args.output)
    print("wrote %d chunks to %s" % (n, args.output), file=sys.stderr)


def cmd_decode(args):
    words = np.fromfile(args.input, dtype="<u8")
    flows, markers = split(words)
    _write_csv(args.output, flow_rows(flows))
    print("%d flow records, %d markers" % (len(flows), len(markers)), file=sys.stderr)
    _print_markers(markers)


def cmd_reference(args):
    from .reference import reference_rows
    t0 = time.monotonic()
    rows, stats = reference_rows(args.pcap, _settings(args))
    _write_csv(args.output, rows)
    print("svdd_ps: %d frames -> %d flows in %.1fs" % (stats["frames"], len(rows), time.monotonic() - t0),
          file=sys.stderr)


def cmd_compare(args):
    from .reference import compare, print_compare
    ok = print_compare(compare(_read_csv(args.pl), _read_csv(args.reference)), sys.stdout)
    return 0 if ok else 1


# ----------------------------------------------------------------- board commands
def _engine(args):
    from .driver import PLEngine
    eng = PLEngine(board=args.board, driver=args.driver, overlay=args.overlay,
                   buf_addr=args.buf_addr, chunk_bytes=args.chunk_bytes)
    print(eng.info, file=sys.stderr)
    return eng


def cmd_run(args):
    eng = _engine(args)
    t0 = time.monotonic()
    rows, markers, nbytes = [], [], 0
    for chunk in pcap_chunks(args.pcap, _settings(args), args.chunk_bytes):
        flows, mk = split(eng.process(chunk))
        rows += flow_rows(flows)
        markers += mk
        nbytes += len(chunk)
    dt = time.monotonic() - t0
    if args.output is not None:
        _write_csv(args.output, rows)
    bad = sum(int(r[CSV_FIELDS.index("ANOMALY")]) for r in rows)
    print("%d flows in %.1fs (%.1f MB/s of pcap through the PL); anomalies %d (%.2f%%)"
          % (len(rows), dt, nbytes / 1e6 / max(dt, 1e-9), bad, 100.0 * bad / max(len(rows), 1)), file=sys.stderr)
    _print_markers(markers)
    if args.check:
        from .reference import compare, print_compare, reference_rows
        print("running the svdd_ps reference on the PS for comparison...", file=sys.stderr)
        ref, _ = reference_rows(args.pcap, _settings(args))
        return 0 if print_compare(compare(rows, ref), sys.stderr) else 1
    return 0


def cmd_selftest(args):
    pcap = Path(args.pcap) if args.pcap else SAMPLE
    if not pcap.exists():
        raise SystemExit("%s not found (deploy.sh copies samples/unsw_sample.pcap)" % pcap)
    args.pcap, args.output, args.check = [str(pcap)], args.output, True
    rc = cmd_run(args)
    print("SELFTEST PASSED" if rc == 0 else "SELFTEST FAILED")
    return rc


def cmd_live(args):
    from svdd_ps.pcap import LiveCapture
    from .stream import LiveChunker
    eng = _engine(args)
    cap = LiveCapture(args.iface)
    chunker = LiveChunker(_settings(args))
    out = open(args.output, "w", newline="") if args.output else None
    w = csv.writer(out) if out else None
    if w:
        w.writerow(CSV_FIELDS)
    deadline = time.monotonic() + args.seconds if args.seconds else None
    next_cut = time.monotonic() + args.period
    n = bad = 0
    a = CSV_FIELDS.index("ANOMALY")

    def send(flush=False):
        nonlocal n, bad
        flows, _ = split(eng.process(chunker.chunk(int(time.time() * 1000000), flush)))
        for r in flow_rows(flows):
            n += 1
            if w:
                w.writerow(r)
            if int(r[a]):
                bad += 1
                print("ANOMALY %s:%s -> %s:%s proto %s score %s (%s)" % (r[2], r[3], r[4], r[5], r[6],
                      r[CSV_FIELDS.index("SCORE")], r[CSV_FIELDS.index("END_REASON")]), flush=True)

    print("capturing on %s, extracting and scoring in the PL; Ctrl-C to stop" % args.iface, file=sys.stderr)
    try:
        for ts, _, frame in cap:
            if frame is not None and chunker.add(ts, frame):
                send()
            now = time.monotonic()
            if now >= next_cut:
                send()
                next_cut = now + args.period
            if deadline is not None and now > deadline:
                break
    except KeyboardInterrupt:
        pass
    finally:
        cap.close()
    send(flush=True)
    if out:
        out.close()
    print("%d flows, %d anomalies" % (n, bad), file=sys.stderr)


# ----------------------------------------------------------------- parser
def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m svdd_pl", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command")
    sub.required = True

    def flow_opts(sp):
        g = sp.add_argument_group("flow expiry (same meaning as in svdd_ps)")
        g.add_argument("--idle", type=float, default=30.0, help="idle timeout, seconds (default 30)")
        g.add_argument("--active", type=float, default=120.0, help="active timeout, seconds (default 120)")
        g.add_argument("--tcp-close", type=float, default=1.0, help="export TCP flows this long after RST/FIN")
        g.add_argument("--no-fin-rst", action="store_true", help="ignore FIN/RST; only use the timeouts")
        g.add_argument("--ttl-both-directions", action="store_true", help="MIN_TTL over both directions")

    def board_opts(sp):
        g = sp.add_argument_group("board")
        g.add_argument("--board", choices=("auto", "pynq-z2", "zedboard"), default="auto")
        g.add_argument("--driver", choices=("auto", "pynq", "devmem"), default="auto",
                       help="pynq (PYNQ image) or devmem (FPGA manager + /dev/mem); auto = pynq if installed")
        g.add_argument("--overlay", help="svdd_pl.bit to load (default: overlay/<board>/svdd_pl.bit)")
        g.add_argument("--buf-addr", type=lambda s: int(s, 0), default=None,
                       help="devmem: physical base of 8 MB Linux does not use (default 0x1F800000, "
                            "free when the kernel boots with mem=504M)")

    def chunk_opt(sp):
        sp.add_argument("--chunk-bytes", type=int, default=DEFAULT_CHUNK, help="pcap bytes per DMA transfer")

    sp = sub.add_parser("run", help="pcap -> PL -> scored CSV (board)")
    sp.add_argument("pcap", nargs="+")
    sp.add_argument("-o", "--output", default="-")
    sp.add_argument("--check", action="store_true", help="also run svdd_ps on the PS and compare")
    flow_opts(sp), board_opts(sp), chunk_opt(sp)
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("selftest", help="sample pcap through the PL and svdd_ps; must match (board)")
    sp.add_argument("--pcap", help="pcap to use (default samples/unsw_sample.pcap)")
    sp.add_argument("-o", "--output", default=None)
    flow_opts(sp), board_opts(sp), chunk_opt(sp)
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("live", help="live traffic -> PL (board, root)")
    sp.add_argument("--iface", default="eth0")
    sp.add_argument("-o", "--output")
    sp.add_argument("--seconds", type=float)
    sp.add_argument("--period", type=float, default=0.5, help="seconds between chunks (expiry tick)")
    flow_opts(sp), board_opts(sp), chunk_opt(sp)
    sp.set_defaults(func=cmd_live)

    sp = sub.add_parser("pack", help="pcap -> chunk file for the HLS testbench")
    sp.add_argument("pcap", nargs="+")
    sp.add_argument("-o", "--output", required=True)
    flow_opts(sp), chunk_opt(sp)
    sp.set_defaults(func=cmd_pack)

    sp = sub.add_parser("decode", help="testbench output -> CSV")
    sp.add_argument("input")
    sp.add_argument("-o", "--output", default="-")
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("reference", help="svdd_ps software pipeline -> CSV")
    sp.add_argument("pcap", nargs="+")
    sp.add_argument("-o", "--output", default="-")
    flow_opts(sp)
    sp.set_defaults(func=cmd_reference)

    sp = sub.add_parser("compare", help="compare a PL CSV with a reference CSV")
    sp.add_argument("pl")
    sp.add_argument("reference")
    sp.set_defaults(func=cmd_compare)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
