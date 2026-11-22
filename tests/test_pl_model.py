"""The HLS design (C model, via the native testbench) against svdd_ps.

Run from pynq-pl/:   ./hls/build_native.sh && python3 -m pytest -q tests

Each case writes a pcap, sends it through the PL C model exactly as the board
would (svdd_pl pack -> testbench -> svdd_pl decode) and through svdd_ps, and
requires every column to match. The UNSW-NB15 capture uses Linux-cooked framing
only, so the other link types are made by re-framing its packets.
"""
import struct
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from svdd_pl.__main__ import main as pl_main            # noqa: E402
from svdd_pl.records import flow_rows, raw_features_of, split   # noqa: E402
from svdd_pl.reference import compare, reference_rows    # noqa: E402
from svdd_pl.stream import Settings                      # noqa: E402
from svdd_ps.pcap import PcapReader                       # noqa: E402

TB = ROOT / "hls" / "build" / "native" / "tb_svdd_pl"
UNSW = ROOT.parent / "pcap" / "1.pcap"
PACKETS = 20000

pytestmark = pytest.mark.skipif(not TB.exists(), reason="run hls/build_native.sh first")


# ------------------------------------------------------------------ pcap re-framing
def _unsw_frames(n=PACKETS):
    """(ts_us, ethertype, network-layer bytes) from the start of the UNSW capture."""
    out = []
    with PcapReader(UNSW) as r:
        for i, (ts, _, data) in enumerate(r):
            if i >= n:
                break
            out.append((ts, struct.unpack(">H", data[14:16])[0], data[16:]))
    return out


def _write_pcap(path, linktype, frames, ns=False, big=False, snaplen=65535):
    o = ">" if big else "<"
    magic = 0xA1B23C4D if ns else 0xA1B2C3D4
    with open(str(path), "wb") as f:
        f.write(struct.pack(o + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype))
        for i, (ts, data) in enumerate(frames):
            cap = data[:snaplen]
            frac = (ts % 1000000) * 1000 + (i * 7) % 1000 if ns else ts % 1000000
            f.write(struct.pack(o + "IIII", ts // 1000000, frac, len(cap), len(data)))
            f.write(cap)


MAC = bytes(range(12))


def frame_as(kind, et, net, i):
    if kind == "ethernet":
        return MAC + struct.pack(">H", et) + net
    if kind == "vlan":                       # 0, 1 or 2 tags, rotating
        tags = [b"", struct.pack(">HH", 0x8100, 7), struct.pack(">HHHH", 0x88A8, 3, 0x8100, 9)][i % 3]
        return MAC + tags + struct.pack(">H", et) + net
    if kind == "raw":
        return net if et == 0x0800 else b"\x60" + net[1:]    # non-IPv4 -> looks like IPv6
    if kind == "null":
        fam = 2 if et == 0x0800 else 24
        return struct.pack("<I" if i % 2 else ">I", fam) + net
    if kind == "sll2":
        return struct.pack(">HHIHBB8s", et, 0, 2, 1, 0, 6, b"\0" * 8) + net
    raise ValueError(kind)


LINKTYPE = {"ethernet": 1, "vlan": 1, "raw": 101, "null": 0, "sll2": 276}


@pytest.fixture(scope="module")
def frames():
    if not UNSW.exists():
        pytest.skip("UNSW-NB15 pcap not present")
    return _unsw_frames()


def run_case(tmp_path, pcaps, settings, chunk_bytes, min_flows=100):
    stream, out = tmp_path / "s.bin", tmp_path / "o.bin"
    flow_args = ["--idle", str(settings.idle), "--active", str(settings.active),
                 "--tcp-close", str(settings.tcp_close)]
    flow_args += [] if settings.close_on_fin_rst else ["--no-fin-rst"]
    flow_args += ["--ttl-both-directions"] if settings.ttl_both else []
    assert pl_main(["pack"] + [str(p) for p in pcaps] + ["-o", str(stream),
                                                         "--chunk-bytes", str(chunk_bytes)] + flow_args) == 0
    feat = tmp_path / "f.bin"
    r = subprocess.run([str(TB), "stream", str(stream), str(out), str(feat)], cwd=str(tmp_path),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr.decode()
    flows, markers = split(np.fromfile(str(out), dtype="<u8"))
    pl = flow_rows(flows)
    # The extraction IP's spec stream (8 uint32 per flow) carries the same features, in
    # the same order as the records; counters saturate at 2^32 - 1.
    words = np.fromfile(str(feat), dtype="<u4").reshape(-1, 8)
    assert len(words) == len(pl)
    want = np.minimum(np.array([raw_features_of(row) for row in pl], dtype=np.uint64).reshape(-1, 8), 2 ** 32 - 1)
    assert (words.astype(np.uint64) == want).all()
    ref, stats = reference_rows([str(p) for p in pcaps], settings)
    m = markers[-1]
    assert not any(mk["errors"] for mk in markers)
    assert (m["frames"], m["ipv4"], m["non_ipv4"], m["malformed"]) == \
        (stats["frames"], stats["ipv4"], stats["non_ipv4"], stats["malformed"])
    res = compare(pl, ref)
    assert res["only_pl"] == 0 and res["only_sw"] == 0, res
    assert res["reason_differs"] == 0, res["reason_examples"]
    assert res["identical"] == len(ref) >= min_flows
    return res


DEFAULT = Settings(30.0, 120.0, 1.0, True, False)


@pytest.mark.parametrize("kind", ["ethernet", "vlan", "raw", "null", "sll2"])
def test_link_types(tmp_path, frames, kind):
    pcap = tmp_path / ("%s.pcap" % kind)
    _write_pcap(pcap, LINKTYPE[kind], [(ts, frame_as(kind, et, net, i)) for i, (ts, et, net) in enumerate(frames)])
    run_case(tmp_path, [pcap], DEFAULT, 1 << 20)


@pytest.mark.parametrize("snaplen", [30, 45, 60])
def test_ns_big_endian_truncated_and_tiny_chunks(tmp_path, frames, snaplen):
    # Nanosecond, big-endian pcap with frames cut short: at 30 bytes the IPv4 header
    # is incomplete (malformed), at 45 the TCP header is (ports 0, no window) while
    # UDP ports survive, at 60 most headers are complete. 1000-byte chunks, so
    # almost every record is split between two chunks.
    pcap = tmp_path / "be_ns.pcap"
    _write_pcap(pcap, 1, [(ts, frame_as("vlan", et, net, i)) for i, (ts, et, net) in enumerate(frames)],
                ns=True, big=True, snaplen=snaplen)
    run_case(tmp_path, [pcap], DEFAULT, 1000, min_flows=0 if snaplen == 30 else 100)


def test_several_files_with_different_link_types(tmp_path, frames):
    half = len(frames) // 2
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    _write_pcap(a, 1, [(ts, frame_as("vlan", et, net, i)) for i, (ts, et, net) in enumerate(frames[:half])])
    _write_pcap(b, 101, [(ts, frame_as("raw", et, net, i)) for i, (ts, et, net) in enumerate(frames[half:])])
    run_case(tmp_path, [a, b], DEFAULT, 4096)


@pytest.mark.parametrize("settings", [
    Settings(2.0, 5.0, 0.25, True, False),     # short timeouts: lots of idle/active/tcp_close exports
    Settings(30.0, 120.0, 1.0, False, True),   # no FIN/RST, MIN_TTL both ways
    Settings(5.0, 120.0, 40.0, True, False),   # TCP close timeout longer than idle
], ids=["short-timeouts", "no-fin-ttl-both", "close-longer-than-idle"])
def test_expiry_settings(tmp_path, settings):
    if not UNSW.exists():
        pytest.skip("UNSW-NB15 pcap not present")
    small = tmp_path / "small.pcap"
    assert subprocess.run([sys.executable, "-m", "svdd_ps", "slice", str(UNSW), str(small),
                           "--packets", str(PACKETS)], cwd=str(ROOT)).returncode == 0
    run_case(tmp_path, [small], settings, 1 << 16)


# ------------------------------------------------------------------ table overflow
def hw_set(src, dst, sport, dport, proto):
    """Python copy of set_of() in hls/svdd_pl.cpp."""
    a, b = (src << 16) | sport, (dst << 16) | dport
    lo, hi = min(a, b), max(a, b)
    hip = hi >> 16
    k = (lo >> 16) ^ (((hip << 7) | (hip >> 25)) & 0xFFFFFFFF) ^ (((lo & 0xFFFF) << 16) | (hi & 0xFFFF)) ^ proto
    k ^= k >> 16
    k = (k * 0x045D9F3B) & 0xFFFFFFFF
    k ^= k >> 16
    return k & 511


def test_full_set_evicts_and_loses_no_flow(tmp_path):
    # 10 UDP flows that all hash to the same set (8 ways): the 9th and 10th each evict one.
    src, dst = 0x0A000001, 0x0A000002
    ports = [p for p in range(1024, 200000) if hw_set(src, dst, p, 53, 17) == hw_set(src, dst, 1024, 53, 17)][:10]
    assert len(ports) == 10
    frames = []
    for i, sp in enumerate(ports):
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0,
                         struct.pack(">I", src), struct.pack(">I", dst))
        frames.append((1000000 + i * 1000, MAC + b"\x08\x00" + ip + struct.pack(">HHHH", sp, 53, 8, 0)))
    pcap = tmp_path / "collide.pcap"
    _write_pcap(pcap, 1, frames)
    stream, out = tmp_path / "s.bin", tmp_path / "o.bin"
    assert pl_main(["pack", str(pcap), "-o", str(stream)]) == 0
    r = subprocess.run([str(TB), "stream", str(stream), str(out)], cwd=str(tmp_path),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr.decode()
    flows, markers = split(np.fromfile(str(out), dtype="<u8"))
    rows = flow_rows(flows)
    reasons = sorted(row[17] for row in rows)
    assert markers[-1]["evicted"] == 2
    assert sorted(int(row[3]) for row in rows) == sorted(ports)        # every flow exactly once
    assert reasons == ["end"] * 8 + ["evict"] * 2
