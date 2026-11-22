"""PL preprocessing (CORDIC log1p + IEEE double steps) against svdd_ps/numpy.

One million random raw feature vectors, spread over every range the PL can see:
byte counts and durations log-uniform up to 2^32 - 1, TTL 0-255, lengths and
windows 0-65535, plus the edge values. Every Q24 code must match.
"""
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from svdd_ps import Preprocessor   # noqa: E402

TB = ROOT / "hls" / "build" / "native" / "tb_svdd_pl"
pytestmark = pytest.mark.skipif(not TB.exists(), reason="run hls/build_native.sh first")


def random_raw(n, seed=1):
    rng = np.random.RandomState(seed)
    raw = np.empty((n, 8), np.uint64)
    for j in range(3):                                   # IN_BYTES, OUT_BYTES, DURATION
        raw[:, j] = np.floor(np.exp(rng.uniform(0, np.log(2.0 ** 32), n))) - 1
    raw[:, 3] = rng.randint(0, 256, n)                   # MIN_TTL
    for j in range(4, 8):                                # lengths and windows
        raw[:, j] = rng.randint(0, 65536, n)
    edges = [0, 1, 2, 9, 10, 31, 73, 255, 1500, 65535, 65536, 2 ** 31, 2 ** 32 - 1]
    for i, e in enumerate(edges):
        raw[i, :] = np.minimum(e, [2 ** 32 - 1] * 3 + [255] + [65535] * 4)
    return np.minimum(raw, 2 ** 32 - 1).astype(np.uint32)


def test_one_million_vectors_match_numpy(tmp_path):
    raw = random_raw(1000000)
    src, out = tmp_path / "raw.bin", tmp_path / "codes.bin"
    raw.astype("<u4").tofile(str(src))
    r = subprocess.run([str(TB), "pre", str(src), str(out)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr.decode()
    got = np.fromfile(str(out), "<i4").reshape(-1, 8)
    want = Preprocessor(ROOT / "assets" / "preprocessing.json").codes(raw.astype(np.float64))
    bad = np.argwhere(got != want)
    assert len(bad) == 0, "%d codes differ, e.g. raw %s -> PL %s, numpy %s" % (
        len(bad), raw[bad[0][0]].tolist(), got[bad[0][0]].tolist(), want[bad[0][0]].tolist())
