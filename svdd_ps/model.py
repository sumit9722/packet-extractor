"""Bit-exact software model of the ``deep_svdd_axis`` HLS core.

Mirrors svdd_inference/{dense,relu,score}.hpp:

* activations and weights are ap_fixed<25,9>: signed codes with 16 fractional bits
* dense: exact products and sums (32 fractional bits), then one convergent
  (round-half-to-even) shift back to 16 bits with saturation to 25 bits
* ReLU after the two hidden layers, none after the embedding layer
* score = sum((embedding - center)^2) as an unsigned code with 32 fractional bits

So for any input codes, :meth:`Q24Model.score` returns the same integer the
FPGA writes to ``m_axis_score``. Weights come from ``model_parameters.h``, the
same integer export that generated the HLS parameters.
"""
import re
from pathlib import Path

import numpy as np

ACT_BITS = 25          # ap_fixed<25, 9>
FRACTIONAL_BITS = 16
SCORE_FRACTIONAL_BITS = 32
_ACT_LOW, _ACT_HIGH = -(1 << (ACT_BITS - 1)), (1 << (ACT_BITS - 1)) - 1


def _round_shift(acc, bits):
    """Arithmetic right shift by ``bits`` with round-half-to-even (AP_RND_CONV)."""
    q = acc >> bits                     # floor
    rem = acc - (q << bits)             # 0 <= rem < 2^bits
    half = 1 << (bits - 1)
    return q + ((rem > half) | ((rem == half) & ((q & 1) == 1)))


def _dense(x, w):
    acc = x @ w.T                        # exact: int64 products/sums at 32 fractional bits
    return np.clip(_round_shift(acc, FRACTIONAL_BITS), _ACT_LOW, _ACT_HIGH)


def _parse_header(path):
    text = Path(path).read_text()
    arrays = {}
    for name, dims, body in re.findall(r"\b(W\d|CENTER)((?:\[\d+\])+)\s*=\s*\{(.*?)\};", text, re.S):
        shape = tuple(int(d) for d in re.findall(r"\d+", dims))
        values = np.array([int(v) for v in re.findall(r"-?\d+", body)], np.int64)
        if values.size != int(np.prod(shape)):
            raise ValueError(f"{path}: {name} has {values.size} values, expected {shape}")
        arrays[name] = values.reshape(shape)
    scalars = {k: int(v) for k, v in re.findall(r"\b(THRESHOLD|VALIDATION_THRESHOLD|FRACTIONAL_BITS)\s*=\s*(-?\d+)", text)}
    return arrays, scalars


class Q24Model:
    """Integer reference of the FPGA core plus the anomaly threshold."""

    def __init__(self, header_path):
        arrays, scalars = _parse_header(header_path)
        missing = {"W0", "W1", "W2", "CENTER"} - set(arrays)
        if missing or "THRESHOLD" not in scalars:
            raise ValueError(f"{header_path}: missing {sorted(missing) or ['THRESHOLD']}")
        if scalars.get("FRACTIONAL_BITS", FRACTIONAL_BITS) != FRACTIONAL_BITS:
            raise ValueError(f"{header_path}: expected {FRACTIONAL_BITS} fractional bits")
        self.weights = [arrays["W0"], arrays["W1"], arrays["W2"]]
        self.center = arrays["CENTER"]
        self.threshold = scalars["THRESHOLD"]
        self.validation_threshold = scalars.get("VALIDATION_THRESHOLD")
        if self.weights[0].shape[1] != 8:
            raise ValueError(f"{header_path}: first layer expects {self.weights[0].shape[1]} inputs")

    def trace(self, codes):
        """All intermediate integer codes, keyed like the golden_outputs.csv column groups."""
        x = np.atleast_2d(np.asarray(codes, np.int64))
        # The core reads TDATA[24:0] as a signed 25-bit value.
        x = ((x & 0x1FFFFFF) ^ 0x1000000) - 0x1000000
        h1 = np.maximum(_dense(x, self.weights[0]), 0)
        h2 = np.maximum(_dense(h1, self.weights[1]), 0)
        emb = _dense(h2, self.weights[2])
        terms = (emb - self.center) ** 2
        scores = terms.sum(axis=1)
        return dict(h1=h1, h2=h2, embedding=emb, distance_terms=terms, scores=scores)

    def score(self, codes):
        """Score codes (uint64, 32 fractional bits) for input codes of shape (N, 8)."""
        return self.trace(codes)["scores"].astype(np.uint64)

    def is_anomaly(self, scores, recalibrated=False):
        t = self.validation_threshold if recalibrated else self.threshold
        return np.asarray(scores, np.uint64) > np.uint64(t)

    @staticmethod
    def score_value(scores):
        """Score codes -> real-valued squared distance."""
        return np.asarray(scores, np.float64) / float(1 << SCORE_FRACTIONAL_BITS)
