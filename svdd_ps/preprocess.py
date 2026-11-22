"""Frozen preprocessing (raw features -> float32 vector -> Q24 input codes).

Re-implements ``svdd_features.preprocessing.Preprocessor.transform`` for the
8-feature compact model with NumPy only (no pandas on the board), and the
input quantizer of ``svdd_baseline.quantization``.
"""
import json
from pathlib import Path

import numpy as np

from .flows import FEATURES

FRACTIONAL_BITS = 16
CODE_BITS = 24
_MAX_VALUE = {"MIN_TTL": 255}  # schema domain limits; others are only >= 0


class Preprocessor:
    def __init__(self, path):
        self.path = Path(path)
        contract = json.loads(self.path.read_text())
        if contract.get("version") != 1:
            raise ValueError(f"{path}: unsupported preprocessing contract version")
        if tuple(contract["raw_columns"]) != FEATURES:
            raise ValueError(f"{path}: raw column order {contract['raw_columns']} "
                             f"does not match the extractor order {list(FEATURES)}")
        entries = contract["entries"]
        if [e["raw_column"] for e in entries] != list(FEATURES) or any(
                e["encoding"] != "numeric" for e in entries):
            raise ValueError(f"{path}: expected 8 numeric entries in feature order")
        self.contract = contract
        self.median = np.array([e["median"] for e in entries], np.float64)
        self.log1p = np.array([e["log1p"] for e in entries], bool)
        self.clip_lower = np.array([e["clip_lower"] for e in entries], np.float64)
        self.clip_upper = np.array([e["clip_upper"] for e in entries], np.float64)
        self.anchor = np.array([e["anchor_lower"] for e in entries], np.float64)
        self.scale = np.array([e["scale"] for e in entries], np.float64)
        self.max_value = np.array([_MAX_VALUE.get(c, np.inf) for c in FEATURES], np.float64)

    def transform(self, raw):
        """Raw features, shape (N, 8) or (8,), -> float32 model input of the same shape."""
        x = np.array(raw, dtype=np.float64, copy=True)
        squeeze = x.ndim == 1
        x = np.atleast_2d(x)
        if x.shape[1] != len(FEATURES):
            raise ValueError(f"expected {len(FEATURES)} features per row, got {x.shape[1]}")
        invalid = ~np.isfinite(x) | (x < 0) | (x > self.max_value)
        x = np.where(invalid, self.median, x)
        with np.errstate(invalid="ignore"):
            x = np.where(self.log1p, np.log1p(x), x)
        out = ((np.clip(x, self.clip_lower, self.clip_upper) - self.anchor) / self.scale)
        out = np.ascontiguousarray(out, dtype=np.float32)
        return out[0] if squeeze else out

    @staticmethod
    def quantize(vectors):
        """float32 vectors -> signed Q24 codes: round_ties_to_even(v * 2^16), 24-bit saturation."""
        v = np.asarray(vectors, np.float32).astype(np.float64)
        codes = np.rint(v * (1 << FRACTIONAL_BITS))
        low, high = -(1 << (CODE_BITS - 1)), (1 << (CODE_BITS - 1)) - 1
        return np.clip(codes, low, high).astype(np.int32)

    def codes(self, raw):
        """Raw features -> Q24 input codes for the FPGA core."""
        return self.quantize(self.transform(raw))
