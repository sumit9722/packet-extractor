"""Board driver logic (svdd_pl/driver.py) against a fake AXI DMA, on the PC."""
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from svdd_pl import driver                                  # noqa: E402
from svdd_pl.records import REC_FLOW, REC_MARKER, REC_WORDS  # noqa: E402

IN_PHYS, OUT_PHYS = 0x1F80_0000, 0x1FC0_0000


def record(kind, seq=0):
    r = np.zeros(REC_WORDS, np.uint64)
    r[0] = kind
    r[15] = seq
    return r


class FakeDma:
    """Pretends to be AXI DMA + svdd_flow_pl: each send produces `groups` of records."""

    def __init__(self, hw, groups, fail=False):
        self.regs, self.hw, self.groups, self.fail = {}, hw, list(groups), fail
        self.recv_armed = 0

    def read(self, off):
        return self.regs.get(off, 0)

    def write(self, off, v):
        r = self.regs
        if off == driver.MM2S_DMACR and v & driver.CR_RESET:
            r.update({driver.MM2S_DMACR: 0, driver.MM2S_DMASR: driver.SR_HALTED, driver.S2MM_DMASR: driver.SR_HALTED})
        elif off in (driver.MM2S_DMACR, driver.S2MM_DMACR):
            r[off] = v
            r[off + 4] = r.get(off + 4, 0) & ~driver.SR_HALTED
        elif off in (driver.MM2S_DMASR, driver.S2MM_DMASR):
            r[off] = r.get(off, 0) & ~(v & driver.SR_CLEAR)
        else:
            r[off] = v
            if off == driver.S2MM_LENGTH:
                self.recv_armed += 1
                self._deliver()
            if off == driver.MM2S_LENGTH:
                assert self.recv_armed, "receive must be armed before the send"
                r[driver.MM2S_DMASR] |= driver.SR_IOC
                self._deliver()

    def _deliver(self):
        r = self.regs
        if self.fail:
            r[driver.S2MM_DMASR] |= 0x40          # decode error
            return
        if not self.groups or r.get(driver.MM2S_LENGTH) is None:
            return
        g = self.groups.pop(0)
        self.hw.out[:len(g)] = g
        r[driver.S2MM_LENGTH] = 8 * len(g)
        r[driver.S2MM_DMASR] |= driver.SR_IOC


def make_engine(groups, fail=False):
    hw = SimpleNamespace(in_phys=IN_PHYS, out_phys=OUT_PHYS, out=np.zeros(driver.OUT_BYTES // 8, np.uint64),
                         sent=[])
    hw.put = lambda data: hw.sent.append(bytes(data))
    hw.get = lambda n: hw.out[:n // 8].copy()
    eng = driver.PLEngine.__new__(driver.PLEngine)
    eng.hw = hw
    hw.regs = FakeDma(hw, groups, fail)
    eng.dma = driver.AxiDma(hw.regs, timeout=0.05)
    eng.dma.reset()
    return eng


def test_receives_groups_until_the_marker():
    full = np.concatenate([record(REC_FLOW, i) for i in range(256)])        # one full group
    tail = np.concatenate([record(REC_FLOW, 256), record(REC_MARKER)])
    eng = make_engine([full, tail])
    words = eng.process(b"\0" * 64)
    assert len(words) == 258 * REC_WORDS
    assert int(words[-REC_WORDS]) & 0xFF == REC_MARKER
    assert eng.hw.regs.recv_armed == 2


def test_dma_error_resets_and_raises():
    eng = make_engine([], fail=True)
    with pytest.raises(RuntimeError, match="DMA receive error"):
        eng.process(b"\0" * 64)
    assert eng.hw.regs.read(driver.MM2S_DMACR) == driver.CR_RUN   # reset and restarted


def test_rejects_unaligned_chunks():
    eng = make_engine([])
    with pytest.raises(ValueError):
        eng.process(b"\0" * 13)


def test_fclk_for_both_boards():
    # PYNQ-Z2: 50 MHz x FDIV 20 = 1000 MHz IO PLL; ZedBoard: 33.33 MHz x 30.
    for ps_clk, fdiv in ((50.0, 20), (33.333333, 30)):
        f, d0, d1 = driver.fclk_divisors(driver.pll_mhz(fdiv << 12, ps_clk), 100.0)
        assert f == pytest.approx(100.0, abs=1e-4) and f <= 100.0 and d0 * d1 == 10


def test_part_check(tmp_path):
    import struct

    def bit(part):
        def field(k, t):
            b = t.encode() + b"\0"
            return k + struct.pack(">H", len(b)) + b
        payload = bytes.fromhex("ffffffffaa995566")
        return (b"\x00\x09" + bytes.fromhex("0ff00ff00ff00ff000") + b"\x00\x01" + field(b"a", "x")
                + field(b"b", part) + field(b"c", "d") + field(b"d", "t") + b"e" + struct.pack(">I", 8) + payload)
    p = tmp_path / "svdd_pl.bit"
    p.write_bytes(bit("7z020clg484"))
    driver.check_part(p, "zedboard")
    with pytest.raises(RuntimeError, match="built for 7z020clg484"):
        driver.check_part(p, "pynq-z2")
