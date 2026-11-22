"""Board side: load the overlay and move chunks through AXI DMA.

    PS memory --MM2S--> svdd_flow_pl (PL) --S2MM--> PS memory

There are two ways to reach the hardware, the same as in zed-ps:

``pynq``    PYNQ image: pynq.Overlay loads the bitstream and pynq.allocate gives
            the DMA buffers.
``devmem``  any Xilinx Linux, no PYNQ: the kernel's FPGA manager loads the
            bitstream, the buffers are 8 MB of DDR that Linux does not use (boot
            with ``mem=504M``), and the registers are reached through /dev/mem.

Either way this file drives the AXI DMA registers itself (simple mode, PG021):
the PL decides how many records come back, and only the S2MM length register
says how many arrived.
"""
import mmap
import os
import struct
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import numpy as np

from .records import REC_BYTES, REC_MARKER, REC_WORDS
from .stream import DEFAULT_CHUNK, HEADER_BYTES

ROOT = Path(__file__).resolve().parent.parent
GROUP_RECORDS = 256
OUT_BYTES = 1 << 16                   # >= (GROUP_RECORDS + 1) * 128
IN_BYTES = 4 << 20                    # biggest chunk the driver accepts

BOARDS = {
    # part in the .bit header, PS_CLK oscillator (MHz), DDR size
    "pynq-z2": {"part": "7z020clg400", "ps_clk": 50.0, "ddr_end": 0x2000_0000},
    "zedboard": {"part": "7z020clg484", "ps_clk": 33.333333, "ddr_end": 0x2000_0000},
}
DEFAULT_BUF_ADDR = 0x1F80_0000        # top 8 MB of the 512 MB DDR, free with mem=504M
FCLK0_MHZ = 100.0

# AXI DMA simple mode registers (byte offsets) and bits
MM2S_DMACR, MM2S_DMASR, MM2S_SA, MM2S_LENGTH = 0x00, 0x04, 0x18, 0x28
S2MM_DMACR, S2MM_DMASR, S2MM_DA, S2MM_LENGTH = 0x30, 0x34, 0x48, 0x58
CR_RUN, CR_RESET = 1, 4
SR_HALTED, SR_IOC = 1, 1 << 12
SR_ERRORS = 0x70                       # internal, slave, decode error
SR_CLEAR = (1 << 12) | (1 << 14)       # IOC and error interrupt bits, write 1 to clear

# Zynq-7000 SLCR (UG585)
SLCR_BASE, SLCR_UNLOCK, UNLOCK_KEY = 0xF800_0000, 0x008, 0xDF0D
ARM_PLL_CTRL, DDR_PLL_CTRL, IO_PLL_CTRL = 0x100, 0x104, 0x108
FPGA0_CLK_CTRL, FPGA0_THR_CTRL, FPGA_RST_CTRL, LVL_SHFTR_EN = 0x170, 0x178, 0x240, 0x900


# ----------------------------------------------------------------- board and files
def detect_board():
    env = os.environ.get("BOARD", "").lower()           # PYNQ images set BOARD=Pynq-Z2
    if "pynq" in env and "z2" in env:
        return "pynq-z2"
    if "zed" in env:
        return "zedboard"
    try:
        model = Path("/proc/device-tree/model").read_bytes().decode(errors="replace").lower()
    except OSError:
        model = ""
    if "zed" in model:
        return "zedboard"
    if "pynq" in model or "z2" in model:
        return "pynq-z2"
    return None


def overlay_for(board):
    return ROOT / "overlay" / board / "svdd_pl.bit"


def bit_payload(raw):
    """(part name, configuration data) of a Xilinx .bit file."""
    if len(raw) < 16 or raw[:2] != b"\x00\x09":
        raise ValueError("not a Xilinx .bit file")
    i, fields = 13, {}
    while i < len(raw):
        key = raw[i:i + 1]
        i += 1
        if key == b"e":
            n = struct.unpack_from(">I", raw, i)[0]
            data = raw[i + 4:i + 4 + n]
            if len(data) != n or n % 4:
                raise ValueError(".bit file is truncated")
            return fields.get("b", ""), data
        n = struct.unpack_from(">H", raw, i)[0]
        fields[key.decode("latin-1")] = raw[i + 2:i + 2 + n].rstrip(b"\0").decode("latin-1")
        i += 2 + n
    raise ValueError("no configuration data in .bit file")


def check_part(bitfile, board):
    part, _ = bit_payload(Path(bitfile).read_bytes())
    want = BOARDS[board]["part"]
    if part and not part.startswith(want):
        raise RuntimeError("%s was built for %s, but this is a %s (%s). Use overlay/%s/svdd_pl.bit."
                           % (bitfile, part, board, want, board))


def fclk_target(hwh):
    """The FCLK0 frequency (MHz) the overlay was built and timed for, from the .hwh."""
    root = ET.parse(str(hwh)).getroot()
    for name in ("PCW_ACT_FPGA0_PERIPHERAL_FREQMHZ", "PCW_FPGA0_PERIPHERAL_FREQMHZ"):
        for prm in root.iter("PARAMETER"):
            if prm.get("NAME") == name:
                try:
                    return float(prm.get("VALUE"))
                except (TypeError, ValueError):
                    pass
    return FCLK0_MHZ


def dma_base(hwh):
    for m in ET.parse(str(hwh)).getroot().iter("MEMRANGE"):
        if m.get("INSTANCE", "").startswith("axi_dma") and m.get("MEMTYPE") == "REGISTER":
            return int(m.get("BASEVALUE"), 16)
    raise RuntimeError("no AXI DMA in %s" % hwh)


# ----------------------------------------------------------------- PL clock (FCLK0)
def pll_mhz(ctrl, ps_clk):
    return ps_clk if ctrl & (1 << 4) else ((ctrl >> 12) & 0x7F) * ps_clk


def fclk_divisors(source_mhz, target_mhz):
    """Best (MHz, divisor0, divisor1) at or below the target; never faster than asked."""
    best = None
    for d1 in range(1, 64):
        for d0 in range(1, 64):
            f = source_mhz / (d0 * d1)
            if f <= target_mhz * 1.000001 and (best is None or f > best[0] + 1e-9):
                best = (f, d0, d1)
    return best


def fclk0_mhz(slcr, ps_clk):
    ctrl = slcr.read(FPGA0_CLK_CTRL)
    pll = {2: ARM_PLL_CTRL, 3: DDR_PLL_CTRL}.get((ctrl >> 4) & 3, IO_PLL_CTRL)
    return pll_mhz(slcr.read(pll), ps_clk) / ((((ctrl >> 8) & 0x3F) or 1) * (((ctrl >> 20) & 0x3F) or 1))


def set_fclk0(slcr, ps_clk, target=FCLK0_MHZ):
    """FCLK0 from the IO PLL at the target (or just below). Linux keeps the SLCR unlocked; leave it so."""
    f, d0, d1 = fclk_divisors(pll_mhz(slcr.read(IO_PLL_CTRL), ps_clk), target)
    slcr.write(SLCR_UNLOCK, UNLOCK_KEY)
    ctrl = slcr.read(FPGA0_CLK_CTRL) & ~((0x3F << 20) | (0x3F << 8) | (0x3 << 4))
    slcr.write(FPGA0_CLK_CTRL, ctrl | (d1 << 20) | (d0 << 8))
    return f


def enable_pl_interface(slcr):
    """FCLK0 not gated, level shifters on, PL resets released. Returns what had to be fixed."""
    fixed = []
    slcr.write(SLCR_UNLOCK, UNLOCK_KEY)
    if slcr.read(FPGA0_THR_CTRL) & 1:
        slcr.write(FPGA0_THR_CTRL, slcr.read(FPGA0_THR_CTRL) & ~1)
        fixed.append("FCLK0 was gated by Linux")
    if slcr.read(LVL_SHFTR_EN) & 0xF != 0xF:
        slcr.write(LVL_SHFTR_EN, 0xF)
        fixed.append("PS-PL level shifters were off")
    if slcr.read(FPGA_RST_CTRL) & 0xF:
        slcr.write(FPGA_RST_CTRL, slcr.read(FPGA_RST_CTRL) & ~0xF)
        fixed.append("FCLK_RESET was held")
    return fixed


# ----------------------------------------------------------------- /dev/mem pieces
class MMIO:
    """A /dev/mem window as 32-bit words (uncached: O_SYNC, outside System RAM)."""

    def __init__(self, fd, base, size):
        start = base - base % mmap.PAGESIZE
        length = -(-(base - start + size) // mmap.PAGESIZE) * mmap.PAGESIZE
        self._map = mmap.mmap(fd, length, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=start)
        self.words = np.frombuffer(self._map, np.uint32, count=size // 4, offset=base - start)

    def read(self, off):
        return int(self.words[off >> 2])

    def write(self, off, value):
        self.words[off >> 2] = value & 0xFFFFFFFF

    def close(self):
        self.words = None
        self._map.close()


def _ram_ranges(iomem):
    out = []
    for line in Path(iomem).read_text().splitlines():
        if line[:1].isspace() or "System RAM" not in line:
            continue
        lo, hi = (int(x, 16) for x in line.split(":")[0].strip().split("-"))
        out.append((lo, hi))
    return out


def check_reserved(addr, size, ddr_end, iomem="/proc/iomem"):
    """Refuse DMA buffers inside memory Linux uses (the DMA writes behind the kernel's back)."""
    if addr % mmap.PAGESIZE:
        raise ValueError("buffer address 0x%08X is not page aligned" % addr)
    if addr + size > ddr_end:
        raise ValueError("buffers 0x%08X-0x%08X run past the end of DDR" % (addr, addr + size - 1))
    for lo, hi in _ram_ranges(iomem):
        if addr <= hi and addr + size - 1 >= lo:
            raise RuntimeError(
                "DMA buffers at 0x%08X are inside Linux's RAM (0x%08X-0x%08X). Add mem=504M to the "
                "kernel command line and reboot, or use --driver pynq on a PYNQ image." % (addr, lo, hi))


def program_pl(bitfile, sysfs="/sys/class/fpga_manager/fpga0", firmware_dir="/lib/firmware"):
    """Load a full bitstream through the Linux FPGA manager (or /dev/xdevcfg on old kernels)."""
    _, data = bit_payload(Path(bitfile).read_bytes())
    data = np.frombuffer(data, ">u4").astype("<u4").tobytes()      # the Zynq manager wants swapped words
    mgr = Path(sysfs)
    if mgr.is_dir() and (mgr / "firmware").exists():
        Path(firmware_dir).mkdir(parents=True, exist_ok=True)
        (Path(firmware_dir) / "svdd_pl.bin").write_bytes(data)
        if (mgr / "flags").exists():
            (mgr / "flags").write_text("0")
        (mgr / "firmware").write_text("svdd_pl.bin")
        state = (mgr / "state").read_text().strip()
        if state != "operating":
            raise RuntimeError("FPGA manager state is %r after loading (see dmesg)" % state)
        return "fpga_manager"
    if Path("/dev/xdevcfg").exists():
        with open("/dev/xdevcfg", "wb") as f:
            f.write(data)
        return "xdevcfg"
    raise RuntimeError("no way to load a bitstream: need a Xilinx kernel with the FPGA manager "
                       "('firmware' file in %s) or /dev/xdevcfg" % sysfs)


# ----------------------------------------------------------------- AXI DMA
class AxiDma:
    """Simple-mode AXI DMA: one MM2S send, then S2MM receives until the PL's marker record."""

    def __init__(self, regs, timeout=5.0):
        self.r, self.timeout = regs, timeout

    def reset(self):
        self.r.write(MM2S_DMACR, CR_RESET)
        deadline = time.monotonic() + self.timeout
        while self.r.read(MM2S_DMACR) & CR_RESET:
            if time.monotonic() > deadline:
                raise TimeoutError("AXI DMA reset did not finish. Is the PL programmed and clocked?")
        for cr, sr in ((MM2S_DMACR, MM2S_DMASR), (S2MM_DMACR, S2MM_DMASR)):
            self.r.write(cr, CR_RUN)
            while self.r.read(sr) & SR_HALTED:
                if time.monotonic() > deadline:
                    raise TimeoutError("AXI DMA stays halted after start")

    def start_recv(self, phys, nbytes):
        self.r.write(S2MM_DMASR, SR_CLEAR)
        self.r.write(S2MM_DA, phys)
        self.r.write(S2MM_LENGTH, nbytes)

    def start_send(self, phys, nbytes):
        self.r.write(MM2S_DMASR, SR_CLEAR)
        self.r.write(MM2S_SA, phys)
        self.r.write(MM2S_LENGTH, nbytes)

    def wait(self, sr_off, what):
        deadline = time.monotonic() + self.timeout
        while True:
            sr = self.r.read(sr_off)
            if sr & SR_ERRORS:
                raise RuntimeError("DMA %s error (DMASR 0x%08X); the DMA is reset on the next chunk" % (what, sr))
            if sr & SR_IOC:
                return
            if time.monotonic() > deadline:
                raise TimeoutError("DMA %s did not finish within %.0fs (DMASR 0x%08X)" % (what, self.timeout, sr))

    def received(self):
        return self.r.read(S2MM_LENGTH)


# ----------------------------------------------------------------- backends
class _DevMemBackend:
    def __init__(self, bitfile, board, buf_addr):
        cfg = BOARDS[board]
        base = dma_base(Path(bitfile).with_suffix(".hwh"))
        self.in_phys, self.out_phys = buf_addr, buf_addr + IN_BYTES
        check_reserved(buf_addr, IN_BYTES + OUT_BYTES, cfg["ddr_end"])
        self._fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
        slcr = MMIO(self._fd, SLCR_BASE, 0x1000)
        try:
            set_fclk0(slcr, cfg["ps_clk"], fclk_target(Path(bitfile).with_suffix(".hwh")))
            loader = program_pl(bitfile)
            fixed = enable_pl_interface(slcr)
            self.fclk = fclk0_mhz(slcr, cfg["ps_clk"])
        finally:
            slcr.close()
        self.regs = MMIO(self._fd, base, 0x100)
        self._in = MMIO(self._fd, self.in_phys, IN_BYTES)
        self._out = MMIO(self._fd, self.out_phys, OUT_BYTES)
        self.info = ("devmem driver: bitstream via %s, DMA at 0x%08X, buffers at 0x%08X, FCLK0 %.2f MHz%s"
                     % (loader, base, buf_addr, self.fclk, (" (fixed: %s)" % "; ".join(fixed)) if fixed else ""))

    def put(self, data):
        # 32-bit copies into uncached memory (wide or unaligned stores could fault)
        src = np.frombuffer(data, np.uint32)
        self._in.words[:len(src)] = src

    def get(self, nbytes):
        return self._out.words[:nbytes // 4].copy().view(np.uint64)

    def close(self):
        for m in (self.regs, self._in, self._out):
            m.close()
        os.close(self._fd)


class _PynqBackend:
    def __init__(self, bitfile, board):
        import pynq
        try:
            from pynq import allocate
        except ImportError:                                   # PYNQ 2.3 and earlier
            xlnk = pynq.Xlnk()

            def allocate(shape, dtype):
                return xlnk.cma_array(shape=shape, dtype=dtype, cacheable=0)

        self.overlay = pynq.Overlay(str(bitfile))
        names = [n for n in self.overlay.ip_dict if "axi_dma" in n]
        if not names:
            raise RuntimeError("no AXI DMA in overlay; IPs: %s" % list(self.overlay.ip_dict))
        base = self.overlay.ip_dict[names[0]]["phys_addr"]
        self.regs = pynq.MMIO(base, 0x10000)
        self._in = allocate(shape=(IN_BYTES,), dtype=np.uint8)
        self._out = allocate(shape=(OUT_BYTES,), dtype=np.uint8)
        self.in_phys = int(getattr(self._in, "physical_address", getattr(self._in, "device_address", 0)))
        self.out_phys = int(getattr(self._out, "physical_address", getattr(self._out, "device_address", 0)))
        # PYNQ computes FCLK0 assuming a 50 MHz PS_CLK (true on the PYNQ-Z2). Set it from the
        # real PLL registers so the ZedBoard (33.3 MHz) also runs at 100 MHz.
        fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
        slcr = MMIO(fd, SLCR_BASE, 0x1000)
        try:
            set_fclk0(slcr, BOARDS[board]["ps_clk"], fclk_target(Path(bitfile).with_suffix(".hwh")))
            self.fclk = fclk0_mhz(slcr, BOARDS[board]["ps_clk"])
        finally:
            slcr.close()
            os.close(fd)
        self.info = "pynq driver: DMA at 0x%08X, FCLK0 %.2f MHz" % (base, self.fclk)

    def put(self, data):
        self._in[:len(data)] = np.frombuffer(data, np.uint8)
        if hasattr(self._in, "flush"):
            self._in.flush()

    def get(self, nbytes):
        if hasattr(self._out, "invalidate"):
            self._out.invalidate()
        return np.array(self._out[:nbytes]).view(np.uint64)

    def close(self):
        for b in (self._in, self._out):
            if hasattr(b, "freebuffer"):
                b.freebuffer()


class PLEngine:
    """Send chunks (stream.py) through svdd_flow_pl and collect the output words."""

    def __init__(self, board="auto", driver="auto", overlay=None, buf_addr=None, chunk_bytes=DEFAULT_CHUNK,
                 timeout=5.0):
        if board == "auto":
            board = detect_board()
            if board is None:
                raise RuntimeError("cannot tell which board this is; pass --board pynq-z2 or --board zedboard")
        if chunk_bytes + HEADER_BYTES + 8 > IN_BYTES:
            raise ValueError("--chunk-bytes must be below %d" % (IN_BYTES - HEADER_BYTES - 8))
        bitfile = Path(overlay) if overlay else overlay_for(board)
        if not bitfile.exists() or not bitfile.with_suffix(".hwh").exists():
            raise FileNotFoundError("%s and its .hwh are needed (copy overlay/%s/ to the board)" % (bitfile, board))
        check_part(bitfile, board)
        if driver == "auto":
            try:
                import pynq  # noqa: F401
                driver = "pynq"
            except ImportError:
                driver = "devmem"
        if driver == "pynq":
            self.hw = _PynqBackend(bitfile, board)
        else:
            self.hw = _DevMemBackend(bitfile, board, DEFAULT_BUF_ADDR if buf_addr is None else buf_addr)
        self.dma = AxiDma(self.hw.regs, timeout)
        self.dma.reset()
        self.info = "%s on %s, %s" % (bitfile.name, board, self.hw.info)

    def process(self, chunk):
        """One chunk in, its output words out (flow records, ending with the marker record)."""
        if len(chunk) > IN_BYTES or len(chunk) % 8:
            raise ValueError("chunk must be a multiple of 8 bytes and at most %d" % IN_BYTES)
        self.hw.put(chunk)
        dma = self.dma
        try:
            dma.start_recv(self.hw.out_phys, OUT_BYTES)        # receive armed first
            dma.start_send(self.hw.in_phys, len(chunk))
            parts = []
            while True:
                dma.wait(S2MM_DMASR, "receive")
                n = dma.received()
                words = self.hw.get(n)
                parts.append(words)
                if n >= REC_BYTES and int(words[-REC_WORDS]) & 0xFF == REC_MARKER:
                    break                                     # the marker ends this chunk's output
                dma.start_recv(self.hw.out_phys, OUT_BYTES)   # a full group of 256: keep receiving
            dma.wait(MM2S_DMASR, "send")
        except (RuntimeError, TimeoutError):
            dma.reset()
            raise
        return np.concatenate(parts)

    def close(self):
        self.hw.close()
