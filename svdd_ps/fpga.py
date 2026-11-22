"""PS <-> PL link on the ZedBoard: send Q24 feature codes to deep_svdd_axis over AXI DMA.

There are two drivers with the same interface (``score_one``, ``score``, ``close``):

``pynq``
    The PYNQ library, for a PYNQ SD-card image (for example the community
    ZedBoard image). PYNQ loads the bitstream and runs the DMA.

``devmem``
    No PYNQ at all, for any ZedBoard Linux with Python 3 and NumPy. The
    bitstream goes in through the kernel's FPGA manager, and the DMA registers
    are written directly through ``/dev/mem``. Needs root, plus one page of DDR
    that Linux does not use for the DMA buffers (boot with ``mem=504M``; see
    ``check_reserved``).

``FpgaScorer(..., driver="auto")`` uses ``pynq`` if it can be imported and
``devmem`` otherwise. Nothing here imports ``pynq`` until it is used, so the
package still runs on a PC.

The IP treats each TLAST-terminated frame of 8 beats as one flow, and the DMA
raises TLAST only at the end of a transfer. So every flow is one MM2S
transfer of 32 bytes (8 x int32) and one S2MM transfer of 8 bytes (uint64
score). Batching several flows into one transfer would need a TLAST framer in
the PL. At Python speeds on the ARM, the extractor is the bottleneck anyway.
"""
import mmap
import os
import struct
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import numpy as np

DEFAULT_OVERLAY = Path(__file__).resolve().parent.parent / "overlay" / "svdd.bit"

# ZedBoard facts.
ZED_PART = "7z020clg484"
ZED_PS_CLK_MHZ = 33.333333      # PS_CLK oscillator (the PYNQ-Z1/Z2 have 50 MHz)
ZED_DDR_END = 0x2000_0000       # 512 MB of DDR3 at physical address 0
DEFAULT_BUF_ADDR = 0x1FF0_0000  # in the top 8 MB that mem=504M keeps away from Linux
FCLK0_MHZ = 100.0               # the HLS core and the overlay were timed for 10 ns

# AXI DMA v7.1 in simple (direct register) mode, PG021. Byte offsets.
MM2S_DMACR, MM2S_DMASR, MM2S_SA, MM2S_LENGTH = 0x00, 0x04, 0x18, 0x28
S2MM_DMACR, S2MM_DMASR, S2MM_DA, S2MM_LENGTH = 0x30, 0x34, 0x48, 0x58
CR_RUN, CR_RESET = 1 << 0, 1 << 2
SR_HALTED = 1 << 0
SR_INT_ERR, SR_SLV_ERR, SR_DEC_ERR = 1 << 4, 1 << 5, 1 << 6
SR_ERRORS = SR_INT_ERR | SR_SLV_ERR | SR_DEC_ERR
SR_IOC_IRQ, SR_ERR_IRQ = 1 << 12, 1 << 14   # write 1 to clear

# Zynq-7000 system-level control registers (UG585, appendix B).
SLCR_BASE, SLCR_UNLOCK, UNLOCK_KEY = 0xF800_0000, 0x008, 0xDF0D
ARM_PLL_CTRL, DDR_PLL_CTRL, IO_PLL_CTRL = 0x100, 0x104, 0x108
FPGA0_CLK_CTRL, FPGA0_THR_CTRL = 0x170, 0x178
FPGA_RST_CTRL, LVL_SHFTR_EN = 0x240, 0x900

IN_OFF, OUT_OFF = 0, 64          # where the 32-byte input and the 8-byte score sit in the buffer page


def FpgaScorer(bitfile=DEFAULT_OVERLAY, driver="auto", buf_addr=DEFAULT_BUF_ADDR, timeout=1.0,
               download=True):
    """Open the FPGA scorer with the chosen driver ("auto", "pynq" or "devmem")."""
    if driver == "auto":
        try:
            import pynq  # noqa: F401
            driver = "pynq"
        except ImportError:
            driver = "devmem"
    if driver == "pynq":
        return PynqScorer(bitfile, timeout=timeout, download=download)
    if driver == "devmem":
        return DevMemScorer(bitfile, buf_addr=buf_addr, timeout=timeout, download=download)
    raise ValueError(f"unknown driver {driver!r} (use auto, pynq or devmem)")


def _check_files(bitfile):
    bitfile = Path(bitfile)
    if not bitfile.exists():
        raise FileNotFoundError(f"{bitfile} not found (copy svdd.bit and svdd.hwh to the board)")
    if not bitfile.with_suffix(".hwh").exists():
        raise FileNotFoundError(f"{bitfile.with_suffix('.hwh')} must sit next to the .bit file")
    return bitfile


def _score_rows(score_one, codes):
    codes = np.atleast_2d(np.asarray(codes, np.int32))
    out = np.empty(len(codes), np.uint64)
    for i, row in enumerate(codes):
        out[i] = score_one(row)
    return out


# ----------------------------------------------------------------- bitstream and .hwh
def bit_payload(raw):
    """Split a Xilinx .bit file into (part name, configuration data).

    Layout: 2-byte length + 9 magic bytes, 2 bytes 0x0001, then fields
    'a' (design), 'b' (part), 'c' (date), 'd' (time), each with a 2-byte length,
    and finally 'e' with a 4-byte length followed by the configuration data.
    """
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


def fpga_manager_bin(raw):
    """The .bit payload as the Linux Zynq FPGA manager wants it: every 32-bit word byte-swapped."""
    part, data = bit_payload(raw)
    swapped = np.frombuffer(data, ">u4").astype("<u4").tobytes()
    if b"\x66\x55\x99\xaa" not in swapped:
        raise ValueError("no sync word in the bitstream")
    return part, swapped


def dma_registers(hwh):
    """(base address, size) of the AXI DMA control registers, read from the .hwh."""
    for m in ET.parse(str(hwh)).getroot().iter("MEMRANGE"):
        if m.get("INSTANCE", "").startswith("axi_dma") and m.get("MEMTYPE") == "REGISTER":
            lo, hi = int(m.get("BASEVALUE"), 16), int(m.get("HIGHVALUE"), 16)
            return lo, hi - lo + 1
    raise RuntimeError(f"no AXI DMA register range in {hwh}")


# ----------------------------------------------------------------- clocks
def pll_mhz(ctrl, ps_clk_mhz=ZED_PS_CLK_MHZ):
    """Output of a Zynq PLL from its *_PLL_CTRL value (FDIV in bits 18:12, bypass in bit 4)."""
    if ctrl & (1 << 4):
        return ps_clk_mhz
    return ((ctrl >> 12) & 0x7F) * ps_clk_mhz


def fclk_divisors(source_mhz, target_mhz):
    """Best (MHz, divisor0, divisor1) at or below the target. Never runs the PL faster than asked."""
    best = None
    for d1 in range(1, 64):
        for d0 in range(1, 64):
            f = source_mhz / (d0 * d1)
            if f <= target_mhz * 1.000001 and (best is None or f > best[0] + 1e-9):
                best = (f, d0, d1)
    return best


def fclk0_mhz(slcr, ps_clk_mhz=ZED_PS_CLK_MHZ):
    """Current FCLK0 frequency, worked out from the SLCR clock registers."""
    ctrl = slcr.read(FPGA0_CLK_CTRL)
    pll = {2: ARM_PLL_CTRL, 3: DDR_PLL_CTRL}.get((ctrl >> 4) & 3, IO_PLL_CTRL)
    d0, d1 = ((ctrl >> 8) & 0x3F) or 1, ((ctrl >> 20) & 0x3F) or 1
    return pll_mhz(slcr.read(pll), ps_clk_mhz) / (d0 * d1)


def set_fclk0(slcr, target_mhz=FCLK0_MHZ, ps_clk_mhz=ZED_PS_CLK_MHZ):
    """Run FCLK0 from the IO PLL as close to target_mhz as possible (never above). Returns the MHz.

    Linux unlocks the SLCR at boot and keeps it unlocked, so this unlocks (no-op)
    and does not lock it again: locking would break the kernel's own clock code.
    """
    f, d0, d1 = fclk_divisors(pll_mhz(slcr.read(IO_PLL_CTRL), ps_clk_mhz), target_mhz)
    slcr.write(SLCR_UNLOCK, UNLOCK_KEY)
    ctrl = slcr.read(FPGA0_CLK_CTRL) & ~((0x3F << 20) | (0x3F << 8) | (0x3 << 4))
    slcr.write(FPGA0_CLK_CTRL, ctrl | (d1 << 20) | (d0 << 8))   # SRCSEL 0 = IO PLL
    return f


def enable_pl_interface(slcr):
    """Make sure the PL can talk to the PS: FCLK0 not gated, level shifters on, PL resets released.

    The FPGA manager normally does the last two. Linux may have gated FCLK0 at
    boot if the device tree did not mark it as used ("disable unused clocks").
    Returns a list of what had to be fixed.
    """
    fixed = []
    slcr.write(SLCR_UNLOCK, UNLOCK_KEY)
    thr = slcr.read(FPGA0_THR_CTRL)
    if thr & 1:
        slcr.write(FPGA0_THR_CTRL, thr & ~1)
        fixed.append("FCLK0 was gated by Linux")
    if slcr.read(LVL_SHFTR_EN) & 0xF != 0xF:
        slcr.write(LVL_SHFTR_EN, 0xF)
        fixed.append("PS-PL level shifters were off")
    if slcr.read(FPGA_RST_CTRL) & 0xF:
        slcr.write(FPGA_RST_CTRL, slcr.read(FPGA_RST_CTRL) & ~0xF)
        fixed.append("FCLK_RESET was held")
    return fixed


# ----------------------------------------------------------------- loading the PL without PYNQ
def program_pl(bitfile, firmware_dir="/lib/firmware", sysfs="/sys/class/fpga_manager/fpga0",
               xdevcfg="/dev/xdevcfg"):
    """Load a full bitstream from Linux. Returns which kernel interface was used."""
    part, data = fpga_manager_bin(Path(bitfile).read_bytes())
    if part and not part.startswith(ZED_PART):
        raise RuntimeError(f"{bitfile} was built for {part}, not the ZedBoard ({ZED_PART}). "
                           "Rebuild with zed-ps/vivado/build.sh.")
    mgr = Path(sysfs)
    if mgr.is_dir() and not (mgr / "firmware").exists():
        raise RuntimeError(
            f"{sysfs} has no 'firmware' file. Loading a bitstream by name is a Xilinx kernel "
            "feature (PetaLinux, PYNQ, linux-xlnx); a mainline kernel needs a device-tree overlay instead.")
    if mgr.is_dir():                       # Xilinx kernels from about 2018 on
        name = "svdd_zed.bin"
        Path(firmware_dir).mkdir(parents=True, exist_ok=True)
        (Path(firmware_dir) / name).write_bytes(data)
        if (mgr / "flags").exists():
            (mgr / "flags").write_text("0")   # 0 = full (not partial) reconfiguration
        (mgr / "firmware").write_text(name)
        state = (mgr / "state").read_text().strip()
        if state != "operating":
            raise RuntimeError(f"FPGA manager state is {state!r} after loading (see dmesg)")
        return "fpga_manager"
    if Path(xdevcfg).exists():             # older Xilinx kernels; finds the sync word itself
        partial = Path("/sys/devices/soc0/amba/f8007000.devcfg/is_partial_bitstream")
        if partial.exists():
            partial.write_text("0")
        with open(xdevcfg, "wb") as f:
            f.write(data)
        return "xdevcfg"
    raise RuntimeError(f"no FPGA loader: neither {sysfs} nor {xdevcfg} exists. The kernel needs "
                       "CONFIG_FPGA_MGR_ZYNQ_FPGA (or the Xilinx devcfg driver).")


def _ram_ranges(iomem):
    """Top-level 'System RAM' ranges in /proc/iomem (needs root to show real addresses)."""
    out = []
    for line in Path(iomem).read_text().splitlines():
        if line[:1].isspace() or "System RAM" not in line:
            continue
        lo, hi = (int(x, 16) for x in line.split(":")[0].strip().split("-"))
        out.append((lo, hi))
    return out


def check_reserved(addr, size, iomem="/proc/iomem", ddr_end=ZED_DDR_END):
    """Refuse a DMA buffer that Linux might be using.

    The DMA writes straight into DDR, so the buffer must be memory the kernel
    does not own. The simplest way is to boot with ``mem=504M``: Linux then
    uses only 0x00000000-0x1F7FFFFF and the default buffer at 0x1FF00000 is free.
    """
    if addr % mmap.PAGESIZE:
        raise ValueError(f"buffer address 0x{addr:08X} is not page aligned")
    if addr + size > ddr_end:
        raise ValueError(f"buffer 0x{addr:08X} is past the end of the ZedBoard's 512 MB DDR")
    for lo, hi in _ram_ranges(iomem):
        if addr <= hi and addr + size - 1 >= lo:
            raise RuntimeError(
                f"buffer 0x{addr:08X} is inside Linux's RAM (0x{lo:08X}-0x{hi:08X} in {iomem}), "
                "so the DMA could overwrite kernel memory. Add mem=504M to the kernel command line "
                "(bootargs) and reboot, or pass --buf-addr for a region you reserved yourself.")


class _MMIO:
    """A /dev/mem window as 32-bit words. Uncached: opened with O_SYNC and outside System RAM."""

    def __init__(self, fd, base, size):
        start = base - base % mmap.PAGESIZE
        length = -(-(base - start + size) // mmap.PAGESIZE) * mmap.PAGESIZE
        self._map = mmap.mmap(fd, length, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
                              offset=start)
        self.words = np.frombuffer(self._map, np.uint32, count=size // 4, offset=base - start)

    def read(self, off):
        return int(self.words[off >> 2])

    def write(self, off, value):
        self.words[off >> 2] = value & 0xFFFFFFFF

    def close(self):
        self.words = None          # drop the NumPy view first, or mmap refuses to close
        self._map.close()


class AxiDmaSimple:
    """Register-level AXI DMA driver for one flow at a time.

    ``regs`` has ``read(off)`` and ``write(off, value)``. ``buf.words`` is a uint32
    view of one uncached page whose physical address is ``buf_phys``. The tests
    run this class against a fake DMA on the PC.
    """

    def __init__(self, regs, buf, buf_phys, timeout=1.0):
        self.r, self.buf, self.phys, self.timeout = regs, buf, buf_phys, timeout

    def reset(self):
        """Soft-reset both channels and start them. Also clears an error halt."""
        self.r.write(MM2S_DMACR, CR_RESET)
        deadline = time.monotonic() + self.timeout
        while self.r.read(MM2S_DMACR) & CR_RESET:
            if time.monotonic() > deadline:
                raise TimeoutError("AXI DMA reset did not finish. Is the PL programmed and clocked?")
        for cr, sr in ((MM2S_DMACR, MM2S_DMASR), (S2MM_DMACR, S2MM_DMASR)):
            self.r.write(cr, CR_RUN)
            while self.r.read(sr) & SR_HALTED:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"AXI DMA channel at 0x{cr:02X} stays halted after start")

    def _wait(self, sr_off, what):
        deadline = time.monotonic() + self.timeout
        while True:
            sr = self.r.read(sr_off)
            if sr & SR_ERRORS:
                kinds = [n for bit, n in ((SR_INT_ERR, "internal"), (SR_SLV_ERR, "slave"),
                                          (SR_DEC_ERR, "decode")) if sr & bit]
                raise RuntimeError(
                    f"DMA {what} error (DMASR 0x{sr:08X}: {', '.join(kinds)}). A decode error means "
                    "the buffer address is outside DDR. Call reset() before the next transfer.")
            if sr & SR_IOC_IRQ:
                return
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"DMA {what} did not finish within {self.timeout}s (DMASR 0x{sr:08X}). The core "
                    "drops frames with a bad TLAST or byte mask and then returns no score. "
                    "Call reset() before the next transfer.")

    def transfer(self, codes):
        """Send 8 int32 codes, return the uint64 score."""
        w = self.buf.words
        # One 32-bit store per word: this memory is uncached, and wide or
        # unaligned copies to it can fault on the Cortex-A9.
        for i, v in enumerate(np.asarray(codes, np.int32).view(np.uint32).tolist()):
            w[IN_OFF // 4 + i] = v
        r = self.r
        r.write(S2MM_DMASR, SR_IOC_IRQ | SR_ERR_IRQ)   # clear the last completion
        r.write(MM2S_DMASR, SR_IOC_IRQ | SR_ERR_IRQ)
        r.write(S2MM_DA, self.phys + OUT_OFF)
        r.write(S2MM_LENGTH, 8)                        # arm the receive first
        r.write(MM2S_SA, self.phys + IN_OFF)
        r.write(MM2S_LENGTH, 32)                       # writing LENGTH starts the send
        self._wait(MM2S_DMASR, "send")
        self._wait(S2MM_DMASR, "receive")
        return int(w[OUT_OFF // 4]) | (int(w[OUT_OFF // 4 + 1]) << 32)


class DevMemScorer:
    """deep_svdd_axis without PYNQ: FPGA manager + /dev/mem. Run as root."""

    def __init__(self, bitfile=DEFAULT_OVERLAY, buf_addr=DEFAULT_BUF_ADDR, timeout=1.0, download=True,
                 fclk_mhz=FCLK0_MHZ, ps_clk_mhz=ZED_PS_CLK_MHZ):
        bitfile = _check_files(bitfile)
        base, _ = dma_registers(bitfile.with_suffix(".hwh"))
        check_reserved(buf_addr, mmap.PAGESIZE)
        self._fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
        self._regs = self._buf = None
        slcr = _MMIO(self._fd, SLCR_BASE, 0x1000)
        try:
            self.loader = "already loaded"
            if download:
                if fclk_mhz:
                    set_fclk0(slcr, fclk_mhz, ps_clk_mhz)   # before loading, so the PL starts on a steady clock
                self.loader = program_pl(bitfile)
            self.fixed = enable_pl_interface(slcr)
            self.fclk_mhz = fclk0_mhz(slcr, ps_clk_mhz)
        finally:
            slcr.close()
        self._regs = _MMIO(self._fd, base, 0x100)
        self._buf = _MMIO(self._fd, buf_addr, mmap.PAGESIZE)
        self.dma = AxiDmaSimple(self._regs, self._buf, buf_addr, timeout)
        self.dma.reset()
        self.info = (f"devmem driver: bitstream via {self.loader}, DMA registers at 0x{base:08X}, "
                     f"buffer at 0x{buf_addr:08X}, FCLK0 {self.fclk_mhz:.2f} MHz")
        if self.fixed:
            self.info += " (fixed: " + "; ".join(self.fixed) + ")"

    def score_one(self, codes):
        """Score one flow: 8 int32 Q24 codes in, uint64 score code out."""
        return self.dma.transfer(codes)

    def score(self, codes):
        """Score codes of shape (N, 8). Returns uint64 score codes."""
        return _score_rows(self.score_one, codes)

    def reset(self):
        self.dma.reset()

    def close(self):
        for m in (self._regs, self._buf):
            if m is not None:
                m.close()
        self._regs = self._buf = None
        os.close(self._fd)


# ----------------------------------------------------------------- PYNQ
class PynqScorer:
    """deep_svdd_axis through the PYNQ library (PYNQ SD image on the ZedBoard)."""

    def __init__(self, bitfile=DEFAULT_OVERLAY, dma_name=None, timeout=1.0, download=True,
                 fclk_mhz=FCLK0_MHZ, ps_clk_mhz=ZED_PS_CLK_MHZ):
        import pynq                      # only available on a PYNQ image
        try:
            from pynq import allocate    # PYNQ 2.4 and later
        except ImportError:              # PYNQ 2.3 and earlier
            xlnk = pynq.Xlnk()

            def allocate(shape, dtype):
                return xlnk.cma_array(shape=shape, dtype=dtype)

        bitfile = _check_files(bitfile)
        self.overlay = pynq.Overlay(str(bitfile), download=download)
        if dma_name is None:
            names = [n for n in self.overlay.ip_dict if "axi_dma" in n]
            if not names:
                raise RuntimeError(f"no AXI DMA in overlay; IPs: {list(self.overlay.ip_dict)}")
            dma_name = names[0]
        self.dma = getattr(self.overlay, dma_name)
        self.timeout = timeout
        self._in = allocate(shape=(8,), dtype=np.int32)
        self._out = allocate(shape=(1,), dtype=np.uint64)

        # PYNQ works out the PL clocks assuming a 50 MHz PS_CLK (true on the
        # PYNQ-Z1/Z2). The ZedBoard has 33.3 MHz, so a stock PYNQ ends up with
        # FCLK0 at about 2/3 of what the .hwh asks for. Slower is safe, but set
        # it straight from the real PLL registers anyway.
        self.fclk_mhz = None
        if fclk_mhz and download:
            fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
            slcr = _MMIO(fd, SLCR_BASE, 0x1000)
            try:
                set_fclk0(slcr, fclk_mhz, ps_clk_mhz)
                self.fclk_mhz = fclk0_mhz(slcr, ps_clk_mhz)
            finally:
                slcr.close()
                os.close(fd)
        clock = f", FCLK0 {self.fclk_mhz:.2f} MHz" if self.fclk_mhz else ""
        self.info = f"pynq driver: IPs {list(self.overlay.ip_dict)}{clock}"

    def _wait(self, channel, what):
        # PYNQ's wait() blocks forever if no score comes back, so poll with a
        # deadline first. Once the channel is idle (or in error), wait() returns
        # at once, raises on DMA errors, and invalidates the receive buffer's cache.
        deadline = time.monotonic() + self.timeout
        while not (channel.idle or getattr(channel, "error", False)):
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"DMA {what} did not finish within {self.timeout}s. The core drops frames "
                    "with a bad TLAST or byte mask and then returns no score. Reload the "
                    "overlay (FpgaScorer(download=True)) to reset the DMA.")
        channel.wait()

    def score_one(self, codes):
        """Score one flow: 8 int32 Q24 codes in, uint64 score code out."""
        self._in[:] = codes
        recv, send = self.dma.recvchannel, self.dma.sendchannel
        recv.transfer(self._out)   # arm S2MM first so the score has somewhere to go
        send.transfer(self._in)    # flushes the buffer, then streams 8 beats with TLAST on the last
        self._wait(send, "send")
        self._wait(recv, "receive")
        return int(self._out[0])

    def score(self, codes):
        """Score codes of shape (N, 8). Returns uint64 score codes."""
        return _score_rows(self.score_one, codes)

    def close(self):
        self._in.freebuffer()
        self._out.freebuffer()
