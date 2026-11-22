"""PS -> PL input: pcap bytes in chunks, each with a 32-byte header (see hls/svdd_pl.hpp).

The PS does no per-packet work for pcap files: it reads the file in big pieces,
puts a header in front, and the PL parses the records itself. A record may be
split across two chunks; the PL carries on where it stopped.
"""
import os
import struct
from collections import namedtuple

MAGIC = 0x4C505653          # "SVPL"
VERSION = 1
HEADER_BYTES = 32
DEFAULT_CHUNK = 1 << 20     # 1 MB of pcap data per DMA transfer

F_RESET = 0x01
F_NEW_FILE = 0x02
F_FLUSH = 0x04
F_TICK = 0x08
F_NS = 0x10
F_BIG_ENDIAN = 0x20
F_TTL_BOTH = 0x40
F_NO_FIN_RST = 0x80

SUPPORTED_LINKTYPES = {0: "BSD loopback", 1: "Ethernet", 12: "raw IP", 14: "raw IP", 101: "raw IP",
                       113: "Linux cooked (SLL)", 228: "raw IPv4", 276: "Linux cooked v2 (SLL2)"}

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 0),
    b"\xa1\xb2\xc3\xd4": (">", F_BIG_ENDIAN),
    b"\x4d\x3c\xb2\xa1": ("<", F_NS),
    b"\xa1\xb2\x3c\x4d": (">", F_NS | F_BIG_ENDIAN),
}


class Settings(namedtuple("Settings", "idle active tcp_close close_on_fin_rst ttl_both")):
    """Flow expiry settings, the same as svdd_ps.FlowExtractor's arguments (seconds)."""

    def flags(self):
        return (F_TTL_BOTH if self.ttl_both else 0) | (0 if self.close_on_fin_rst else F_NO_FIN_RST)

    def micros(self):
        out = []
        for name in ("idle", "active", "tcp_close"):
            us = int(getattr(self, name) * 1000000)   # flows.py does int(seconds * 1_000_000)
            if not 0 <= us < 1 << 32:
                raise ValueError("--%s must be between 0 and 4294 seconds" % name.replace("_", "-"))
            out.append(us)
        return out


DEFAULT_SETTINGS = Settings(30.0, 120.0, 1.0, True, False)


def chunk_header(flags, linktype, data_bytes, settings=DEFAULT_SETTINGS, now_us=0):
    idle_us, active_us, close_us = settings.micros()
    w0 = MAGIC | (VERSION << 32) | ((flags | settings.flags()) << 40) | (linktype << 48)
    return struct.pack("<QQQQ", w0, data_bytes | (close_us << 32), idle_us | (active_us << 32), now_us)


def make_chunk(flags, linktype, data, settings=DEFAULT_SETTINGS, now_us=0):
    """Header + data, padded to whole 8-byte beats (the PL ignores the padding)."""
    pad = (-len(data)) % 8
    return chunk_header(flags, linktype, len(data), settings, now_us) + bytes(data) + b"\0" * pad


def pcap_format(path):
    """(format flags, link type) of a classic pcap file; raises for anything the PL can't read."""
    with open(str(path), "rb") as f:
        header = f.read(24)
    if len(header) < 24:
        raise ValueError("%s: too short to be a pcap file" % path)
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        raise ValueError("%s: pcapng is not supported; convert it with "
                         "'editcap -F pcap in.pcapng out.pcap'" % path)
    if header[:4] not in _PCAP_MAGIC:
        raise ValueError("%s: not a pcap file (magic %s)" % (path, header[:4].hex()))
    order, flags = _PCAP_MAGIC[header[:4]]
    linktype = struct.unpack(order + "I", header[20:24])[0]
    if linktype not in SUPPORTED_LINKTYPES:
        raise ValueError("%s: link type %d is not supported by the PL parser" % (path, linktype))
    return flags, linktype


def pcap_chunks(paths, settings=DEFAULT_SETTINGS, chunk_bytes=DEFAULT_CHUNK, reset=True, flush=True):
    """Chunks for several pcap files read back to back as one capture.

    The first chunk resets the PL, the first chunk of each file restarts the
    record parser, and the last chunk flushes the flow table.
    """
    paths = [str(p) for p in paths]
    formats = [pcap_format(p) for p in paths]       # check every file before sending anything
    first = True
    for i, (path, (fmt, linktype)) in enumerate(zip(paths, formats)):
        left = os.path.getsize(path) - 24
        new_file = True
        with open(path, "rb") as f:
            f.seek(24)
            while True:
                data = f.read(min(chunk_bytes, left)) if left > 0 else b""
                left -= len(data)
                flags = fmt
                if first and reset:
                    flags |= F_RESET
                if new_file:
                    flags |= F_NEW_FILE
                if left <= 0 and i == len(paths) - 1 and flush:
                    flags |= F_FLUSH
                yield make_chunk(flags, linktype, data, settings)
                first = new_file = False
                if left <= 0:
                    break


class LiveChunker:
    """Pack live Ethernet frames into pcap records and cut a chunk every ``period`` seconds.

    The only per-packet work on the PS: append a 16-byte record header and the
    first ``snaplen`` bytes of the frame. Every chunk carries F_TICK with the
    current time, so idle flows expire even when no packets arrive.
    """

    def __init__(self, settings=DEFAULT_SETTINGS, max_bytes=DEFAULT_CHUNK - 4096):
        self.settings = settings
        self.max_bytes = max_bytes
        self.buf = bytearray()
        self.first = True
        self._rec = struct.Struct("<IIII")

    def add(self, ts_us, frame):
        self.buf += self._rec.pack(ts_us // 1000000, ts_us % 1000000, len(frame), len(frame))
        self.buf += frame
        return len(self.buf) >= self.max_bytes

    def chunk(self, now_us, flush=False):
        flags = F_TICK | (F_RESET | F_NEW_FILE if self.first else 0) | (F_FLUSH if flush else 0)
        self.first = False
        data, self.buf = bytes(self.buf), bytearray()
        return make_chunk(flags, 1, data, self.settings, now_us)


def write_stream_file(chunks, path):
    """Save chunks as [uint32 length][chunk]... for the C testbench (hls/tb_svdd_pl.cpp)."""
    n = 0
    with open(str(path), "wb") as f:
        for c in chunks:
            f.write(struct.pack("<I", len(c)))
            f.write(c)
            n += 1
    return n
