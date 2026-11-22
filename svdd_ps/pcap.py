"""Packet sources (PCAP files, live capture) and a minimal IPv4 header parser.

Pure Python with no third-party packages, so it runs unchanged on the ZedBoard
ARM cores. Only the header fields the extractor needs are decoded.
"""
import socket
import struct
import time

# Link-layer header types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_LINUX_SLL2 = 276
_RAW_ALIASES = (12, 14)  # some platforms write raw IP with these DLT values

ETHERTYPE_IPV4 = 0x0800
_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

_U16 = struct.Struct(">H")
_IPV4 = struct.Struct(">BBHHHBBH4s4s")     # 20-byte IPv4 header
_TCP = struct.Struct(">HHIIBBH")           # ports, seq, ack, offset, flags, window
_PORTS = struct.Struct(">HH")

# pcap magic -> (byte order, timestamp divisor to get microseconds)
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1),      # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1),      # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1000),   # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1000),   # big-endian, nanoseconds
}


class PcapReader:
    """Stream packets from a classic libpcap file without loading it into memory.

    Iterating yields ``(timestamp_us, linktype, frame_bytes)``.
    """

    def __init__(self, path):
        self.path = str(path)
        self._f = open(self.path, "rb", buffering=1 << 20)
        header = self._f.read(24)
        if len(header) < 24:
            raise ValueError(f"{self.path}: too short to be a pcap file")
        magic = header[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError(f"{self.path}: pcapng is not supported; convert it with "
                             "'editcap -F pcap in.pcapng out.pcap'")
        if magic not in _MAGIC:
            raise ValueError(f"{self.path}: not a pcap file (magic {magic.hex()})")
        order, self._ts_div = _MAGIC[magic]
        _, _, _, _, self.snaplen, self.linktype = struct.unpack(order + "HHiIII", header[4:])
        self.global_header = header
        self._rec = struct.Struct(order + "IIII")

    def records(self):
        """Yield ``(record_header_bytes, frame_bytes)`` exactly as stored (for slicing)."""
        read = self._f.read
        size = self._rec.size
        while True:
            h = read(size)
            if len(h) < size:
                return
            caplen = self._rec.unpack(h)[2]
            data = read(caplen)
            if len(data) < caplen:
                return  # truncated final record
            yield h, data

    def __iter__(self):
        read = self._f.read
        unpack = self._rec.unpack
        size = self._rec.size
        div = self._ts_div
        lt = self.linktype
        while True:
            h = read(size)
            if len(h) < size:
                return
            sec, frac, caplen, _ = unpack(h)
            data = read(caplen)
            if len(data) < caplen:
                return
            yield sec * 1_000_000 + frac // div, lt, data

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def write_pcap_slice(src, dst, max_packets=None, max_seconds=None):
    """Copy the first packets of ``src`` into a new pcap file ``dst``.

    Stops after ``max_packets`` packets or ``max_seconds`` of capture time,
    whichever comes first. Returns the number of packets written.
    """
    n = 0
    first = None
    with PcapReader(src) as r, open(dst, "wb") as out:
        out.write(r.global_header)
        for h, data in r.records():
            if max_packets is not None and n >= max_packets:
                break
            if max_seconds is not None:
                sec = r._rec.unpack(h)[0]
                if first is None:
                    first = sec
                if sec - first >= max_seconds:
                    break
            out.write(h)
            out.write(data)
            n += 1
    return n


def _now_us():
    # time.time_ns() needs Python 3.7; a double still holds microseconds exactly today.
    return int(time.time() * 1_000_000)


class LiveCapture:
    """Capture Ethernet frames from a Linux interface (needs root, e.g. on the ZedBoard).

    Iterating yields ``(timestamp_us, LINKTYPE_ETHERNET, frame_bytes)``. When no
    packet arrives within ``tick`` seconds it yields ``(now_us, None, None)`` so
    the caller can still expire idle flows.
    """

    def __init__(self, iface, snaplen=256, tick=0.5):
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("live capture needs Linux AF_PACKET sockets")
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.bind((iface, 0))
        self.sock.settimeout(tick)
        self.snaplen = snaplen  # headers only: the IP Total Length field gives the real size

    def __iter__(self):
        recv = self.sock.recv
        snap = self.snaplen
        while True:
            try:
                data = recv(snap)
            except socket.timeout:
                yield _now_us(), None, None
                continue
            yield _now_us(), LINKTYPE_ETHERNET, data

    def close(self):
        self.sock.close()


def ip_offset(linktype, data):
    """Return the offset of the IPv4 header in a frame, or -1 if it is not IPv4."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return -1
        et = _U16.unpack_from(data, 12)[0]
        off = 14
        while et in _VLAN_TYPES and len(data) >= off + 4:
            et = _U16.unpack_from(data, off + 2)[0]
            off += 4
        return off if et == ETHERTYPE_IPV4 else -1
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return -1
        return 16 if _U16.unpack_from(data, 14)[0] == ETHERTYPE_IPV4 else -1
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return -1
        return 20 if _U16.unpack_from(data, 0)[0] == ETHERTYPE_IPV4 else -1
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4) or linktype in _RAW_ALIASES:
        return 0 if data and data[0] >> 4 == 4 else -1
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return -1
        family = int.from_bytes(data[:4], "little")
        if family > 0xFFFF:  # written on a big-endian host
            family = int.from_bytes(data[:4], "big")
        return 4 if family == socket.AF_INET else -1
    raise ValueError(f"unsupported pcap link type {linktype}")


def parse_ipv4(data, off):
    """Decode the fields the flow extractor needs from an IPv4 packet.

    Returns ``(src, dst, proto, sport, dport, ttl, ip_total_length, tcp_window, tcp_flags)``
    or ``None``. ``src``/``dst`` are 4-byte strings. ``tcp_window`` is the raw,
    unscaled 16-bit field, or -1 when the packet has no complete TCP header.

    Ports are 0 for protocols without ports, for non-first fragments, and for
    ICMP. Giving ICMP no ports pairs echo requests with their replies in one
    bidirectional flow (keyed on the address pair).
    """
    if len(data) < off + 20:
        return None
    vihl, _, total_len, _, frag, ttl, proto, _, src, dst = _IPV4.unpack_from(data, off)
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20:
        return None
    l4 = off + ihl
    sport = dport = flags = 0
    win = -1
    if frag & 0x1FFF == 0:  # only the first fragment carries the L4 header
        if proto == 6:
            if len(data) >= l4 + 16:
                sport, dport, _, _, _, flags, win = _TCP.unpack_from(data, l4)
        elif proto == 17 or proto == 132:  # UDP, SCTP
            if len(data) >= l4 + 4:
                sport, dport = _PORTS.unpack_from(data, l4)
    return src, dst, proto, sport, dport, ttl, total_len, win, flags
