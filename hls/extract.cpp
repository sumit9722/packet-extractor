// svdd_flow_extract: the feature extraction IP (see svdd_pl.hpp for the stream formats).
//
// Reference behaviour: ../svdd_ps (pcap.py, flows.py). The comments name the Python
// lines each rule copies.
#include "svdd_pl.hpp"

namespace svpl {

// =====================================================================================
// Stage 1: parse. Walks the pcap record stream one byte per clock and pulls out the
// header fields that svdd_ps/pcap.py ip_offset() and parse_ipv4() read. Bytes past
// CAP are skipped up to 8 per clock.
// =====================================================================================
namespace {

enum Link { LINK_UNKNOWN = 0, LINK_IPV4 = 1, LINK_OTHER = 2 };

struct frame_t {
    ap_uint<32> sec, frac;                // record timestamp, as stored
    ap_uint<32> caplen, remain;           // frame length, bytes still to come
    ap_uint<8> p;                         // bytes examined so far (stops at CAP)
    ap_uint<2> link;                      // ip_offset() verdict so far
    bool cap_on;                          // IPv4 header capture armed at ip_off
    ap_uint<8> ip_off, et_pos, hold0, hold1, hold2;
    ap_uint<4> version;
    ap_uint<8> ihl;                       // IPv4 header length in bytes (255 = not seen yet)
    ap_uint<16> total_len, frag, sport, dport, win;
    ap_uint<8> ttl, proto, tcp_flags;
    ap_uint<32> src, dst;
};

bool is_raw(ap_uint<16> lt) {
    return lt == LT_RAW || lt == LT_IPV4 || lt == LT_RAW_ALT1 || lt == LT_RAW_ALT2;
}

ap_uint<32> swap32(ap_uint<32> x) { return (x(7, 0), x(15, 8), x(23, 16), x(31, 24)); }

void start_frame(frame_t& f, ap_uint<16> lt, ap_uint<32> sec, ap_uint<32> frac, ap_uint<32> caplen) {
    f.sec = sec;
    f.frac = frac;
    f.caplen = caplen;
    f.remain = caplen;
    f.p = 0;
    f.et_pos = 12;                        // Ethernet: first EtherType at bytes 12-13
    f.ihl = 255;
    f.version = 0;
    f.cap_on = false;
    f.ip_off = 0;
    f.link = LINK_UNKNOWN;
    if (is_raw(lt)) {
        f.cap_on = true;                  // IPv4 at offset 0 if byte 0 says version 4
    } else if (lt != LT_ETHERNET && lt != LT_LINUX_SLL && lt != LT_LINUX_SLL2 && lt != LT_NULL) {
        f.link = LINK_OTHER;
    }
}

void frame_byte(frame_t& f, ap_uint<8> b, ap_uint<16> lt) {
    const ap_uint<8> p = f.p;             // < CAP here

    // ---- link layer: pcap.py ip_offset()
    if (f.link == LINK_UNKNOWN) {
        if (lt == LT_ETHERNET) {
            if (p == f.et_pos) {
                f.hold0 = b;
            } else if (p == f.et_pos + 1) {
                const ap_uint<16> et = (f.hold0, b);
                const ap_uint<8> off = f.et_pos + 2;
                if (et == 0x0800) {
                    f.link = LINK_IPV4;
                    f.ip_off = off;
                    f.cap_on = true;
                } else if ((et == 0x8100 || et == 0x88A8 || et == 0x9100) && f.remain >= 5) {
                    // VLAN tag and caplen >= off + 4 (remain = caplen - p, off = p + 1):
                    // the next EtherType follows the tag
                    f.et_pos = off + 2;
                } else {
                    f.link = LINK_OTHER;
                }
            }
        } else if (lt == LT_LINUX_SLL) {
            if (p == 14) {
                f.hold0 = b;
            } else if (p == 15) {
                if ((f.hold0, b) == 0x0800) {
                    f.link = LINK_IPV4;
                    f.ip_off = 16;
                    f.cap_on = true;
                } else {
                    f.link = LINK_OTHER;
                }
            }
        } else if (lt == LT_LINUX_SLL2) {
            if (p == 0) {
                f.hold0 = b;
            } else if (p == 1) {
                if (f.caplen >= 20 && (f.hold0, b) == 0x0800) {
                    f.link = LINK_IPV4;
                    f.ip_off = 20;
                    f.cap_on = true;
                } else {
                    f.link = LINK_OTHER;
                }
            }
        } else if (is_raw(lt)) {
            if (p == 0) f.link = (b(7, 4) == 4) ? LINK_IPV4 : LINK_OTHER;
        } else if (lt == LT_NULL) {
            if (p == 0) {
                f.hold0 = b;
            } else if (p == 1) {
                f.hold1 = b;
            } else if (p == 2) {
                f.hold2 = b;
            } else if (p == 3) {
                const ap_uint<32> le = (b, f.hold2, f.hold1, f.hold0);
                const ap_uint<32> family = (le > 0xFFFF) ? ap_uint<32>((f.hold0, f.hold1, f.hold2, b)) : le;
                if (family == 2) {        // AF_INET
                    f.link = LINK_IPV4;
                    f.ip_off = 4;
                    f.cap_on = true;
                } else {
                    f.link = LINK_OTHER;
                }
            }
        }
    }

    // ---- IPv4 and L4 header fields: pcap.py parse_ipv4()
    if (f.cap_on && p >= f.ip_off) {
        const ap_uint<8> q = p - f.ip_off;
        if (q == 0) {
            f.version = b(7, 4);
            f.ihl = ap_uint<8>(b(3, 0)) * 4;
        }
        if (q == 2) f.total_len(15, 8) = b;
        if (q == 3) f.total_len(7, 0) = b;
        if (q == 6) f.frag(15, 8) = b;
        if (q == 7) f.frag(7, 0) = b;
        if (q == 8) f.ttl = b;
        if (q == 9) f.proto = b;
        if (q >= 12 && q < 16) f.src = (f.src(23, 0), b);
        if (q >= 16 && q < 20) f.dst = (f.dst(23, 0), b);
        if (q >= f.ihl) {                 // L4 header: ports, TCP flags and window
            const ap_uint<8> r = q - f.ihl;
            if (r == 0) f.sport(15, 8) = b;
            if (r == 1) f.sport(7, 0) = b;
            if (r == 2) f.dport(15, 8) = b;
            if (r == 3) f.dport(7, 0) = b;
            if (r == 13) f.tcp_flags = b;
            if (r == 14) f.win(15, 8) = b;
            if (r == 15) f.win(7, 0) = b;
        }
    }
}

void finish_frame(const frame_t& f, bool ns, parse_stats_t& st, hls::stream<pkt_tok_t>& out) {
    pkt_tok_t t = {};
    // pcap.py PcapReader: sec * 1_000_000 + frac // div
    t.ts = ap_uint<64>(f.sec) * 1000000 + (ns ? ap_uint<32>(f.frac / 1000) : f.frac);
    t.kind = T_OTHER;
    st.frames++;
    if (f.link != LINK_IPV4) {
        st.non_ipv4++;                    // ip_offset() < 0
    } else if (f.caplen < ap_uint<33>(f.ip_off) + 20 || f.version != 4 || f.ihl < 20) {
        st.malformed++;                   // parse_ipv4() returned None
    } else {
        const ap_uint<10> l4 = ap_uint<10>(f.ip_off) + f.ihl;
        const bool first_frag = f.frag(12, 0) == 0;
        const bool tcp = first_frag && f.proto == 6 && f.caplen >= ap_uint<33>(l4) + 16;
        const bool ports = first_frag && (f.proto == 17 || f.proto == 132) && f.caplen >= ap_uint<33>(l4) + 4;
        const ap_uint<11> need = tcp ? ap_uint<11>(l4 + 16) : ports ? ap_uint<11>(l4 + 4)
                                                                    : ap_uint<11>(f.ip_off + 20);
        if (need > CAP) {
            st.malformed++;               // headers deeper than this design looks (many VLAN tags)
            st.deep++;
        } else {
            st.ipv4++;
            t.kind = T_PKT;
            t.src = f.src;
            t.dst = f.dst;
            t.proto = f.proto;
            t.ttl = f.ttl;
            t.len = f.total_len;
            t.has_win = tcp;
            if (tcp || ports) {
                t.sport = f.sport;
                t.dport = f.dport;
            }
            if (tcp) {
                t.tcp_flags = f.tcp_flags;
                t.win = f.win;
            }
        }
    }
    out.write(t);
}

pkt_tok_t control(ap_uint<3> kind) {
    pkt_tok_t t = {};
    t.kind = kind;
    return t;
}

}  // namespace

void parse(hls::stream<beat_t>& in, hls::stream<pkt_tok_t>& out) {
    // Parser state survives between chunks: a record may continue in the next chunk.
    static frame_t f;
    static bool in_frame = false;
    static ap_uint<4> hdr_n = 0;
    static ap_uint<128> hdr = 0;
    static parse_stats_t st;

    // ---- chunk header
    ap_uint<64> w[HEADER_BEATS];
    bool last = false;
    int got = 0;
header:
    for (int i = 0; i < HEADER_BEATS; i++) {
        w[i] = 0;
        if (!last) {
            const beat_t b = in.read();
            w[i] = b.data;
            last = b.last;
            got++;
        }
    }
    st.errors = 0;
    const ap_uint<8> flags = w[0](47, 40);
    const ap_uint<16> lt = w[0](63, 48);
    const bool ns = flags & F_NS;
    const bool be = flags & F_BIG_ENDIAN;
    if (got != HEADER_BEATS || w[0](31, 0) != MAGIC || w[0](39, 32) != VERSION) {
        st.errors = st.errors | ap_uint<8>(E_MAGIC);             // not one of our chunks: skip it whole
    drain_bad:
        while (!last) last = in.read().last;
        pkt_tok_t m = control(T_MARKER);
        m.st = st;
        out.write(m);
        return;
    }
    if (flags & F_RESET) {
        st = parse_stats_t();
        st.errors = 0;
        in_frame = false;
        hdr_n = 0;
        out.write(control(T_RESET));
    }
    st.chunks++;
    pkt_tok_t cfg = control(T_CONFIG);
    cfg.ts = w[1](63, 32);                // TCP close timeout
    cfg.src = w[2](31, 0);                // idle timeout
    cfg.dst = w[2](63, 32);               // active timeout
    cfg.tcp_flags = flags;
    out.write(cfg);
    if (flags & F_NEW_FILE) {             // a record cut off at the end of the last file is dropped,
        in_frame = false;                 // like PcapReader does with a truncated final record
        hdr_n = 0;
    }

    // ---- chunk data
    // One byte per clock while inside a record header or the first CAP bytes of a frame;
    // the rest of the frame is skipped a whole beat at a time. To meet 100 MHz no long
    // chain of 32-bit compares may sit in one clock: both possible counter updates are
    // computed side by side, and a finished frame's token is written one clock later.
    ap_uint<32> left = w[1](31, 0);       // chunk data bytes not yet consumed
    ap_uint<64> word = 0;
    ap_uint<3> idx = 0;                   // next byte of `word`
    ap_uint<4> avail = 8;                 // bytes of `word` from idx on (kept as a register)
    bool need = true;                     // `word` is used up: read the next beat first
    bool pending = false;                 // a frame ended last clock: emit its token now
data:
    while (left != 0) {
#pragma HLS PIPELINE II=1
        if (pending) {
            finish_frame(f, ns, st, out);
            pending = false;
        }
        if (need) {                       // idx and avail are already 0 and 8 here
            if (last) {
                st.errors = st.errors | ap_uint<8>(E_SHORT);     // TLAST before the declared length
                break;
            }
            const beat_t b = in.read();
            word = b.data;
            last = b.last;
        }
        ap_uint<8> bytes[8];
#pragma HLS ARRAY_PARTITION variable=bytes complete
        for (int k = 0; k < 8; k++) bytes[k] = word(8 * k + 7, 8 * k);
        const ap_uint<8> byte = bytes[idx];
        const ap_int<34> rem_all = ap_int<34>(f.remain) - avail;
        const ap_int<34> left_all = ap_int<34>(left) - avail;
        const bool skip_all = in_frame && f.p == CAP && rem_all >= 0 && left_all >= 0;
        if (!in_frame) {
            hdr = (byte, hdr(127, 8));    // 16-byte record header, first byte ends up in [7:0]
            if (hdr_n == 15) {
                ap_uint<32> sec = hdr(31, 0), frac = hdr(63, 32), caplen = hdr(95, 64);
                if (be) {
                    sec = swap32(sec);
                    frac = swap32(frac);
                    caplen = swap32(caplen);
                }
                start_frame(f, lt, sec, frac, caplen);
                if (caplen == 0) pending = true;
                else in_frame = true;
                hdr_n = 0;
            } else {
                hdr_n++;
            }
        } else {
            if (f.p != CAP) {
                frame_byte(f, byte, lt);
                f.p++;
            }
            const bool end = skip_all ? rem_all == 0 : f.remain == 1;
            f.remain = skip_all ? ap_uint<32>(rem_all) : ap_uint<32>(f.remain - 1);
            if (end) {
                pending = true;
                in_frame = false;
            }
        }
        need = skip_all || idx == 7;
        idx = skip_all ? ap_uint<3>(0) : ap_uint<3>(idx + 1);
        avail = (skip_all || avail == 1) ? ap_uint<4>(8) : ap_uint<4>(avail - 1);
        left = skip_all ? ap_uint<32>(left_all) : ap_uint<32>(left - 1);
    }
    if (pending) finish_frame(f, ns, st, out);
    if (!last) {
        st.errors = st.errors | ap_uint<8>(E_LONG);              // more beats than declared: skip to TLAST
    drain_long:
        while (!last) last = in.read().last;
    }
    if (flags & F_TICK) {
        pkt_tok_t t = control(T_TICK);
        t.ts = w[3];
        out.write(t);
    }
    if (flags & F_FLUSH) out.write(control(T_FLUSH));
    pkt_tok_t m = control(T_MARKER);
    m.st = st;
    out.write(m);
}

// =====================================================================================
// Stage 2: flow table. Same rules as svdd_ps/flows.py FlowExtractor, with one change in
// *when* flows leave the table (not *which* packets they contain):
//
// Python calls expire(now) after every frame and removes timed-out flows at once. The
// hardware does it lazily: when a packet finds its flow, it first asks "would expire()
// at the previous frame have removed this flow?" and if so exports it then. A scan
// pointer also visits one set after every frame (and all sets on a TICK) to export
// flows that never see another packet. Exported records come out in a different order
// than in Python; their contents are the same.
// =====================================================================================
namespace {

struct entry_t {
    bool valid;
    ap_uint<32> src, dst;                 // src = sender of the flow's first packet
    ap_uint<16> sport, dport;
    ap_uint<8> proto;
    ap_uint<64> first, last;
    ap_uint<32> in_pkts, out_pkts;
    ap_uint<48> in_bytes, out_bytes;
    ap_uint<8> min_ttl;
    ap_uint<16> max_len, min_len, win_in, win_out;
    bool fin_in, fin_out, closing;
    ap_uint<48> deadline;                 // expire() removes the flow once now > deadline
};

struct flow_cfg_t {
    ap_uint<32> idle_us, active_us, close_us;
    bool ttl_both, fin_rst;
    bool close_first;                     // close_us < idle_us, worked out once per chunk
};

ap_uint<SET_BITS> set_of(ap_uint<32> src, ap_uint<32> dst, ap_uint<16> sport, ap_uint<16> dport,
                         ap_uint<8> proto) {
    // Order the two endpoints so both directions of a flow land in the same set.
    const ap_uint<48> a = (src, sport), b = (dst, dport);
    const ap_uint<48> lo = (a < b) ? a : b;
    const ap_uint<48> hi = (a < b) ? b : a;
    const ap_uint<32> hip = hi(47, 16);
    ap_uint<32> k = lo(47, 16) ^ ((hip << 7) | (hip >> 25)) ^ ap_uint<32>((lo(15, 0), hi(15, 0))) ^ proto;
    k ^= k >> 16;
    k = k * ap_uint<32>(0x045d9f3b);
    k ^= k >> 16;
    return k(SET_BITS - 1, 0);
}

// Time comparisons use the low 48 bits of the microsecond timestamps with wrap-around
// arithmetic: the same answers as Python's integers while times differ by less than
// 2^47 us (4.4 years), with much shorter carry chains than 64/66-bit maths.
typedef ap_uint<48> t48_t;

// now - then > limit
bool older(ap_uint<64> now, ap_uint<64> then, ap_uint<32> limit) {
    const t48_t d = now(47, 0) - then(47, 0);
    return !d[47] && d > limit;
}

// Would FlowExtractor.expire(now) remove this flow? A torn-down TCP flow goes after
// close_us ("tcp_close"), any flow after idle_us ("idle"), whichever is shorter. The
// limit is folded into e.deadline when the entry is written (set_deadline), so this
// is one 48-bit comparison: now - deadline > 0.
bool expired(const entry_t& e, ap_uint<64> now, const flow_cfg_t& c) {
    const t48_t d = now(47, 0) - e.deadline;
    return !d[47] && d != 0;
}

ap_uint<3> expiry_reason(const entry_t& e, const flow_cfg_t& c) {
    return (e.closing && c.close_first) ? ap_uint<3>(R_TCP_CLOSE) : ap_uint<3>(R_IDLE);
}

void set_deadline(entry_t& e, const flow_cfg_t& c) {
    e.deadline = e.last(47, 0) + t48_t((e.closing && c.close_first) ? c.close_us : c.idle_us);
}

void emit(hls::stream<flow_tok_t>& out, const entry_t& e, ap_uint<3> reason, ap_uint<32>& exported) {
#pragma HLS INLINE
    flow_tok_t t = {};
    t.marker = false;
    t.reason = reason;
    t.first = e.first;
    t.last = e.last;
    t.src = e.src;
    t.dst = e.dst;
    t.sport = e.sport;
    t.dport = e.dport;
    t.proto = e.proto;
    t.in_pkts = e.in_pkts;
    t.out_pkts = e.out_pkts;
    t.in_bytes = e.in_bytes;
    t.out_bytes = e.out_bytes;
    t.min_ttl = e.min_ttl;
    t.max_len = e.max_len;
    t.min_len = e.min_len;
    t.win_in = e.win_in;
    t.win_out = e.win_out;
    t.seq = exported;
    exported++;
    out.write(t);
}

entry_t new_flow(const pkt_tok_t& p) {   // flows.py _Flow.__init__
    entry_t e = {};
    e.valid = true;
    e.src = p.src;
    e.dst = p.dst;
    e.sport = p.sport;
    e.dport = p.dport;
    e.proto = p.proto;
    e.first = p.ts;
    e.last = p.ts;
    e.min_ttl = 255;
    e.max_len = 0;
    e.min_len = 0xFFFF;
    return e;
}

ap_uint<48> add_sat48(ap_uint<48> a, ap_uint<16> b) {   // byte counters saturate, never wrap
    const ap_uint<49> s = ap_uint<49>(a) + b;
    return s[48] ? ap_uint<48>(-1) : ap_uint<48>(s);
}

void add_packet(entry_t& e, const pkt_tok_t& p, bool forward, const flow_cfg_t& c) {
    if (p.ts > e.last) e.last = p.ts;    // flows.py FlowExtractor.packet()
    if (forward) {
        if (e.in_pkts != 0xFFFFFFFFu) e.in_pkts++;
        e.in_bytes = add_sat48(e.in_bytes, p.len);
        if (p.has_win && p.win > e.win_in) e.win_in = p.win;
        if (p.ttl < e.min_ttl) e.min_ttl = p.ttl;
    } else {
        if (e.out_pkts != 0xFFFFFFFFu) e.out_pkts++;
        e.out_bytes = add_sat48(e.out_bytes, p.len);
        if (p.has_win && p.win > e.win_out) e.win_out = p.win;
        if (c.ttl_both && p.ttl < e.min_ttl) e.min_ttl = p.ttl;
    }
    if (p.len > e.max_len) e.max_len = p.len;
    if (p.len < e.min_len) e.min_len = p.len;
    if (p.proto == 6 && (p.tcp_flags & (TCP_FIN | TCP_RST)) && c.fin_rst) {
        if (p.tcp_flags & TCP_FIN) {
            if (forward) e.fin_in = true;
            else e.fin_out = true;
        }
        if (!e.closing && ((p.tcp_flags & TCP_RST) || (e.fin_in && e.fin_out))) e.closing = true;
    }
}

}  // namespace

void flow_table(hls::stream<pkt_tok_t>& in, hls::stream<flow_tok_t>& out) {
    static entry_t table[NWAYS][NSETS];
#pragma HLS ARRAY_PARTITION variable=table dim=1 complete
#pragma HLS AGGREGATE variable=table compact=bit
#pragma HLS BIND_STORAGE variable=table type=ram_2p impl=bram
    static flow_cfg_t cfg = {30000000, 120000000, 1000000, false, true, true};
    static ap_uint<3> evict_ptr = 0;
    static ap_uint<64> prev_ts = 0;       // time of the last expire() call in Python terms
    static bool have_prev = false;
    static ap_uint<SET_BITS> scan_ptr = 0;
    static ap_uint<32> exported = 0, evicted = 0;
    static ap_uint<16> open = 0, peak = 0;

tokens:
    while (true) {
        const pkt_tok_t t = in.read();
        if (t.kind == T_MARKER) {
            flow_tok_t m = {};
            m.marker = true;
            m.st = t.st;
            m.seq = exported;
            m.evicted = evicted;
            m.open = open;
            m.peak = peak;
            out.write(m);
            break;
        }
        if (t.kind == T_CONFIG) {
            cfg.idle_us = t.src;
            cfg.active_us = t.dst;
            cfg.close_us = t.ts(31, 0);
            cfg.ttl_both = t.tcp_flags & F_TTL_BOTH;
            cfg.fin_rst = !(t.tcp_flags & F_NO_FIN_RST);
            cfg.close_first = cfg.close_us < cfg.idle_us;   // (settings are fixed for a run)
        } else if (t.kind == T_RESET) {
        clear_sets:
            for (int s = 0; s < NSETS; s++) {
            clear_ways:
                for (int w = 0; w < NWAYS; w++) {
#pragma HLS PIPELINE off
                    table[w][s].valid = false;
                }
            }
            have_prev = false;
            scan_ptr = 0;
            exported = evicted = 0;
            open = peak = 0;
        } else if (t.kind == T_FLUSH) {   // flows.py flush(): everything left is "end", except
        flush_sets:                       // flows that expire() at the last frame already took
            for (int s = 0; s < NSETS; s++) {
            flush_ways:
                for (int w = 0; w < NWAYS; w++) {
#pragma HLS PIPELINE off   // runs once per capture or tick: no need for speed
                    const entry_t e = table[w][s];
                    if (e.valid) {
                        const bool gone = have_prev && expired(e, prev_ts, cfg);
                        emit(out, e, gone ? expiry_reason(e, cfg) : ap_uint<3>(R_END), exported);
                        table[w][s].valid = false;
                    }
                }
            }
            open = 0;
        } else if (t.kind == T_TICK) {    // live capture tick: expire(now) over the whole table
        tick_sets:
            for (int s = 0; s < NSETS; s++) {
            tick_ways:
                for (int w = 0; w < NWAYS; w++) {
#pragma HLS PIPELINE off   // runs once per capture or tick: no need for speed
                    const entry_t e = table[w][s];
                    if (e.valid && expired(e, t.ts, cfg)) {
                        emit(out, e, expiry_reason(e, cfg), exported);
                        table[w][s].valid = false;
                        open--;
                    }
                }
            }
            prev_ts = t.ts;
            have_prev = true;
        } else {                          // a frame: T_PKT or T_OTHER
            if (t.kind == T_PKT) {
                const ap_uint<SET_BITS> s = set_of(t.src, t.dst, t.sport, t.dport, t.proto);
                entry_t e[NWAYS];
#pragma HLS ARRAY_PARTITION variable=e complete
                // Every check is done for all 8 ways side by side; the hit way then only
                // selects single bits. (Selecting the way first and comparing its 48-bit
                // times afterwards put everything in one long chain.)
                bool hitv[NWAYS], fwdv[NWAYS], gone_prev[NWAYS], idle_now[NWAYS], too_old[NWAYS];
#pragma HLS ARRAY_PARTITION variable=hitv complete
#pragma HLS ARRAY_PARTITION variable=fwdv complete
#pragma HLS ARRAY_PARTITION variable=gone_prev complete
#pragma HLS ARRAY_PARTITION variable=idle_now complete
#pragma HLS ARRAY_PARTITION variable=too_old complete
                int hit = -1, free_way = -1, stale = -1;
            ways:
                for (int w = 0; w < NWAYS; w++) {
#pragma HLS UNROLL
                    e[w] = table[w][s];
                    const bool fwd = e[w].src == t.src && e[w].dst == t.dst && e[w].sport == t.sport &&
                                     e[w].dport == t.dport && e[w].proto == t.proto;
                    const bool rev = e[w].src == t.dst && e[w].dst == t.src && e[w].sport == t.dport &&
                                     e[w].dport == t.sport && e[w].proto == t.proto;
                    hitv[w] = e[w].valid && (fwd || rev);
                    fwdv[w] = fwd;                 // flows.py looks up the forward key first
                    gone_prev[w] = e[w].valid && have_prev && expired(e[w], prev_ts, cfg);
                    idle_now[w] = older(t.ts, e[w].last, cfg.idle_us);
                    too_old[w] = older(t.ts, e[w].first, cfg.active_us);
                }
            pick:
                for (int w = NWAYS - 1; w >= 0; w--) {   // lowest matching way wins
#pragma HLS UNROLL
                    if (hitv[w]) hit = w;
                    if (!e[w].valid) free_way = w;
                    if (gone_prev[w]) stale = w;
                }

                int way;
                entry_t f;
                bool forward = true;
                if (hit >= 0) {
                    way = hit;
                    f = e[hit];
                    ap_uint<3> reason = R_NONE;
                    if (gone_prev[hit]) {
                        reason = expiry_reason(f, cfg);  // expire() at the previous frame took it
                    } else if (idle_now[hit]) {
                        reason = R_IDLE;
                    } else if (too_old[hit]) {
                        reason = R_ACTIVE;
                    } else if (f.closing && (t.tcp_flags & TCP_SYN) && !(t.tcp_flags & TCP_ACK)) {
                        reason = R_CLOSED;               // new connection on a closed 5-tuple
                    }
                    if (reason != R_NONE) {
                        emit(out, f, reason, exported);
                        f = new_flow(t);
                    } else {
                        forward = fwdv[hit];
                    }
                } else {
                    if (free_way >= 0) {
                        way = free_way;
                        open++;
                        if (open > peak) peak = open;
                    } else if (stale >= 0) {
                        way = stale;
                        emit(out, e[stale], expiry_reason(e[stale], cfg), exported);
                    } else {
                        way = evict_ptr;                 // set full: the only real deviation
                        emit(out, e[evict_ptr], R_EVICT, exported);
                        evict_ptr++;
                        evicted++;
                    }
                    f = new_flow(t);
                }
                add_packet(f, t, forward, cfg);
                set_deadline(f, cfg);
                table[way][s] = f;
            }

            // expire(now) after the frame, one set at a time
            int found = -1;
            entry_t g[NWAYS];
#pragma HLS ARRAY_PARTITION variable=g complete
        scan:
            for (int w = 0; w < NWAYS; w++) {
#pragma HLS UNROLL
                g[w] = table[w][scan_ptr];
                if (g[w].valid && expired(g[w], t.ts, cfg) && found < 0) found = w;
            }
            if (found >= 0) {
                emit(out, g[found], expiry_reason(g[found], cfg), exported);
                table[found][scan_ptr].valid = false;
                open--;
            } else {
                scan_ptr++;
            }
            prev_ts = t.ts;
            have_prev = true;
        }
    }
}

// =====================================================================================
// Stage 3: emit_records. Snapshot of a finished flow -> the 8 raw feature words of the
// handoff spec (flows.py _export() and raw_features()) and the metadata record.
// =====================================================================================
namespace {

const ap_uint<64> U32_MAX = 0xFFFFFFFFull;

void write_meta(hls::stream<beat_t>& out, const ap_uint<64> w[REC_WORDS]) {
meta_words:
    for (int i = 0; i < REC_WORDS; i++) {
#pragma HLS PIPELINE II=1
        beat_t b;
        b.data = w[i];
        b.keep = -1;
        b.strb = -1;
        b.last = i == REC_WORDS - 1;
        out.write(b);
    }
}

}  // namespace

void emit_records(hls::stream<flow_tok_t>& in, hls::stream<feat_beat_t>& feat, hls::stream<beat_t>& meta) {
records:
    while (true) {
        const flow_tok_t f = in.read();
        ap_uint<64> w[REC_WORDS];
#pragma HLS ARRAY_PARTITION variable=w complete
        for (int i = 0; i < REC_WORDS; i++) w[i] = 0;
        if (f.marker) {
            w[0] = REC_MARKER | (ap_uint<64>(f.st.errors) << 8);
            w[1] = f.st.chunks;
            w[2] = f.st.frames;
            w[3] = f.st.ipv4;
            w[4] = f.st.non_ipv4;
            w[5] = f.st.malformed;
            w[6] = f.seq;
            w[7] = f.evicted;
            w[8] = f.open;
            w[9] = f.peak;
            w[10] = f.st.deep;
            write_meta(meta, w);
            break;
        }

        // flows.py _export(); raw_features() saturates to uint32 like this record
        const ap_uint<64> duration = (f.last - f.first) / 1000;
        const ap_uint<33> packets = ap_uint<33>(f.in_pkts) + f.out_pkts;
        const ap_uint<8> min_ttl = (packets == 1) ? ap_uint<8>(0) : f.min_ttl;
        const ap_uint<16> min_len = (f.out_pkts == 0) ? ap_uint<16>(0) : f.min_len;
        const ap_uint<64> wide[3] = {f.in_bytes, f.out_bytes, duration};
        ap_uint<32> raw[8];
        ap_uint<8> saturated = 0;
        for (int i = 0; i < 3; i++) {
            saturated[i] = wide[i] > U32_MAX;
            raw[i] = saturated[i] ? ap_uint<32>(U32_MAX) : ap_uint<32>(wide[i]);
        }
        raw[3] = min_ttl;
        raw[4] = f.max_len;
        raw[5] = min_len;
        raw[6] = f.win_in;
        raw[7] = f.win_out;

        // The eight feature words: one per beat, TLAST on word 7 (handoff spec section 2).
    feature_words:
        for (int i = 0; i < 8; i++) {
#pragma HLS PIPELINE II=1
            feat_beat_t b;
            b.data = raw[i];
            b.keep = 0xF;
            b.strb = 0xF;
            b.user = 0;                   // every field measured
            b.last = i == 7;
            feat.write(b);
        }

        const bool pkt_sat = f.in_pkts == 0xFFFFFFFFu || f.out_pkts == 0xFFFFFFFFu;
        w[0] = REC_FLOW | (ap_uint<64>(f.reason) << 8) | (ap_uint<64>(f.proto) << 16) |
               (ap_uint<64>(f.sport) << 32) | (ap_uint<64>(f.dport) << 48);
        w[1] = f.first;
        w[2] = f.last;
        w[3] = (f.dst, f.src);
        w[4] = (f.out_pkts, f.in_pkts);
        w[5] = f.in_bytes;
        w[6] = f.out_bytes;
        w[7] = duration;
        w[8] = (ap_uint<16>(0), min_len, f.max_len, ap_uint<16>(min_ttl));
        w[9] = (ap_uint<15>(0), ap_uint<1>(pkt_sat), saturated, ap_uint<8>(0), f.win_out, f.win_in);
        w[15] = f.seq;
        write_meta(meta, w);
    }
}

}  // namespace svpl

// =====================================================================================
// Top level: one call handles one input chunk (until its TLAST). With ap_ctrl_none the
// core restarts by itself.
// =====================================================================================
void svdd_flow_extract(hls::stream<beat_t>& s_axis, hls::stream<feat_beat_t>& m_axis_features,
                       hls::stream<beat_t>& m_axis_meta) {
#pragma HLS INTERFACE axis port=s_axis register_mode=both
#pragma HLS INTERFACE axis port=m_axis_features register_mode=both
#pragma HLS INTERFACE axis port=m_axis_meta register_mode=both
#pragma HLS INTERFACE ap_ctrl_none port=return
#pragma HLS DATAFLOW
    hls::stream<svpl::pkt_tok_t, 16> pkts("pkts");
    hls::stream<svpl::flow_tok_t, 16> flows("flows");
    // Wide but shallow: shift registers in LUTs instead of BRAM.
#pragma HLS BIND_STORAGE variable=pkts type=fifo impl=srl
#pragma HLS BIND_STORAGE variable=flows type=fifo impl=srl
    svpl::parse(s_axis, pkts);
    svpl::flow_table(pkts, flows);
    svpl::emit_records(flows, m_axis_features, m_axis_meta);
}
