// pynq-pl: packet extraction, preprocessing and Deep SVDD in the PL, as separate IPs
// joined by the AXI4-Stream interfaces of the FPGA handoff spec (../../readme.md, section 2).
//
//   DMA MM2S --(64-bit pcap chunks)--> svdd_flow_extract   (the feature extraction IP)
//        m_axis_features: 8 x 32-bit raw feature words per flow, TLAST on word 7   [spec 2]
//        m_axis_meta:     64-bit flow metadata (5-tuple, times, counters, status) and
//                         chunk markers, kept outside the eight feature words     [spec 2]
//   svdd_preprocess: raw words -> 8 x Q24 codes, sign-extended 32-bit words,
//                    same eight-beat framing                                      [spec 2, 3]
//   deep_svdd_axis:  the unchanged inference IP from ../../svdd_inference
//   svdd_record_join: metadata + codes + score -> one 128-byte record per flow --> DMA S2MM
//
// Inside svdd_flow_extract, three dataflow stages run at the same time:
//   parse         pcap record headers, link layer, IPv4, TCP/UDP fields (1 byte per clock,
//                 payload bytes skipped 8 at a time)
//   flow_table    bidirectional flow table, 512 sets x 8 ways in BRAM, expiry rules of
//                 svdd_ps/flows.py
//   emit_records  flow snapshot -> the 8 raw feature words + the metadata record
//
// The byte layouts below are mirrored in svdd_pl/stream.py and svdd_pl/records.py.
#pragma once

#include <ap_axi_sdata.h>
#include <ap_int.h>
#include <hls_stream.h>

typedef ap_axiu<64, 0, 0, 0> beat_t;          // pcap chunks in, metadata, records out
typedef ap_axiu<32, 1, 0, 0> feat_beat_t;     // raw feature word; TUSER[0] = field unknown
typedef ap_axiu<32, 0, 0, 0> q24_beat_t;      // Q24 code word (deep_svdd_axis input format)
typedef ap_axiu<64, 0, 0, 0> score_beat_t;    // deep_svdd_axis output

namespace svpl {

// ----------------------------------------------------------------- input chunk header
// 4 beats, little-endian:
//   beat 0: [31:0] magic "SVPL"  [39:32] version  [47:40] flags  [63:48] pcap link type
//   beat 1: [31:0] data bytes in this chunk       [63:32] TCP close timeout (us)
//   beat 2: [31:0] idle timeout (us)              [63:32] active timeout (us)
//   beat 3: [63:0] now (us), used with F_TICK
// then ceil(data_bytes / 8) beats of pcap data (record headers + frames, no global
// header). TLAST is on the last beat of the chunk.
constexpr unsigned MAGIC = 0x4C505653u;   // bytes 'S' 'V' 'P' 'L'
constexpr unsigned VERSION = 1;
constexpr int HEADER_BEATS = 4;

constexpr unsigned F_RESET = 0x01;        // before the data: clear flow table, counters, parser
constexpr unsigned F_NEW_FILE = 0x02;     // the data starts at the first record of a pcap file
constexpr unsigned F_FLUSH = 0x04;        // after the data: export every open flow (end of capture)
constexpr unsigned F_TICK = 0x08;         // after the data: expire flows as of "now" (live capture)
constexpr unsigned F_NS = 0x10;           // record timestamps are in nanoseconds
constexpr unsigned F_BIG_ENDIAN = 0x20;   // record headers are big-endian
constexpr unsigned F_TTL_BOTH = 0x40;     // MIN_TTL over both directions (svdd_ps --ttl-both-directions)
constexpr unsigned F_NO_FIN_RST = 0x80;   // ignore FIN/RST (svdd_ps --no-fin-rst)

constexpr unsigned LT_NULL = 0, LT_ETHERNET = 1, LT_RAW = 101, LT_LINUX_SLL = 113,
                   LT_IPV4 = 228, LT_LINUX_SLL2 = 276, LT_RAW_ALT1 = 12, LT_RAW_ALT2 = 14;

constexpr int CAP = 128;                  // bytes of each frame examined for header fields

// ----------------------------------------------------------------- flow table
constexpr int SET_BITS = 9;
constexpr int NSETS = 1 << SET_BITS;      // 512 sets
constexpr int NWAYS = 8;                  // x 8 ways = 4096 flows open at once

// ----------------------------------------------------------------- feature stream [spec 2]
// m_axis_features carries one completed flow as 8 beats, TDATA[31:0] = the raw unsigned
// feature in model order (IN_BYTES, OUT_BYTES, FLOW_DURATION_MILLISECONDS, MIN_TTL,
// MAX_IP_PKT_LEN, MIN_IP_PKT_LEN, TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT), 8- and 16-bit fields
// zero-extended, TKEEP = TSTRB = 4'b1111, TLAST on word 7, no interleaving.
// TUSER[0] = 1 marks a field the extractor could not measure; svdd_preprocess then uses
// the saved median (spec 3). This extractor measures every field, so it always sends 0,
// and a source without TUSER (tied to 0) counts as "all known".
// Counters wider than 32 bits saturate at 2^32 - 1 in the feature word (never wrap); the
// metadata record says which ones did.
//
// ----------------------------------------------------------------- metadata and output records
// 16 little-endian 64-bit words, TLAST on the last. svdd_flow_extract writes words 0-9
// and 15 (the metadata record); svdd_record_join adds the codes, the score and the
// anomaly bits and passes the result to the PS. Flow record:
//   w0  [7:0] 0xF1  [15:8] end reason  [23:16] protocol  [24] anomaly (THRESHOLD)
//       [25] anomaly (VALIDATION_THRESHOLD)  [47:32] src port  [63:48] dst port
//   w1  first packet time (us)            w2  last packet time (us)
//   w3  [31:0] src IPv4  [63:32] dst IPv4 (a.b.c.d = a<<24 | b<<16 | c<<8 | d)
//   w4  [31:0] IN_PKTS   [63:32] OUT_PKTS (both saturate at 2^32 - 1)
//   w5  IN_BYTES         w6  OUT_BYTES          w7  FLOW_DURATION_MILLISECONDS (full width)
//   w8  [15:0] MIN_TTL  [31:16] MAX_IP_PKT_LEN  [47:32] MIN_IP_PKT_LEN
//   w9  [15:0] TCP_WIN_MAX_IN  [31:16] TCP_WIN_MAX_OUT
//       [39:32] feature words marked unknown (bit i = word i; always 0 here)
//       [47:40] feature words saturated to 32 bits (bit i = word i)
//       [48]    a packet counter saturated
//   w10..w13  the 8 Q24 input codes, int32 each (w10 = code0 | code1 << 32, ...)   (join)
//   w14 score code (32 fractional bits)                                            (join)
//   w15 flow sequence number since reset = the flow handle for correlation [spec 2]
// Marker record (end of every chunk; the join IP passes it on with TLAST):
//   w0  [7:0] 0xA5  [15:8] chunk error flags
//   w1  chunks since reset  w2 frames  w3 IPv4 packets  w4 non-IPv4 frames  w5 malformed
//   w6  flows exported  w7 flows evicted (table set full)  w8 flows open now
//   w9  most flows open at once  w10 frames whose headers were deeper than CAP
// TLAST also closes every group of GROUP_RECORDS flow records at the join output, so the
// receive buffer never needs to be bigger than (GROUP_RECORDS + 1) * 128 bytes.
constexpr int REC_WORDS = 16;
constexpr int GROUP_RECORDS = 256;
constexpr unsigned REC_FLOW = 0xF1, REC_MARKER = 0xA5;

enum Reason { R_NONE = 0, R_IDLE = 1, R_ACTIVE = 2, R_TCP_CLOSE = 3, R_CLOSED = 4, R_END = 5,
              R_EVICT = 6 };
enum TokKind { T_PKT = 0, T_OTHER = 1, T_CONFIG = 2, T_TICK = 3, T_FLUSH = 4, T_RESET = 5,
               T_MARKER = 6 };
constexpr unsigned E_MAGIC = 1, E_SHORT = 2, E_LONG = 4;   // chunk error flags

// TCP flags
constexpr unsigned TCP_FIN = 0x01, TCP_SYN = 0x02, TCP_RST = 0x04, TCP_ACK = 0x10;

struct parse_stats_t {
    ap_uint<32> chunks, frames, ipv4, non_ipv4, malformed, deep;
    ap_uint<8> errors;                    // error flags of the current chunk
};

// parse -> flow_table
struct pkt_tok_t {
    ap_uint<3> kind;                      // TokKind
    ap_uint<64> ts;                       // PKT/OTHER: frame time; TICK: now; CONFIG: close timeout
    ap_uint<32> src, dst;                 // CONFIG: idle timeout, active timeout
    ap_uint<16> sport, dport;
    ap_uint<8> proto, ttl;
    ap_uint<8> tcp_flags;                 // CONFIG: chunk flags
    ap_uint<16> len, win;
    bool has_win;                         // false when the packet has no complete TCP header
    parse_stats_t st;                     // MARKER only
};

// flow_table -> score
struct flow_tok_t {
    bool marker;
    ap_uint<3> reason;
    ap_uint<64> first, last;
    ap_uint<32> src, dst;
    ap_uint<16> sport, dport;
    ap_uint<8> proto;
    ap_uint<32> in_pkts, out_pkts;
    ap_uint<48> in_bytes, out_bytes;
    ap_uint<8> min_ttl;
    ap_uint<16> max_len, min_len, win_in, win_out;
    ap_uint<32> seq;                      // flow: sequence number; marker: flows exported
    // marker only
    parse_stats_t st;
    ap_uint<32> evicted;
    ap_uint<16> open, peak;
};

// Preprocessing pieces, also used by the testbench.
void preprocess(const ap_uint<32> raw[8], const bool unknown[8], ap_int<32> codes[8]);
double log1p_u32(ap_uint<32> x);
ap_int<32> quantize_q16(float v);

}  // namespace svpl

// The three HLS top functions (one IP each).
void svdd_flow_extract(hls::stream<beat_t>& s_axis, hls::stream<feat_beat_t>& m_axis_features,
                       hls::stream<beat_t>& m_axis_meta);
void svdd_preprocess(hls::stream<feat_beat_t>& s_axis_raw, hls::stream<q24_beat_t>& m_axis_q24,
                     hls::stream<q24_beat_t>& m_axis_codes);
void svdd_record_join(hls::stream<beat_t>& s_axis_meta, hls::stream<q24_beat_t>& s_axis_codes,
                      hls::stream<score_beat_t>& s_axis_score, hls::stream<beat_t>& m_axis);
