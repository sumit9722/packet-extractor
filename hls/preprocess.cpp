// svdd_preprocess: 8 raw feature words in, 8 Q24 codes out (twice: one stream for
// deep_svdd_axis, one copy for svdd_record_join). Formats in svdd_pl.hpp.
//
// Reference: ../svdd_ps/preprocess.py (float64, then float32, then Q24 codes).
#include "svdd_pl.hpp"

#include "cordic_table.hpp"
#include "preprocess_params.hpp"

namespace svpl {

ap_int<32> quantize_q16(float v) {
    // preprocess.py quantize(): rint(float64(v) * 2^16), ties to even, then 24-bit saturation.
    union {
        float f;
        unsigned int u;
    } bits;
    bits.f = v;
    const ap_uint<32> b = bits.u;
    const bool neg = b[31];
    const ap_uint<8> e = b(30, 23);
    const ap_uint<64> m = (ap_uint<1>(1), b(22, 0));   // 24-bit significand
    ap_uint<64> mag = 0;
    if (e != 0) {                         // zero and subnormals round to 0
        const int sh = e.to_int() - 134;  // |v| * 2^16 = m * 2^(e - 127 - 23 + 16)
        if (sh >= 0) {
            mag = ap_uint<64>(1) << 40;   // at least 2^23: saturates below
        } else if (-sh <= 25) {
            const int s = -sh;
            ap_uint<64> q = m >> s;
            const ap_uint<64> rem = m - (q << s);
            const ap_uint<64> half = ap_uint<64>(1) << (s - 1);
            if (rem > half || (rem == half && q[0])) q++;
            mag = q;
        }
    }
    if (neg) return (mag > (1 << 23)) ? ap_int<32>(-(1 << 23)) : ap_int<32>(-ap_int<32>(mag));
    return (mag > (1 << 23) - 1) ? ap_int<32>((1 << 23) - 1) : ap_int<32>(mag);
}

namespace {

typedef ap_fixed<70, 4> cfix_t;           // CORDIC x, y, z: 66 fraction bits
typedef ap_fixed<72, 6> lfix_t;           // ln(1 + x) <= 32 ln 2: 66 fraction bits

// A positive fixed-point value to the nearest double (ties to even).
double fix_to_double(lfix_t v) {
    const ap_uint<72> b = v.range();
    const int lz = b.countLeadingZeros();
    const ap_uint<72> n = b << lz;        // leading one now at bit 71
    const int exp2 = (71 - lz) - CORDIC_FRAC;
    ap_uint<54> m = n(71, 19);            // 53 significant bits
    const bool round = n[18];
    const bool sticky = n(17, 0) != 0;
    int e = exp2;
    if (round && (sticky || m[0])) {
        m++;
        if (m[53]) {
            m >>= 1;
            e++;
        }
    }
    const ap_uint<64> bits = (ap_uint<1>(0), ap_uint<11>(e + 1023), ap_uint<52>(m(51, 0)));
    union {
        unsigned long long u;
        double d;
    } c;
    c.u = bits.to_uint64();
    return c.d;
}

}  // namespace

// ln(1 + x) for an integer x, as the nearest double to a result good to about 2^-58.
//
// HLS's own double-precision log1p is a fully pipelined unit (57 DSPs, ~17k LUTs) and
// would not leave room for anything else. Inputs here are integers, so:
//   1 + x = m * 2^e with m in [1, 2), and ln(1 + x) = e ln 2 + ln m.
// ln m comes from hyperbolic CORDIC in vectoring mode (shifts and adds only):
// starting from (m + 1, m - 1, 0), the angle register converges to atanh((m-1)/(m+1))
// = ln(m) / 2. An error this small changes a Q24 code only if the exact value sits
// within ~2^-50 of a rounding boundary; tests/ checks millions of inputs against numpy.
double log1p_u32(ap_uint<32> x) {
    if (x == 0) return 0.0;
    const ap_uint<33> v = ap_uint<33>(x) + 1;
    const int e = 32 - v.countLeadingZeros();             // v in [2^e, 2^(e+1))
    cfix_t m;
    m.range() = ap_uint<70>(v) << (CORDIC_FRAC - e);      // v / 2^e
    cfix_t X = m + 1, Y = m - 1, Z = 0;
cordic:
    for (int k = 0; k < CORDIC_STEPS; k++) {
#pragma HLS PIPELINE II=2
        const int i = CORDIC_SHIFT[k];
        cfix_t a;
        a.range() = (ap_uint<70>(CORDIC_ATANH_HI[k]) << 64) | ap_uint<70>(CORDIC_ATANH_LO[k]);
        const cfix_t xs = X >> i, ys = Y >> i;
        if (Y < 0) {
            X = X + ys;
            Y = Y + xs;
            Z = Z - a;
        } else {
            X = X - ys;
            Y = Y - xs;
            Z = Z + a;
        }
    }
    lfix_t ln2;
    ln2.range() = (ap_uint<72>(LN2_HI) << 64) | ap_uint<72>(LN2_LO);
    lfix_t L = ln2 * e;
    L += lfix_t(Z) * 2;
    return fix_to_double(L);
}

// preprocess.py transform() + quantize(). A field is replaced by the saved median when it
// is marked unknown or out of its domain (MIN_TTL above 255); uint32 words can't be
// negative or non-finite, the other invalid cases in preprocess.py.
void preprocess(const ap_uint<32> raw[8], const bool unknown[8], ap_int<32> codes[8]) {
features:
    for (int i = 0; i < 8; i++) {
#pragma HLS PIPELINE off
        const bool invalid = unknown[i] || (i == 3 && raw[i] > 255);
        const ap_uint<32> r = invalid ? ap_uint<32>(PRE_MEDIAN[i]) : raw[i];
        double x = (double)r.to_uint();
        if (PRE_LOG1P[i]) x = log1p_u32(r);
        if (x < PRE_CLIP_LO[i]) x = PRE_CLIP_LO[i];
        else if (x > PRE_CLIP_HI[i]) x = PRE_CLIP_HI[i];
        const double v = (x - PRE_ANCHOR[i]) / PRE_SCALE[i];
        codes[i] = quantize_q16((float)v);
    }
}

}  // namespace svpl

// One call = one flow. Frames are checked like deep_svdd_axis does: a frame with an early
// or missing TLAST, or with a partial TKEEP/TSTRB, is dropped instead of mixing flows.
void svdd_preprocess(hls::stream<feat_beat_t>& s_axis_raw, hls::stream<q24_beat_t>& m_axis_q24,
                     hls::stream<q24_beat_t>& m_axis_codes) {
#pragma HLS INTERFACE axis port=s_axis_raw register_mode=both
#pragma HLS INTERFACE axis port=m_axis_q24 register_mode=both
#pragma HLS INTERFACE axis port=m_axis_codes register_mode=both
#pragma HLS INTERFACE ap_ctrl_none port=return
    ap_uint<32> raw[8];
    bool unknown[8];
    ap_uint<4> bytes_ok = 0xF;
    bool last = false;
read_frame:
    for (int i = 0; i < 8; i++) {
#pragma HLS PIPELINE off
        const feat_beat_t b = s_axis_raw.read();
        last = b.last;
        if (last && i != 7) return;      // early TLAST: drop the frame
        raw[i] = b.data;
        unknown[i] = b.user[0];
        bytes_ok &= b.keep & b.strb;
    }
    if (!last) {                         // too long: skip to its TLAST
    drain:
        while (!s_axis_raw.read().last) {
        }
        return;
    }
    if (bytes_ok != 0xF) return;

    ap_int<32> codes[8];
    svpl::preprocess(raw, unknown, codes);
write_codes:
    for (int i = 0; i < 8; i++) {
#pragma HLS PIPELINE II=1
        q24_beat_t b;
        b.data = codes[i];               // Q24 code in [23:0], sign-extended into [31:24]
        b.keep = 0xF;
        b.strb = 0xF;
        b.last = i == 7;
        m_axis_q24.write(b);
        m_axis_codes.write(b);
    }
}
