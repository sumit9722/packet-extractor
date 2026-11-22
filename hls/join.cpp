// svdd_record_join: metadata record + Q24 codes + score -> the 128-byte record for the PS.
// Formats in svdd_pl.hpp.
#include "svdd_pl.hpp"

#include "preprocess_params.hpp"

// One call = one metadata record. A flow record waits for its 8 codes (from
// svdd_preprocess) and its score (from deep_svdd_axis); both come in flow order. A marker
// record passes straight through and ends the chunk's output with TLAST.
void svdd_record_join(hls::stream<beat_t>& s_axis_meta, hls::stream<q24_beat_t>& s_axis_codes,
                      hls::stream<score_beat_t>& s_axis_score, hls::stream<beat_t>& m_axis) {
#pragma HLS INTERFACE axis port=s_axis_meta register_mode=both
#pragma HLS INTERFACE axis port=s_axis_codes register_mode=both
#pragma HLS INTERFACE axis port=s_axis_score register_mode=both
#pragma HLS INTERFACE axis port=m_axis register_mode=both
#pragma HLS INTERFACE ap_ctrl_none port=return
    using namespace svpl;
    static ap_uint<16> group = 0;
    ap_uint<64> w[REC_WORDS];
#pragma HLS ARRAY_PARTITION variable=w complete
read_meta:
    for (int i = 0; i < REC_WORDS; i++) {
#pragma HLS PIPELINE II=1
        w[i] = s_axis_meta.read().data;
    }
    bool close = true;
    if ((w[0] & 0xFF) == REC_FLOW) {
        ap_uint<32> c[8];
    read_codes:
        for (int i = 0; i < 8; i++) {
#pragma HLS PIPELINE II=1
            c[i] = s_axis_codes.read().data;
        }
        const ap_uint<64> sc = s_axis_score.read().data;
        for (int i = 0; i < 4; i++) w[10 + i] = (c[2 * i + 1], c[2 * i]);
        w[14] = sc;
        w[0] = w[0] | (ap_uint<64>(sc > SCORE_THRESHOLD) << 24) | (ap_uint<64>(sc > SCORE_THRESHOLD_RECAL) << 25);
        group++;
        close = group == GROUP_RECORDS;
    }
    if (close) group = 0;               // a marker always closes the group
write_record:
    for (int i = 0; i < REC_WORDS; i++) {
#pragma HLS PIPELINE II=1
        beat_t b;
        b.data = w[i];
        b.keep = -1;
        b.strb = -1;
        b.last = close && i == REC_WORDS - 1;
        m_axis.write(b);
    }
}
