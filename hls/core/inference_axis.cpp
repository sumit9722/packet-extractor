#include "inference_axis.hpp"

#include "inference.hpp"

void deep_svdd_axis(hls::stream<svdd_feature_beat_t>& s_axis_features,
                    hls::stream<svdd_score_beat_t>& m_axis_score) {
#pragma HLS INTERFACE axis port=s_axis_features register_mode=both
#pragma HLS INTERFACE axis port=m_axis_score register_mode=both
#pragma HLS INTERFACE ap_ctrl_none port=return

    constexpr int kFeatureCount = 8;
    static_assert(activation_t::width == 25 && activation_t::iwidth == 9,
                  "The feature stream carries signed fixed-point values with 16 fractional bits");
    static_assert(score_t::width == 64 && score_t::iwidth == 32,
                  "The score stream carries unsigned fixed-point values with 32 fractional bits");

    activation_t features[kFeatureCount];
    ap_uint<4> valid_bytes = 0xf;
    bool last = false;

    for (int i = 0; i < kFeatureCount; ++i) {
#pragma HLS PIPELINE off
        const svdd_feature_beat_t beat = s_axis_features.read();
        last = beat.last;
        if (last && i != kFeatureCount - 1) {
            return;
        }
        valid_bytes &= beat.keep & beat.strb;
        features[i].range(24, 0) = beat.data.range(24, 0);
    }

    if (!last) {
        // Discard the rest of the oversized packet through its TLAST.
        do {
            last = s_axis_features.read().last;
        } while (!last);
        return;
    }
    if (valid_bytes != 0xf) {
        return;
    }

    const score_t score = deep_svdd_inference(features);
    svdd_score_beat_t result;
    result.data = score.range(63, 0);
    result.keep = 0xff;
    result.strb = 0xff;
    result.last = 1;
    m_axis_score.write(result);
}
