#pragma once

#include <ap_axi_sdata.h>
#include <hls_stream.h>

using svdd_feature_beat_t = ap_axiu<32, 0, 0, 0>;
using svdd_score_beat_t = ap_axiu<64, 0, 0, 0>;

void deep_svdd_axis(hls::stream<svdd_feature_beat_t>& s_axis_features,
                    hls::stream<svdd_score_beat_t>& m_axis_score);
