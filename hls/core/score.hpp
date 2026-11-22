#pragma once

#include "relu.hpp"

using delta_t = ap_fixed<26, 10>;
using score_t = ap_ufixed<64, 32>;

template <int N>
score_t svdd_score(const activation_t z[N], const activation_t center[N]) {
	score_t score = 0;

	for (int i = 0; i < N; i++) {
		const delta_t delta = delta_t(z[i]) - delta_t(center[i]);
		score += delta * delta;
	}

	return score;
}
