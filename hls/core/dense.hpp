#pragma once

#include "relu.hpp"

template <int IN, int OUT>
void dense_layer(const activation_t input[IN],
		const activation_t weights[OUT][IN],
		activation_t output[OUT]) {
	using product_t = ap_fixed<50, 18>;
	using accumulator_t = ap_fixed<64, 32>;
	using rounded_t = ap_fixed<25, 9, AP_RND_CONV, AP_SAT>;

	for (int out = 0; out < OUT; out++) {
		accumulator_t sum = 0;

		for (int in = 0; in < IN; in++) {
			const product_t product = weights[out][in] * input[in];
			sum += product;
		}

		output[out] = rounded_t(sum);
	}
}
