#pragma once

#include <ap_fixed.h>

using activation_t = ap_fixed<25, 9>;

template <int N>
void relu_layer(const activation_t input[N],  activation_t output[N]) {
	const activation_t zero = 0;

	for (int i = 0; i < N; i++) {
		const activation_t x = input[i];
		output[i] = (x < zero) ? zero : x;
	}
}
