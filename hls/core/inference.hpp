#include "dense.hpp"
#include "model_params.hpp"
#include "relu.hpp"
#include "score.hpp"

score_t deep_svdd_inference(const activation_t features[8]) {
	activation_t pre1[32], hidden1[32];
	activation_t pre2[16], hidden2[16];

	activation_t embedding[8];

	dense_layer<8, 32>(features, W1, pre1);
	relu_layer<32>(pre1, hidden1);

	dense_layer<32, 16>(hidden1, W2, pre2);
	relu_layer<16>(pre2, hidden2);

	dense_layer<16, 8>(hidden2, W3, embedding);
	return svdd_score<8>(embedding, CENTER);
}
