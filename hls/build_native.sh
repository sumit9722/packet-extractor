#!/usr/bin/env bash
# Build the testbench as a normal Linux program (seconds instead of a Vitis HLS csim
# run). It links the same bit-accurate floating-point models that csim uses, so the
# results are the same; Vitis HLS csim (run_hls.sh) stays the official check.
#
#   ./build_native.sh            -> build/native/tb_svdd_pl
set -euo pipefail
cd "$(dirname "$0")"
HLS="${XILINX_HLS:-$HOME/tools/Vitis_HLS/2023.2}"
L1="$HLS/lnx64/lib/csim"
L2="$HLS/lnx64/tools/fpo_v7_1"
mkdir -p build/native
rm -f build/native/tb_svdd_pl
# --allow-multiple-definition: the 2023.2 headers define hls::bitwidth<void> in every
# translation unit, which newer GCC versions reject at link time.
if ! g++ -O2 -std=c++14 -I"$HLS/include" -I. -Wno-unknown-pragmas \
        extract.cpp preprocess.cpp join.cpp core/inference_axis.cpp tb_svdd_pl.cpp \
        -o build/native/tb_svdd_pl \
        -Wl,--allow-multiple-definition -L"$L1" -L"$L2" \
        -lhlsm-GCC46 -lhlsmc++-GCC46 -lIp_floating_point_v7_1_bitacc_cmodel -lmpfr -lgmp \
        -Wl,-rpath,"$L1:$L2" 2> build/native/compile.log; then
    grep -v "multiple definition" build/native/compile.log >&2
    echo "compile FAILED" >&2
    exit 1
fi
echo "built $(pwd)/build/native/tb_svdd_pl"
