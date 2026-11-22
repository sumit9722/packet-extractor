#!/usr/bin/env bash
# Run Vitis HLS on synth.tcl under a memory cap (like vivado/build.sh): if it
# goes over the limit, the kernel kills only Vitis HLS instead of freezing the PC.
#
#   ./run_hls.sh                 csim + csynth + export
#   STEPS="cosim" ./run_hls.sh   RTL co-simulation of each IP (after csynth)
#   TOPS="svdd_preprocess" ./run_hls.sh   only some of the three IPs
#   MEM=8G ./run_hls.sh          raise the cap
#
# Vitis HLS refuses project paths that contain a space ("FPGA Project"), so the
# sources are copied to $HLS_BUILD (default ~/.cache/svdd_pl_hls) and the
# results are copied back: the IP zip to ip/, the reports to reports/.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"

MEM="${MEM:-6G}"
HLS_SETTINGS="${HLS_SETTINGS:-$HOME/tools/Vitis_HLS/2023.2/settings64.sh}"
BUILD="${HLS_BUILD:-$HOME/.cache/svdd_pl_hls}"
export STEPS="${STEPS:-csim csynth export}"
if [[ $BUILD == *" "* ]]; then
    echo "HLS_BUILD must not contain spaces: $BUILD" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$HLS_SETTINGS"

rm -rf "$BUILD/src" "$BUILD/vitis_hls.log"
mkdir -p "$BUILD/src"
cp -r ./*.cpp ./*.hpp synth.tcl core tb_data "$BUILD/src/"
cd "$BUILD"
echo "Vitis HLS ($STEPS) in $BUILD with a ${MEM} memory cap. Log: $BUILD/vitis_hls.log"
status=0
systemd-run --user --scope --quiet -p MemoryMax="$MEM" -p MemorySwapMax=0 \
    vitis_hls -f src/synth.tcl || status=$?
mkdir -p "$HERE/reports"
cp -f "$BUILD/vitis_hls.log" "$HERE/reports/vitis_hls.log" 2>/dev/null || true
if [[ $status -ne 0 ]] || grep -q "^ERROR:" "$BUILD/vitis_hls.log"; then
    echo "Vitis HLS FAILED (exit $status); see $HERE/reports/vitis_hls.log" >&2
    grep "^ERROR:" "$BUILD/vitis_hls.log" | head -5 >&2 || true
    exit 1
fi
if [[ $STEPS == *csynth* ]]; then
    for prj in "$BUILD"/prj_*; do
        top=${prj##*/prj_}
        rm -rf "$HERE/reports/$top"
        mkdir -p "$HERE/reports/$top"
        cp -f "$prj"/solution1/syn/report/*.rpt "$HERE/reports/$top/"
    done
fi
if [[ $STEPS == *cosim* ]]; then
    for prj in "$BUILD"/prj_*; do
        top=${prj##*/prj_}
        mkdir -p "$HERE/reports/$top"
        cp -f "$prj"/solution1/sim/report/*.rpt "$HERE/reports/$top/" 2>/dev/null || true
    done
    cp -f "$BUILD"/src/tb_data/small_out_cosim_*.bin "$HERE/tb_data/" 2>/dev/null || true
fi
if [[ $STEPS == *export* ]]; then
    mkdir -p "$HERE/ip"
    rm -f "$HERE"/ip/*.zip
    cp -f "$BUILD"/src/ip/*.zip "$HERE/ip/"
fi
cp -f "$BUILD"/src/tb_data/small_out.bin "$HERE/tb_data/" 2>/dev/null || true
echo "results copied to $HERE/reports (and ip/ after export)"
