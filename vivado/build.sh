#!/usr/bin/env bash
# Build the overlay for one board under a memory cap (Vivado gets killed, not the PC).
#
#   ./build.sh pynq-z2
#   ./build.sh zedboard
#   ./build.sh all              both, one after the other
#   MEM=8G ./build.sh zedboard  raise the cap
set -euo pipefail
cd "$(dirname "$0")"

MEM="${MEM:-6G}"
VIVADO_SETTINGS="${VIVADO_SETTINGS:-$HOME/tools/Vivado/2023.2/settings64.sh}"
boards=("$@")
[[ ${#boards[@]} -eq 0 ]] && { echo "usage: $0 pynq-z2|zedboard|all" >&2; exit 1; }
[[ ${boards[0]} == all ]] && boards=(pynq-z2 zedboard)

# The three HLS IPs come as zips from hls/run_hls.sh; unpack each into hls/ip/<name>/.
for ip in svdd_flow_extract svdd_preprocess svdd_record_join; do
    zip=$(ls -t ../hls/ip/*_${ip}_*.zip 2>/dev/null | head -1)
    [[ -n $zip ]] || { echo "no $ip zip in ../hls/ip: run ../hls/run_hls.sh first" >&2; exit 1; }
    rm -rf "../hls/ip/$ip"
    mkdir -p "../hls/ip/$ip"
    unzip -q -o "$zip" -d "../hls/ip/$ip"
done
rm -rf ../hls/ip/svdd_flow_pl                 # the earlier single-IP version

# shellcheck disable=SC1090
source "$VIVADO_SETTINGS"
if systemd-run --user --scope --quiet -p MemoryMax="$MEM" -p MemorySwapMax=0 true >/dev/null 2>&1; then
    cap_note="with a ${MEM} memory cap"
    capped() { systemd-run --user --scope --quiet -p MemoryMax="$MEM" -p MemorySwapMax=0 "$@"; }
else
    echo "warning: user systemd scope unavailable; running without the $MEM memory cap" >&2
    cap_note="without a memory cap"
    capped() { "$@"; }
fi
for b in "${boards[@]}"; do
    echo "Building $b $cap_note. Log: $(pwd)/build_$b.log"
    capped vivado -mode batch -nojournal -log "build_$b.log" -source build_overlay.tcl -tclargs "$b"
done
