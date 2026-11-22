#!/usr/bin/env bash
# Simulate the pynq-pl overlay of one board in the Vivado simulator (xsim): the block
# design from ../build_overlay.tcl (Zynq PS model, AXI DMA, the four IPs) driven by
# tb_svdd_pl.sv with 2,000 real UNSW-NB15 packets. Details in README.md.
#
#   ./run_sim.sh pynq-z2              batch run, ends with TEST PASSED or TEST FAILED
#   ./run_sim.sh zedboard
#   ./run_sim.sh all                  both boards, one after the other
#   ./run_sim.sh pynq-z2 gui          the same run in the xsim GUI, with the stream waveforms
#
#   MAX_CHUNKS=1 ./run_sim.sh ...     only the first chunk (about 1/6 of the run)
#   STREAM=s.bin EXPECT=o.bin ./run_sim.sh ...   another capture (README.md says how to make one)
#   SETUP=1 ./run_sim.sh ...          rebuild the block design even if nothing changed
#   MEM=5G ./run_sim.sh ...           memory cap (default 4G; Vivado/xsim get killed, not the PC)
#   SAIF=1 ./run_sim.sh ...           also write results/<board>/pl_activity.saif (for ../../../power)
set -euo pipefail
cd "$(dirname "$0")"
TB=$(pwd)
ROOT=$(cd ../.. && pwd)                       # pynq-pl

MEM="${MEM:-4G}"
VIVADO_SETTINGS="${VIVADO_SETTINGS:-$HOME/tools/Vivado/2023.2/settings64.sh}"
STREAM="${STREAM:-$ROOT/hls/tb_data/small_stream.bin}"
EXPECT="${EXPECT:-$ROOT/hls/tb_data/small_out.bin}"
REFERENCE="${REFERENCE:-}"                    # svdd_ps CSV for the extra Python check
[[ -z $REFERENCE && $STREAM == "$ROOT/hls/tb_data/small_stream.bin" ]] && REFERENCE="$ROOT/hls/tb_data/small_ref.csv"
MAX_CHUNKS="${MAX_CHUNKS:-0}"

boards=()
mode=batch
for a in "$@"; do
    case $a in
        pynq-z2|zedboard) boards+=("$a") ;;
        all) boards+=(pynq-z2 zedboard) ;;
        gui) mode=gui ;;
        *) echo "usage: $0 pynq-z2|zedboard|all [gui]" >&2; exit 2 ;;
    esac
done
[[ ${#boards[@]} -gt 0 ]] || { echo "usage: $0 pynq-z2|zedboard|all [gui]" >&2; exit 2; }
for f in "$STREAM" "$EXPECT"; do [[ -f $f ]] || { echo "missing $f" >&2; exit 1; }; done

# The block design needs the three HLS IPs unpacked, like ../build.sh does.
for ip in svdd_flow_extract svdd_preprocess svdd_record_join; do
    [[ -f $ROOT/hls/ip/$ip/component.xml ]] && continue
    zip=$(ls -t "$ROOT"/hls/ip/*_${ip}_*.zip 2>/dev/null | head -1)
    [[ -n $zip ]] || { echo "no $ip IP in $ROOT/hls/ip: run hls/run_hls.sh first" >&2; exit 1; }
    mkdir -p "$ROOT/hls/ip/$ip" && unzip -q -o "$zip" -d "$ROOT/hls/ip/$ip"
done

# shellcheck disable=SC1090
source "$VIVADO_SETTINGS"
if systemd-run --user --scope --quiet -p MemoryMax="$MEM" -p MemorySwapMax=0 true >/dev/null 2>&1; then
    capped() { systemd-run --user --scope --quiet -p MemoryMax="$MEM" -p MemorySwapMax=0 "$@"; }
else
    echo "warning: user systemd scope unavailable; running without the $MEM memory cap" >&2
    capped() { "$@"; }
fi

status=0
for b in "${boards[@]}"; do
    sim_dir="$TB/build_$b/svdd_pl_overlay.sim/sim_1/behav/xsim"
    res="$TB/results/$b"
    mkdir -p "$res"
    echo "=== $b ==="

    # 1. Block design + simulation scripts (Vivado, about a minute). Redone only when the
    #    design scripts or the IPs changed.
    stamp="$TB/build_$b/.setup_done"
    if [[ ${SETUP:-0} == 1 || ! -f $stamp || ../build_overlay.tcl -nt $stamp || sim_overlay.tcl -nt $stamp ]] ||
       [[ -n $(find "$ROOT/hls/ip" "$ROOT/../svdd_inference/inference_axis_ip/solution1/impl/ip" -newer "$stamp" -print -quit 2>/dev/null) ]]; then
        echo "[1/3] block design and simulation scripts (log: $res/setup.log)"
        rm -f "$stamp"
        # Run from results/<board> so Vivado's scratch folders (.Xil, NA) land there.
        (cd "$res" && capped vivado -mode batch -nojournal -log setup.log -source ../../sim_overlay.tcl -tclargs "$b" \
            > setup.stdout 2>&1) || { echo "Vivado setup failed, see $res/setup.log" >&2; status=1; continue; }
        touch "$stamp"
    else
        echo "[1/3] block design unchanged (SETUP=1 to redo it)"
    fi

    # 2. Compile and elaborate (scripts written by Vivado; they use paths relative to sim_dir)
    echo "[2/3] compile and elaborate (logs in $sim_dir)"
    cd "$sim_dir"
    if ! capped bash ./compile.sh > "$res/compile.stdout" 2>&1 || ! capped bash ./elaborate.sh > "$res/elaborate.stdout" 2>&1; then
        grep -h -m 20 'ERROR' compile.log elaborate.log 2>/dev/null >&2 || true
        echo "compile/elaborate failed, see $sim_dir/compile.log and elaborate.log" >&2
        status=1; cd "$TB"; continue
    fi

    # 3. Simulate. The testbench opens stream.bin and expect.bin in its working directory.
    cp "$STREAM" stream.bin
    cp "$EXPECT" expect.bin
    rm -f pl_out.bin "$res"/{simulate.log,pl_out.bin,pl.csv,compare.txt} "$res"/setup_*.backup.log
    args=(-testplusarg "dma_base=$(cat dma_base)" -testplusarg "max_chunks=$MAX_CHUNKS")
    if [[ $mode == gui ]]; then
        echo "[3/3] xsim GUI"
        cp "$TB/tb_svdd_pl.wcfg" .
        printf 'run all\n' > run_gui.tcl
        capped xsim tb_svdd_pl_behav "${args[@]}" -gui -view tb_svdd_pl.wcfg -tclbatch run_gui.tcl -log simulate.log || true
    else
        echo "[3/3] simulation (log: $res/simulate.log)"
        rm -f pl_activity.saif
        if [[ ${SAIF:-0} == 1 ]]; then
            # For the power test (../../../power): record the switching activity of every PL
            # cell and of the nets between them, but not of the PS model, which is a hard
            # block on the chip and has its own power model.
            echo "    SAIF=1: recording switching activity to $res/pl_activity.saif (slower)"
            cat > run_all.tcl <<'EOF'
open_saif pl_activity.saif
log_saif [get_objects /tb_svdd_pl/dut/svdd_pl_i/*]
foreach scope [get_scopes /tb_svdd_pl/dut/svdd_pl_i/*] {
    if {![string match */processing_system7_0 $scope]} { log_saif [get_objects -r $scope/*] }
}
run all
close_saif
quit
EOF
        else
            printf 'run all\nquit\n' > run_all.tcl
        fi
        start=$(date +%s)
        capped xsim tb_svdd_pl_behav "${args[@]}" -tclbatch run_all.tcl -log simulate.log > /dev/null 2>&1 || true
        echo "    $(( $(date +%s) - start )) s of wall time"
    fi
    cp simulate.log "$res/simulate.log"
    [[ -f pl_out.bin ]] && cp pl_out.bin "$res/pl_out.bin"
    [[ -f pl_activity.saif ]] && mv pl_activity.saif "$res/pl_activity.saif"
    cd "$TB"

    grep '^\[tb\]\|^Error\|^ERROR\|^Fatal\|^FATAL' "$res/simulate.log" | grep -v 'chunk [0-9]*:' | head -60 || true
    if grep -q '^TEST PASSED' "$res/simulate.log"; then
        echo "$b: TEST PASSED"
    else
        grep -m1 '^TEST FAILED' "$res/simulate.log" || echo "no TEST PASSED/FAILED line: the simulation did not finish"
        echo "$b: TEST FAILED  (log: $res/simulate.log)"
        status=1
        continue
    fi

    # Extra check: the PL's records against the Python pipeline (svdd_ps), not only against
    # the C model. Needs python3 with numpy, and the whole capture (MAX_CHUNKS=0).
    if [[ -n $REFERENCE && $MAX_CHUNKS == 0 ]] && python3 -c 'import numpy' 2>/dev/null; then
        if (cd "$ROOT" && python3 -m svdd_pl decode "$res/pl_out.bin" -o "$res/pl.csv" &&
                python3 -m svdd_pl compare "$res/pl.csv" "$REFERENCE") > "$res/compare.txt" 2>&1; then
            echo "$b: records also match svdd_ps (Python), see $res/compare.txt"
        else
            echo "$b: records differ from svdd_ps, see $res/compare.txt"
            status=1
        fi
    fi
done
exit $status
