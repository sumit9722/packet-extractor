# Vitis HLS flow for the three pynq-pl IPs. Run through ./run_hls.sh (memory cap), e.g.
#   ./run_hls.sh                      csim + csynth + export for all three IPs (default)
#   STEPS="cosim" ./run_hls.sh        RTL co-simulation of each IP on tb_data/small_stream.bin
#   TOPS="svdd_preprocess" ./run_hls.sh   only some of the IPs
#
# Every project uses the same testbench, which chains all IPs as in the block design
# (extract -> preprocess -> deep_svdd_axis -> join). In cosim the project's own IP runs as
# RTL and the others as C, so each IP is checked in its real surroundings.
set here  [file dirname [file normalize [info script]]]
set steps [expr {[info exists ::env(STEPS)] ? $::env(STEPS) : "csim csynth export"}]
set tops  [expr {[info exists ::env(TOPS)] ? $::env(TOPS) : "svdd_flow_extract svdd_preprocess svdd_record_join"}]
set data  "$here/tb_data"
set src   [dict create svdd_flow_extract extract.cpp svdd_preprocess preprocess.cpp svdd_record_join join.cpp]
set names [dict create svdd_flow_extract "SVDD feature extraction (pcap -> 8 raw words)" \
                       svdd_preprocess   "SVDD preprocessing (raw words -> Q24 codes)" \
                       svdd_record_join  "SVDD record join (metadata + codes + score)"]
set cflags "-I$here -std=c++14"
set argv "stream $data/small_stream.bin $data/small_out.bin"
set first 1

foreach top $tops {
    open_project prj_$top
    set_top $top
    add_files $here/[dict get $src $top] -cflags $cflags
    foreach f [list tb_svdd_pl.cpp core/inference_axis.cpp {*}[dict values $src]] {
        if {$f ne [dict get $src $top]} { add_files -tb $here/$f -cflags $cflags }
    }
    if {[lsearch $steps csynth] >= 0} {
        open_solution -reset solution1 -flow_target vivado
    } else {
        open_solution solution1 -flow_target vivado
    }
    # Family-level IP: this one build serves the PYNQ-Z2 (clg400) and the ZedBoard (clg484).
    set_part {xc7z020clg400-1}
    create_clock -period 10 -name default
    # Schedule for 8 ns: HLS's delay estimates were ~1.2 ns optimistic for the flow-table
    # logic after place and route, so leave real margin.
    set_clock_uncertainty 2
    config_rtl -reset control -reset_level low
    config_export -format ip_catalog -rtl verilog -vendor bits.edu -library hls -version 1.0 \
        -display_name [dict get $names $top] -ipname $top

    if {$first && [lsearch $steps csim] >= 0} {
        csim_design -ldflags {-B/usr/bin/} -argv $argv     ;# the same chain for every project
    }
    if {[lsearch $steps csynth] >= 0} { csynth_design }
    if {[lsearch $steps cosim] >= 0} {
        cosim_design -ldflags {-B/usr/bin/} -argv $argv -trace_level none
        file copy -force $data/small_out.bin $data/small_out_cosim_$top.bin
    }
    if {[lsearch $steps export] >= 0} {
        export_design
        file mkdir $here/ip
        foreach f [glob -nocomplain [file join prj_$top solution1 impl ip *.zip]] {
            file copy -force $f $here/ip/
        }
    }
    close_project
    set first 0
}
exit
