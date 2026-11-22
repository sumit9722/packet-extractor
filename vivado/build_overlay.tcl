# Build the pynq-pl overlay: Zynq PS7 <-> AXI DMA <-> extraction / preprocessing / Deep SVDD IPs.
#
#   ./build.sh pynq-z2        or        ./build.sh zedboard
#
# (build.sh runs Vivado under a memory cap; see ../../pynq-ps/README.md for why.)
# Produces ../overlay/<board>/svdd_pl.bit and svdd_pl.hwh plus timing/utilization reports.
#
# Block design (stream formats in ../hls/svdd_pl.hpp and the handoff spec, section 2):
#   PS7 M_AXI_GP0 --AXI-Lite--> axi_dma (control registers)
#   axi_dma M_AXIS_MM2S (64)     --> svdd_flow_extract s_axis          (pcap chunks)
#   svdd_flow_extract m_axis_features (32: 8 raw words/flow, TLAST on 7) --> svdd_preprocess s_axis_raw
#   svdd_flow_extract m_axis_meta (64)                --> svdd_record_join s_axis_meta
#   svdd_preprocess m_axis_q24 (32: 8 Q24 words/flow) --> deep_svdd_axis s_axis_features
#   svdd_preprocess m_axis_codes (32)                 --> svdd_record_join s_axis_codes
#   deep_svdd_axis m_axis_score (64)                  --> svdd_record_join s_axis_score
#   svdd_record_join m_axis (64)  --> axi_dma S_AXIS_S2MM               (128-byte records)
#   axi_dma M_AXI_MM2S / M_AXI_S2MM --> PS7 S_AXI_HP0 (DDR)
# deep_svdd_axis is the IP exported in ../../svdd_inference, used as it is.
#   Everything on FCLK_CLK0 (100 MHz, or FCLK_MHZ).
set board [lindex $argv 0]
# PL clock (FCLK0). 100 MHz unless FCLK_MHZ is set, e.g. FCLK_MHZ=83.333333 ./build.sh ...
set fclk [expr {[info exists ::env(FCLK_MHZ)] ? $::env(FCLK_MHZ) : 100}]
switch -- $board {
    pynq-z2  { set part xc7z020clg400-1; set board_glob {*:pynq-z2:*}; set xhub_glob *pynq-z2* }
    zedboard { set part xc7z020clg484-1; set board_glob {*:zedboard:*}; set xhub_glob *zedboard* }
    default  { error "usage: build.sh pynq-z2|zedboard" }
}

set script_dir [file dirname [file normalize [info script]]]
set root       [file normalize "$script_dir/.."]
set ip_dir     "$root/hls/ip"
set build_dir  "$script_dir/build_$board"
set out_dir    "$root/overlay/$board"
set proj       svdd_pl_overlay
set bd         svdd_pl

set svdd_ip    [file normalize "$root/../svdd_inference/inference_axis_ip/solution1/impl/ip"]
set our_ips    {svdd_flow_extract svdd_preprocess svdd_record_join}
set ip_repos   [list $svdd_ip]
foreach ip $our_ips {
    if {![file exists "$ip_dir/$ip/component.xml"]} {
        error "HLS IP $ip not found in $ip_dir. Run hls/run_hls.sh first (build.sh unpacks the zips)."
    }
    lappend ip_repos "$ip_dir/$ip"
}
if {![file exists "$svdd_ip/component.xml"]} {
    error "deep_svdd_axis IP not found at $svdd_ip. Run vitis_hls -f build_axis.tcl in svdd_inference/ first."
}

# Board files give the exact DDR/MIO preset. Without them the bare part is fine:
# the PS setup comes from the SD card's boot files, and this bitstream only
# programs the PL (the design uses no PL pins).
proc find_board {glob} { return [lindex [lsort [get_board_parts -quiet $glob]] end] }
set board_part [find_board $board_glob]
if {$board_part eq ""} {
    catch {
        xhub::refresh_catalog [xhub::get_xstores xilinx_board_store]
        set item [lindex [xhub::get_xitems -quiet $xhub_glob] 0]
        if {$item ne ""} { xhub::install $item }
        set_param board.repoPaths [get_property LOCAL_ROOT_DIR [xhub::get_xstores xilinx_board_store]]
    }
    set board_part [find_board $board_glob]
}

# Keep peak RAM low: one global synthesis run, one job, four threads.
set_param general.maxThreads 4

file delete -force $build_dir
create_project $proj $build_dir -part $part
if {$board_part ne ""} {
    puts "INFO: using board part $board_part"
    set_property board_part $board_part [current_project]
} else {
    puts "WARNING: no board files for $board; building with part $part only"
}
set_property ip_repo_paths $ip_repos [current_project]
update_ip_catalog

create_bd_design $bd
set ps [create_bd_cell -type ip -vlnv xilinx.com:ip:processing_system7 processing_system7_0]
apply_bd_automation -rule xilinx.com:bd_rule:processing_system7 \
    -config [list make_external "FIXED_IO, DDR" apply_board_preset [expr {$board_part ne "" ? 1 : 0}] \
                  Master Disable Slave Disable] $ps
set_property -dict [list \
    CONFIG.PCW_USE_M_AXI_GP0 {1} \
    CONFIG.PCW_USE_S_AXI_HP0 {1} \
    CONFIG.PCW_S_AXI_HP0_DATA_WIDTH {64} \
    CONFIG.PCW_EN_CLK0_PORT {1} \
    CONFIG.PCW_EN_RST0_PORT {1} \
    CONFIG.PCW_FPGA0_PERIPHERAL_FREQMHZ $fclk \
] $ps

set dma [create_bd_cell -type ip -vlnv xilinx.com:ip:axi_dma axi_dma]
set_property -dict [list \
    CONFIG.c_include_sg {0} \
    CONFIG.c_sg_length_width {26} \
    CONFIG.c_include_mm2s {1} \
    CONFIG.c_include_s2mm {1} \
    CONFIG.c_m_axi_mm2s_data_width {64} \
    CONFIG.c_m_axis_mm2s_tdata_width {64} \
    CONFIG.c_m_axi_s2mm_data_width {64} \
    CONFIG.c_s_axis_s2mm_tdata_width {64} \
    CONFIG.c_mm2s_burst_size {64} \
    CONFIG.c_s2mm_burst_size {16} \
] $dma

set ext  [create_bd_cell -type ip -vlnv bits.edu:hls:svdd_flow_extract svdd_flow_extract_0]
set pre  [create_bd_cell -type ip -vlnv bits.edu:hls:svdd_preprocess svdd_preprocess_0]
set svdd [create_bd_cell -type ip -vlnv xilinx.com:hls:deep_svdd_axis deep_svdd_axis_0]
set join [create_bd_cell -type ip -vlnv bits.edu:hls:svdd_record_join svdd_record_join_0]

apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
    -config [list Clk_master {Auto} Clk_slave {Auto} Clk_xbar {Auto} \
                  Master {/processing_system7_0/M_AXI_GP0} Slave {/axi_dma/S_AXI_LITE} \
                  ddr_seg {Auto} intc_ip {New AXI Interconnect} master_apm {0}] \
    [get_bd_intf_pins axi_dma/S_AXI_LITE]
apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
    -config [list Clk_master {Auto} Clk_slave {Auto} Clk_xbar {Auto} \
                  Master {/axi_dma/M_AXI_MM2S} Slave {/processing_system7_0/S_AXI_HP0} \
                  ddr_seg {Auto} intc_ip {New AXI Interconnect} master_apm {0}] \
    [get_bd_intf_pins processing_system7_0/S_AXI_HP0]
apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
    -config [list Clk_master {Auto} Clk_slave {Auto} Clk_xbar {Auto} \
                  Master {/axi_dma/M_AXI_S2MM} Slave {/processing_system7_0/S_AXI_HP0} \
                  ddr_seg {Auto} intc_ip {/axi_mem_intercon} master_apm {0}] \
    [get_bd_intf_pins axi_dma/M_AXI_S2MM]

proc stream {from to} { connect_bd_intf_net [get_bd_intf_pins $from] [get_bd_intf_pins $to] }
stream axi_dma/M_AXIS_MM2S                  svdd_flow_extract_0/s_axis
stream svdd_flow_extract_0/m_axis_features  svdd_preprocess_0/s_axis_raw
stream svdd_flow_extract_0/m_axis_meta      svdd_record_join_0/s_axis_meta
stream svdd_preprocess_0/m_axis_q24         deep_svdd_axis_0/s_axis_features
stream svdd_preprocess_0/m_axis_codes       svdd_record_join_0/s_axis_codes
stream deep_svdd_axis_0/m_axis_score        svdd_record_join_0/s_axis_score
stream svdd_record_join_0/m_axis            axi_dma/S_AXIS_S2MM

set rst [get_bd_cells -quiet -filter {VLNV =~ "*proc_sys_reset*"}]
foreach cell {svdd_flow_extract_0 svdd_preprocess_0 deep_svdd_axis_0 svdd_record_join_0} {
    connect_bd_net [get_bd_pins processing_system7_0/FCLK_CLK0] [get_bd_pins $cell/ap_clk]
    connect_bd_net [get_bd_pins [lindex $rst 0]/peripheral_aresetn] [get_bd_pins $cell/ap_rst_n]
}

assign_bd_address
validate_bd_design
save_bd_design

set bd_file [get_files $bd.bd]
set_property synth_checkpoint_mode None $bd_file
generate_target all $bd_file
make_wrapper -files $bd_file -top
add_files -norecurse [glob $build_dir/$proj.gen/sources_1/bd/$bd/hdl/${bd}_wrapper.v]
set_property top ${bd}_wrapper [current_fileset]
update_compile_order -fileset sources_1

# Synthesis, place and route inside this one Vivado process. launch_runs would start a
# second Vivado for synthesis while this one waits, and the two together went over the
# 6 GB cap on this PC.
# -flatten_hierarchy none: cross-boundary optimization of the flattened design went
# past 6 GB of RAM here; keeping the hierarchy holds synthesis near 3 GB.
set_param general.maxThreads 2
synth_design -top ${bd}_wrapper -part $part -flatten_hierarchy none
opt_design
place_design
phys_opt_design
route_design

# Plain paths (no glob): the space in "FPGA Project" breaks Tcl lists.
file mkdir $out_dir
write_bitstream -force "$out_dir/svdd_pl.bit"
file copy -force "$build_dir/$proj.gen/sources_1/bd/$bd/hw_handoff/$bd.hwh" "$out_dir/svdd_pl.hwh"
report_utilization -file $out_dir/utilization.rpt
report_timing_summary -file $out_dir/timing.rpt
report_timing -max_paths 30 -nworst 1 -sort_by slack -file $out_dir/timing_paths.rpt
set wns [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -setup]]
set whs [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -hold]]
puts "INFO: worst setup slack = $wns ns, worst hold slack = $whs ns"
if {$wns < 0 || $whs < 0} { puts "WARNING: timing NOT met; the overlay may misbehave." }
puts "INFO: overlay written to $out_dir"
