# Prepare the simulation of one board's overlay: the block design from ../build_overlay.tcl
# (Zynq PS, AXI DMA, the four IPs) plus tb_svdd_pl.sv. run_sim.sh calls this, then runs
# the generated compile and elaborate scripts and the simulator itself, so Vivado is not
# holding memory while xsim runs.
#
#   vivado -mode batch -source sim_overlay.tcl -tclargs pynq-z2|zedboard
#
# Output: build_<board>/svdd_pl_overlay.sim/sim_1/behav/xsim/ with compile.sh,
# elaborate.sh, the IP memory files, and dma_base (the DMA's address on M_AXI_GP0).
set board  [lindex $argv 0]
set tb_dir [file dirname [file normalize [info script]]]

# build_overlay.tcl makes the project and the block design exactly as for the bitstream.
# With ::svdd_sim_build set it uses that folder and stops after save_bd_design.
set ::svdd_sim_build "$tb_dir/build_$board"
source [file normalize "$tb_dir/../build_overlay.tcl"]

set bd_file [get_files $bd.bd]
generate_target simulation $bd_file
make_wrapper -files $bd_file -top
# [list ...]: a plain string with the space in "FPGA Project" would be split into two files
add_files -norecurse [list "$build_dir/$proj.gen/sources_1/bd/$bd/hdl/${bd}_wrapper.v"]
set_property top ${bd}_wrapper [current_fileset]

set sim [get_filesets sim_1]
add_files -fileset $sim -norecurse [list "$tb_dir/tb_svdd_pl.sv"]
set_property top tb_svdd_pl $sim
set_property top_lib xil_defaultlib $sim
update_compile_order -fileset $sim

# Where M_AXI_GP0 sees the DMA's registers (0x40400000 on both boards, but read it anyway)
set segs [get_bd_addr_segs -of_objects [get_bd_addr_spaces processing_system7_0/Data]]
set dma_seg [lindex [lsearch -all -inline -glob $segs *axi_dma*] 0]
if {$dma_seg eq ""} { error "no axi_dma segment in the PS address map: $segs" }
set dma_base [format %08x [get_property OFFSET $dma_seg]]
puts "INFO: AXI DMA registers at 0x$dma_base"

# Settings for "Run Simulation" in the Vivado GUI on this project: the waveform groups,
# run to the end, and the plusargs. Paths are relative to the simulation folder, so the
# space in "FPGA Project" never reaches xsim's command line.
proc relpath {from to} {
    set f [file split [file normalize $from]]
    set t [file split [file normalize $to]]
    set i 0
    while {$i < [llength $f] && $i < [llength $t] && [lindex $f $i] eq [lindex $t $i]} { incr i }
    return [join [concat [lrepeat [expr {[llength $f] - $i}] ..] [lrange $t $i end]] /]
}
set sim_dir "$build_dir/$proj.sim/sim_1/behav/xsim"
set data [relpath $sim_dir "$root/hls/tb_data"]
add_files -fileset $sim -norecurse [list "$tb_dir/tb_svdd_pl.wcfg"]
set_property -name {xsim.view} -value [list "$tb_dir/tb_svdd_pl.wcfg"] -objects $sim
set_property -name {xsim.simulate.runtime} -value {all} -objects $sim
set_property -name {xsim.simulate.log_all_signals} -value {false} -objects $sim
set_property -name {xsim.simulate.xsim.more_options} -objects $sim -value \
    "-testplusarg dma_base=$dma_base -testplusarg stream=$data/small_stream.bin -testplusarg expect=$data/small_out.bin"

launch_simulation -simset $sim -mode behavioral -scripts_only
set f [open "$sim_dir/dma_base" w]
puts $f $dma_base
close $f
puts "INFO: simulation scripts in $sim_dir"
