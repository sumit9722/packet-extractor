open_saif pl_activity.saif
log_saif [get_objects /tb_svdd_pl/dut/svdd_pl_i/*]
foreach scope [get_scopes /tb_svdd_pl/dut/svdd_pl_i/*] {
    if {![string match */processing_system7_0 $scope]} { log_saif [get_objects -r $scope/*] }
}
run all
close_saif
quit
