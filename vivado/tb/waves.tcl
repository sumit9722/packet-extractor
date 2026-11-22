# Waveform groups: the PL streams in data-flow order. Signal names are the taps at the top
# of tb_svdd_pl.sv. tb_svdd_pl.wcfg (what Vivado opens) was saved from this script:
#   in an xsim of the testbench:  source waves.tcl; save_wave_config tb_svdd_pl.wcfg
set tb /tb_svdd_pl

proc group {name signals} {
    global tb
    set g [add_wave_group $name]
    foreach {sig radix} $signals {
        add_wave -into $g -radix $radix $tb/$sig
    }
}

group "PL clock and reset (FCLK_CLK0, proc_sys_reset)" {
    clk bin  rst_n bin
}
group "1. AXI DMA MM2S -> svdd_flow_extract: pcap chunks, 64-bit" {
    in_tvalid bin  in_tready bin  in_tlast bin  in_tdata hex
}
group "2. svdd_flow_extract m_axis_features: 8 raw features per flow (spec section 2)" {
    feat_tvalid bin  feat_tready bin  feat_tlast bin  feat_tuser bin  feat_tkeep hex  feat_tdata unsigned
    feat_flow unsigned  feat_beat unsigned
}
group "3. svdd_preprocess -> deep_svdd_axis: 8 Q24 codes per flow" {
    q24_tvalid bin  q24_tready bin  q24_tlast bin  q24_tdata dec  q24_flow unsigned
}
group "4. deep_svdd_axis m_axis_score: score code (32 fraction bits)" {
    score_tvalid bin  score_tready bin  score_tdata unsigned  score_flow unsigned
}
group "5. svdd_flow_extract m_axis_meta: flow identity for the join" {
    meta_tvalid bin  meta_tready bin  meta_tlast bin  meta_tdata hex
}
group "6. svdd_preprocess m_axis_codes: copy of the codes for the join" {
    codes_tvalid bin  codes_tready bin  codes_tlast bin  codes_tdata dec
}
group "7. svdd_record_join -> AXI DMA S2MM: 128-byte records, 64-bit" {
    out_tvalid bin  out_tready bin  out_tlast bin  out_tdata hex
}
group "Test 2: spec bring-up vector -> second svdd_preprocess + deep_svdd_axis" {
    bu_tvalid bin  bu_tready bin  bu_tlast bin  bu_tuser bin  bu_tkeep hex  bu_tdata unsigned
    bu_q_tvalid bin  bu_q_tlast bin  bu_q_tdata dec  bu_s_tvalid bin  bu_s_tdata unsigned
}
group "Progress" {
    chunks unsigned  flows unsigned  errors unsigned
}
