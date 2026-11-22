
wire kernel_monitor_reset;
wire kernel_monitor_clock;
wire kernel_monitor_report;
assign kernel_monitor_reset = ~ap_rst_n;
assign kernel_monitor_clock = ap_clk;
assign kernel_monitor_report = 1'b0;
wire [6:0] axis_block_sigs;
wire [12:0] inst_idle_sigs;
wire [2:0] inst_block_sigs;
wire kernel_block;

assign axis_block_sigs[0] = ~parse_U0.grp_parse_Pipeline_header_fu_417.s_axis_TDATA_blk_n;
assign axis_block_sigs[1] = ~parse_U0.grp_parse_Pipeline_drain_bad_fu_432.s_axis_TDATA_blk_n;
assign axis_block_sigs[2] = ~parse_U0.grp_parse_Pipeline_data_fu_445.s_axis_TDATA_blk_n;
assign axis_block_sigs[3] = ~parse_U0.grp_parse_Pipeline_drain_long_fu_587.s_axis_TDATA_blk_n;
assign axis_block_sigs[4] = ~emit_records_U0.grp_emit_records_Pipeline_meta_words1_fu_334.m_axis_meta_TDATA_blk_n;
assign axis_block_sigs[5] = ~emit_records_U0.grp_emit_records_Pipeline_feature_words_fu_364.m_axis_features_TDATA_blk_n;
assign axis_block_sigs[6] = ~emit_records_U0.grp_emit_records_Pipeline_meta_words_fu_379.m_axis_meta_TDATA_blk_n;

assign inst_idle_sigs[0] = parse_U0.ap_idle;
assign inst_block_sigs[0] = (parse_U0.ap_done & ~parse_U0.ap_continue) | ~parse_U0.pkts_blk_n | ~parse_U0.grp_parse_Pipeline_data_fu_445.pkts_blk_n | ~parse_U0.grp_p_anonymous_namespace_finish_frame_fu_536.pkts_blk_n;
assign inst_idle_sigs[1] = flow_table_U0.ap_idle;
assign inst_block_sigs[1] = (flow_table_U0.ap_done & ~flow_table_U0.ap_continue) | ~flow_table_U0.pkts_blk_n | ~flow_table_U0.flows_blk_n;
assign inst_idle_sigs[2] = emit_records_U0.ap_idle;
assign inst_block_sigs[2] = (emit_records_U0.ap_done & ~emit_records_U0.ap_continue) | ~emit_records_U0.flows_blk_n;

assign inst_idle_sigs[3] = 1'b0;
assign inst_idle_sigs[4] = parse_U0.ap_idle;
assign inst_idle_sigs[5] = parse_U0.grp_parse_Pipeline_header_fu_417.ap_idle;
assign inst_idle_sigs[6] = parse_U0.grp_parse_Pipeline_drain_bad_fu_432.ap_idle;
assign inst_idle_sigs[7] = parse_U0.grp_parse_Pipeline_data_fu_445.ap_idle;
assign inst_idle_sigs[8] = parse_U0.grp_parse_Pipeline_drain_long_fu_587.ap_idle;
assign inst_idle_sigs[9] = emit_records_U0.ap_idle;
assign inst_idle_sigs[10] = emit_records_U0.grp_emit_records_Pipeline_meta_words1_fu_334.ap_idle;
assign inst_idle_sigs[11] = emit_records_U0.grp_emit_records_Pipeline_feature_words_fu_364.ap_idle;
assign inst_idle_sigs[12] = emit_records_U0.grp_emit_records_Pipeline_meta_words_fu_379.ap_idle;

svdd_flow_extract_hls_deadlock_idx0_monitor svdd_flow_extract_hls_deadlock_idx0_monitor_U (
    .clock(kernel_monitor_clock),
    .reset(kernel_monitor_reset),
    .axis_block_sigs(axis_block_sigs),
    .inst_idle_sigs(inst_idle_sigs),
    .inst_block_sigs(inst_block_sigs),
    .block(kernel_block)
);


always @ (kernel_block or kernel_monitor_reset) begin
    if (kernel_block == 1'b1 && kernel_monitor_reset == 1'b0) begin
        find_kernel_block = 1'b1;
    end
    else begin
        find_kernel_block = 1'b0;
    end
end
