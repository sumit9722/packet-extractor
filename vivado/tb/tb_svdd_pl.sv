// Testbench for the pynq-pl overlay: the whole block design of one board, exactly as
// ../build_overlay.tcl builds it for the bitstream, driven the way svdd_pl/driver.py drives
// the real board.
//
//   Zynq PS (Xilinx VIP model)                 PL (the block design, unchanged)
//   ─────────────────────────────────          ──────────────────────────────────────────────
//   M_AXI_GP0  ── AXI-Lite ─────────────────►  axi_dma registers
//   DDR model  ◄── S_AXI_HP0 ──── MM2S/S2MM ─  axi_dma ──► svdd_flow_extract ──► svdd_preprocess
//                                                 ▲              │ meta              │ q24   │ codes
//                                                 │              ▼                   ▼       │
//                                                 └──── svdd_record_join ◄── deep_svdd_axis ◄┘
//
// Test 1, the full PL with a real UNSW-NB15 capture (sim_overlay.tcl passes the files):
//   for each chunk of the stream file (the same 32-byte header + pcap bytes the board sends)
//     - write the chunk into the DDR model at IN_ADDR (backdoor, no simulation time)
//     - program the AXI DMA over M_AXI_GP0 like AxiDma in driver.py: arm the S2MM receive,
//       start the MM2S send, poll DMASR for IOC, read S2MM_LENGTH, re-arm until the
//       chunk's marker record has arrived
//     - read the records back from the DDR model and compare every 64-bit word with the
//       expected output (the C model's output, hls/tb_data/small_out.bin)
//   while monitors inside the block design check
//     - the handoff spec framing of m_axis_features: 8 beats per flow, TLAST on word 7 only,
//       TKEEP = TSTRB = 4'hF, TUSER = 0                                            [spec 2]
//     - the AXI4-Stream rule on every PL stream: TVALID, TDATA and TLAST hold while TVALID
//       waits for TREADY
//     - each flow's 8 feature words, its 8 Q24 codes into deep_svdd_axis and its score
//       against the expected record
//
// Test 2, the extractor -> model interface on its own: a separate svdd_preprocess +
//   deep_svdd_axis pair (the same RTL as in the block design) gets
//     - the spec section 4 bring-up vector        -> codes 41347 ... 17476, score 51193
//     - a frame with an early TLAST and one with TKEEP != F   -> both dropped
//     - the bring-up vector with TUSER = 1 on every word      -> the saved medians' codes
//
// Use in a Vivado project that has the svdd_pl block design (e.g. the bitstream project
// vivado/build_pynq-z2 or vivado/build_zedboard made by ../build_overlay.tcl):
//   1. Add Sources -> Add or create simulation sources -> this file; set tb_svdd_pl as top
//   2. Run Behavioral Simulation, then "run all" in the Tcl console (or set
//      xsim.simulate.runtime to "all"). The whole run is about 5 ms of simulated time.
// Nothing else is needed. Optional plusargs (xsim.simulate.xsim.more_options):
//   -testplusarg max_chunks=1   only the first chunk (under a minute; 0 = all 6)
//   -testplusarg stream=FILE  -testplusarg expect=FILE  -testplusarg out=FILE  -testplusarg dma_base=HEX
// The last line is "TEST PASSED" or "TEST FAILED".
`timescale 1ns / 1ps

// AXI4-Stream rule check on one stream: once TVALID is high it stays high, with TDATA and
// TLAST unchanged, until TREADY takes the beat. Also counts beats.
module axis_rules #(
    parameter string NAME = "",
    parameter int W = 32
) (
    input logic clk,
    input logic rst_n,
    input logic tvalid,
    input logic tready,
    input logic tlast,
    input logic [W-1:0] tdata
);
    logic held = 0, last_q;
    logic [W-1:0] data_q;
    int errors = 0;
    longint beats = 0;
    always @(posedge clk) begin
        if (rst_n !== 1'b1) begin
            held <= 0;
        end else begin
            if ($isunknown(tvalid) || (tvalid && $isunknown(tready))) begin
                errors++;
                if (errors <= 5) $error("[%s] TVALID or TREADY is X", NAME);
            end
            if (held && (tvalid !== 1'b1 || tdata !== data_q || tlast !== last_q)) begin
                errors++;
                if (errors <= 5) $error("[%s] TVALID/TDATA/TLAST changed before TREADY took the beat", NAME);
            end
            held   <= tvalid && !tready;
            data_q <= tdata;
            last_q <= tlast;
            if (tvalid && tready) beats++;
        end
    end
endmodule


module tb_svdd_pl;

    // ------------------------------------------------------------------ settings
    // Defaults work in any project with the svdd_pl block design; plusargs override them.
    string stream_file = "";                  // "" = find hls/tb_data/small_stream.bin
    string expect_file = "";                  // "" = find hls/tb_data/small_out.bin
    string out_file = "pl_out.bin";
    logic [31:0] dma_base = 32'h41E0_0000;    // where assign_bd_address puts axi_dma (both boards)
    int max_chunks = 0;

    // The test data in pynq-pl/hls/tb_data, looked for in the simulation folder of the
    // bitstream project (vivado/build_<board>), of the tb project (vivado/tb/build_<board>),
    // and at its absolute path.
    localparam string DATA_DIR = "/home/chilsu/Documents/FPGA Project/Deep SVDD/pynq-pl/hls/tb_data/";
    function automatic string find_data(input string given, input string local_name, input string file_name);
        string tries[$];
        if (given != "") return given;
        tries.push_back(local_name);
        tries.push_back({"../../../../../../hls/tb_data/", file_name});
        tries.push_back({"../../../../../../../hls/tb_data/", file_name});
        tries.push_back({DATA_DIR, file_name});
        foreach (tries[i]) begin
            int fd = $fopen(tries[i], "rb");
            if (fd != 0) begin
                $fclose(fd);
                return tries[i];
            end
        end
        return {DATA_DIR, file_name};
    endfunction

    // The DMA buffers driver.py uses with the devmem driver (top 8 MB of the 512 MB DDR).
    localparam logic [31:0] IN_ADDR = 32'h1F80_0000;
    localparam logic [31:0] OUT_ADDR = 32'h1FC0_0000;
    localparam int OUT_BYTES = 1 << 16;               // receive length armed each time
    localparam int REC_WORDS = 16, REC_BYTES = 128, GROUP_RECORDS = 256;
    localparam logic [7:0] REC_FLOW = 8'hF1, REC_MARKER = 8'hA5;

    // AXI DMA simple-mode registers and bits (PG021), the same names as in driver.py
    localparam logic [31:0] MM2S_DMACR = 'h00, MM2S_DMASR = 'h04, MM2S_SA = 'h18, MM2S_LENGTH = 'h28;
    localparam logic [31:0] S2MM_DMACR = 'h30, S2MM_DMASR = 'h34, S2MM_DA = 'h48, S2MM_LENGTH = 'h58;
    localparam logic [31:0] CR_RUN = 1, CR_RESET = 4, SR_HALTED = 1, SR_IOC = 1 << 12, SR_ERRORS = 'h70;
    localparam logic [31:0] SR_CLEAR = (1 << 12) | (1 << 14);

    // ------------------------------------------------------------------ the board's block design
    // The Zynq model only needs its clock and reset pins; DDR and MIO pins stay open. The
    // model makes FCLK_CLK0 (100 MHz) itself, so PS_CLK only has to toggle.
    logic ps_clk = 0, ps_rst_n = 0;
    always #10 ps_clk = ~ps_clk;
    wire ps_clk_w = ps_clk, ps_porb_w = ps_rst_n, ps_srstb_w = ps_rst_n;

    svdd_pl_wrapper dut (
        .FIXED_IO_ps_clk  (ps_clk_w),
        .FIXED_IO_ps_porb (ps_porb_w),
        .FIXED_IO_ps_srstb(ps_srstb_w)
    );

`define PS dut.svdd_pl_i.processing_system7_0.inst
`define BD dut.svdd_pl_i

    wire clk = `BD.processing_system7_0.FCLK_CLK0;
    wire rst_n = `BD.svdd_flow_extract_0.ap_rst_n;        // from proc_sys_reset

    // Named taps on the PL streams (shorter names in the waveform window too)
    wire        in_tvalid = `BD.svdd_flow_extract_0.s_axis_TVALID;          // DMA MM2S -> extractor
    wire        in_tready = `BD.svdd_flow_extract_0.s_axis_TREADY;
    wire [63:0] in_tdata = `BD.svdd_flow_extract_0.s_axis_TDATA;
    wire        in_tlast = `BD.svdd_flow_extract_0.s_axis_TLAST;

    wire        feat_tvalid = `BD.svdd_flow_extract_0.m_axis_features_TVALID;  // spec stream
    wire        feat_tready = `BD.svdd_flow_extract_0.m_axis_features_TREADY;
    wire [31:0] feat_tdata = `BD.svdd_flow_extract_0.m_axis_features_TDATA;
    wire [ 3:0] feat_tkeep = `BD.svdd_flow_extract_0.m_axis_features_TKEEP;
    wire [ 3:0] feat_tstrb = `BD.svdd_flow_extract_0.m_axis_features_TSTRB;
    wire [ 0:0] feat_tuser = `BD.svdd_flow_extract_0.m_axis_features_TUSER;
    wire        feat_tlast = `BD.svdd_flow_extract_0.m_axis_features_TLAST;

    wire        meta_tvalid = `BD.svdd_flow_extract_0.m_axis_meta_TVALID;      // extractor -> join
    wire        meta_tready = `BD.svdd_flow_extract_0.m_axis_meta_TREADY;
    wire [63:0] meta_tdata = `BD.svdd_flow_extract_0.m_axis_meta_TDATA;
    wire        meta_tlast = `BD.svdd_flow_extract_0.m_axis_meta_TLAST;

    wire        q24_tvalid = `BD.deep_svdd_axis_0.s_axis_features_TVALID;      // preprocess -> model
    wire        q24_tready = `BD.deep_svdd_axis_0.s_axis_features_TREADY;
    wire [31:0] q24_tdata = `BD.deep_svdd_axis_0.s_axis_features_TDATA;
    wire        q24_tlast = `BD.deep_svdd_axis_0.s_axis_features_TLAST;

    wire        codes_tvalid = `BD.svdd_preprocess_0.m_axis_codes_TVALID;      // preprocess -> join
    wire        codes_tready = `BD.svdd_preprocess_0.m_axis_codes_TREADY;
    wire [31:0] codes_tdata = `BD.svdd_preprocess_0.m_axis_codes_TDATA;
    wire        codes_tlast = `BD.svdd_preprocess_0.m_axis_codes_TLAST;

    wire        score_tvalid = `BD.deep_svdd_axis_0.m_axis_score_TVALID;       // model -> join
    wire        score_tready = `BD.deep_svdd_axis_0.m_axis_score_TREADY;
    wire [63:0] score_tdata = `BD.deep_svdd_axis_0.m_axis_score_TDATA;
    wire        score_tlast = `BD.deep_svdd_axis_0.m_axis_score_TLAST;

    wire        out_tvalid = `BD.svdd_record_join_0.m_axis_TVALID;             // join -> DMA S2MM
    wire        out_tready = `BD.svdd_record_join_0.m_axis_TREADY;
    wire [63:0] out_tdata = `BD.svdd_record_join_0.m_axis_TDATA;
    wire        out_tlast = `BD.svdd_record_join_0.m_axis_TLAST;

    axis_rules #(.NAME("dma -> svdd_flow_extract"), .W(64)) rules_in (clk, rst_n, in_tvalid, in_tready, in_tlast, in_tdata);
    axis_rules #(.NAME("m_axis_features"), .W(32)) rules_feat (clk, rst_n, feat_tvalid, feat_tready, feat_tlast, feat_tdata);
    axis_rules #(.NAME("m_axis_meta"), .W(64)) rules_meta (clk, rst_n, meta_tvalid, meta_tready, meta_tlast, meta_tdata);
    axis_rules #(.NAME("q24 -> deep_svdd_axis"), .W(32)) rules_q24 (clk, rst_n, q24_tvalid, q24_tready, q24_tlast, q24_tdata);
    axis_rules #(.NAME("m_axis_codes"), .W(32)) rules_codes (clk, rst_n, codes_tvalid, codes_tready, codes_tlast, codes_tdata);
    axis_rules #(.NAME("m_axis_score"), .W(64)) rules_score (clk, rst_n, score_tvalid, score_tready, score_tlast, score_tdata);
    axis_rules #(.NAME("svdd_record_join -> dma"), .W(64)) rules_out (clk, rst_n, out_tvalid, out_tready, out_tlast, out_tdata);

    // ------------------------------------------------------------------ expected results
    // The expected output words, and per flow (in output order) the 8 feature words, the
    // 8 codes and the score taken from its record.
    logic [63:0] exp_words[$];
    logic [31:0] exp_feat[$][8];
    logic [31:0] exp_code[$][8];
    logic [63:0] exp_score[$];

    function automatic logic [31:0] sat32(input logic [63:0] v);
        return v > 64'hFFFF_FFFF ? 32'hFFFF_FFFF : v[31:0];
    endfunction

    task automatic load_expected();
        int fd, c;
        logic [63:0] w;
        fd = $fopen(expect_file, "rb");
        if (fd == 0) $fatal(1, "cannot open the expected output %s", expect_file);
        forever begin
            w = 0;
            for (int i = 0; i < 8; i++) begin
                c = $fgetc(fd);
                if (c < 0) break;
                w[8*i+:8] = c[7:0];
            end
            if (c < 0) break;
            exp_words.push_back(w);
        end
        $fclose(fd);
        if (exp_words.size() % REC_WORDS != 0) $fatal(1, "%s is not a whole number of 128-byte records", expect_file);
        for (int r = 0; r < exp_words.size() / REC_WORDS; r++) begin
            logic [63:0] rec[REC_WORDS];
            logic [31:0] f[8], k[8];
            for (int i = 0; i < REC_WORDS; i++) rec[i] = exp_words[r*REC_WORDS+i];
            if (rec[0][7:0] != REC_FLOW) continue;
            f = '{sat32(rec[5]), sat32(rec[6]), sat32(rec[7]), rec[8][15:0], rec[8][31:16], rec[8][47:32],
                  rec[9][15:0], rec[9][31:16]};
            for (int i = 0; i < 4; i++) begin
                k[2*i]   = rec[10+i][31:0];
                k[2*i+1] = rec[10+i][63:32];
            end
            exp_feat.push_back(f);
            exp_code.push_back(k);
            exp_score.push_back(rec[14]);
        end
        $display("[tb] expected: %0d records, %0d flows (%s)", exp_words.size() / REC_WORDS, exp_feat.size(), expect_file);
    endtask

    // ------------------------------------------------------------------ monitors on the PL streams
    int errors = 0;
    task automatic fail(input string msg);
        errors++;
        if (errors <= 20) $error("%s", msg);
        else if (errors == 21) $display("[tb] (further errors not shown)");
    endtask

    // Feature stream: spec framing + values. TLAST must be on word 7 and nowhere else.
    int feat_flow = 0, feat_beat = 0;
    always @(posedge clk) if (rst_n === 1'b1 && feat_tvalid && feat_tready) begin
        if (feat_tkeep !== 4'hF || feat_tstrb !== 4'hF)
            fail($sformatf("m_axis_features flow %0d word %0d: TKEEP=%h TSTRB=%h, spec says F", feat_flow, feat_beat, feat_tkeep, feat_tstrb));
        if (feat_tuser !== 1'b0)
            fail($sformatf("m_axis_features flow %0d word %0d: TUSER=%b, every field is measured here", feat_flow, feat_beat, feat_tuser));
        if (feat_tlast !== (feat_beat == 7))
            fail($sformatf("m_axis_features flow %0d word %0d: TLAST=%b, spec says TLAST on word 7 only", feat_flow, feat_beat, feat_tlast));
        if (feat_flow < exp_feat.size() && feat_tdata !== exp_feat[feat_flow][feat_beat])
            fail($sformatf("m_axis_features flow %0d word %0d: %0d, expected %0d", feat_flow, feat_beat, feat_tdata, exp_feat[feat_flow][feat_beat]));
        if (feat_beat == 7) begin
            feat_beat <= 0;
            feat_flow <= feat_flow + 1;
        end else feat_beat <= feat_beat + 1;
    end

    // Q24 codes going into deep_svdd_axis: Q24 code sign-extended to 32 bits, TLAST on word 7.
    int q24_flow = 0, q24_beat = 0;
    always @(posedge clk) if (rst_n === 1'b1 && q24_tvalid && q24_tready) begin
        if (q24_tlast !== (q24_beat == 7))
            fail($sformatf("deep_svdd_axis input flow %0d word %0d: TLAST=%b", q24_flow, q24_beat, q24_tlast));
        if (q24_tdata[31:24] !== {8{q24_tdata[23]}})
            fail($sformatf("deep_svdd_axis input flow %0d word %0d: %h is not a sign-extended 24-bit code", q24_flow, q24_beat, q24_tdata));
        if (q24_flow < exp_code.size() && q24_tdata !== exp_code[q24_flow][q24_beat])
            fail($sformatf("deep_svdd_axis input flow %0d word %0d: code %0d, expected %0d", q24_flow, q24_beat,
                           $signed(q24_tdata), $signed(exp_code[q24_flow][q24_beat])));
        if (q24_beat == 7) begin
            q24_beat <= 0;
            q24_flow <= q24_flow + 1;
        end else q24_beat <= q24_beat + 1;
    end

    // Scores out of deep_svdd_axis
    int score_flow = 0;
    always @(posedge clk) if (rst_n === 1'b1 && score_tvalid && score_tready) begin
        if (score_flow < exp_score.size() && score_tdata !== exp_score[score_flow])
            fail($sformatf("deep_svdd_axis score of flow %0d: %0d, expected %0d", score_flow, score_tdata, exp_score[score_flow]));
        score_flow <= score_flow + 1;
    end

    // ------------------------------------------------------------------ PS side: the driver.py sequence
    logic [1:0] resp;

    task automatic reg_write(input logic [31:0] off, input logic [31:0] value);
        `PS.write_data(dma_base + off, 4, value, resp);
        if (resp !== 2'b00) fail($sformatf("AXI-Lite write to DMA offset 0x%02h: response %b", off, resp));
    endtask

    task automatic reg_read(input logic [31:0] off, output logic [31:0] value);
        logic [2047:0] data;
        `PS.read_data(dma_base + off, 4, data, resp);
        if (resp !== 2'b00) fail($sformatf("AXI-Lite read of DMA offset 0x%02h: response %b", off, resp));
        value = data[31:0];
    endtask

    // AxiDma.reset(): reset, then set RUN on both channels and wait until they are not halted
    task automatic dma_reset();
        logic [31:0] v;
        reg_write(MM2S_DMACR, CR_RESET);
        do reg_read(MM2S_DMACR, v); while (v & CR_RESET);
        reg_write(MM2S_DMACR, CR_RUN);
        do reg_read(MM2S_DMASR, v); while (v & SR_HALTED);
        reg_write(S2MM_DMACR, CR_RUN);
        do reg_read(S2MM_DMASR, v); while (v & SR_HALTED);
    endtask

    task automatic start_recv(input logic [31:0] phys, input int nbytes);
        reg_write(S2MM_DMASR, SR_CLEAR);
        reg_write(S2MM_DA, phys);
        reg_write(S2MM_LENGTH, nbytes);
    endtask

    task automatic start_send(input logic [31:0] phys, input int nbytes);
        reg_write(MM2S_DMASR, SR_CLEAR);
        reg_write(MM2S_SA, phys);
        reg_write(MM2S_LENGTH, nbytes);
    endtask

    // AxiDma.wait(): poll DMASR until IOC (or an error), with a 20 ms simulated-time limit
    task automatic dma_wait(input logic [31:0] sr_off, input string what, output bit ok);
        logic [31:0] sr;
        realtime t0 = $realtime;
        ok = 0;
        forever begin
            reg_read(sr_off, sr);
            if (sr & SR_ERRORS) begin
                fail($sformatf("DMA %s error, DMASR 0x%08h", what, sr));
                return;
            end
            if (sr & SR_IOC) begin
                ok = 1;
                return;
            end
            if ($realtime - t0 > 20_000_000) begin
                fail($sformatf("DMA %s did not finish within 20 ms of simulated time (DMASR 0x%08h)", what, sr));
                return;
            end
            #500;
        end
    endtask

    // Backdoor copies between the testbench and the Zynq model's DDR (128 bytes per call)
    task automatic ddr_write(input logic [31:0] addr, ref byte unsigned bytes[$]);
        for (int off = 0; off < bytes.size(); off += 128) begin
            logic [1023:0] d = '0;
            int n = bytes.size() - off < 128 ? bytes.size() - off : 128;
            for (int i = 0; i < n; i++) d[8*i+:8] = bytes[off+i];
            `PS.write_mem(d, addr + off, n);
        end
    endtask

    task automatic ddr_read_words(input logic [31:0] addr, input int nbytes, ref logic [63:0] words[$]);
        for (int off = 0; off < nbytes; off += 128) begin
            logic [1023:0] d;
            int n = nbytes - off < 128 ? nbytes - off : 128;
            `PS.read_mem(addr + off, n, d);
            for (int i = 0; i < n / 8; i++) words.push_back(d[64*i+:64]);
        end
    endtask

    // ------------------------------------------------------------------ test 1: the full PL
    int out_fd;
    int exp_pos = 0;          // next expected word
    int chunks = 0, flows = 0, markers = 0, anomalies = 0, receives = 0;
    longint cycles = 0;
    always @(posedge clk) cycles++;
    logic [63:0] last_marker[REC_WORDS];

    // One chunk through the PL, as PLEngine.process() does it on the board
    task automatic run_chunk(ref byte unsigned chunk[$]);
        logic [63:0] got[$];
        bit ok, done = 0;
        ddr_write(IN_ADDR, chunk);
        start_recv(OUT_ADDR, OUT_BYTES);           // receive armed first
        start_send(IN_ADDR, chunk.size());
        while (!done) begin
            logic [31:0] n;
            int first = got.size();
            dma_wait(S2MM_DMASR, "receive", ok);
            if (!ok) return;
            reg_read(S2MM_LENGTH, n);
            receives++;
            if (n == 0 || n % REC_BYTES != 0 || n > (GROUP_RECORDS + 1) * REC_BYTES) begin
                fail($sformatf("chunk %0d: one S2MM transfer brought %0d bytes, not a whole number of records <= %0d",
                               chunks, n, (GROUP_RECORDS + 1) * REC_BYTES));
                return;
            end
            ddr_read_words(OUT_ADDR, n, got);
            done = got[got.size()-REC_WORDS][7:0] == REC_MARKER;
            if (!done && n != GROUP_RECORDS * REC_BYTES)
                fail($sformatf("chunk %0d: TLAST after %0d records with no marker; the join IP closes groups of %0d",
                               chunks, n / REC_BYTES, GROUP_RECORDS));
            if (!done) start_recv(OUT_ADDR, OUT_BYTES);   // a full group of 256: keep receiving
        end
        dma_wait(MM2S_DMASR, "send", ok);

        // Compare with the expected words of this chunk, record by record
        for (int r = 0; r < got.size() / REC_WORDS; r++) begin
            logic [63:0] w0 = got[r*REC_WORDS];
            if (w0[7:0] == REC_FLOW) begin
                flows++;
                anomalies += w0[24];
            end else if (w0[7:0] == REC_MARKER) begin
                markers++;
                for (int i = 0; i < REC_WORDS; i++) last_marker[i] = got[r*REC_WORDS+i];
                if (w0[15:8] != 0) fail($sformatf("chunk %0d: marker reports chunk error flags 0x%02h", chunks, w0[15:8]));
            end else fail($sformatf("chunk %0d record %0d: unknown record type 0x%02h", chunks, r, w0[7:0]));
            for (int i = 0; i < REC_WORDS; i++) begin
                int p = exp_pos + r * REC_WORDS + i;
                if (p >= exp_words.size()) begin
                    fail($sformatf("chunk %0d: more output than expected (record %0d)", chunks, r));
                    break;
                end
                if (got[r*REC_WORDS+i] !== exp_words[p])
                    fail($sformatf("chunk %0d record %0d (%s) word %0d: got %h, expected %h", chunks, r,
                                   w0[7:0] == REC_MARKER ? "marker" : "flow", i, got[r*REC_WORDS+i], exp_words[p]));
            end
        end
        exp_pos += got.size();
        foreach (got[i]) for (int b = 0; b < 8; b++) $fwrite(out_fd, "%c", got[i][8*b+:8]);
        $display("[tb] chunk %0d: %0d bytes in, %0d records out, %0d flows so far, t = %0t", chunks, chunk.size(),
                 got.size() / REC_WORDS, flows, $time);
    endtask

    task automatic test_full_pl();
        int fd, c;
        longint start_cycles;
        fd = $fopen(stream_file, "rb");
        if (fd == 0) $fatal(1, "cannot open the stream file %s", stream_file);
        out_fd = $fopen(out_file, "wb");
        dma_reset();
        start_cycles = cycles;
        forever begin
            byte unsigned chunk[$];
            int unsigned len = 0;
            for (int i = 0; i < 4; i++) begin
                c = $fgetc(fd);
                if (c < 0) break;
                len |= int'(c[7:0]) << (8 * i);
            end
            if (c < 0) break;
            for (int i = 0; i < len; i++) chunk.push_back($fgetc(fd));
            run_chunk(chunk);
            chunks++;
            if (errors > 50 || (max_chunks > 0 && chunks >= max_chunks)) break;
        end
        $fclose(fd);
        $fclose(out_fd);
        if (max_chunks == 0 && exp_pos != exp_words.size())
            fail($sformatf("got %0d output words, expected %0d", exp_pos, exp_words.size()));
        $display("[tb] test 1 (full PL): %0d chunks, %0d flows, %0d markers, %0d S2MM transfers, %0d anomalies",
                 chunks, flows, markers, receives, anomalies);
        $display("[tb]   last marker: frames %0d, IPv4 %0d, other %0d, malformed %0d, flows %0d, evicted %0d, peak open %0d",
                 last_marker[2], last_marker[3], last_marker[4], last_marker[5], last_marker[6], last_marker[7], last_marker[9]);
        $display("[tb]   %0d clocks of FCLK0 including the PS polling, %.1f clocks per packet",
                 cycles - start_cycles, real'(cycles - start_cycles) / real'(last_marker[2] > 0 ? last_marker[2] : 1));
        $display("[tb]   stream monitors: %0d feature frames, %0d Q24 frames, %0d scores", feat_flow, q24_flow, score_flow);
        if (feat_flow != flows || q24_flow != flows || score_flow != flows)
            fail($sformatf("stream monitors saw %0d / %0d / %0d flows, the DMA returned %0d", feat_flow, q24_flow, score_flow, flows));
    endtask

    // ------------------------------------------------------------------ test 2: extractor -> model interface
    // A second svdd_preprocess -> deep_svdd_axis pair, wired like in the block design,
    // fed straight from the testbench as the spec's feature stream.
    logic [31:0] bu_tdata = 0;
    logic bu_tvalid = 0, bu_tlast = 0;
    logic [3:0] bu_tkeep = 4'hF;
    logic [0:0] bu_tuser = 0;
    wire bu_tready;
    wire [31:0] bu_q_tdata, bu_c_tdata;
    wire [3:0] bu_q_tkeep, bu_q_tstrb, bu_c_tkeep, bu_c_tstrb;
    wire bu_q_tvalid, bu_q_tready, bu_q_tlast, bu_c_tvalid, bu_c_tlast;
    wire [63:0] bu_s_tdata;
    wire [7:0] bu_s_tkeep, bu_s_tstrb;
    wire bu_s_tvalid, bu_s_tlast;

    svdd_preprocess bu_pre (
        .ap_clk(clk), .ap_rst_n(rst_n),
        .s_axis_raw_TDATA(bu_tdata), .s_axis_raw_TVALID(bu_tvalid), .s_axis_raw_TREADY(bu_tready),
        .s_axis_raw_TKEEP(bu_tkeep), .s_axis_raw_TSTRB(bu_tkeep), .s_axis_raw_TUSER(bu_tuser), .s_axis_raw_TLAST(bu_tlast),
        .m_axis_q24_TDATA(bu_q_tdata), .m_axis_q24_TVALID(bu_q_tvalid), .m_axis_q24_TREADY(bu_q_tready),
        .m_axis_q24_TKEEP(bu_q_tkeep), .m_axis_q24_TSTRB(bu_q_tstrb), .m_axis_q24_TLAST(bu_q_tlast),
        .m_axis_codes_TDATA(bu_c_tdata), .m_axis_codes_TVALID(bu_c_tvalid), .m_axis_codes_TREADY(1'b1),
        .m_axis_codes_TKEEP(bu_c_tkeep), .m_axis_codes_TSTRB(bu_c_tstrb), .m_axis_codes_TLAST(bu_c_tlast)
    );
    deep_svdd_axis bu_svdd (
        .ap_clk(clk), .ap_rst_n(rst_n),
        .s_axis_features_TDATA(bu_q_tdata), .s_axis_features_TVALID(bu_q_tvalid), .s_axis_features_TREADY(bu_q_tready),
        .s_axis_features_TKEEP(bu_q_tkeep), .s_axis_features_TSTRB(bu_q_tstrb), .s_axis_features_TLAST(bu_q_tlast),
        .m_axis_score_TDATA(bu_s_tdata), .m_axis_score_TVALID(bu_s_tvalid), .m_axis_score_TREADY(1'b1),
        .m_axis_score_TKEEP(bu_s_tkeep), .m_axis_score_TSTRB(bu_s_tstrb), .m_axis_score_TLAST(bu_s_tlast)
    );

    logic [31:0] bu_codes[$];
    logic [63:0] bu_scores[$];
    always @(posedge clk) if (rst_n === 1'b1) begin
        if (bu_q_tvalid && bu_q_tready) bu_codes.push_back(bu_q_tdata);
        if (bu_s_tvalid) bu_scores.push_back(bu_s_tdata);
    end

    task automatic bu_beat(input logic [31:0] d, input bit last, input logic [3:0] keep, input bit user);
        @(negedge clk);
        bu_tdata  = d;
        bu_tlast  = last;
        bu_tkeep  = keep;
        bu_tuser  = user;
        bu_tvalid = 1;
        @(posedge clk);
        while (bu_tready !== 1'b1) @(posedge clk);
        @(negedge clk);
        bu_tvalid = 0;
    endtask

    // nbeats beats of v, TLAST on beat last_at, TKEEP = keep on beat bad_at
    task automatic bu_frame(input logic [31:0] v[8], input int nbeats, input int last_at, input int bad_at,
                            input logic [3:0] keep, input bit user);
        for (int i = 0; i < nbeats; i++) bu_beat(v[i%8], i == last_at, i == bad_at ? keep : 4'hF, user);
    endtask

    task automatic bu_expect(input string what, input logic [31:0] codes[8], input logic [63:0] score);
        int waited = 0;
        while ((bu_codes.size() < 8 || bu_scores.size() < 1) && waited < 20000) begin
            @(posedge clk);
            waited++;
        end
        if (bu_codes.size() < 8 || bu_scores.size() < 1) begin
            fail($sformatf("test 2, %s: no output within 20000 clocks", what));
            return;
        end
        for (int i = 0; i < 8; i++) begin
            logic [31:0] c = bu_codes.pop_front();
            if (c !== codes[i]) fail($sformatf("test 2, %s: code %0d = %0d, expected %0d", what, i, $signed(c), $signed(codes[i])));
        end
        begin
            logic [63:0] s = bu_scores.pop_front();
            if (s !== score) fail($sformatf("test 2, %s: score %0d, expected %0d", what, s, score));
            else $display("[tb] test 2, %s: codes and score %0d exact", what, s);
        end
    endtask

    task automatic test_interface();
        // Handoff spec section 4: raw features -> Q24 codes -> score
        logic [31:0] raw[8] = '{1817, 2512, 1552, 31, 106, 52, 20272, 17376};
        logic [31:0] codes[8] = '{41347, 36297, 46490, 65536, 1516, 42598, 20389, 17476};
        // TUSER = 1 on every word: preprocess.py's saved medians (1684, 2512, 29, 31, 510, 52, 13032, 13032)
        logic [31:0] med_codes[8] = '{40744, 36297, 21519, 65536, 20070, 42598, 13107, 13107};
        bu_frame(raw, 8, 7, -1, 4'hF, 0);
        bu_expect("bring-up vector", codes, 51193);

        // Malformed frames are dropped without output; the next good frame is scored normally
        bu_frame(raw, 5, 4, -1, 4'hF, 0);           // early TLAST
        bu_frame(raw, 8, 7, 2, 4'h7, 0);            // a partial TKEEP/TSTRB
        bu_frame(raw, 8, 7, -1, 4'hF, 0);
        bu_expect("bring-up vector after two bad frames", codes, 51193);
        repeat (5000) @(posedge clk);
        if (bu_codes.size() != 0 || bu_scores.size() != 0)
            fail("test 2: a malformed frame produced output");
        else $display("[tb] test 2: the frame with an early TLAST and the one with TKEEP = 7 were dropped");

        bu_frame(raw, 8, 7, -1, 4'hF, 1);
        bu_expect("all fields unknown (TUSER = 1) -> medians", med_codes, 726422);
    endtask

    // ------------------------------------------------------------------ main
    initial begin
        void'($value$plusargs("stream=%s", stream_file));
        void'($value$plusargs("expect=%s", expect_file));
        void'($value$plusargs("out=%s", out_file));
        void'($value$plusargs("dma_base=%h", dma_base));
        void'($value$plusargs("max_chunks=%d", max_chunks));
        stream_file = find_data(stream_file, "stream.bin", "small_stream.bin");
        expect_file = find_data(expect_file, "expect.bin", "small_out.bin");
        $display("[tb] stream %s, expected %s, DMA registers at 0x%08h", stream_file, expect_file, dma_base);
        load_expected();

        // Power-on reset of the Zynq model, then the PL reset (FCLK_RESET0_N -> proc_sys_reset)
        `PS.set_debug_level_info(0);
        `PS.set_stop_on_error(1);
        repeat (20) @(posedge ps_clk);
        ps_rst_n = 1;
        `PS.fpga_soft_reset(32'h1);
        repeat (20) @(posedge ps_clk);
        `PS.fpga_soft_reset(32'h0);
        wait (rst_n === 1'b1);
        repeat (20) @(posedge clk);
        $display("[tb] PL out of reset at %0t", $time);

        fork
            test_full_pl();
            test_interface();
        join

        errors += rules_in.errors + rules_feat.errors + rules_meta.errors + rules_q24.errors +
                  rules_codes.errors + rules_score.errors + rules_out.errors;
        $display("[tb] AXI4-Stream beats: in %0d, features %0d, meta %0d, q24 %0d, codes %0d, score %0d, out %0d",
                 rules_in.beats, rules_feat.beats, rules_meta.beats, rules_q24.beats, rules_codes.beats,
                 rules_score.beats, rules_out.beats);
        if (errors == 0) $display("TEST PASSED");
        else $display("TEST FAILED (%0d errors)", errors);
        $finish;
    end

    // Nothing may hang: give up after 200 ms of simulated time (the 2000-packet run needs ~5 ms)
    initial begin
        #200_000_000;
        $display("[tb] timeout: no result after 200 ms of simulated time");
        $display("TEST FAILED (timeout)");
        $finish;
    end

endmodule
