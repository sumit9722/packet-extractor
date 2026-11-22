# Testbench of the PL (Vivado simulator)

This simulates **the whole overlay of one board**: the same block design that
`../build_overlay.tcl` turns into the bitstream. That means the Zynq PS, AXI DMA,
interconnects, reset block and the four IPs. It drives the overlay the way
`svdd_pl/driver.py` drives the real board, with 2,000 real UNSW-NB15 packets.

```text
tb_svdd_pl.sv
 ├─ Zynq PS = Xilinx's simulation model (processing_system7 VIP)
 │    • DDR model: the testbench writes each pcap chunk here and reads the records back
 │    • M_AXI_GP0: the testbench programs the AXI DMA registers like driver.py does
 │
 └─ PL, unchanged from the bitstream's block design
      axi_dma ─MM2S─► svdd_flow_extract ─features─► svdd_preprocess ─q24─► deep_svdd_axis
         ▲                    │ meta                        │ codes             │ score
         └─S2MM── svdd_record_join ◄────────────────────────┴───────────────────┘
```

## Run it in the Vivado GUI

The testbench is `tb_svdd_pl.sv`. Each board has a ready Vivado project with it
set as the simulation top:

| Board | Project to open |
|---|---|
| PYNQ-Z2 | `pynq-pl/vivado/tb/build_pynq-z2/svdd_pl_overlay.xpr` |
| ZedBoard | `pynq-pl/vivado/tb/build_zedboard/svdd_pl_overlay.xpr` |

(Not `pynq-pl/vivado/build_pynq-z2/...`: that is the bitstream project, and it has
no testbench.)

1. In Vivado: **File → Project → Open…** and pick the `.xpr` above.
2. In the Flow Navigator on the left: **SIMULATION → Run Simulation → Run Behavioral Simulation**.
3. Vivado compiles for about 2 minutes. Then it opens the waveform window with the
   PL streams grouped in data-flow order and runs to the end, which takes about
   6–8 minutes. The Tcl console prints a `[tb] …` line per chunk and finishes
   with **`TEST PASSED`**.

The project already has the settings this needs: run time `all`, the waveform
layout `tb_svdd_pl.wcfg`, and the plusargs (DMA address, `hls/tb_data` files). To
get a quicker look, add `-testplusarg max_chunks=1` under **Settings → Simulation →
Simulation → xsim.simulate.xsim.more_options**. Then only the first chunk runs,
in under a minute.

If a project folder is missing, `./run_sim.sh <board>` creates it. That command
rebuilds the folder whenever `../build_overlay.tcl`, `sim_overlay.tcl` or an IP
changes, so close the project in Vivado first.

## Run it from the terminal

```sh
cd pynq-pl/vivado/tb
./run_sim.sh pynq-z2           # PYNQ-Z2 block design
./run_sim.sh zedboard          # ZedBoard block design
./run_sim.sh all               # both, one after the other
./run_sim.sh pynq-z2 gui       # the same run in the xsim GUI with the stream waveforms
```

One board takes about 8 minutes the first time: 1 minute for the block design,
1–2 minutes to compile, and about 6 minutes to simulate. A rerun skips the block
design unless `../build_overlay.tcl`, `sim_overlay.tcl` or an IP has changed.
`MAX_CHUNKS=1` simulates only the first chunk, in under a minute.

The run ends with `<board>: TEST PASSED` or `TEST FAILED`, and the first errors are
printed. Everything is also saved in `results/<board>/`:

| File | Contents |
|---|---|
| `simulate.log` | Full simulator log, with one line per chunk and the summary |
| `pl_out.bin` | Every record the DMA wrote to DDR, in the same format the board returns |
| `pl.csv`, `compare.txt` | Those records decoded, and the comparison with the Python pipeline |
| `setup.log`, `compile.stdout`, `elaborate.stdout` | Vivado and compiler output |

## What it checks

**Test 1: the full PL, through the DMA, as on the board.** For each of the 6
chunks in `hls/tb_data/small_stream.bin`:

1. The testbench writes the chunk (32-byte header + pcap bytes) into DDR at `0x1F800000`.
2. It programs the AXI DMA over `M_AXI_GP0` with the exact sequence of `AxiDma` in
   `driver.py`. That is: reset, arm the S2MM receive, start the MM2S send, poll
   DMASR for IOC, read `S2MM_LENGTH`, and re-arm the receive until the chunk's
   marker record arrives.
3. It reads the records from DDR and compares **every 64-bit word** with the
   C model's output (`hls/tb_data/small_out.bin`).

Meanwhile, monitors inside the block design check:

- **`m_axis_features` against the handoff spec, section 2:** 8 beats per flow,
  TLAST on word 7 only, TKEEP = TSTRB = `F`, TUSER = 0. Every feature word is
  checked against the expected value.
- **The input to `deep_svdd_axis`:** each code is a sign-extended 24-bit Q24
  value equal to the expected one, and each score matches.
- **The AXI4-Stream rule on all seven PL streams:** once TVALID is high, TDATA and
  TLAST don't change until TREADY takes the beat.
- **The receive sizes:** whole 128-byte records, and TLAST after every 256 flow
  records or after a marker.

At the end, `run_sim.sh` decodes `pl_out.bin` and compares it with
`hls/tb_data/small_ref.csv` from the Python pipeline `svdd_ps`. So the hardware is
checked against two references that were written separately.

**Test 2: the extractor → model interface on its own.** A second
`svdd_preprocess` + `deep_svdd_axis` pair (the same RTL) gets feature frames
straight from the testbench:

- The bring-up vector from spec section 4 gives codes `41347 … 17476` and
  score **51193**.
- A frame with an early TLAST and a frame with TKEEP = `7` are both dropped. The
  next good frame is still scored correctly.
- TUSER = 1 on every word gives the codes of the saved medians, with score 726422.

## Result

| | PYNQ-Z2 | ZedBoard |
|---|---|---|
| Board preset / part | `tul.com.tw:pynq-z2`, xc7z020clg400-1 | `avnet.com:zedboard`, xc7z020clg484-1 |
| Test 1: 298 flows + 6 markers, every word vs C model | PASS | PASS |
| Records vs Python `svdd_ps` | MATCH (END_REASON too) | MATCH (END_REASON too) |
| Spec framing, AXI4-Stream rules, codes, scores | 0 errors | 0 errors |
| DMA transfers | 6 sends, 7 receives (the last chunk returns 256 + 29 + marker) | same |
| Test 2: bring-up 51193, bad frames dropped, medians | PASS | PASS |
| DMA registers (read from the address map) | `0x41E00000` | `0x41E00000` |
| Simulation time / peak memory | 5.6 min / 1.5 GB | 6.2 min / about 1.5 GB |

On the PYNQ-Z2 run, 2,000 packets took 503,174 clocks of FCLK0. That's 252 clocks
per packet, but it includes the PS polling the DMA and waiting for each chunk's
records before sending the next. The PL by itself needs about 135 (see the HLS
cosim numbers in `../../README.md`).

## Another capture

```sh
cd pynq-pl
python3 -m svdd_pl pack my.pcap -o my_stream.bin --chunk-bytes 65536
./hls/build_native.sh && ./hls/build/native/tb_svdd_pl stream my_stream.bin my_expect.bin
python3 -m svdd_pl reference my.pcap -o my_ref.csv
cd vivado/tb
STREAM=$PWD/../../my_stream.bin EXPECT=$PWD/../../my_expect.bin REFERENCE=$PWD/../../my_ref.csv ./run_sim.sh pynq-z2
```

The simulation runs at about 6 packets per second of wall time, so keep captures to a few thousand packets.

## Files

| File | What it is |
|---|---|
| `tb_svdd_pl.sv` | The testbench (both tests, the monitors, the driver.py DMA sequence) |
| `sim_overlay.tcl` | Builds the block design by sourcing `../build_overlay.tcl`, adds the testbench, writes the xsim scripts |
| `run_sim.sh` | Runs everything under a memory cap and prints the result |
| `tb_svdd_pl.wcfg` | Waveform layout Vivado opens (the PL streams, grouped in data-flow order) |
| `waves.tcl` | The script `tb_svdd_pl.wcfg` was saved from, for changing the groups |
| `build_<board>/`, `results/<board>/` | Generated; safe to delete |

Notes:

- The only change to `../build_overlay.tcl` is that it can stop after saving the
  block design when `sim_overlay.tcl` sources it. The bitstream build is unchanged.
- `run_sim.sh` runs Vivado and xsim under `MemoryMax=4G` (`MEM=5G` to change it),
  like `../build.sh`. If the limit is hit, only the simulator is killed.
- Vivado runs only to write the scripts. Compiling and simulating happen without
  it, so it isn't holding memory during the 6-minute run.
- Vivado splits plain-string file paths at the space in "FPGA Project".
  `sim_overlay.tcl` wraps them in `[list ...]`, and the generated scripts use
  relative paths.
