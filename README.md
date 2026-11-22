# pynq-pl: packet extractor, preprocessing and Deep SVDD all in the PL

`pynq-ps` runs the packet extractor in Python on the ARM (PS) and only the
Deep SVDD core in the FPGA (PL). In `pynq-pl`, **everything after reading
the capture runs in the PL**. The ARM only copies the pcap file to the PL
in 1 MB pieces and reads back one record per finished flow. It builds for
the **PYNQ-Z2** and the **ZedBoard**.

The PL side is split into IPs that talk over the AXI4-Stream interface of the
FPGA handoff spec (`../../readme.md`, section 2). The feature extraction IP
emits the spec's **eight raw uint32 words per flow**, and the Deep SVDD IP
from `../svdd_inference` is used exactly as exported.

```text
PS (ARM, Python: svdd_pl)        PL (FPGA, 100 MHz)
─────────────────────────        ───────────────────────────────────────────────────────────────
pcap file / eth0
  read 1 MB, add 32-byte header
            ── AXI DMA MM2S ──►  svdd_flow_extract   the feature extraction IP
                 (64-bit)          parse       pcap records, Ethernet/VLAN/SLL/SLL2/raw/loopback,
                                               IPv4, TCP/UDP; 1 byte per clock, payload 8 per clock
                                   flow_table  4096 flows (512 sets x 8 ways, BRAM), svdd_ps rules
                                   emit        flow snapshot -> spec record + metadata
                                     │ m_axis_features: 8 x 32-bit raw words, TLAST on word 7   [spec 2]
                                     │ m_axis_meta:     5-tuple, times, counters, status, markers
                                     ▼
                                 svdd_preprocess     median for unknown fields, log1p (CORDIC),
                                                     clip, scale in IEEE double -> float32 -> Q24
                                     │ 8 x 32-bit Q24 codes, sign-extended, TLAST on word 7   [spec 2, 3]
                                     ▼
                                 deep_svdd_axis      the inference IP from ../svdd_inference, unchanged
                                     │ 64-bit score code
                                     ▼
                                 svdd_record_join    metadata + codes + score
  128-byte records ◄─ DMA S2MM ──  one record per flow: 5-tuple, times, counters,
                 (64-bit)          8 features, 8 codes, score, anomaly bits
```

Why the packets still go through the ARM: on both boards the Ethernet port
is wired to the PS (MIO pins), not to the PL. So packets always arrive through
the PS. For pcap files the PS does no work per packet. For live capture it
only wraps each frame in a 16-byte pcap record header.

## The result

On all three UNSW-NB15 pcaps (5,168,214 packets), the PL design's C model gives
**the same 58,281 flows as `svdd_ps`**. Every column matches: 5-tuple,
start/end times, packet and byte counters, the 8 features, the 8 Q24 input
codes, the score, the anomaly decision, and the end reason. The generated
Verilog (RTL co-simulation, 2,000 packets) gives the same records too. The
PYNQ-Z2 overlay meets timing at 100 MHz.

| Check | Result |
|---|---|
| C model vs `svdd_ps`, all 3 UNSW pcaps | 58,281 / 58,281 flows identical in every column |
| Extraction IP's spec stream, all 3 UNSW pcaps | 58,281 records = 466,248 beats, 0 framing violations, every record equal to `svdd_ps` `raw_features` |
| C model vs `svdd_ps`, 12 re-framed captures (Ethernet, VLAN, raw, loopback, SLL2, big-endian ns, truncated at 30/45/60 bytes, 1000-byte chunks, two files, other expiry settings) | identical, frame counters too |
| PL preprocessing vs numpy, 1,000,000 random vectors | 8,000,000 / 8,000,000 codes identical |
| Set overflow (10 flows in one 8-way set) | 2 evicted, every flow exported exactly once |
| Spec section 4 bring-up vector through `svdd_preprocess` → `deep_svdd_axis` | codes and score 51193 exact |
| Unknown field (TUSER = 1), MIN_TTL > 255 | saved median used, as in `preprocess.py` |
| Vitis HLS csim | built-in checks + 2,000-packet capture pass |
| RTL co-simulation (Verilog, xsim), each IP in turn as RTL inside the C chain | PASS ×3; 298 / 298 flows identical to `svdd_ps` each time |
| Vivado, PYNQ-Z2 | timing met at 100 MHz (WNS +0.080 ns, WHS +0.016 ns) |
| Vivado, ZedBoard | timing met at 100 MHz (WNS +0.080 ns, WHS +0.016 ns) |
| Board | **not run yet** |

Resources (whole overlay, same on both boards):

| | LUT | FF | BRAM tiles | DSP |
|---|---:|---:|---:|---:|
| Whole overlay (Vivado) | 36,362 (68%) | 39,877 (37%) | 68 (49%) | 91 (41%) |
| `svdd_flow_extract` (HLS estimate) | 26,430 | 22,984 | 60 | 24 |
| `svdd_preprocess` (HLS estimate) | 7,582 | 3,810 | 1 | 11 |
| `svdd_record_join` (HLS estimate) | 957 | 2,463 | 0 | 0 |
| `deep_svdd_axis` (its own HLS report) | 4,556 | 7,751 | 0 | 57 |

The PS-side `pynq-ps` overlay used 4,663 LUTs. The difference is the parser,
the 4,096-flow table (most of the BRAM) and the double-precision preprocessing.

## Folders

| Path | What it is |
|---|---|
| `hls/svdd_pl.hpp` | Stream formats and declarations shared by the three IPs |
| `hls/extract.cpp` | `svdd_flow_extract`, the feature extraction IP: `parse`, `flow_table`, `emit_records` |
| `hls/preprocess.cpp` | `svdd_preprocess`: raw words → Q24 codes (CORDIC log1p, IEEE double steps) |
| `hls/join.cpp` | `svdd_record_join`: metadata + codes + score → the 128-byte record |
| `hls/core/` | The Deep SVDD source from `../svdd_inference` (copied, only for the C testbench; the overlay uses the exported IP) |
| `hls/gen_params.py` | Writes `preprocess_params.hpp` (from `assets/preprocessing.json`) and `cordic_table.hpp` |
| `hls/tb_svdd_pl.cpp` | Testbench: chains the four IPs as in the block design; built-in checks, chunk replay (optionally saving the spec feature stream), preprocessing-only mode |
| `hls/run_hls.sh`, `hls/synth.tcl` | Vitis HLS csim + synthesis + IP export (memory capped) |
| `hls/build_native.sh` | Builds the testbench as a normal program for fast checks |
| `hls/tb_data/` | A 2000-packet capture, its chunk file and its reference CSV (used by csim and cosim) |
| `hls/ip/`, `hls/reports/<ip>/` | Exported IP zips and HLS reports, one folder per IP |
| `vivado/build.sh`, `vivado/build_overlay.tcl` | Block design and bitstream, `./build.sh pynq-z2` or `./build.sh zedboard` |
| `overlay/<board>/svdd_pl.{bit,hwh}` | Built overlays, with timing and utilization reports |
| `svdd_pl/` | PS-side Python: `stream.py` (chunks), `records.py` (decoding), `driver.py` (DMA, both boards), `reference.py` (compare with svdd_ps), CLI |
| `svdd_ps/` | The software pipeline from `zed-ps` (Python 3.6 version), used as the reference |
| `notebooks/svdd_pl.ipynb` | Board notebook (PYNQ images) |
| `tests/` | PC tests: C model against svdd_ps, preprocessing against numpy, driver logic |
| `deploy.sh` | Copy to a board over ssh |

## The feature extractor interface (handoff spec, section 2)

`svdd_flow_extract` is the spec's "feature extraction IP". Its `m_axis_features` port
can feed `svdd_preprocess` (as here), the PS through a DMA, or any other consumer.

| Spec rule | `m_axis_features` here |
|---|---|
| Word order | IN_BYTES, OUT_BYTES, FLOW_DURATION_MILLISECONDS, MIN_TTL, MAX_IP_PKT_LEN, MIN_IP_PKT_LEN, TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT |
| TDATA[31:0] | one unsigned raw feature per beat, 8- and 16-bit fields zero-extended; in a DMA buffer, eight little-endian uint32 = 32 bytes per flow |
| TVALID / TREADY | HLS AXI4-Stream handshake with register slices; the record is a snapshot copied out of the flow table, so later packets can't change a record in flight |
| TKEEP, TSTRB | 4'b1111 on every beat |
| TLAST | on word 7 only; 8 beats per record, never interleaved |
| Flow correlation | kept outside the eight words, on `m_axis_meta`: 5-tuple, first/last time, packet and byte counters, end reason, and a flow sequence number (the flow handle). Records on both ports come in the same order |
| Unknown fields | TUSER[0] = 1 on a beat marks the field as unknown, and `svdd_preprocess` then uses the saved median. Every field is measured here, so it is always 0 (a source without TUSER also counts as "all known") |
| Overflow | counters are wider inside (48-bit bytes, 64-bit time) and saturate instead of wrapping. A word that didn't fit in 32 bits is sent as 2^32 − 1 and flagged in the metadata (`w9[47:40]`, one bit per word; `w9[48]` for the packet counters) |
| Clock, reset | `ap_clk` and active-low `ap_rst_n` (the spec's aclk/aresetn); reset clears the flow table and any partial record |

The Q24 stream into `deep_svdd_axis` uses the same eight-beat framing, with each
code in TDATA[23:0] sign-extended into [31:24], as the spec describes for the PS → core path.
`svdd_preprocess` drops a malformed frame (early or missing TLAST, partial
TKEEP/TSTRB) the same way `deep_svdd_axis` does.

**The packet events inside the extractor** (spec section 1, "if a separate parser
feeds the extractor") are the `pkt_tok_t` tokens between the `parse` and
`flow_table` stages: IPv4 source/destination, protocol, ports, capture timestamp,
TTL, IPv4 Total Length, and the TCP window with a validity bit (`has_win`), all
decoded from network byte order in the parser.

## The data formats

**PS → PL, one chunk per DMA transfer.** There is a 32-byte header, then raw
pcap bytes (record headers and frames, without the 24-byte file header).
Records may be split between chunks, and the PL carries on where it stopped.

| Header word | Contents |
|---|---|
| 0 | `"SVPL"`, version 1, flags, pcap link type |
| 1 | data bytes in this chunk, TCP close timeout (µs) |
| 2 | idle timeout (µs), active timeout (µs) |
| 3 | "now" in µs (for live capture ticks) |

The flags are: reset (first chunk of a run), new file, flush (last chunk: export
every open flow), tick (live capture: expire flows as of "now"), timestamps in
ns, big-endian file, MIN_TTL both directions, ignore FIN/RST. The last four
are the same options as in `svdd_ps`.

**PL → PS.** `svdd_record_join` sends each finished flow as a 128-byte record
(16 words, layout in `hls/svdd_pl.hpp`): the extractor's metadata, the 8 Q24
codes and the score, with the anomaly bits set from the two thresholds. Every
chunk's output ends with a 128-byte *marker* record with the counters: chunks,
frames, IPv4, other, malformed, flows, evictions, open flows, and the peak
number of open flows. TLAST closes the marker and every group of 256 flow
records, so a 64 KB receive buffer is always enough. This format is the same
as before the IPs were split, so the PS-side Python did not change.

## How the hardware matches the Python exactly

**Header parsing** copies `svdd_ps/pcap.py` rule for rule: the VLAN tag loop,
Linux-cooked v1/v2 framing, loopback with either byte order, raw IP, the
"malformed" conditions, ports only on first fragments, and a TCP window only
when 16 bytes of TCP header are present. The parser looks at the first 128
bytes of each frame. That is enough for any IPv4 + TCP header behind up to 9
VLAN tags. Deeper headers are counted separately and would show up in the
marker record (none in UNSW-NB15).

**Flow expiry.** Python checks every flow after every frame and removes the
expired ones at once. Hardware can't scan 4096 entries per packet. So it does
two things:

- *Lazily.* When a packet finds its flow, the hardware first asks: "would
  Python's expire() at the previous frame already have removed this flow?" If
  so, it exports that flow first and starts a new one, exactly as Python would.
- *By scanning.* After every frame, one set (8 flows) is checked and expired
  flows are exported. The whole table is covered every 512 frames (about 0.25 s
  of UNSW traffic).

So flows leave the table at slightly different times and in a different order
than in Python, but with the same packets, counters and end reason. A flow is
only *evicted* (exported early, reason `evict`) if all 8 ways of its set are
live. That never happened on UNSW-NB15, which peaks at 1,108 open flows in a
4,096-entry table. A test forces it with 10 flows built to collide in one set:
2 are evicted, and all 10 still come out exactly once.

To fit the 10 ns clock, each table entry stores its expiry deadline
(`last + timeout`), written when the entry is updated. Times are compared on
their low 48 bits with wrap-around, which is exact while two timestamps are
less than 2⁴⁷ µs (4.4 years) apart. All 8 ways are checked side by side
before one is picked. The timeouts come from the chunk header. They are
assumed fixed for a whole run (the PS always sends the same values), because
entries keep the deadline computed when they were last written.

**Preprocessing.** numpy computes `log1p`, clip, `(x - anchor) / scale` in
float64, then float32, then rounds to the nearest Q16 code (ties to even). The
PL does the same steps in IEEE double, with two exceptions:

- `log1p` is a hyperbolic CORDIC, ~2⁻⁵⁸ accurate, rounded to the nearest
  double. HLS's own double `log1p` alone took 57 DSPs and 17k LUTs (32% of the
  chip). The CORDIC uses only shifts and adds. On 270,225 test inputs it equals
  the C library's `log1p` (what numpy uses) or differs by 1 ulp in 33 cases.
  A 1-ulp difference would change a code only if the value sat within about
  2⁻⁵⁰ of a rounding boundary.
- The final float32 → Q16 rounding is done on the float's bits, ties to even.

One million random feature vectors (8 million codes) and all 58,281 UNSW flows
give exactly numpy's codes.

## On the PC

```sh
cd pynq-pl
./hls/build_native.sh                 # testbench as a normal program (seconds)
python3 -m pytest -q tests            # 19 tests: C model vs svdd_ps, preprocessing vs numpy, driver logic

# the full UNSW comparison (about 1 minute; a pipe avoids writing 3 GB):
mkfifo /tmp/s.fifo
python3 -m svdd_pl pack ../pcap/{1,2,3}.pcap -o /tmp/s.fifo &
./hls/build/native/tb_svdd_pl stream /tmp/s.fifo /tmp/out.bin
python3 -m svdd_pl decode /tmp/out.bin -o pl.csv
python3 -m svdd_pl reference ../pcap/{1,2,3}.pcap -o ref.csv
python3 -m svdd_pl compare pl.csv ref.csv          # RESULT: MATCH
```

Building the hardware:

```sh
python3 hls/gen_params.py             # only if assets/ changed
./hls/run_hls.sh                      # Vitis HLS: csim + synthesis + export of the 3 IPs (~8 min)
STEPS=cosim MEM=3G ./hls/run_hls.sh   # optional: RTL co-simulation, each IP in turn (~12 min)
./vivado/build.sh pynq-z2             # or zedboard, or all (~25 min each)
```

Notes from getting this to build on this PC (15 GB RAM):

- Vitis HLS refuses paths with spaces ("FPGA Project"). So `run_hls.sh` copies
  the sources to `~/.cache/svdd_pl_hls`, runs there, and copies the IP and
  reports back.
- Both scripts run the tools under a 6 GB memory cap, like in `pynq-ps`. The
  first Vivado attempts hit the cap. `launch_runs` ran a second Vivado for
  synthesis while the first waited, and flattened synthesis used too much
  memory in cross-boundary optimization. The script now runs synthesis, place
  and route in one process, keeps the hierarchy, and peaks at 3.7 GB.
- HLS is told to schedule for 8 ns, not 10. Its delay estimates were about
  1.2 ns optimistic for the flow-table logic after place and route.
- If a future change misses timing, build with a slower PL clock, e.g.
  `FCLK_MHZ=83.333333 ./vivado/build.sh pynq-z2`. The driver reads the
  clock from the `.hwh` and sets FCLK0 to match.

## On the board

1. Get Linux on the SD card:
   - **PYNQ-Z2:** the official PYNQ image.
   - **ZedBoard:** see `../zed-ps/README.md`. Either the community PYNQ image,
     or PetaLinux with Python 3 + NumPy. Without PYNQ, the kernel must boot with
     `mem=504M`, because the `devmem` driver uses the top 8 MB of DDR for the
     DMA buffers.
2. `BOARD=xilinx@<ip> ./deploy.sh` (add `zedboard` or `pynq-z2` to copy only one overlay).
3. On the board, as root:

```sh
cd ~/jupyter_notebooks/pynq-pl          # or ~/pynq-pl without PYNQ
sudo python3 -m svdd_pl selftest        # sample pcap through the PL and through svdd_ps: must MATCH
sudo python3 -m svdd_pl run samples/unsw_sample.pcap -o scored.csv
sudo python3 -m svdd_pl run big.pcap --check -o scored.csv   # also compare with svdd_ps
sudo python3 -m svdd_pl live --iface eth0 --seconds 60
```

The board is detected from PYNQ's `BOARD` variable or the device tree. If
that fails, pass `--board pynq-z2` or `--board zedboar\documentclass[conference]{IEEEtran}
\IEEEoverridecommandlockouts
\usepackage{cite}
\usepackage{amsmath,amssymb,amsfonts}
\usepackage{algorithmic}
\usepackage{graphicx}
\usepackage{textcomp}
\usepackage{xcolor}
\usepackage{tikz}
\usetikzlibrary{positioning,arrows.meta,fit}
\def\BibTeX{{\rm B\kern-.05em{\sc i\kern-.025em b}\kern-.08em
    T\kern-.1667em\lower.7ex\hbox{E}\kern-.125emX}}

% Marks values that must be filled in from the trained run (runs/software/)
\newcommand{\todo}[1]{\textcolor{red}{[TODO: #1]}}

\begin{document}

\title{Network Anomaly Detector Using Deep SVDD Model}

\author{\IEEEauthorblockN{1\textsuperscript{st} Nandan Bali}
\IEEEauthorblockA{\textit{Department of Electrical and Electronics Engineering} \\
\textit{Birla Institute of Technology and Science, Pilani}\\
Pilani, India \\
f20240380@pilani.bits-pilani.ac.in}
\and
\IEEEauthorblockN{2\textsuperscript{nd} Ameya Mukul Karnik}
\IEEEauthorblockA{\textit{Department of Electrical and Electronics Engineering} \\
\textit{Birla Institute of Technology and Science, Pilani}\\
Pilani, India \\
f20240380@pilani.bits-pilani.ac.in}
\and
\IEEEauthorblockN{3\textsuperscript{rd} Sumit Kumar Shah}
\IEEEauthorblockA{\textit{Department of Computer Science} \\
\textit{Birla Institute of Technology and Science, Pilani}\\
Pilani, India \\
f20240024@pilani.bits-pilani.ac.in}
}


\maketitle

\begin{abstract}
Signature-based intrusion detection misses attacks it has never seen, and
labeled attack traffic is scarce and imbalanced. This paper presents a network
anomaly detector that learns only what normal traffic looks like and runs from
packet capture to anomaly score in the programmable logic of a low-cost
Zynq-7020 FPGA, with the processor only moving bytes. A bias-free 8-32-16-8
Deep Support Vector Data Description (Deep SVDD) network is trained only on
benign NF-UNSW-NB15-v3 flows, under a leakage-safe chronological split, with
eight hardware-cheap features chosen without attack labels and a threshold
frozen before any test data are read. Quantized to 24-bit fixed point in Vitis
High-Level Synthesis, it reproduces all 256 golden reference scores bit for
bit. An on-chip extractor parses packets, keeps a 4096-entry bidirectional flow
table, and computes and preprocesses the features; on 5.2 million UNSW-NB15
packets its C model matches a software reference extractor on all 58\,281
flows, and RTL co-simulation of a sample confirms the hardware. The complete
system meets timing at 100~MHz on the Pynq-Z2 and ZedBoard using 68\% of the
lookup tables. In C simulation on 100\,000 held-out test flows the detector
reaches an AUROC of 0.9998 and detects all 8\,913 attacks at a false-positive
rate of 1.09\%. Isolation Forest is analyzed as a hardware alternative.
\end{abstract}

\begin{IEEEkeywords}
anomaly detection, Deep SVDD, network intrusion detection, NetFlow, flow
extraction, FPGA, high-level synthesis, fixed-point arithmetic, isolation forest
\end{IEEEkeywords}

%=====================================================================
\section{Introduction}
%=====================================================================
Signature-based network intrusion detection systems (NIDS) are blind to novel
attacks, and supervised classifiers can only learn attack classes present in
their labeled, typically scarce and imbalanced training data \cite{sommer2010}.
Anomaly detection reverses the problem: a model is fitted only to benign
traffic, and any flow that does not resemble it is reported \cite{chandola2009}.
Deep Support Vector Data Description (Deep SVDD) \cite{ruff2018} maps normal
data into a small hypersphere around a fixed center and uses the squared
distance to the center as the score. Inference is a small multilayer perceptron
followed by a sum of squares, which suits hardware acceleration at line rate.

This work builds a complete pipeline from a NetFlow dataset to an FPGA detector
that consumes raw packets on the Pynq-Z2 (Zynq-7020, \texttt{xc7z020clg400-1});
the same design also targets the ZedBoard. The contributions are:
\begin{itemize}
\item a leakage-aware protocol for NF-UNSW-NB15-v3: a chronological 60/20/20
split with a 60~s embargo, duplicate purging and a hash-enforced
freeze-before-test rule;
\item label-free selection of eight features that need only counters,
comparators and one timestamp subtraction, with a bounded preprocessing
contract;
\item a bit-exact fixed-point Deep SVDD core in Vitis HLS behind a
self-resynchronizing AXI4-Stream interface;
\item an on-chip network feature extractor and preprocessing pipeline, verified
flow for flow against a software reference on the full UNSW-NB15 captures;
\item an analytical comparison with Isolation Forest as a hardware alternative.
\end{itemize}

%=====================================================================
\section{Background and Related Work}\label{sec:bg}
%=====================================================================
\subsection{Deep SVDD}
Classical SVDD \cite{tax2004} encloses normal data in a minimum-volume
hypersphere in a kernel feature space. Deep SVDD \cite{ruff2018} replaces the
kernel with a neural network $\phi(\cdot;\mathcal{W})$ and, in its one-class
form, minimizes
\begin{equation}
\mathcal{L}(\mathcal{W}) = \frac{1}{n}\sum_{i=1}^{n}
\left\lVert \phi(\mathbf{x}_i;\mathcal{W}) - \mathbf{c} \right\rVert^2
+ \frac{\lambda}{2}\sum_{\ell}\left\lVert \mathbf{W}^{\ell}\right\rVert_F^2,
\label{eq:loss}
\end{equation}
where $\mathbf{x}_i$ are normal training samples, $\mathbf{c}$ is a fixed
center and $\lambda$ is a weight-decay coefficient. The anomaly score is
\begin{equation}
s(\mathbf{x}) = \left\lVert \phi(\mathbf{x};\mathcal{W}) - \mathbf{c}\right\rVert^2
= \sum_{j=1}^{k}\left(z_j - c_j\right)^2 .
\label{eq:score}
\end{equation}
Because \eqref{eq:loss} is trivially minimized by a network that maps every
input to $\mathbf{c}$, Ruff et al.\ prescribe no bias terms and a fixed center
away from the origin; both are used here.

\subsection{NetFlow Data and FPGA Inference}
NetFlow summarizes each conversation between two endpoints into one record of
counters and header statistics. Sarhan et al.\ re-exported public NIDS
datasets, including UNSW-NB15 \cite{moustafa2015}, into a common NetFlow
feature set \cite{sarhan2021,sarhan2022}; version 3 \cite{nfv3} adds
millisecond flow timestamps, enabling time-ordered evaluation. Random splits of
flow data leak information between partitions \cite{kaufman2012}. FPGA
accelerators for neural networks commonly use fixed-point or integer
arithmetic \cite{jacob2018}, often generated by frameworks such as hls4ml
\cite{duarte2018} and FINN \cite{umuroglu2017}. Our design is written by hand
for Vitis HLS \cite{ug1399} so that every rounding and overflow decision matches
a software integer reference.

%=====================================================================
\section{Dataset and Leakage-Safe Protocol}\label{sec:data}
%=====================================================================
\subsection{Dataset Acquisition and Audit}
The official NF-UNSW-NB15-v3 archive \cite{nfv3} was verified against its BagIt
SHA-1 manifests, and the CSV hash is pinned in code. The file contains
2\,365\,424 flows with 53 features plus a \texttt{Label} and an \texttt{Attack}
family: 2\,237\,731 benign flows and 127\,693 attacks from nine families
(Table~\ref{tab:families}). A full inspection confirmed that \texttt{Label}$=0$
exactly when \texttt{Attack} is benign, and found 14\,815 duplicate rows and
230\,815 repeated feature vectors, none with conflicting labels. The two
\texttt{*\_SECOND\_BYTES} columns contain many missing and infinite values and
were excluded, as were IP addresses, timestamps and transaction identifiers,
which in a testbed identify attackers directly.

\begin{table}[htbp]
\caption{Flow Counts per Class in NF-UNSW-NB15-v3}
\begin{center}
\begin{tabular}{|l|r||l|r|}
\hline
\textbf{Class} & \textbf{Flows} & \textbf{Class} & \textbf{Flows} \\
\hline
Benign & 2\,237\,731 & Reconnaissance & 17\,074 \\
Exploits & 42\,748 & DoS & 5\,980 \\
Fuzzers & 33\,816 & Backdoor & 4\,659 \\
Generic & 19\,651 & Shellcode & 2\,381 \\
Analysis & 1\,226 & Worms & 158 \\
\hline
\end{tabular}
\label{tab:families}
\end{center}
\end{table}

\subsection{Chronological Split}
Let $t_1$ and $t_2$ be the 60th and 80th percentiles of flow start times and
let $g = 60$~s be an embargo. A flow is assigned to training if it ends before
$t_1-g$, to validation if it starts after $t_1+g$ and ends before $t_2-g$, and to
test if it starts after $t_2+g$; all other flows are discarded. A feature vector
that appears in more than one partition is kept only at its earliest occurrence,
and an assertion verifies that no feature hash is shared. This removed 7\,253
boundary flows and 120\,705 later duplicates (Table~\ref{tab:split}). Each
partition was then sampled uniformly, without class balancing, to at most
100\,000 rows with a fixed seed.

\begin{table}[htbp]
\caption{Chronological Partitions After Purging}
\begin{center}
\begin{tabular}{|l|r|r|r|}
\hline
\textbf{Partition} & \textbf{Flows} & \textbf{Benign} & \textbf{Attack} \\
\hline
Train & 1\,417\,416 & 1\,375\,035 & 42\,381 \\
Validation & 411\,229 & 373\,424 & 37\,805 \\
Test & 408\,821 & 372\,824 & 35\,997 \\
\hline
\end{tabular}
\label{tab:split}
\end{center}
\end{table}

%=====================================================================
\section{Feature Selection and Preprocessing}\label{sec:feat}
%=====================================================================
\subsection{Hardware-Aware Feature Selection}
Every column was annotated with its meaning, units, per-flow state and an
extraction cost from 1 (latch or compare a header field) to 5 (payload
parsing). \emph{Track A} uses only benign training flows: it removes
near-constant features and greedily keeps features in order of cost and a
declared priority, discarding any feature with an absolute Pearson or Spearman
correlation of at least 0.95 to one already kept (e.g., \texttt{MAX\_TTL} and
\texttt{MIN\_TTL}: 0.991). Never seeing an attack, it cannot overfit to the
attacks in this dataset. \emph{Track B}, for comparison only, estimates mutual
information with the label \cite{kraskov2004} and runs max-relevance
min-redundancy selection \cite{peng2005}; it ranked the TTL fields and the
minimum packet length highest (Fig.~\ref{fig:features}), a warning sign, since
TTL often reflects testbed topology rather than attack behavior.

The selected candidate, \emph{A\_compact}, contains \texttt{IN\_BYTES},
\texttt{OUT\_BYTES}, \texttt{FLOW\_DURATION\_MILLISECONDS}, \texttt{MIN\_TTL},
\texttt{MAX\_IP\_PKT\_LEN}, \texttt{MIN\_IP\_PKT\_LEN}, \texttt{TCP\_WIN\_MAX\_IN}
and \texttt{TCP\_WIN\_MAX\_OUT}: each is a counter, a running extremum or a
single timestamp subtraction, with no division, payload parsing or cross-flow
state.

\begin{figure*}[t]
\centerline{\includegraphics[width=0.9\textwidth]{fig_features.png}}
\caption{Left: Pearson correlation among the eight selected features on benign
training flows (Track A). Right: mutual information between candidate features
and the attack label on a mixed training sample (Track B, comparison only).}
\label{fig:features}
\end{figure*}

\subsection{Preprocessing Contract}
Preprocessing is fitted on benign training flows and saved as a JSON contract
listing every constant, so that software and hardware produce identical
inputs. Invalid values (missing, infinite, negative or out of domain) are
replaced by the benign median. Counters and durations are transformed as
$u=\log(1+x)$, other features use $u=x$. With $a$ and $b$ the 0.1\% and 99.9\%
benign quantiles of $u$ and $\Delta = b-a$, the model input is
\begin{equation}
\tilde{x} = \frac{\operatorname{clip}\!\left(u,\; a-\Delta,\; a+4\Delta\right) - a}{\Delta}
\in [-1,\,4].
\label{eq:prep}
\end{equation}
A hard clip at the normal quantile would map an attacker's TTL of 254 to the
benign value of 31; the asymmetric range keeps such values distinguishable while
bounding every input for fixed-point arithmetic. Table~\ref{tab:prep} lists the
constants; in the complete system the contract is evaluated in the FPGA
(Section~\ref{sec:ext}).

\begin{table}[htbp]
\caption{Preprocessing Constants for the Selected Features}
\begin{center}
\begin{tabular}{|l|c|r|r|r|}
\hline
\textbf{Feature} & \textbf{log} & \textbf{Median} & \textbf{$a$} & \textbf{$b$} \\
\hline
IN\_BYTES & yes & 1684 & 2.303 & 10.549 \\
OUT\_BYTES & yes & 2512 & 0 & 14.136 \\
FLOW\_DURATION\_MS & yes & 29 & 0 & 10.358 \\
MIN\_TTL & no & 31 & 0 & 31 \\
MAX\_IP\_PKT\_LEN & no & 510 & 73 & 1500 \\
MIN\_IP\_PKT\_LEN & no & 52 & 0 & 80 \\
TCP\_WIN\_MAX\_IN & no & 13032 & 0 & 65160 \\
TCP\_WIN\_MAX\_OUT & no & 13032 & 0 & 65160 \\
\hline
\end{tabular}
\label{tab:prep}
\end{center}
\end{table}

%=====================================================================
\section{Model, Training and Calibration}\label{sec:model}
%=====================================================================
The encoder is a bias-free multilayer perceptron with layer widths
$8\rightarrow32\rightarrow16\rightarrow8$:
\begin{equation}
\mathbf{h}_1 = \sigma(\mathbf{W}_1\tilde{\mathbf{x}}),\quad
\mathbf{h}_2 = \sigma(\mathbf{W}_2\mathbf{h}_1),\quad
\mathbf{z} = \mathbf{W}_3\mathbf{h}_2,
\label{eq:mlp}
\end{equation}
where $\sigma$ is the ReLU; the linear output layer lets the embedding surround
a center with negative coordinates. The 896 weights cost 896
multiply-accumulate operations per inference. Hidden layers use
Kaiming-uniform \cite{he2015} and the output layer Xavier-uniform
\cite{glorot2010} initialization. The center is the mean embedding of all
benign training flows in double precision, with coordinates below 0.1 in
magnitude moved to $\pm0.1$, and is checked to be unchanged after every epoch.

Training minimizes \eqref{eq:loss} with $\lambda=10^{-6}$ using Adam
\cite{kingma2015} in PyTorch \cite{paszke2019} (learning rate $10^{-3}$, batch
1024, at most 30 epochs, deterministic). A collapse warning is raised if the
embedding variance falls below $10^{-4}$ of its initial value, and early
stopping keeps the weights with the lowest benign validation distance. The
compact model with seed 7 was declared primary in advance; other seeds and an
all-feature model serve as comparisons.

The threshold $\tau = 1.3971\times10^{-3}$ is the 99th percentile of benign
validation scores, targeting a 1\% false-positive rate (FPR) without attack
labels; a flow is anomalous when $s(\mathbf{x})>\tau$. Before any test flow is
loaded, checkpoint hashes, center, thresholds and the hash of the test row
identifiers are written to a freeze file that cannot be changed, and test
scores are bound to it by a receipt, so the test evaluation runs only once.

%=====================================================================
\section{Fixed-Point Design}\label{sec:fixed}
%=====================================================================
Two formats, Q16\_I6 and Q24\_I8, were declared in advance. In Q$B$\_I$I$ a value
is a $B$-bit two's-complement integer with $F=B-I$ fractional bits. Inputs,
weights and the center are quantized as
\begin{equation}
q(v) = \operatorname{clip}\!\left(\operatorname{round}(v\cdot2^{F}),\,
-2^{B-1},\, 2^{B-1}-1\right).
\label{eq:quant}
\end{equation}
Each dot product is accumulated exactly at $2F$ fractional bits, rounded once
to $F$ bits half-to-even and saturated to $B$ bits, then passed through ReLU on
hidden layers. The difference $z_j-c_j$ is widened to $B+1$ bits and the score
is accumulated exactly at $2F$ fractional bits. An integer-only Python model
implements these rules. For Q24\_I8 ($F=16$) no saturation occurred at any
stage on the golden set, and the largest accumulators needed 52 to 54 bits. The
threshold becomes the integer code $T=\lfloor \tau\cdot2^{32}\rfloor =
6\,000\,531$; a threshold recalibrated on quantized validation scores is
$T'=6\,018\,545$ (calibration FPR 0.989\% on 90\,686 benign flows).

In HLS (Table~\ref{tab:types}) activations keep 16 fractional bits in 25 bits,
matching the DSP48E1 A-input, and one \texttt{AP\_RND\_CONV}, \texttt{AP\_SAT}
cast per neuron reproduces the reference's rounding and clipping.

\begin{table}[htbp]
\caption{Fixed-Point Types in the HLS Design}
\begin{center}
\begin{tabular}{|l|l|l|}
\hline
\textbf{Type} & \textbf{Format} & \textbf{Use} \\
\hline
activation & \texttt{ap\_fixed<25,9>} & inputs, weights, layers \\
product & \texttt{ap\_fixed<50,18>} & exact product \\
accumulator & \texttt{ap\_fixed<64,32>} & exact dot product \\
rounded & \texttt{<25,9,RND\_CONV,SAT>} & one cast per neuron \\
delta & \texttt{ap\_fixed<26,10>} & $z_j-c_j$ \\
score & \texttt{ap\_ufixed<64,32>} & exact sum of squares \\
\hline
\end{tabular}
\label{tab:types}
\end{center}
\end{table}

%=====================================================================
\section{Inference Core}\label{sec:hw}
%=====================================================================
The core consists of bias-free dense layers, ReLUs and a squared-distance
score. In each dense layer the loop over output neurons is pipelined with an
initiation interval (II) of one and the inner loop is unrolled, producing one
neuron per clock; weights are exact multiples of $2^{-16}$ in per-column
read-only memories. The top-level \texttt{deep\_svdd\_axis} exposes two
AXI4-Stream \cite{axis} ports with register slices and uses
\texttt{ap\_ctrl\_none}, so it runs continuously without a control interface
(Fig.~\ref{fig:arch}). A frame is eight 32-bit beats, each carrying one signed
code scaled by $2^{16}$ in bits 24:0, with \texttt{TLAST} on the eighth; the
output is one 64-bit beat with the unsigned score scaled by $2^{32}$. Frames
with an early \texttt{TLAST} or partially valid \texttt{TKEEP}/\texttt{TSTRB}
are dropped and overlong frames are drained, so a malformed frame costs one
score and never mixes flows. The threshold is applied by the consumer, so the
operating point can change without re-synthesis.

\begin{figure}[htbp]
\centering
\begin{tikzpicture}[
  node distance=2.6mm,
  blk/.style={draw, rounded corners=1pt, minimum width=4.2cm, minimum height=5mm,
              font=\scriptsize, align=center},
  arr/.style={-{Stealth[length=1.6mm]}, thick}]
\node[blk, fill=gray!12] (ps) {ARM (PS): capture bytes, 1\,MB chunks};
\node[blk, below=of ps] (dma1) {AXI DMA (MM2S)};
\node[blk, below=of dma1] (ext) {Feature extraction IP\\packet parser, flow table (4096)};
\node[blk, below=of ext] (pre) {Preprocessing IP\\median, $\log(1+x)$, clip, scale, Q24};
\node[blk, below=of pre] (svdd) {\texttt{deep\_svdd\_axis}\\frame check, 3 dense layers, score};
\node[blk, below=of svdd] (join) {Record join IP};
\node[blk, below=of join] (dma2) {AXI DMA (S2MM)};
\node[blk, below=of dma2, fill=gray!12] (out) {ARM (PS): flow records and scores};
\draw[arr] (ps) -- (dma1);
\draw[arr] (dma1) -- node[right, font=\tiny]{64-bit beats} (ext);
\draw[arr] (ext) -- node[right, font=\tiny]{8 raw 32-bit words} (pre);
\draw[arr] (pre) -- node[right, font=\tiny]{8 Q24 words} (svdd);
\draw[arr] (svdd) -- node[right, font=\tiny]{64-bit score} (join);
\draw[arr] (join) -- (dma2);
\draw[arr] (dma2) -- (out);
\draw[arr] (ext.west) -- ++(-0.3,0) |- node[pos=0.25, left, font=\tiny]{metadata} (join.west);
\end{tikzpicture}
\caption{Data path on the Zynq-7020. Shaded blocks run on the processing system
(PS); all other blocks are IP cores in the programmable logic (PL) at 100~MHz,
connected by AXI4-Stream.}
\label{fig:arch}
\end{figure}

%=====================================================================
\section{Network Feature Extractor}\label{sec:ext}
%=====================================================================
\subsection{System Partition}
On both boards the Ethernet port is wired to the processing system, so the ARM
reads a capture file, or wraps live frames as capture records, and streams the
raw bytes over AXI DMA in 1~MB chunks with a short header carrying the capture
format and expiry settings. All per-packet work happens in four IP cores in the
PL (Fig.~\ref{fig:arch}). The feature extraction IP emits each finished flow as
eight 32-bit beats, one raw unsigned feature per beat in model order with
\texttt{TLAST} on the eighth, so it can feed the inference path or a DMA buffer
directly; five-tuple, timestamps, counters and status travel on a separate
metadata stream. Internal counters are wider than 32 bits and saturate, with
saturation flagged in the metadata. The preprocessing IP produces Q24\_I8 codes
in the same framing, the unchanged \texttt{deep\_svdd\_axis} scores them, and a
join IP assembles metadata, codes and score into a 128-byte record per flow.

\subsection{Packet Parser and Flow Table}
The parser walks the capture records one byte per clock, decoding the link
layer (Ethernet with VLAN tags, Linux cooked capture, raw IP, loopback), the
IPv4 header and the TCP or UDP ports from the first 128 bytes of each frame,
and skips the payload eight bytes per clock, yielding per packet the
five-tuple, timestamp, TTL, total length and TCP window.

Flows live in a 512-set, 8-way table of 4096 entries in block RAM. Both
directions hash to the same set, the first packet fixes the orientation, and
each entry holds first and last timestamps, directional packet and byte
counters, TTL and length extrema and the two window maxima. A flow ends after
30~s idle, at the first packet after 120~s of activity, 1~s after TCP teardown,
or when a SYN reopens a closed five-tuple. Where the software reference checks
expiry after every packet, the hardware exports a flow when its next packet
arrives or when a background scan of one set per packet reaches it, judged at
the time of the previous packet, so every flow contains exactly the same
packets. Storing each entry's expiry deadline and testing all eight ways in
parallel let the table close timing at 100~MHz. A full set evicts and counts one
flow; the UNSW-NB15 captures never filled a set (at most 1108 open flows).

The reference counts both copies of every forwarded packet, which the router
capture of UNSW-NB15 records on the way in and out, and takes \texttt{MIN\_TTL}
from the source-to-destination direction only. Both rules were inferred from
the dataset: its byte counts are almost always even, as double counting
predicts, and benign flows show a \texttt{MIN\_TTL} of 31 although their replies
carry lower TTLs.

\subsection{Preprocessing in Hardware}
The preprocessing IP evaluates \eqref{eq:prep} as the software does: fields
marked unknown on \texttt{TUSER} and out-of-domain values take the median,
clip, subtraction and division use IEEE double precision, and the result is
rounded to float32 and then to the nearest Q24 code, ties to even. Only
$\log(1+x)$ differs: the HLS double-precision function alone needed 57 DSP
slices and a third of the lookup tables, so it was replaced by a hyperbolic
CORDIC on the mantissa of the integer input, built from shifts and additions and
accurate to about $2^{-58}$. On 270\,225 inputs it equals the C library result
or differs by one unit in the last place (33 cases), which can change a code only
if the exact value lies within about $2^{-50}$ of a rounding boundary.

%=====================================================================
\section{Results}\label{sec:results}
%=====================================================================
\subsection{Functional Verification}
C-simulation unit tests of the core cover signed arithmetic,
round-half-to-even, rounding after accumulation, saturation before ReLU and
exact score corner cases. A golden test of
256 test flows, covering every attack family and the 32 flows closest to the
threshold on each side, matched the integer reference bit for bit in C
simulation and in the generated RTL. An interface test with early and late
\texttt{TLAST} and partial \texttt{TKEEP}/\texttt{TSTRB} confirms that only the
three valid frames of seven are scored, in order. A golden benign flow lands
almost on the center (score code 51\,193), while an attack flow whose
\texttt{MIN\_TTL} input saturates at 4.0 scores about 600 times the threshold.

\subsection{Feature Extractor Verification}
The four IP cores were simulated as a chain against the software reference
extractor, preprocessing and integer model. On all three UNSW-NB15 capture files
(5\,168\,214 packets, 40 minutes of traffic) the hardware model produced the
same 58\,281 flows, with every five-tuple, timestamp, counter, feature, input
code, score and end reason identical, and all 466\,248 feature beats followed
the eight-beat framing. Twelve captures re-framed from the same packets cover
VLAN tags, raw IP, loopback, cooked capture v2, big-endian nanosecond files,
frames truncated at 30, 45 and 60 bytes, 1000-byte DMA chunks and other expiry
settings, all identical. The preprocessing IP matched all 8\,000\,000 codes of
one million random feature vectors, and RTL co-simulation of each new IP inside
the chain reproduced all 298 flows of a 2000-packet capture.

\subsection{Implementation Results}
The inference core alone has an HLS-estimated maximum frequency of 138~MHz and a
latency of 158 cycles, about 1.7~\textmu s per flow at 100~MHz.
Table~\ref{tab:synth} lists the complete system, which with Vivado 2023.2 meets
timing at 100~MHz after place and route on both the Pynq-Z2 and the ZedBoard
(worst setup slack 0.080~ns, hold 0.016~ns). In RTL co-simulation the extractor processed the 2000-packet sample,
including the final flush, in 273\,623 cycles, under 140 cycles per packet
($>7\times10^{5}$ packets/s), and the preprocessing IP accepted a flow
about every 900 cycles; with one flow per 89 packets, the parser sets the
throughput.

\begin{table}[htbp]
\caption{Resources: HLS Estimates per IP Core and Routed Total}
\begin{center}
\begin{tabular}{|l|r|r|r|r|}
\hline
\textbf{IP core} & \textbf{LUT} & \textbf{FF} & \textbf{BRAM18} & \textbf{DSP} \\
\hline
\texttt{deep\_svdd\_axis} & 4\,556 & 7\,751 & 0 & 57 \\
Feature extraction & 26\,430 & 22\,984 & 120 & 24 \\
Preprocessing & 7\,582 & 3\,810 & 2 & 11 \\
Record join & 957 & 2\,463 & 0 & 0 \\
\hline
Complete (routed) & 36\,362 & 39\,877 & 136 & 91 \\
Share of Zynq-7020 & 68\% & 37\% & 49\% & 41\% \\
\hline
\end{tabular}
\label{tab:synth}
\end{center}
\end{table}

\subsection{Detection Performance}
The frozen Q24\_I8 core was evaluated in HLS C simulation on the 100\,000-flow
test sample, which contains 91\,087 benign and 8\,913 attack flows (attacks are
positive). It reaches an AUROC of 0.99976 and an average precision of 0.99453.
Table~\ref{tab:detect} gives the
confusion matrix at $T$ and $T'$. Every attack is detected at both thresholds,
so each family in the sample has 100\% recall. The FPR of 1.09\% at $T$ stays
close to the 1\% target although $T$ was calibrated on earlier validation
flows, and $T'$ removes 10 false alarms without missing an attack. With benign
flows outnumbering attacks ten to one, an FPR near 1\% still gives about one
false alarm per nine detected attacks, hence the precision of 0.90.
\todo{Add the float32 model's test metrics for comparison, if available from
\texttt{runs/software/}.}

\begin{table}[htbp]
\caption{Test-Set Detection Performance of the Q24\_I8 Core (HLS C Simulation, 100\,000 Flows)}
\begin{center}
\begin{tabular}{|l|r|r|}
\hline
\textbf{Metric} & \textbf{Original $T$} & \textbf{Recalibrated $T'$} \\
\hline
Threshold code & 6\,000\,531 & 6\,018\,545 \\
\hline
True negatives & 90\,095 & 90\,105 \\
False positives & 992 & 982 \\
False negatives & 0 & 0 \\
True positives & 8\,913 & 8\,913 \\
\hline
Recall & 1.0000 & 1.0000 \\
Precision & 0.8998 & 0.9008 \\
F1 score & 0.9473 & 0.9478 \\
FPR & 1.089\% & 1.078\% \\
\hline
AUROC & \multicolumn{2}{c|}{0.99976} \\
Average precision & \multicolumn{2}{c|}{0.99453} \\
\hline
\end{tabular}
\label{tab:detect}
\end{center}
\end{table}

%=====================================================================
\section{Comparative Study: Isolation Forest}\label{sec:iforest}
%=====================================================================
Isolation Forest (iForest) \cite{liu2008} is a widely used non-neural detector
for the same one-class setting. It builds $t$ random binary trees, each on a
subsample of $\psi$ training points, whose internal nodes split a randomly
chosen feature at a random value within its range in the node. Anomalies are
isolated after fewer splits, so the score $2^{-E[h(\mathbf{x})]/c(\psi)}$
decreases with the average path length $E[h(\mathbf{x})]$, where $c(\psi)$
normalizes for the subsample size. Like Deep SVDD it needs no attack labels.
Table~\ref{tab:iforest} compares the two as hardware for the same eight
features, for the default $t=100$ and $\psi=256$ of \cite{liu2008}, whose trees
are at most 8 levels deep with at most 511 nodes. The figures are analytical;
iForest's detection accuracy on the frozen split was not measured.

\begin{table}[htbp]
\caption{Deep SVDD and Isolation Forest as Hardware (Analytical)}
\begin{center}
\footnotesize
\begin{tabular}{|p{1.35cm}|p{2.85cm}|p{2.85cm}|}
\hline
 & \textbf{Deep SVDD (this work)} & \textbf{iForest ($t=100$, $\psi=256$)} \\
\hline
Training & gradient descent & random splits, no optimization \\
Model & 904 values, 23~kbit & $\le$51\,100 nodes, $\approx$2.0~Mbit \\
Per flow & 896 MACs, fixed schedule & $\le$800 comparisons, data-dependent \\
Inputs & preprocessed Q24 codes & raw integer features \\
Resource & 57 DSP, no BRAM & 56--100 BRAM36, no DSP \\
Decision & distance $>T$ & mean path length below a bound \\
\hline
\end{tabular}
\label{tab:iforest}
\end{center}
\end{table}

Since $\log(1+x)$ and the affine map of \eqref{eq:prep} are increasing, every
iForest split can be rewritten as an integer threshold on the raw feature, so
the preprocessing IP (7\,582 LUTs, 11 DSP slices) would disappear; the decision
needs no exponential because the score is monotone in the summed path length;
and comparisons are exact by construction. The cost is memory: at about 40 bits
per node, one block RAM per tree for parallel traversal takes 100 BRAM36 (71\%
of the device), which does not fit beside the 60 BRAM36 of the flow table, while
packing the trees into about 56 BRAM36 fits but serializes up to 900
data-dependent node reads per flow, similar to the 900 cycles of the
preprocessing it replaces. Deep SVDD keeps its 23~kbit of weights in logic,
runs a fixed schedule with constant latency, and learns nonlinear features
rather than axis-parallel splits. A fair accuracy comparison would fit and
calibrate iForest on the same benign training and validation flows.

%=====================================================================
\section{Limitations and Future Work}\label{sec:limits}
%=====================================================================
The evaluation uses a single testbed dataset whose hosts appear in all periods,
and the selected features include \texttt{MIN\_TTL}, which can reflect testbed
topology rather than attack behavior, so the near-perfect separation may not
carry over to other networks. Detection results come from C simulation of the
core on the dataset's features. The extractor reproduces our software reference
exactly, but agreement with the nProbe exporter behind the dataset, including
its timeouts and byte accounting, has not been checked flow by flow. All results
are from simulation and implementation reports; on-board measurements remain
to be done, and the routed design meets timing with only 80~ps of margin. The
Isolation Forest comparison is analytical.

%=====================================================================
\section{Conclusion}
%=====================================================================
This paper presented a complete path from network traffic to a streaming FPGA
anomaly detector based on Deep SVDD, trained only on benign traffic. The
Q24\_I8 core matches its integer reference bit for bit and, in C simulation on
100\,000 held-out flows, detects every attack at a 1.09\% false-positive rate
with an AUROC of 0.9998. An on-chip feature extractor and preprocessing pipeline
reproduce the software reference on all 58\,281 flows from 5.2 million packets,
and the system fits in 68\% of the logic of a Zynq-7020 at 100~MHz. Isolation
Forest would remove the preprocessing arithmetic, but its trees would compete
with the flow table for block RAM.

% \section*{Acknowledgment}
% Add acknowledgments here if required.

\begin{thebibliography}{00}
\bibitem{sommer2010} R. Sommer and V. Paxson, ``Outside the closed world: On using machine learning for network intrusion detection,'' in Proc. IEEE Symp. Security and Privacy, 2010, pp. 305--316.
\bibitem{chandola2009} V. Chandola, A. Banerjee, and V. Kumar, ``Anomaly detection: A survey,'' ACM Comput. Surv., vol. 41, no. 3, pp. 1--58, 2009.
\bibitem{ruff2018} L. Ruff, R. Vandermeulen, N. Goernitz, L. Deecke, S. A. Siddiqui, A. Binder, E. M\"uller, and M. Kloft, ``Deep one-class classification,'' in Proc. 35th Int. Conf. Machine Learning (ICML), 2018, pp. 4393--4402.
\bibitem{tax2004} D. M. J. Tax and R. P. W. Duin, ``Support vector data description,'' Machine Learning, vol. 54, no. 1, pp. 45--66, 2004.
\bibitem{moustafa2015} N. Moustafa and J. Slay, ``UNSW-NB15: A comprehensive data set for network intrusion detection systems,'' in Proc. Military Communications and Information Systems Conf. (MilCIS), 2015, pp. 1--6.
\bibitem{sarhan2021} M. Sarhan, S. Layeghy, N. Moustafa, and M. Portmann, ``NetFlow datasets for machine learning-based network intrusion detection systems,'' in Big Data Technologies and Applications, Springer, 2021, pp. 117--135.
\bibitem{sarhan2022} M. Sarhan, S. Layeghy, and M. Portmann, ``Towards a standard feature set for network intrusion detection system datasets,'' Mobile Networks and Applications, vol. 27, pp. 357--370, 2022.
\bibitem{nfv3} The University of Queensland, ``NF-UNSW-NB15-v3,'' dataset, doi: 10.48610/6E0EDA1.
\bibitem{kaufman2012} S. Kaufman, S. Rosset, C. Perlich, and O. Stitelman, ``Leakage in data mining: Formulation, detection, and avoidance,'' ACM Trans. Knowl. Discov. Data, vol. 6, no. 4, pp. 1--21, 2012.
\bibitem{jacob2018} B. Jacob, S. Kligys, B. Chen, M. Zhu, M. Tang, A. Howard, H. Adam, and D. Kalenichenko, ``Quantization and training of neural networks for efficient integer-arithmetic-only inference,'' in Proc. IEEE/CVF Conf. Computer Vision and Pattern Recognition (CVPR), 2018, pp. 2704--2713.
\bibitem{duarte2018} J. Duarte et al., ``Fast inference of deep neural networks in FPGAs for particle physics,'' J. Instrumentation, vol. 13, no. 7, p. P07027, 2018.
\bibitem{umuroglu2017} Y. Umuroglu, N. J. Fraser, G. Gambardella, M. Blott, P. Leong, M. Jahre, and K. Vissers, ``FINN: A framework for fast, scalable binarized neural network inference,'' in Proc. ACM/SIGDA Int. Symp. Field-Programmable Gate Arrays (FPGA), 2017, pp. 65--74.
\bibitem{ug1399} AMD Xilinx, ``Vitis High-Level Synthesis User Guide,'' UG1399, v2023.2, 2023.
\bibitem{kraskov2004} A. Kraskov, H. St\"ogbauer, and P. Grassberger, ``Estimating mutual information,'' Phys. Rev. E, vol. 69, no. 6, p. 066138, 2004.
\bibitem{peng2005} H. Peng, F. Long, and C. Ding, ``Feature selection based on mutual information: Criteria of max-dependency, max-relevance, and min-redundancy,'' IEEE Trans. Pattern Anal. Mach. Intell., vol. 27, no. 8, pp. 1226--1238, 2005.
\bibitem{he2015} K. He, X. Zhang, S. Ren, and J. Sun, ``Delving deep into rectifiers: Surpassing human-level performance on ImageNet classification,'' in Proc. IEEE Int. Conf. Computer Vision (ICCV), 2015, pp. 1026--1034.
\bibitem{glorot2010} X. Glorot and Y. Bengio, ``Understanding the difficulty of training deep feedforward neural networks,'' in Proc. 13th Int. Conf. Artificial Intelligence and Statistics (AISTATS), 2010, pp. 249--256.
\bibitem{kingma2015} D. P. Kingma and J. Ba, ``Adam: A method for stochastic optimization,'' in Proc. Int. Conf. Learning Representations (ICLR), 2015.
\bibitem{paszke2019} A. Paszke et al., ``PyTorch: An imperative style, high-performance deep learning library,'' in Advances in Neural Information Processing Systems (NeurIPS), vol. 32, 2019.
\bibitem{axis} ARM Ltd., ``AMBA 4 AXI4-Stream Protocol Specification,'' IHI 0051A, 2010.
\bibitem{liu2008} F. T. Liu, K. M. Ting, and Z.-H. Zhou, ``Isolation forest,'' in Proc. 8th IEEE Int. Conf. Data Mining (ICDM), 2008, pp. 413--422.
\end{thebibliography}

\end{document}
d`. `--driver pynq|devmem`
works as in `zed-ps`. The driver sets FCLK0 to 100 MHz from the real PLL
registers, because PYNQ assumes a 50 MHz crystal and the ZedBoard has 33.3 MHz.
It also refuses a bitstream built for the other board.

**Speed.** RTL co-simulation of the UNSW sample (mostly small packets, 190
bytes on average) measured about 135 clocks per packet. At 100 MHz that is
roughly **740,000 packets/s, or about 140 MB/s**. Scoring a finished flow
takes about 1,000 clocks in `svdd_preprocess` (the three CORDIC logs and the
double-precision divides run one after another), about 100,000 flows/s, plus
about 170 in `deep_svdd_axis`. UNSW averages one flow
per 90 packets, so scoring never holds up the parser. `svdd_ps` on the
Cortex-A9 is estimated at 15–30k packets/s, so the PL is roughly 25–50 times
faster. On the board the limit will probably be reading the file from the SD
card (20–90 MB/s) and copying it into the DMA buffer. `run` prints the MB/s it
achieved. None of this is measured on a board yet.
