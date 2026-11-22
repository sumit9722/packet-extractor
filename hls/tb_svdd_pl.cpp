// Testbench for the pynq-pl IP chain, connected as in the block design:
//   svdd_flow_extract -> svdd_preprocess -> deep_svdd_axis (core/, unchanged) -> svdd_record_join
//
//   (no arguments)              built-in checks + the small stream in tb_data/ (used by cosim)
//   stream IN.bin OUT.bin [FEAT.bin]
//                               replay chunks written by "python3 -m svdd_pl pack" and save every
//                               output beat (decode with "python3 -m svdd_pl decode"); optionally
//                               also the extractor's raw feature words (uint32, 8 per flow)
//   pre IN.bin OUT.bin          preprocessing only: N x 8 uint32 raw features -> N x 8 int32 codes
//
// Every feature beat is checked against the handoff spec's interface rules (8 beats per
// flow, TLAST on word 7 only, TKEEP = TSTRB = 1111).
// IN.bin for "stream" is a sequence of [uint32 length][length bytes of chunk].
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "core/inference_axis.hpp"
#include "svdd_pl.hpp"

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        std::cerr << "FAIL: " << what << "\n";
        failures++;
    }
}

uint64_t le64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

std::vector<uint32_t> feature_words;    // every raw feature word the extractor sent
long spec_violations = 0;

// Run one chunk through the IP chain. Returns the output beats; checks the framing.
std::vector<uint64_t> run_chunk(const std::vector<unsigned char>& chunk, bool& marker_ok) {
    hls::stream<beat_t> in("in"), meta("meta"), out("out");
    hls::stream<feat_beat_t> feat("feat"), feat2("feat2");
    hls::stream<q24_beat_t> q24("q24"), codes("codes");
    hls::stream<score_beat_t> score("score");
    const size_t beats = chunk.size() / 8;
    for (size_t i = 0; i < beats; i++) {
        beat_t b;
        b.data = le64(&chunk[8 * i]);
        b.keep = -1;
        b.strb = -1;
        b.last = (i == beats - 1);
        in.write(b);
    }
    svdd_flow_extract(in, feat, meta);

    // The feature stream must follow the handoff spec's framing.
    long n = 0;
    while (!feat.empty()) {
        const feat_beat_t b = feat.read();
        const bool want_last = n % 8 == 7;
        if (b.keep != 0xF || b.strb != 0xF || bool(b.last) != want_last || b.user != 0) spec_violations++;
        feature_words.push_back(b.data.to_uint());
        feat2.write(b);
        n++;
    }
    if (n % 8) spec_violations++;

    while (!feat2.empty()) svdd_preprocess(feat2, q24, codes);
    while (!q24.empty()) deep_svdd_axis(q24, score);
    while (!meta.empty()) svdd_record_join(meta, codes, score, out);
    check(codes.empty() && score.empty(), "join left codes or scores unread");
    std::vector<uint64_t> words;
    bool last = false;
    int since_last = 0;
    while (!out.empty()) {
        const beat_t b = out.read();
        words.push_back(b.data.to_uint64());
        last = b.last;
        since_last = last ? 0 : since_last + 1;
    }
    marker_ok = !words.empty() && words.size() % svpl::REC_WORDS == 0 && last &&
                (words[words.size() - svpl::REC_WORDS] & 0xFF) == svpl::REC_MARKER;
    check(in.empty(), "core left input beats unread");
    return words;
}

std::vector<unsigned char> header(unsigned flags, unsigned linktype, uint32_t data_bytes) {
    std::vector<unsigned char> h(32, 0);
    const uint64_t w0 = svpl::MAGIC | (uint64_t(svpl::VERSION) << 32) | (uint64_t(flags) << 40) |
                        (uint64_t(linktype) << 48);
    const uint64_t w1 = data_bytes | (uint64_t(1000000) << 32);
    const uint64_t w2 = 30000000ull | (uint64_t(120000000) << 32);
    for (int i = 0; i < 8; i++) {
        h[i] = (w0 >> (8 * i)) & 0xFF;
        h[8 + i] = (w1 >> (8 * i)) & 0xFF;
        h[16 + i] = (w2 >> (8 * i)) & 0xFF;
    }
    return h;
}

void builtin_checks() {
    // Q16 rounding: ties go to the even code, as numpy.rint does.
    const float lsb = 1.0f / 65536.0f;
    check(svpl::quantize_q16(0.5f * lsb) == 0, "0.5 LSB -> 0");
    check(svpl::quantize_q16(1.5f * lsb) == 2, "1.5 LSB -> 2");
    check(svpl::quantize_q16(2.5f * lsb) == 2, "2.5 LSB -> 2");
    check(svpl::quantize_q16(-1.5f * lsb) == -2, "-1.5 LSB -> -2");
    check(svpl::quantize_q16(1.0f) == 65536, "1.0 -> 65536");
    check(svpl::quantize_q16(200.0f) == (1 << 23) - 1, "positive saturation");
    check(svpl::quantize_q16(-200.0f) == -(1 << 23), "negative saturation");
    check(svpl::quantize_q16(-128.0f) == -(1 << 23), "-128 is exactly the most negative code");

    // CORDIC log1p against the C library (what numpy uses): within 1 ulp everywhere tried.
    {
        long n = 0, off_by_one = 0, worse = 0;
        auto try_x = [&](uint32_t x) {
            const double got = svpl::log1p_u32(x), want = std::log1p(double(x));
            int64_t a, b;
            std::memcpy(&a, &got, 8);
            std::memcpy(&b, &want, 8);
            const int64_t d = a > b ? a - b : b - a;
            n++;
            if (d == 1) off_by_one++;
            if (d > 1) {
                if (worse < 5) std::cerr << "log1p(" << x << "): " << d << " ulp off\n";
                worse++;
            }
        };
        for (uint32_t x = 0; x < 70000; x++) try_x(x);
        for (int e = 0; e < 32; e++)
            for (int d = -3; d <= 3; d++) try_x(uint32_t((uint64_t(1) << e) + d));
        uint64_t r = 88172645463325252ull;
        for (int i = 0; i < 200000; i++) {
            r ^= r << 13, r ^= r >> 7, r ^= r << 17;
            try_x(uint32_t(r >> (r & 31)));
        }
        try_x(0xFFFFFFFFu);
        check(worse == 0, "log1p_u32 within 1 ulp of log1p");
        std::cerr << "log1p_u32: " << n << " inputs, " << off_by_one << " differ by 1 ulp from libm, "
                  << worse << " by more\n";
    }

    // Bring-up vector from the handoff spec: raw -> codes.
    const ap_uint<32> raw[8] = {1817, 2512, 1552, 31, 106, 52, 20272, 17376};
    const int want[8] = {41347, 36297, 46490, 65536, 1516, 42598, 20389, 17476};
    ap_int<32> codes[8];
    bool known[8] = {false, false, false, false, false, false, false, false};
    svpl::preprocess(raw, known, codes);
    for (int i = 0; i < 8; i++) check(codes[i] == want[i], "bring-up code " + std::to_string(i));

    // ... and through the stream IPs: preprocessing IP -> deep_svdd_axis -> score 51193 (spec 4).
    {
        hls::stream<feat_beat_t> f("f");
        hls::stream<q24_beat_t> q("q"), c("c");
        hls::stream<score_beat_t> sc("sc");
        for (int i = 0; i < 8; i++) {
            feat_beat_t b;
            b.data = raw[i];
            b.keep = 0xF;
            b.strb = 0xF;
            b.user = 0;
            b.last = i == 7;
            f.write(b);
        }
        svdd_preprocess(f, q, c);
        for (int i = 0; i < 8; i++) {
            const q24_beat_t qb = q.read();
            q.write(qb);
            check(ap_int<32>(qb.data) == want[i] && qb.last == (i == 7), "Q24 beat " + std::to_string(i));
        }
        deep_svdd_axis(q, sc);
        check(!sc.empty() && sc.read().data == 51193, "bring-up score 51193");
        for (int i = 0; i < 8; i++) check(ap_int<32>(c.read().data) == want[i], "Q24 copy for the join IP");
    }

    // Unknown fields (TUSER = 1) and MIN_TTL above 255 use the saved median, as preprocess.py does.
    {
        const ap_uint<32> med[8] = {1684, 2512, 29, 31, 510, 52, 13032, 13032};
        ap_int<32> want_med[8], got[8];
        svpl::preprocess(med, known, want_med);
        bool unknown[8];
        for (int i = 0; i < 8; i++) unknown[i] = true;
        svpl::preprocess(raw, unknown, got);
        for (int i = 0; i < 8; i++) check(got[i] == want_med[i], "unknown field -> median " + std::to_string(i));
        ap_uint<32> ttl[8] = {1817, 2512, 1552, 300, 106, 52, 20272, 17376};
        svpl::preprocess(ttl, known, got);
        check(got[3] == want_med[3], "MIN_TTL 300 -> median");
    }

    // A chunk that is not ours is skipped and reported.
    std::vector<unsigned char> junk(64, 0x11);
    bool ok = false;
    std::vector<uint64_t> w = run_chunk(junk, ok);
    check(ok && w.size() == 16 && ((w[0] >> 8) & svpl::E_MAGIC), "bad magic -> marker with error");

    // One Ethernet/IPv4/UDP frame, then flush: exactly one flow comes out.
    std::vector<unsigned char> frame = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,               // Ethernet
        0x45, 0, 0, 33, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,  // IPv4, len 33, TTL 64, UDP
        0x30, 0x39, 0x00, 0x35, 0, 13, 0, 0, 'h', 'e', 'l', 'l', 'o'};      // UDP 12345 -> 53
    std::vector<unsigned char> data(16, 0);
    const uint32_t caplen = frame.size();
    data[0] = 100;                                                   // 100 s
    for (int i = 0; i < 4; i++) data[8 + i] = data[12 + i] = (caplen >> (8 * i)) & 0xFF;
    data.insert(data.end(), frame.begin(), frame.end());
    std::vector<unsigned char> chunk = header(svpl::F_RESET | svpl::F_NEW_FILE | svpl::F_FLUSH, 1, data.size());
    chunk.insert(chunk.end(), data.begin(), data.end());
    while (chunk.size() % 8) chunk.push_back(0);
    w = run_chunk(chunk, ok);
    check(ok && w.size() == 32, "one frame -> one flow record + marker");
    if (w.size() == 32) {
        check((w[0] & 0xFF) == svpl::REC_FLOW && ((w[0] >> 8) & 0xFF) == svpl::R_END, "flow record, reason end");
        check(((w[0] >> 16) & 0xFF) == 17 && ((w[0] >> 32) & 0xFFFF) == 12345 && (w[0] >> 48) == 53, "5-tuple ports");
        check(w[1] == 100000000ull && w[3] == ((uint64_t(0x0A000002) << 32) | 0x0A000001), "time and addresses");
        check(w[4] == 1 && w[5] == 33 && w[6] == 0 && w[7] == 0, "counters");
        check((w[8] & 0xFFFF) == 0 && ((w[8] >> 16) & 0xFFFF) == 33, "single packet: MIN_TTL 0, MAX_LEN 33");
        check(w[16 + 2] == 1 && w[16 + 3] == 1 && w[16 + 4] == 0 && w[16 + 6] == 1, "marker counters");
    }
}

bool read_file(const char* path, std::vector<unsigned char>& buf) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    buf.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

int run_stream(const char* in_path, const char* out_path, const char* feat_path = nullptr) {
    std::ifstream in(in_path, std::ios::binary);   // read chunk by chunk: the input can be GBs
    if (!in) {
        std::cerr << "cannot read " << in_path << "\n";
        return 1;
    }
    std::ofstream out(out_path, std::ios::binary);
    std::ofstream feat_out;
    if (feat_path) feat_out.open(feat_path, std::ios::binary);
    feature_words.clear();                         // drop what the built-in checks produced
    size_t chunks = 0, words = 0, feats = 0;
    unsigned char len[4];
    while (in.read(reinterpret_cast<char*>(len), 4)) {
        const uint32_t n = len[0] | (len[1] << 8) | (len[2] << 16) | (uint32_t(len[3]) << 24);
        std::vector<unsigned char> chunk(n);
        if (!in.read(reinterpret_cast<char*>(chunk.data()), n)) {
            std::cerr << "truncated stream file\n";
            return 1;
        }
        bool ok = false;
        const std::vector<uint64_t> w = run_chunk(chunk, ok);
        check(ok, "chunk " + std::to_string(chunks) + " output framing");
        out.write(reinterpret_cast<const char*>(w.data()), w.size() * 8);
        if (feat_path) feat_out.write(reinterpret_cast<const char*>(feature_words.data()), feature_words.size() * 4);
        feats += feature_words.size();
        feature_words.clear();
        chunks++;
        words += w.size();
        if (chunks % 100 == 0) std::cerr << "  " << chunks << " chunks\n";
    }
    std::cerr << chunks << " chunks -> " << words / svpl::REC_WORDS << " records, " << feats / 8
              << " feature records (" << spec_violations << " beats breaking the spec framing)\n";
    check(spec_violations == 0, "feature stream follows the handoff spec framing");
    return 0;
}

int run_pre(const char* in_path, const char* out_path) {
    std::vector<unsigned char> all;
    if (!read_file(in_path, all)) return 1;
    std::ofstream out(out_path, std::ios::binary);
    const size_t n = all.size() / 32;
    for (size_t r = 0; r < n; r++) {
        ap_uint<32> raw[8];
        for (int i = 0; i < 8; i++) {
            const unsigned char* p = &all[32 * r + 4 * i];
            raw[i] = p[0] | (p[1] << 8) | (p[2] << 16) | (uint32_t(p[3]) << 24);
        }
        ap_int<32> codes[8];
        const bool known[8] = {false, false, false, false, false, false, false, false};
        svpl::preprocess(raw, known, codes);
        for (int i = 0; i < 8; i++) {
            const int32_t c = codes[i].to_int();
            out.write(reinterpret_cast<const char*>(&c), 4);
        }
    }
    std::cerr << n << " vectors preprocessed\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    builtin_checks();
    int rc = 0;
    if (argc >= 4 && std::string(argv[1]) == "stream") {
        rc = run_stream(argv[2], argv[3], argc >= 5 ? argv[4] : nullptr);
    } else if (argc >= 4 && std::string(argv[1]) == "pre") {
        rc = run_pre(argv[2], argv[3]);
    } else {
        // Default (also what cosim runs): the small capture shipped in tb_data/, if present.
        std::ifstream probe("tb_data/small_stream.bin");
        if (probe) rc = run_stream("tb_data/small_stream.bin", "tb_data/small_out.bin");
    }
    if (failures) std::cerr << failures << " CHECKS FAILED\n";
    else std::cerr << "all testbench checks passed\n";
    return (rc || failures) ? 1 : 0;
}
