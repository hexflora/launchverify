#include "launchverify/report.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>

namespace lv::report {
namespace {

std::string trim_ascii(std::string_view in) {
    auto is_space = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    std::size_t b = 0;
    std::size_t e = in.size();
    while (b < e && is_space(in[b])) ++b;
    while (e > b && is_space(in[e - 1])) --e;
    return std::string(in.substr(b, e - b));
}

std::string lower_ascii(std::string in) {
    std::transform(in.begin(), in.end(), in.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return in;
}

const char* state_text(lv::signature::signature_state s) {
    using lv::signature::signature_state;
    switch (s) {
        case signature_state::unsigned_file: return "unsigned";
        case signature_state::signed_valid: return "signed (valid)";
        case signature_state::signed_invalid: return "signed (invalid)";
    }
    return "unknown";
}

const char* verdict_text(lv::signature::trust_verdict v) {
    using lv::signature::trust_verdict;
    switch (v) {
        case trust_verdict::trusted: return "trusted";
        case trust_verdict::not_trusted: return "not trusted";
        case trust_verdict::no_signature: return "no signature";
    }
    return "unknown";
}

} // namespace

bool sha256_matches(const verification_report& r, std::string_view expected_hex) {
    std::string trimmed = trim_ascii(expected_hex);
    return lower_ascii(trimmed) == lower_ascii(r.hashes.sha256_hex);
}

std::string format_report(const verification_report& r) {
    std::string out;
    out += "File: " + r.path.string() + "\n";
    out += "Size: " + std::to_string(r.file_size) + " bytes\n";
    out += "\n";
    out += "Hashes\n";
    out += "  SHA-256: " + r.hashes.sha256_hex + "\n";
    out += "  SHA-1:   " + r.hashes.sha1_hex + "\n";
    out += "  MD5:     " + r.hashes.md5_hex + "\n";
    out += "\n";
    out += "Signature\n";
    out += "  State:   " + std::string(state_text(r.signature.state)) + "\n";
    out += "  Verdict: " + std::string(verdict_text(r.signature.verdict)) + "\n";
    if (r.signature.verdict == lv::signature::trust_verdict::not_trusted) {
        out += "  WinVerifyTrust: " + r.signature.winverifytrust_error + "\n";
    }
    if (r.signature.signer) {
        out += "\n";
        out += "Signer\n";
        out += "  Subject:    " + r.signature.signer->subject + "\n";
        out += "  Issuer:     " + r.signature.signer->issuer + "\n";
        out += "  Serial:     " + r.signature.signer->serial + "\n";
        out += "  Thumbprint: " + r.signature.signer->sha256_thumbprint + "\n";
        out += "  Not before: " + r.signature.signer->not_before + "\n";
        out += "  Not after:  " + r.signature.signer->not_after + "\n";
    }
    if (!r.signature.chain.empty()) {
        out += "\n";
        out += "Certificate chain (leaf first)\n";
        for (const auto& c : r.signature.chain) {
            out += "  - " + c.info.subject + "\n";
            out += "      status: " + c.status + "\n";
        }
    }
    if (r.signature.timestamp) {
        out += "\n";
        out += "Timestamp\n";
        out += "  Authority: " + r.signature.timestamp->authority + "\n";
        out += "  Time:      " + r.signature.timestamp->time + "\n";
    }
    return out;
}

} // namespace lv::report
