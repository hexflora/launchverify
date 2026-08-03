#include <string>

#include <catch2/catch_test_macros.hpp>

#include "launchverify/report.h"

namespace {

lv::report::verification_report make_report() {
    lv::report::verification_report r;
    r.path = L"C:\\tmp\\demo.exe";
    r.file_size = 1234;
    r.hashes.sha256_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    r.hashes.sha1_hex = "a9993e364706816aba3e25717850c26c9cd0d89d";
    r.hashes.md5_hex = "900150983cd24fb0d6963f7d28e17f72";
    r.signature.state = lv::signature::signature_state::signed_valid;
    r.signature.verdict = lv::signature::trust_verdict::not_trusted;
    r.signature.winverifytrust_error = "0x800B010B";
    lv::signature::cert_info signer;
    signer.subject = "LaunchVerify Test Signer";
    signer.issuer = "LaunchVerify Test Signer";
    signer.serial = "1234";
    signer.sha256_thumbprint = "a1b2c3d4e5f60718293a4b5c6d7e8f90123a4b5c6d7e8f90";
    r.signature.signer = signer;
    lv::signature::chain_cert leaf;
    leaf.info = signer;
    leaf.has_error = true;
    leaf.status = "UNTRUSTED ROOT";
    r.signature.chain.push_back(leaf);
    return r;
}

} // namespace

TEST_CASE("sha256_matches compares case-insensitively after trimming") {
    auto r = make_report();
    CHECK(lv::report::sha256_matches(r, "  BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  "));
    CHECK(lv::report::sha256_matches(r, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_FALSE(lv::report::sha256_matches(r, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae"));
    CHECK_FALSE(lv::report::sha256_matches(r, "deadbeef"));
    CHECK_FALSE(lv::report::sha256_matches(r, ""));
}

TEST_CASE("format_report contains expected sections") {
    auto r = make_report();
    std::string text = lv::report::format_report(r);
    CHECK(text.find("SHA-256") != std::string::npos);
    CHECK(text.find("SHA-1") != std::string::npos);
    CHECK(text.find("MD5") != std::string::npos);
    CHECK(text.find("Signer") != std::string::npos);
    CHECK(text.find("LaunchVerify Test Signer") != std::string::npos);
    CHECK(text.find("UNTRUSTED ROOT") != std::string::npos);
    CHECK(text.find("Verdict") != std::string::npos);
}

TEST_CASE("format_report is deterministic") {
    auto r = make_report();
    CHECK(lv::report::format_report(r) == lv::report::format_report(r));
}
