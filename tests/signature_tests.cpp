#include <filesystem>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "launchverify/signature.h"

namespace {

std::filesystem::path fixture(const char* name) {
    return std::filesystem::path(__FILE__).parent_path() / "fixtures" / name;
}

} // namespace

TEST_CASE("unsigned exe reports unsigned/no signature") {
    auto r = lv::signature::verify_signature(fixture("unsigned.exe"));
    REQUIRE(r);
    CHECK(r->state == lv::signature::signature_state::unsigned_file);
    CHECK(r->verdict == lv::signature::trust_verdict::no_signature);
}

TEST_CASE("self-signed exe is a valid signature but not trusted") {
    auto r = lv::signature::verify_signature(fixture("signed-selfsigned.exe"));
    REQUIRE(r);
    CHECK(r->state == lv::signature::signature_state::signed_valid);
    CHECK(r->verdict == lv::signature::trust_verdict::not_trusted);
}

TEST_CASE("expired-cert exe is not trusted") {
    auto r = lv::signature::verify_signature(fixture("signed-expired.exe"));
    REQUIRE(r);
    CHECK(r->verdict == lv::signature::trust_verdict::not_trusted);
}

TEST_CASE("tampered exe is an invalid signature") {
    auto r = lv::signature::verify_signature(fixture("signed-tampered.exe"));
    REQUIRE(r);
    CHECK(r->state == lv::signature::signature_state::signed_invalid);
    CHECK(r->verdict == lv::signature::trust_verdict::not_trusted);
}

TEST_CASE("nonexistent file is an error") {
    auto r = lv::signature::verify_signature(std::filesystem::temp_directory_path() / "lv_no_such_file.exe");
    REQUIRE_FALSE(r);
}