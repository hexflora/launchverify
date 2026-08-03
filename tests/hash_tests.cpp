#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "launchverify/hash.h"

namespace {

std::filesystem::path temp_dir() {
    auto dir = std::filesystem::temp_directory_path();
    auto p = dir / "lv_hash_tests";
    std::filesystem::create_directories(p);
    return p;
}

std::filesystem::path write_file(const std::string& name, const std::string& bytes) {
    auto p = temp_dir() / name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) {
        throw std::runtime_error("cannot open temp file");
    }
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!f) {
        throw std::runtime_error("failed writing temp file");
    }
    return p;
}

} // namespace

TEST_CASE("hash of \"abc\" matches known vectors") {
    auto p = write_file("abc.bin", "abc");
    auto r = lv::hash::compute_file_hashes(p);
    REQUIRE(r);
    CHECK(r->sha256_hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(r->sha1_hex == "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(r->md5_hex == "900150983cd24fb0d6963f7d28e17f72");
}

TEST_CASE("hash of empty file matches known vectors") {
    auto p = write_file("empty.bin", "");
    auto r = lv::hash::compute_file_hashes(p);
    REQUIRE(r);
    CHECK(r->sha256_hex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(r->sha1_hex == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    CHECK(r->md5_hex == "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_CASE("hash of multi-chunk file matches known vectors") {
    // 3 MiB of the byte 0x61 ('a'); digests computed with certutil/Get-FileHash.
    std::string data(3u * 1024u * 1024u, 'a');
    auto p = write_file("big.bin", data);
    auto r = lv::hash::compute_file_hashes(p);
    REQUIRE(r);
    CHECK(r->sha256_hex == "6f850bc94ae6f7de14297c01616c36d712d22864497b28a63b81d776b035e656");
    CHECK(r->sha1_hex == "95fabf9f3f6a52aaadcf57e61a66fd56f893095b");
    CHECK(r->md5_hex == "6a11a8872b36343799a15617bea78cef");
}

TEST_CASE("chunk-boundary files produce distinct, correctly-sized digests") {
    const std::string one_mib(1024u * 1024u, '\0');
    const std::string one_mib_minus(1024u * 1024u - 1u, '\0');
    const std::string one_mib_plus(1024u * 1024u + 1u, '\0');

    auto ra = lv::hash::compute_file_hashes(write_file("c_1m.bin", one_mib));
    auto rb = lv::hash::compute_file_hashes(write_file("c_1m_minus.bin", one_mib_minus));
    auto rc = lv::hash::compute_file_hashes(write_file("c_1m_plus.bin", one_mib_plus));
    REQUIRE(ra);
    REQUIRE(rb);
    REQUIRE(rc);

    CHECK(ra->sha256_hex == "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58");
    CHECK(rb->sha256_hex == "ca7ed0c4a8e67cbdc461c4cb0d286d2fabbd9f0c41a7f42b665f72ebaa8aec56");
    CHECK(rc->sha256_hex == "2cb74edba754a81d121c9db6833704a8e7d417e5b13d1a19f4a52f007d644264");

    for (const auto* hex : {&ra->sha256_hex, &rb->sha256_hex, &rc->sha256_hex}) {
        CHECK(hex->size() == 64);
        CHECK(hex->find_first_of("ABCDEF") == std::string::npos);  // lowercase
    }
}

TEST_CASE("hash of nonexistent file is an error") {
    auto p = std::filesystem::temp_directory_path() / "lv_does_not_exist.bin";
    std::filesystem::remove(p);
    auto r = lv::hash::compute_file_hashes(p);
    REQUIRE_FALSE(r);
}