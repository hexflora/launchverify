#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "launchverify/hash.h"
#include "launchverify/signature.h"

namespace lv::report {

struct verification_report {
    std::filesystem::path path;
    std::uint64_t file_size;
    hash::file_hashes hashes;
    signature::signature_report signature;
};

// Case-insensitive, whitespace-trimmed comparison of the expected digest.
bool sha256_matches(const verification_report& r, std::string_view expected_hex);

// Pure formatter (no I/O). Produces a human-readable report.
std::string format_report(const verification_report& r);

} // namespace lv::report