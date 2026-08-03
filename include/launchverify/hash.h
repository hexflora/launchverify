#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

#include "launchverify/error.h"

namespace lv::hash {

enum class algo : std::uint8_t { sha256, sha1, md5 };

struct file_hashes {
    std::string sha256_hex;
    std::string sha1_hex;
    std::string md5_hex;
};

// Streams the file once, computing SHA-256, SHA-1 and MD5 simultaneously.
result<file_hashes> compute_file_hashes(const std::filesystem::path& path);

} // namespace lv::hash