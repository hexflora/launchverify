#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "launchverify/error.h"

namespace lv::signature {

enum class signature_state : std::uint8_t { unsigned_file, signed_valid, signed_invalid };
enum class trust_verdict : std::uint8_t { trusted, not_trusted, no_signature };

struct cert_info {
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string sha256_thumbprint;
    std::string not_before;  // ISO 8601 local
    std::string not_after;   // ISO 8601 local
};

struct chain_cert {
    cert_info info;
    bool has_error;        // any CERT_TRUST_STATUS error flags set
    std::string status;    // human-readable; e.g. "EXPIRED", "UNTRUSTED ROOT", "REVOKED", "OK"
};

struct timestamp_info {
    std::string authority;  // timestamp signer subject
    std::string time;       // ISO 8601 local
};

struct signature_report {
    signature_state state;
    trust_verdict verdict;
    std::string winverifytrust_error;  // populated when not_trusted
    std::optional<cert_info> signer;
    std::vector<chain_cert> chain;     // root-last ordering
    std::optional<timestamp_info> timestamp;
};

result<signature_report> verify_signature(const std::filesystem::path& path);

} // namespace lv::signature