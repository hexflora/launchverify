#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "launchverify/error.h"
#include "launchverify/hash.h"
#include "launchverify/report.h"
#include "launchverify/signature.h"

namespace {

constexpr const char* kVersion = "0.1.0";

void print_usage() {
    std::printf("launchverify %s\n", kVersion);
    std::printf("usage: launchverify <path> [--expect-sha256 <hex>]\n");
}

int print_error(const lv::verify_error& e) {
    std::fprintf(stderr, "error: %s\n", e.message.c_str());
    if (e.code) {
        std::fprintf(stderr, "  code: 0x%llX\n", static_cast<unsigned long long>(*e.code));
    }
    return 2;
}

} // namespace

int main(int argc, char* argv[]) {
    std::filesystem::path path;
    std::optional<std::string> expected_sha256;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--version") {
            std::printf("launchverify %s\n", kVersion);
            return 0;
        }
        if (arg == "--expect-sha256") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "error: --expect-sha256 requires a hex argument\n");
                return 2;
            }
            expected_sha256 = argv[++i];
            continue;
        }
        if (arg.starts_with('-')) {
            std::fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
            return 2;
        }
        path = arg;
    }

    if (path.empty()) {
        print_usage();
        return 2;
    }

    std::error_code ec;
    const std::uintmax_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        std::fprintf(stderr, "error: cannot stat '%s': %s\n", path.string().c_str(), ec.message().c_str());
        return 2;
    }

    auto hashes = lv::hash::compute_file_hashes(path);
    if (!hashes) return print_error(hashes.error());

    auto signature = lv::signature::verify_signature(path);
    if (!signature) return print_error(signature.error());

    lv::report::verification_report report;
    report.path = path;
    report.file_size = static_cast<std::uint64_t>(size);
    report.hashes = std::move(*hashes);
    report.signature = std::move(*signature);

    bool hash_mismatch = false;
    if (expected_sha256 && !lv::report::sha256_matches(report, *expected_sha256)) {
        hash_mismatch = true;
        std::printf("Hash check: MISMATCH (expected %s)\n", expected_sha256->c_str());
    }

    std::printf("%s", lv::report::format_report(report).c_str());

    const bool untrusted =
        report.signature.verdict == lv::signature::trust_verdict::not_trusted ||
        report.signature.verdict == lv::signature::trust_verdict::no_signature;
    if (untrusted || hash_mismatch) return 1;
    return 0;
}