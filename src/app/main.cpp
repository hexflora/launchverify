#include <cstdio>
#include <string_view>

#include "launchverify/error.h"

namespace {

constexpr const char* kVersion = "0.1.0";

void print_usage() {
    std::printf("launchverify %s\n", kVersion);
    std::printf("usage: launchverify <path> [--expect-sha256 <hex>]\n");
}

} // namespace

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (std::string_view{argv[i]} == "--version") {
            std::printf("launchverify %s\n", kVersion);
            return 0;
        }
    }
    if (argc < 2) {
        print_usage();
        return 2;
    }
    print_usage();
    return 2;
}