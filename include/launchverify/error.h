#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace lv {

// Error type shared by all library modules. `code` carries a Windows
// NTSTATUS/HRESULT/GetLastError value when the failure originates from a
// Win32/BCrypt/WinTrust call; it is std::nullopt for non-system failures.
struct verify_error {
    std::string message;
    std::optional<std::int64_t> code;
};

template <typename T>
using result = std::expected<T, verify_error>;

[[nodiscard]] inline std::string to_string(const verify_error& e) {
    return e.message;
}

} // namespace lv