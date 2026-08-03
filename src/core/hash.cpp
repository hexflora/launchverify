#include "launchverify/hash.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lv::hash {
namespace {

constexpr std::uint32_t kChunkSize = 1u << 20;  // 1 MiB

class verify_error_exception {
public:
    explicit verify_error_exception(verify_error e) : error_(std::move(e)) {}
    const verify_error& get() const noexcept { return error_; }

private:
    verify_error error_;
};

[[noreturn]] void fail(std::string message, std::int64_t code) {
    throw verify_error_exception(verify_error{std::move(message), code});
}

class alg_handle {
public:
    BCRYPT_ALG_HANDLE h = nullptr;
    alg_handle() = default;
    explicit alg_handle(BCRYPT_ALG_HANDLE handle) : h(handle) {}
    ~alg_handle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
    alg_handle(const alg_handle&) = delete;
    alg_handle& operator=(const alg_handle&) = delete;
    alg_handle(alg_handle&& o) noexcept : h(o.h) { o.h = nullptr; }
    alg_handle& operator=(alg_handle&& o) noexcept {
        if (this != &o) {
            if (h) BCryptCloseAlgorithmProvider(h, 0);
            h = o.h;
            o.h = nullptr;
        }
        return *this;
    }
};

class hash_handle {
public:
    BCRYPT_HASH_HANDLE h = nullptr;
    hash_handle() = default;
    explicit hash_handle(BCRYPT_HASH_HANDLE handle) : h(handle) {}
    ~hash_handle() { if (h) BCryptDestroyHash(h); }
    hash_handle(const hash_handle&) = delete;
    hash_handle& operator=(const hash_handle&) = delete;
    hash_handle(hash_handle&& o) noexcept : h(o.h) { o.h = nullptr; }
    hash_handle& operator=(hash_handle&& o) noexcept {
        if (this != &o) {
            if (h) BCryptDestroyHash(h);
            h = o.h;
            o.h = nullptr;
        }
        return *this;
    }
};

class file_handle {
public:
    HANDLE h = INVALID_HANDLE_VALUE;
    file_handle() = default;
    explicit file_handle(HANDLE handle) : h(handle) {}
    ~file_handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    file_handle(const file_handle&) = delete;
    file_handle& operator=(const file_handle&) = delete;
    file_handle(file_handle&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
    file_handle& operator=(file_handle&& o) noexcept {
        if (this != &o) {
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
            h = o.h;
            o.h = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    bool ok() const noexcept { return h != INVALID_HANDLE_VALUE; }
};

alg_handle open_algorithm(PCWSTR name) {
    alg_handle a;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&a.h, name, nullptr, 0);
    if (st < 0) {
        fail(std::string("BCryptOpenAlgorithmProvider failed"), static_cast<std::int64_t>(st));
    }
    return a;
}

std::uint32_t hash_length(BCRYPT_ALG_HANDLE a) {
    DWORD len = 0;
    DWORD written = 0;
    NTSTATUS st = BCryptGetProperty(a, BCRYPT_HASH_LENGTH,
                                    reinterpret_cast<PUCHAR>(&len), sizeof(len), &written, 0);
    if (st < 0) {
        fail("BCryptGetProperty(BCRYPT_HASH_LENGTH) failed", static_cast<std::int64_t>(st));
    }
    return len;
}

std::string hex_encode(const std::vector<UCHAR>& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (UCHAR b : bytes) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

// One BCrypt hash state that is fed all file bytes, then finalized.
struct hasher_state {
    alg_handle alg;
    hash_handle template_hash;
    hash_handle work;
};

hasher_state make_hasher(PCWSTR name) {
    hasher_state s;
    s.alg = open_algorithm(name);
    NTSTATUS st = BCryptCreateHash(s.alg.h, &s.template_hash.h, nullptr, 0, nullptr, 0, 0);
    if (st < 0) {
        fail("BCryptCreateHash failed", static_cast<std::int64_t>(st));
    }
    st = BCryptDuplicateHash(s.template_hash.h, &s.work.h, nullptr, 0, 0);
    if (st < 0) {
        fail("BCryptDuplicateHash failed", static_cast<std::int64_t>(st));
    }
    return s;
}

void feed(hasher_state& s, const UCHAR* data, std::size_t size) {
    if (size == 0) return;
    NTSTATUS st = BCryptHashData(s.work.h, const_cast<PUCHAR>(data),
                                 static_cast<ULONG>(size), 0);
    if (st < 0) {
        fail("BCryptHashData failed", static_cast<std::int64_t>(st));
    }
}

std::string finish(hasher_state& s) {
    std::vector<UCHAR> digest(hash_length(s.alg.h));
    NTSTATUS st = BCryptFinishHash(s.work.h, digest.data(),
                                   static_cast<ULONG>(digest.size()), 0);
    if (st < 0) {
        fail("BCryptFinishHash failed", static_cast<std::int64_t>(st));
    }
    return hex_encode(digest);
}

file_hashes compute(const std::filesystem::path& path) {
    file_handle fh{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr)};
    if (!fh.ok()) {
        fail("CreateFileW failed to open file", static_cast<std::int64_t>(GetLastError()));
    }

    hasher_state sha256 = make_hasher(BCRYPT_SHA256_ALGORITHM);
    hasher_state sha1 = make_hasher(BCRYPT_SHA1_ALGORITHM);
    hasher_state md5 = make_hasher(BCRYPT_MD5_ALGORITHM);

    std::vector<UCHAR> buffer(kChunkSize);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(fh.h, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            fail("ReadFile failed", static_cast<std::int64_t>(GetLastError()));
        }
        if (read == 0) break;
        feed(sha256, buffer.data(), read);
        feed(sha1, buffer.data(), read);
        feed(md5, buffer.data(), read);
    }

    return file_hashes{finish(sha256), finish(sha1), finish(md5)};
}

} // namespace

result<file_hashes> compute_file_hashes(const std::filesystem::path& path) {
    try {
        return compute(path);
    } catch (const verify_error_exception& e) {
        return std::unexpected(e.get());
    }
}

} // namespace lv::hash