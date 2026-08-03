# LaunchVerify Core Engine + Build Skeleton — Design Spec

Date: 2026-08-03
Status: Approved
Version: 0.1.0 milestone

## Overview

Milestone 1 of LaunchVerify: a production-quality core verification library and
the build skeleton to support it. This milestone produces:

- A CMake build (Ninja, C++23, MinGW-w64 GCC/UCRT64) that compiles cleanly.
- `launchverify_core`, a static library with three modules: hashing, signature
  verification, and reporting.
- `launchverify`, a minimal console driver to exercise the library and produce
  human-readable reports.
- A Catch2 unit test suite covering hashes and signature verdicts.
- README, CHANGELOG, and architecture documentation.

Future goals (GUI, CLI polish, Explorer integration, tray monitor, package
verification, etc.) are explicitly out of scope for this milestone.

## Architecture

Single static library plus a console driver:

```
launchverify_core (static lib)
  include/launchverify/hash.h        streaming hashing via BCrypt
  include/launchverify/signature.h   Authenticode trust + cert chain + timestamp
  include/launchverify/report.h      result model + human-readable formatter
  include/launchverify/error.h       error type shared by all modules
  src/core/hash.cpp
  src/core/signature.cpp
  src/core/report.cpp
launchverify (console driver)        src/app/main.cpp
tests/                               Catch2 tests + fixtures
scripts/make-fixtures.ps1            regenerates signature test fixtures
docs/architecture.md
```

### Conventions

- Namespace `lv`.
- C++23. No exceptions across the library boundary.
- `using result<T> = std::expected<T, verify_error>` everywhere instead of
  throwing for expected failures.
- RAII for all Windows handles (smart wrappers owning `HANDLE`, `BCRYPT_ALG_HANDLE`,
  `BCRYPT_HASH_HANDLE`, `CERT_CONTEXT`, chain engine/contexts, file handles).
- No raw owning pointers, no macros, no global mutable state.
- const correctness throughout.

## Build system

- Root `CMakeLists.txt`; in-tree `cmake/` for toolchain/options helpers if needed.
- Generator: Ninja. Compiler: MSYS2 MinGW-w64 GCC (UCRT64). C++23 standard.
- Warning flags: `-Wall -Wextra -Wpedantic -Werror` on the core library and driver.
- Test framework: Catch2 v3 via CMake FetchContent (`Catch2` v3.x tag).
- Options:
  - `BUILD_TESTS` (default ON in a developer checkout).
- Required link libraries: `bcrypt`, `wintrust`, `crypt32`. No OpenSSL.

### Prerequisites (documented in README)

- MSYS2 with `mingw-w64-ucrt-x86_64-gcc` installed.
- `mingw-w64-ucrt-x86_64-cmake` and `mingw-w64-ucrt-x86_64-ninja` installed via
  pacman (these are NOT present in the current environment and must be added).

## Module 1: Hashing (`hash.h`)

Streaming hash computation that reads the file once and produces all three
digests (SHA-256, SHA-1, MD5) in a single pass.

```cpp
namespace lv::hash {

enum class algo : std::uint8_t { sha256, sha1, md5 };

struct file_hashes {
    std::string sha256_hex;
    std::string sha1_hex;
    std::string md5_hex;
};

result<file_hashes> compute_file_hashes(const std::filesystem::path& path);

} // namespace lv::hash
```

Implementation notes:

- Read in 1 MiB chunks via a RAII file handle.
- Create one algorithm handle per digest algorithm, then derive three hash
  handles with `BCryptDuplicateHash` so a single buffer feeds all three.
- Finalize each, render as lowercase hex.
- Empty files are valid input (hash of empty stream).
- Any file-open/read/BCrypt failure returns `verify_error`, never throws.
- `std::filesystem::path` is used for input paths; filenames stay `wchar_t`-native
  on Windows (no ANSI conversion).

## Module 2: Signature verification (`signature.h`)

Authenticode verification driven by official Windows APIs only.

```cpp
namespace lv::signature {

enum class signature_state : std::uint8_t { unsigned_file, signed_valid, signed_invalid };
enum class trust_verdict : std::uint8_t { trusted, not_trusted, no_signature };

struct cert_info {
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string sha256_thumbprint;
    std::string not_before;   // ISO 8601 local
    std::string not_after;    // ISO 8601 local
};

struct chain_cert {
    cert_info info;
    bool has_error;          // any CERT_TRUST_STATUS error flags set
    std::string status;      // human-readable status (e.g. "EXPIRED", "UNTRUSTED ROOT", "REVOKED", "OK")
};

struct timestamp_info {
    std::string authority;   // timestamp signer subject
    std::string time;        // ISO 8601 local
};

struct signature_report {
    signature_state state;
    trust_verdict verdict;
    std::string winverifytrust_error;   // populated when not_trusted
    std::optional<cert_info> signer;
    std::vector<chain_cert> chain;      // root-last ordering as returned
    std::optional<timestamp_info> timestamp;
};

result<signature_report> verify_signature(const std::filesystem::path& path);

} // namespace lv::signature
```

Implementation notes:

- `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`, UI flags off.
  The returned `HRESULT` maps to `signature_state` and `trust_verdict`:
  - `TRUST_E_NOSIGNATURE` / `TRUST_E_SUBJECT_FORM_UNKNOWN` → `unsigned_file`,
    `no_signature`.
  - Success → `signed_valid` / `trusted`.
  - Any other failure → `signed_invalid` / `not_trusted` with the formatted
    `HRESULT` stored in `winverifytrust_error`.
- `CryptQueryObject` (`CERT_QUERY_OBJECT_FILE`) to obtain the signer
  `CERT_CONTEXT`: subject, issuer, serial, SHA-256 thumbprint, validity dates.
- `CertGetCertificateChain` to build the chain with revocation checking
  attempted (best-effort; a failed revocation fetch due to offline/unsupported
  does NOT fail the operation — it is surfaced as a status flag only).
- Chain validation honors current-time expiry, so an expired cert surfaces as
  `EXPIRED` in the chain status and as `not_trusted` from `WinVerifyTrust`.
- Timestamp: presence and authority are extracted from the signer info
  (`szOID_RSA_TIMESTAMP_TOKEN`) and reported. Deep cryptographic verification of
  the timestamp counter-signature is a documented follow-up, not part of this
  milestone.
- Never disable chain validation or weaken trust checks to make a case pass.

### Known limitation (documented)

WinVerifyTrust returns `not_trusted` for signatures whose cert does not chain to
a trusted root (e.g. self-signed test certs, internal CA certs), even when the
signature is cryptographically sound. Surfacing a "cryptographically valid but
untrusted root" signal separately from the trust verdict is a documented
follow-up. We do NOT weaken the trust verdict to work around it.

## Module 3: Report (`report.h`)

Combines hash + signature results into one object and renders it as text.

```cpp
namespace lv::report {

struct verification_report {
    std::filesystem::path path;
    std::uint64_t file_size;
    hash::file_hashes hashes;
    signature::signature_report signature;
};

// Optional caller-provided expected digest for manual comparison.
bool sha256_matches(const verification_report& r, std::string_view expected_hex);

std::string format_report(const verification_report& r);   // human-readable

} // namespace lv::report
```

`format_report` output covers: file path, size, all three digests, signature
state, trust verdict, signer identity, chain (root-last), and timestamp. The
formatter is a plain pure function (no I/O) so it is directly unit-testable.

## Console driver (`src/app/main.cpp`)

Usage: `launchverify <path> [--expect-sha256 <hex>]`

- Loads the file, computes hashes, verifies signature, formats and prints the
  report.
- `--expect-sha256` enables manual hash comparison; a mismatch is reported in
  the output and reflected in the exit code.
- Exit codes:
  - `0` — report produced and signature is `trusted` or the file is unsigned.
  - `1` — report produced but signature is present and `not_trusted`/invalid, or
    an expected-hash mismatch occurred.
  - `2` — hard error (file unreadable, verification failed to run).
- Prints errors to stderr.
- This is a demo driver; the full CLI (flags, JSON output, multiple files,
  recursive scan) is a future milestone.

## Tests

Catch2 v3. `enable_testing()` and `add_test` per test binary.

### Hash tests (`tests/hash_tests.cpp`)

- Known vectors: `"abc"` content file → SHA-256
  `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`, SHA-1
  `a9993e364706816aba3e25717850c26c9cd0d89d`, MD5
  `900150983cd24fb0d6963f7d28e17f72`; empty file → SHA-256
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, SHA-1
  `da39a3ee5e6b4b0d3255bfef95601890afd80709`, MD5
  `d41d8cd98f00b204e9800998ecf8427e`.
- Streaming: patterned file larger than the 1 MiB chunk (multiple chunks) vs. a
  known-good digest computed independently (embedded constant).
- Chunk-boundary exactness: files sized exactly 1 MiB, exactly 1 MiB + 1 byte,
  and exactly 1 MiB - 1 byte.
- Hex output is lowercase, 64/40/32 chars respectively.
- Nonexistent file → returns `verify_error`.

### Signature tests (`tests/signature_tests.cpp`)

Fixtures generated by `scripts/make-fixtures.ps1` and committed under
`tests/fixtures/`:

- `unsigned.exe` — a trivial compiled PE with no signature.
- `signed-selfsigned.exe` — signed with a self-signed cert.
- `signed-expired.exe` — signed with an expired cert.
- `signed-tampered.exe` — a validly signed PE with one byte flipped after signing.

Assertions:

- unsigned → `state == unsigned_file`, `verdict == no_signature`.
- self-signed → `state == signed_valid`, `verdict == not_trusted`, chain shows a
  status containing `UNTRUSTED`/`ROOT`.
- expired → `verdict == not_trusted`, chain status contains `EXPIRED`.
- tampered → `state == signed_invalid`, `verdict == not_trusted`.
- signer subject matches the cert used to generate the fixture.
- `verify_signature` on a nonexistent file → `verify_error`.

`scripts/make-fixtures.ps1` uses PowerShell `New-SelfSignedCertificate` +
`Set-AuthenticodeSignature` and is committed for regeneration; the generated
fixture binaries are also committed so tests run without a signing tool.

### Report tests (`tests/report_tests.cpp`)

- `sha256_matches` true/false/whitespace-trimmed cases.
- `format_report` contains expected sections (digest labels, signer, verdict).
- Deterministic output for a fixed input (snapshot-style equality on the text).

## Documentation

- `README.md`: rewritten. Covers building (including pacman cmake/ninja install
  step), prerequisites, running the driver, exit codes, security model,
  supported Windows versions (Windows 10/11), and limitations.
- `CHANGELOG.md`: created with `[Unreleased]` → Added sections describing the
  core engine, driver, tests, and build.
- `docs/architecture.md`: module responsibilities, data flow, Windows API usage,
  and follow-up roadmap.
- `LICENSE`: already present (MIT) — unchanged.

## Versioning

- Project version set to `0.1.0` in CMake.
- SemVer strictly followed; no alternative schemes.

## Out of scope (follow-ups, documented in CHANGELOG/architecture)

- GUI.
- Full CLI (JSON output, multi-file, recursion).
- Crypto-only validity independent of trust root.
- Deep cryptographic timestamp verification.
- Trusted-root-signed test fixture (requires mutating the machine cert store).
- Explorer context menu, tray monitor, PowerShell module, package verification,
  VirusTotal, portable mode, auto-update.
