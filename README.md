<div align="center">

<img src="logo.svg" alt="LaunchVerify logo" width="96" height="96">

# launchverify

**Verify Windows executables, installers, and Authenticode signatures before launching applications.**

[![C++](https://img.shields.io/badge/C%2B%2B-23-blue?style=flat-square&logo=cplusplus&logoColor=white)](https://isocpp.org)
[![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-0078d4?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

[Features](#features) • [Building](#building) • [Usage](#usage) • [Library](#library) • [Testing](#testing) • [Security model](#security-model)

</div>

LaunchVerify is a Windows-first verification tool that checks the integrity and Authenticode signature of a binary before you run it. It streams the file through SHA-256, SHA-1, and MD5 in a single pass, validates the embedded signature with `WinVerifyTrust`, and reports the signer certificate, the full chain trust status, and timestamp presence — all in one human-readable report.

The core verification logic ships as a small C++23 static library, driven by a console CLI that returns script-friendly exit codes.

## Features

- **Single-pass hashing** — SHA-256, SHA-1, and MD5 computed simultaneously while streaming, via the Windows BCrypt API.
- **Authenticode validation** — trust verdict from `WinVerifyTrust` (trusted / not trusted / no signature) without weakening any chain checks.
- **Signer details** — subject, issuer, serial, SHA-256 thumbprint, and validity window extracted from the embedded PKCS#7.
- **Chain status** — per-certificate trust errors surfaced with readable labels (`UNTRUSTED ROOT`, `EXPIRED`, `REVOKED`, ...).
- **Timestamp detection** — presence and authority of an RFC 3161 counter-signature, read from the unauthenticated attributes.
- **Hash pinning** — compare the file's SHA-256 against a known-good digest with `--expect-sha256`.
- **Library-friendly errors** — every entry point returns `lv::result<T>`; expected failures are data, not exceptions.
- **No execution** — analyzed binaries are never run.

## Building

### Prerequisites

- Windows 10/11
- [MSYS2](https://www.msys2.org) with the UCRT64 toolchain: `mingw-w64-ucrt-x86_64-gcc`
- CMake and Ninja (installed via MSYS2):

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja
```

### Build

From an MSYS2 **UCRT64** shell, in the repo root:

```bash
cmake -B build -G Ninja
cmake --build build
```

This produces `build/launchverify.exe` and the `launchverify_core` static library.

> [!TIP]
> You can skip building the unit tests with `cmake -B build -G Ninja -DBUILD_TESTS=OFF`.

## Usage

```bash
launchverify.exe <path> [--expect-sha256 <hex>]
```

Example run against a signed but untrusted (self-signed) binary:

```text
$ launchverify.exe tests/fixtures/signed-selfsigned.exe
File: tests/fixtures/signed-selfsigned.exe
Size: 132656 bytes

Hashes
  SHA-256: 383a6a5e6121b120f4e0b04a56f5598ed7fa79d83fb471e2b9738a69f436aff0
  SHA-1:   ee8cbc90aa1c4198fafacfacf05cd1f72712150f
  MD5:     3285768ca891a91e52d228ee6b90d679

Signature
  State:   signed (valid)
  Verdict: not trusted
  WinVerifyTrust: 0x800B0109

Signer
  Subject:    LaunchVerify Test Signer
  ...
Certificate chain (leaf first)
  - LaunchVerify Test Signer
      status: UNTRUSTED ROOT
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Signature trusted. |
| `1` | Signature present but not trusted/invalid, file unsigned, or expected-hash mismatch. |
| `2` | Hard error (unreadable file, verification failed). |

## Library

Consume `launchverify_core` directly from C++:

```cpp
#include <cstdio>
#include "launchverify/hash.h"
#include "launchverify/report.h"
#include "launchverify/signature.h"

int main() {
    std::filesystem::path p = "C:/path/to/app.exe";

    auto hashes = lv::hash::compute_file_hashes(p);
    auto sig = lv::signature::verify_signature(p);
    if (!hashes || !sig) return 1;

    lv::report::verification_report report;
    report.path = p;
    report.hashes = std::move(*hashes);
    report.signature = std::move(*sig);

    std::printf("%s", lv::report::format_report(report).c_str());
    return 0;
}
```

See [docs/architecture.md](docs/architecture.md) for the module breakdown and Windows API usage.

## Testing

```bash
cmake --build build --target launchverify_tests
build/launchverify_tests.exe
```

The suite covers hash vectors (including the 3 MiB boundary cases), signature verdicts across unsigned / self-signed / expired / tampered fixtures, signer identity, chain status, and report output.

Regenerate the Authenticode test fixtures (requires `gcc` and PowerShell with `New-SelfSignedCertificate`):

```bash
pwsh -File scripts/make-fixtures.ps1
```

## Security model

- Certificate validation is **never disabled or weakened**.
- Revocation is surfaced via chain status flags; network revocation fetches are best-effort and offline-tolerant.
- Analyzed binaries are **never executed**.
- Expected verification failures (unsigned, expired, untrusted) are returned as data, not exceptions.

## Limitations

- Certs that do not chain to a trusted root (self-signed, internal CA) report `not trusted` even when cryptographically valid.
- Timestamp presence and authority are extracted; cryptographic verification of the timestamp counter-signature is a future milestone.

## Roadmap

- Native Windows GUI.
- Full CLI: JSON output, multiple files, recursive scan.
- Explorer context menu, tray monitor, PowerShell module.
- Package verification (MSI/MSIX), GitHub release asset verification.
