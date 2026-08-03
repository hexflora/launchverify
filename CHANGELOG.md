# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CMake/Ninja build system (C++23, MinGW-w64 GCC/UCRT64) with `-Werror`.
- `launchverify_core` static library:
  - Streaming SHA-256, SHA-1, and MD5 hashing via BCrypt (single pass).
  - Authenticode signature verification via WinVerifyTrust.
  - Signer certificate, certificate chain, and timestamp extraction.
  - Human-readable verification report formatting.
- `launchverify` console driver with `--expect-sha256` hash comparison.
- Catch2 unit test suite (hash vectors, signature verdicts, report output).
- Authenticode test fixtures and regeneration script (`scripts/make-fixtures.ps1`).
- Architecture documentation.
