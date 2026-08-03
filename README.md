# launchverify

Verify Windows executables, installers, and Authenticode signatures before
launching applications.

## Status

Milestone 1 (0.1.0): core verification library, console driver, unit tests.

## Building

Prerequisites:

- Windows 10/11
- MSYS2 with `mingw-w64-ucrt-x86_64-gcc`
- CMake and Ninja (install in MSYS2):
  `pacman -S --needed mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja`

From an MSYS2 UCRT64 shell, in the repo root:

```sh
cmake -B build -G Ninja
cmake --build build
```

## Usage

```sh
build/launchverify.exe <path> [--expect-sha256 <hex>]
```

Exit codes:

- `0` — signature trusted.
- `1` — signature present but not trusted/invalid, file unsigned, or
  expected-hash mismatch.
- `2` — hard error (unreadable file, verification failed).

## Testing

```sh
cmake --build build --target launchverify_tests
build/launchverify_tests.exe
```

Regenerate Authenticode test fixtures:

```sh
pwsh -File scripts/make-fixtures.ps1
```

## Supported Windows versions

Windows 10 and 11.

## Security model

- Certificate validation is never disabled or weakened.
- Analyzed binaries are never executed.
- Expected verification failures are surfaced as data (not exceptions).
- Revocation is reported via certificate chain status.

## Limitations

- Certs that do not chain to a trusted root (self-signed, internal CA) report
  `not trusted` even when cryptographically valid.
- Timestamp presence and authority are extracted; cryptographic verification of
  the timestamp counter-signature is a future milestone.