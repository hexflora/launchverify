# Architecture

## Overview

LaunchVerify verifies Windows executables and installers before they run.
Milestone 1 ships the core verification library, a console driver, and unit
tests. The GUI, CLI polish, and ecosystem integrations are future milestones.

## Modules

`launchverify_core` (static lib, namespace `lv`):

- `lv::hash` — single-pass streaming SHA-256/SHA-1/MD5 using BCrypt.
- `lv::signature` — Authenticode verification via WinVerifyTrust
  (state/verdict), signer identity via CryptQueryObject, certificate chain via
  CertGetCertificateChain, and timestamp presence/authority.
- `lv::report` — combines hash + signature results; pure text formatter.
- `lv::verify_error` / `lv::result<T>` — error model shared by all modules.

## Data flow

`launchverify <path>` →
  `lv::hash::compute_file_hashes` + `lv::signature::verify_signature` →
  `lv::report::verification_report` → `lv::report::format_report` → stdout.

## Windows API usage

| Concern        | API                                |
|----------------|------------------------------------|
| Hashing        | BCrypt (BCRYPT_SHA256/1/MD5)       |
| Trust verdict  | WinVerifyTrust (GENERIC_VERIFY_V2) |
| Signer cert    | CryptQueryObject, CertGetSubjectCertificateFromStore |
| Chain          | CertGetCertificateChain            |
| Timestamp      | CryptMsgGetParam (unauth attrs)    |

## Security model

- Certificate validation is never disabled or weakened.
- Revocation is surfaced via chain status flags; revocation network fetches are
  best-effort and offline-tolerant.
- Analyzed binaries are never executed.
- All library entry points return `lv::result<T>`; expected failures (unsigned,
  expired, untrusted) are data, not exceptions.

## Limitations

- `WinVerifyTrust` reports `not_trusted` for certs that do not chain to a
  trusted root (e.g. self-signed), even when the signature is cryptographically
  valid. A separate "cryptographically valid but untrusted root" signal is a
  planned follow-up.
- Timestamp presence and authority are extracted; cryptographic verification of
  the timestamp counter-signature is a planned follow-up.
- Deep online revocation fetching is limited to chain status flags.

## Roadmap (future milestones)

- GUI (native Windows).
- Full CLI: JSON output, multiple files, recursive scan.
- Explorer context menu, tray monitor, PowerShell module.
- Package verification (MSI/MSIX), GitHub release asset verification.
- VirusTotal integration (opt-in, disabled by default), portable mode.