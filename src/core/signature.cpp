#include "launchverify/signature.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace lv::signature {
namespace {

struct wintrust_result {
    HRESULT hr = E_FAIL;
    signature_state state = signature_state::signed_invalid;
    trust_verdict verdict = trust_verdict::not_trusted;
    std::string error_text;
};

std::string format_hresult(HRESULT hr) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%08X", static_cast<unsigned>(hr));
    return buf;
}

// Runs WinVerifyTrust with GENERIC_VERIFY_V2, no UI, no revocation network
// fetch (revocation status is surfaced separately via CertGetCertificateChain).
wintrust_result run_wintrust(const std::wstring& path) {
    wintrust_result out;

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(WINTRUST_DATA);
    data.pFile = &file_info;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    out.hr = WinVerifyTrust(nullptr, &action, &data);
    out.error_text = format_hresult(out.hr);

    if (out.hr == S_OK) {
        out.state = signature_state::signed_valid;
        out.verdict = trust_verdict::trusted;
    } else if (out.hr == TRUST_E_NOSIGNATURE || out.hr == TRUST_E_SUBJECT_FORM_UNKNOWN) {
        out.state = signature_state::unsigned_file;
        out.verdict = trust_verdict::no_signature;
    } else if (out.hr == TRUST_E_SUBJECT_NOT_TRUSTED || out.hr == CERT_E_UNTRUSTEDROOT) {
        // A signature is present and cryptographically intact, but its chain
        // does not verify to a trusted root (e.g. self-signed cert). Report
        // signed_valid / not_trusted rather than treating it as invalid.
        out.state = signature_state::signed_valid;
        out.verdict = trust_verdict::not_trusted;
    } else {
        // Any other failure (bad digest, expired cert, etc.).
        out.state = signature_state::signed_invalid;
        out.verdict = trust_verdict::not_trusted;
    }
    return out;
}

} // namespace

result<signature_report> verify_signature(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return std::unexpected(verify_error{
            "file does not exist: " + path.string(), std::nullopt});
    }

    signature_report report;
    const std::wstring wpath = path.wstring();

    wintrust_result wr = run_wintrust(wpath);
    report.state = wr.state;
    report.verdict = wr.verdict;
    report.winverifytrust_error = wr.error_text;
    // signer, chain, timestamp populated in Task 5.

    return report;
}

} // namespace lv::signature