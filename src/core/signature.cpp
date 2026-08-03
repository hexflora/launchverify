#include "launchverify/signature.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lv::signature {
namespace {

std::string format_hresult(HRESULT hr) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%08X", static_cast<unsigned>(hr));
    return buf;
}

std::string wstring_to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), len, nullptr, nullptr);
    return out;
}

std::string name_of_cert(PCCERT_CONTEXT ctx, DWORD type) {
    DWORD chars = CertGetNameStringW(ctx, type, 0, nullptr, nullptr, 0);
    if (chars == 0) return {};
    std::wstring w(static_cast<std::size_t>(chars), L'\0');
    CertGetNameStringW(ctx, type, 0, nullptr, w.data(), chars);
    if (!w.empty()) w.pop_back();
    return wstring_to_utf8(w);
}

std::string serial_of_cert(PCCERT_CONTEXT ctx) {
    const CRYPT_INTEGER_BLOB& s = ctx->pCertInfo->SerialNumber;
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.cbData * 2);
    for (DWORD i = 0; i < s.cbData; ++i) {
        out.push_back(kHex[(s.pbData[i] >> 4) & 0xF]);
        out.push_back(kHex[s.pbData[i] & 0xF]);
    }
    return out;
}

std::string thumbprint_of_cert(PCCERT_CONTEXT ctx) {
    DWORD cb = 0;
    if (!CryptHashCertificate(0, CALG_SHA_256, 0, ctx->pbCertEncoded,
                              ctx->cbCertEncoded, nullptr, &cb)) {
        return {};
    }
    std::vector<BYTE> digest(cb);
    if (!CryptHashCertificate(0, CALG_SHA_256, 0, ctx->pbCertEncoded,
                              ctx->cbCertEncoded, digest.data(), &cb)) {
        return {};
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(cb * 2);
    for (DWORD i = 0; i < cb; ++i) {
        out.push_back(kHex[(digest[i] >> 4) & 0xF]);
        out.push_back(kHex[digest[i] & 0xF]);
    }
    return out;
}

std::string iso8601_from_filetime(const FILETIME& ft) {
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return {};
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

cert_info info_from_cert(PCCERT_CONTEXT ctx) {
    cert_info info;
    info.subject = name_of_cert(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE);
    info.issuer = name_of_cert(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE);
    info.serial = serial_of_cert(ctx);
    info.sha256_thumbprint = thumbprint_of_cert(ctx);
    info.not_before = iso8601_from_filetime(ctx->pCertInfo->NotBefore);
    info.not_after = iso8601_from_filetime(ctx->pCertInfo->NotAfter);
    return info;
}

// Human-readable label for a single CERT_TRUST_STATUS error flag.
const char* trust_error_label(DWORD flag) {
    switch (flag) {
        case CERT_TRUST_IS_NOT_TIME_VALID: return "EXPIRED";
        case CERT_TRUST_IS_NOT_TIME_NESTED: return "NOT TIME NESTED";
        case CERT_TRUST_IS_REVOKED: return "REVOKED";
        case CERT_TRUST_IS_NOT_SIGNATURE_VALID: return "BAD SIGNATURE";
        case CERT_TRUST_IS_NOT_VALID_FOR_USAGE: return "INVALID FOR USAGE";
        case CERT_TRUST_IS_UNTRUSTED_ROOT: return "UNTRUSTED ROOT";
        case CERT_TRUST_REVOCATION_STATUS_UNKNOWN: return "REVOCATION STATUS UNKNOWN";
        case CERT_TRUST_IS_OFFLINE_REVOCATION: return "REVOCATION OFFLINE";
        case CERT_TRUST_IS_EXPLICIT_DISTRUST: return "EXPLICITLY DISTRUSTED";
        case CERT_TRUST_IS_PARTIAL_CHAIN: return "PARTIAL CHAIN";
        case CERT_TRUST_CTL_IS_NOT_TIME_VALID: return "CTL NOT TIME VALID";
        case CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID: return "CTL BAD SIGNATURE";
        case CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE: return "CTL INVALID FOR USAGE";
        case CERT_TRUST_IS_CYCLIC: return "CYCLIC CHAIN";
        case CERT_TRUST_INVALID_EXTENSION: return "INVALID EXTENSION";
        case CERT_TRUST_INVALID_POLICY_CONSTRAINTS: return "INVALID POLICY CONSTRAINTS";
        case CERT_TRUST_INVALID_BASIC_CONSTRAINTS: return "INVALID BASIC CONSTRAINTS";
        case CERT_TRUST_INVALID_NAME_CONSTRAINTS: return "INVALID NAME CONSTRAINTS";
        case CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT: return "UNSUPPORTED NAME CONSTRAINT";
        case CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT: return "UNDEFINED NAME CONSTRAINT";
        case CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT: return "NAME CONSTRAINT VIOLATION";
        case CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT: return "EXCLUDED NAME CONSTRAINT";
        case CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY: return "NO ISSUANCE CHAIN POLICY";
        default: return nullptr;
    }
}

std::string trust_status_text(DWORD error_status) {
    if (error_status == 0) return "OK";
    std::string out;
    bool first = true;
    for (DWORD bit = 1; bit != 0; bit <<= 1) {
        if ((error_status & bit) == 0) continue;
        const char* label = trust_error_label(bit);
        if (label == nullptr) continue;
        if (!first) out += " | ";
        out += label;
        first = false;
    }
    if (out.empty()) out = "UNKNOWN (" + format_hresult(error_status) + ")";
    return out;
}

// Looks up the signer's CERT_CONTEXT from the PKCS#7 message.
PCCERT_CONTEXT find_signer_cert(HCERTSTORE store, HCRYPTMSG msg) {
    DWORD signer_count = 0;
    DWORD cb = sizeof(signer_count);
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_COUNT_PARAM, 0, &signer_count, &cb)) return nullptr;
    for (DWORD i = 0; i < signer_count; ++i) {
        DWORD cb_info = 0;
        if (!CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, i, nullptr, &cb_info)) continue;
        std::vector<BYTE> info_buf(cb_info);
        if (!CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, i, info_buf.data(), &cb_info)) continue;
        auto* cert_info = reinterpret_cast<CERT_INFO*>(info_buf.data());
        // The signer CERT_INFO from the PKCS#7 carries only issuer + serial;
        // CertGetSubjectCertificateFromStore matches on those.
        PCCERT_CONTEXT found = CertGetSubjectCertificateFromStore(
            store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_info);
        if (found) return found;
    }
    return nullptr;
}

struct query_object_result {
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    ~query_object_result() {
        if (msg) CryptMsgClose(msg);
        if (store) CertCloseStore(store, 0);
    }
};

// Extracts timestamp presence + authority from the PKCS#7 signer info.
std::optional<timestamp_info> extract_timestamp(HCRYPTMSG msg) {
    static const char* kTimestampOid = "1.3.6.1.4.1.311.3.3.1";  // szOID_RSA_TIMESTAMP_TOKEN
    DWORD cb_signer = 0;
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cb_signer)) return std::nullopt;
    std::vector<BYTE> signer_buf(cb_signer);
    if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signer_buf.data(), &cb_signer)) return std::nullopt;
    const auto* signer = reinterpret_cast<CMSG_SIGNER_INFO*>(signer_buf.data());

    for (DWORD i = 0; i < signer->UnauthAttrs.cAttr; ++i) {
        const CRYPT_ATTRIBUTE& attr = signer->UnauthAttrs.rgAttr[i];
        if (std::string_view(attr.pszObjId) != kTimestampOid || attr.cValue == 0) continue;

        timestamp_info t;
        const DATA_BLOB& blob = attr.rgValue[0];

        HCERTSTORE ts_store = nullptr;
        HCRYPTMSG ts_msg = nullptr;
        DWORD type = 0;
        if (CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_ALL,
                             CERT_QUERY_FORMAT_FLAG_ALL, 0, nullptr, &type, nullptr,
                             &ts_store, &ts_msg, nullptr)) {
            PCCERT_CONTEXT signer_cert = find_signer_cert(ts_store, ts_msg);
            if (signer_cert) {
                t.authority = name_of_cert(signer_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE);
                CertFreeCertificateContext(signer_cert);
            }
            if (ts_msg) CryptMsgClose(ts_msg);
            if (ts_store) CertCloseStore(ts_store, 0);
        }
        return t;
    }
    return std::nullopt;
}

struct chain_context {
    PCCERT_CHAIN_CONTEXT ctx = nullptr;
    ~chain_context() { if (ctx) CertFreeCertificateChain(ctx); }
};

std::vector<chain_cert> build_chain(PCCERT_CONTEXT leaf) {
    std::vector<chain_cert> out;
    CERT_CHAIN_PARA para{};
    para.cbSize = sizeof(para);
    // No EKU restriction; revocation fetch is best-effort via the system engine.
    chain_context chain{};
    if (!CertGetCertificateChain(nullptr, leaf, nullptr, nullptr, &para, 0,
                                 nullptr, &chain.ctx)) {
        return out;
    }
    if (chain.ctx->cChain == 0 || chain.ctx->rgpChain[0]->cElement == 0) return out;
    const CERT_SIMPLE_CHAIN& simple = *chain.ctx->rgpChain[0];
    out.reserve(simple.cElement);
    for (DWORD i = 0; i < simple.cElement; ++i) {
        const CERT_CHAIN_ELEMENT& el = *simple.rgpElement[i];
        chain_cert cc;
        cc.info = info_from_cert(el.pCertContext);
        cc.has_error = el.TrustStatus.dwErrorStatus != 0;
        cc.status = trust_status_text(el.TrustStatus.dwErrorStatus);
        out.push_back(std::move(cc));
    }
    return out;
}

// Builds signer info, chain, and timestamp from the embedded PKCS#7.
void enrich(signature_report& report, const std::wstring& path) {
    query_object_result q;
    DWORD content_type = 0;
    DWORD format_type = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_ALL,
                          0, nullptr, &content_type, &format_type,
                          &q.store, &q.msg, nullptr)) {
        return;
    }
    PCCERT_CONTEXT signer = find_signer_cert(q.store, q.msg);
    if (signer) {
        report.signer = info_from_cert(signer);
        report.chain = build_chain(signer);
        CertFreeCertificateContext(signer);
    }
    report.timestamp = extract_timestamp(q.msg);
}

// Runs WinVerifyTrust with GENERIC_VERIFY_V2, no UI, no revocation network
// fetch (revocation status is surfaced separately via CertGetCertificateChain).
struct wintrust_result {
    HRESULT hr = E_FAIL;
    signature_state state = signature_state::signed_invalid;
    trust_verdict verdict = trust_verdict::not_trusted;
    std::string error_text;
};

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
    enrich(report, wpath);

    return report;
}

} // namespace lv::signature
