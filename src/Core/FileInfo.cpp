#include "Core/FileInfo.h"

#include "Core/ScopeHandle.h"

#include <windows.h>

// BCrypt 提供 SHA-256；wintrust/mscat/crypt32 提供签名校验与证书提取。
// wincrypt.h 必须排在 mscat.h 之前：mscat.h 依赖 CRYPT_HASH_BLOB / HCRYPTPROV 等类型定义。
#include <bcrypt.h>
#include <wincrypt.h>
#include <mscat.h>
#include <softpub.h>
#include <wintrust.h>

#include <cwctype>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace GuardDog {

namespace {

// BCrypt / Cert / Catalog 的资源释放函数签名与 CloseHandle 不一致，
// 这里用最小的 RAII 结构体兜住，避免任何早期 return 泄漏句柄。
struct BcryptAlgorithm {
    BCRYPT_ALG_HANDLE handle = nullptr;
    ~BcryptAlgorithm() {
        if (handle != nullptr) {
            BCryptCloseAlgorithmProvider(handle, 0);
        }
    }
};

struct BcryptHash {
    BCRYPT_HASH_HANDLE handle = nullptr;
    ~BcryptHash() {
        if (handle != nullptr) {
            BCryptDestroyHash(handle);
        }
    }
};

struct CertContextGuard {
    PCCERT_CONTEXT context = nullptr;
    ~CertContextGuard() {
        if (context != nullptr) {
            CertFreeCertificateContext(context);
        }
    }
};

struct CatAdminGuard {
    HCATADMIN handle = nullptr;
    ~CatAdminGuard() {
        if (handle != nullptr) {
            CryptCATAdminReleaseContext(handle, 0);
        }
    }
};

struct CatInfoGuard {
    HCATADMIN admin = nullptr;
    HCATINFO handle = nullptr;
    ~CatInfoGuard() {
        if (handle != nullptr) {
            CryptCATAdminReleaseCatalogContext(admin, handle, 0);
        }
    }
};

// 用 WinVerifyTrust 做策略校验。
// 必须做——否则任何带签名结构的文件都能在证书里写个"某某公司"来冒充大厂，
// 匹配签名者这个维度就彻底失去意义。
bool VerifyTrustPolicy(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;  // 不做在线吊销检查，避免服务卡在网络请求上
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG verifyStatus = WinVerifyTrust(nullptr, &policy, &trustData);

    // 无论成功失败都必须关闭状态，否则会泄漏验证上下文
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trustData);

    return verifyStatus == ERROR_SUCCESS;
}

// 从已打开的 PKCS#7 签名消息中取签名者证书的显示名
bool ExtractSignerFromMessage(HCERTSTORE store, HCRYPTMSG message, std::wstring& signerName) {
    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) ||
        signerInfoSize == 0) {
        return false;
    }

    std::vector<BYTE> signerBuffer(signerInfoSize);
    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signerBuffer.data(),
                          &signerInfoSize)) {
        return false;
    }

    auto* signerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerBuffer.data());
    CERT_INFO certInfo{};
    certInfo.Issuer = signerInfo->Issuer;
    certInfo.SerialNumber = signerInfo->SerialNumber;

    CertContextGuard certificate;
    certificate.context =
        CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                   CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);
    if (certificate.context == nullptr) {
        return false;
    }

    wchar_t nameBuffer[512] = {};
    const DWORD length = CertGetNameStringW(certificate.context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                            nullptr, nameBuffer, _countof(nameBuffer));
    if (length <= 1) {  // 长度为 1 表示只写入了结束符，没有可用名称
        return false;
    }

    signerName.assign(nameBuffer);
    return true;
}

// 从文件自带的嵌入签名（PE 的 certificate table）中取签名者
bool ExtractEmbeddedSigner(const std::wstring& path, std::wstring& signerName) {
    HCERTSTORE storeRaw = nullptr;
    HCRYPTMSG messageRaw = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, nullptr, nullptr, nullptr, &storeRaw, &messageRaw, nullptr)) {
        return false;
    }

    ScopeHandle store;
    store.Reset(reinterpret_cast<HANDLE>(storeRaw), [](HANDLE handle) {
        CertCloseStore(reinterpret_cast<HCERTSTORE>(handle), 0);
    });

    ScopeHandle message;
    message.Reset(reinterpret_cast<HANDLE>(messageRaw), [](HANDLE handle) {
        CryptMsgClose(reinterpret_cast<HCRYPTMSG>(handle));
    });

    return ExtractSignerFromMessage(storeRaw, messageRaw, signerName);
}

// 从系统 catalog（CatRoot 下的 .cat 文件）中取签名者。
// 相当一部分系统组件（例如 notepad.exe）本体不含嵌入签名，签名只登记在 catalog 里；
// 少这一步就会把它们误判成"未签名"，使白名单的签名者规则失效。
bool ExtractCatalogSigner(const std::wstring& path, std::wstring& signerName) {
    ScopeHandle file;
    file.Reset(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.IsValid()) {
        return false;
    }

    // catalog 以文件内容的哈希作为索引键
    DWORD hashSize = 0;
    if (!CryptCATAdminCalcHashFromFileHandle(file.Get(), &hashSize, nullptr, 0) || hashSize == 0) {
        return false;
    }

    std::vector<BYTE> hash(hashSize);
    if (!CryptCATAdminCalcHashFromFileHandle(file.Get(), &hashSize, hash.data(), 0)) {
        return false;
    }

    CatAdminGuard admin;
    if (!CryptCATAdminAcquireContext(&admin.handle, nullptr, 0)) {
        return false;
    }

    CatInfoGuard catalog;
    catalog.admin = admin.handle;
    catalog.handle =
        CryptCATAdminEnumCatalogFromHash(admin.handle, hash.data(), hashSize, 0, nullptr);
    if (catalog.handle == nullptr) {
        return false;  // 该文件没有对应的 catalog 条目
    }

    CATALOG_INFO catalogInfo{};
    catalogInfo.cbStruct = sizeof(catalogInfo);
    if (!CryptCATCatalogInfoFromContext(catalog.handle, &catalogInfo, 0)) {
        return false;
    }

    // 关键：catalog 只是"系统目录里的一份签名清单"，必须校验它自身的签名。
    // .cat 文件带有嵌入签名，所以这里走的是和普通文件一样的策略校验；
    // 而 CatRoot 目录本身受系统保护，伪造条目需要同时突破系统 ACL 与签名链，实际不可行。
    if (!VerifyTrustPolicy(catalogInfo.wszCatalogFile)) {
        return false;
    }

    // .cat 本身就是 PKCS#7 签名文件，签名者即该 catalog 的签发方（通常是微软）
    HCERTSTORE storeRaw = nullptr;
    HCRYPTMSG messageRaw = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, catalogInfo.wszCatalogFile,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr, &storeRaw,
                          &messageRaw, nullptr)) {
        return false;
    }

    ScopeHandle store;
    store.Reset(reinterpret_cast<HANDLE>(storeRaw), [](HANDLE handle) {
        CertCloseStore(reinterpret_cast<HCERTSTORE>(handle), 0);
    });

    ScopeHandle message;
    message.Reset(reinterpret_cast<HANDLE>(messageRaw), [](HANDLE handle) {
        CryptMsgClose(reinterpret_cast<HCRYPTMSG>(handle));
    });

    return ExtractSignerFromMessage(storeRaw, messageRaw, signerName);
}

} // namespace

std::wstring NormalizeHash(const std::wstring& text) {
    std::wstring result;
    result.reserve(text.size());

    for (const wchar_t ch : text) {
        if (ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n') {
            continue;
        }
        result.push_back(static_cast<wchar_t>(towlower(ch)));
    }

    const std::wstring prefix = L"sha256:";
    if (result.size() > prefix.size() && result.compare(0, prefix.size(), prefix) == 0) {
        result.erase(0, prefix.size());
    }
    return result;
}

bool ComputeFileSha256(const std::wstring& path, std::wstring& hexDigest) {
    ScopeHandle file;
    file.Reset(CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                           nullptr));
    if (!file.IsValid()) {
        return false;
    }

    BcryptAlgorithm algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        return false;
    }

    BcryptHash hash;
    if (BCryptCreateHash(algorithm.handle, &hash.handle, nullptr, 0, nullptr, 0, 0) < 0) {
        return false;
    }

    // 64KB 分块流式计算：流氓软件的安装包动辄几百 MB，
    // 一次性读入内存既慢又可能触发内存压力
    std::vector<BYTE> buffer(64 * 1024);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file.Get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            return false;
        }
        if (read == 0) {
            break;
        }
        if (BCryptHashData(hash.handle, buffer.data(), read, 0) < 0) {
            return false;
        }
    }

    BYTE digest[32] = {};
    if (BCryptFinishHash(hash.handle, digest, sizeof(digest), 0) < 0) {
        return false;
    }

    static const wchar_t kHexDigits[] = L"0123456789abcdef";
    std::wstring result;
    result.reserve(sizeof(digest) * 2);
    for (const BYTE byte : digest) {
        result.push_back(kHexDigits[byte >> 4]);
        result.push_back(kHexDigits[byte & 0x0F]);
    }

    hexDigest = std::move(result);
    return true;
}

bool GetFileSignerName(const std::wstring& path, std::wstring& signerName) {
    // 第一步：嵌入签名路径。
    // 注意 WTD_CHOICE_FILE 只校验文件自带的签名、**不含** catalog，
    // 所以校验失败不代表文件没签名（系统组件常把签名登记在 .cat 里），
    // 不能在这里就直接判定"无签名"。
    if (VerifyTrustPolicy(path) && ExtractEmbeddedSigner(path, signerName)) {
        return true;
    }

    // 第二步：catalog 签名路径（内部会先校验 catalog 自身的签名是否可信）
    return ExtractCatalogSigner(path, signerName);
}

} // namespace GuardDog