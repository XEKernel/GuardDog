#include "Core/Matcher.h"

#include "Core/ConfigManager.h"
#include "Core/FileInfo.h"

#include <cwctype>
#include <mutex>
#include <string.h>
#include <unordered_map>

namespace GuardDog {

namespace {

// ---------------------------------------------------------------------------
// 文件身份缓存
// 签名校验要解 ASN.1 并做策略校验，哈希要读完整文件；
// 而兜底轮询每 500ms 就会把所有进程过一遍，不缓存会让 CPU 和磁盘直接打满。
// ---------------------------------------------------------------------------
struct IdentityEntry {
    bool signerResolved = false;
    bool hashResolved = false;
    std::wstring signer;  // 空字符串表示"未签名或校验失败"，同样需要缓存，避免反复做昂贵校验
    std::wstring hash;

    // 缓存只按路径做键，若同一路径的文件被替换（流氓软件自我更新），旧文件的
    // 签名者/哈希结论会被错误地套用到新文件上，可能让新文件借旧结论通过白名单。
    // 记录文件大小与最后写入时间，命中时比对，识别出"同名不同文件"从而强制重算。
    //
    // 两个维度各自记录时间戳，不共用：签名与哈希是分别按需计算的，
    // 若共用一个时间戳，"先重算签名（顺带刷新了时间戳）、而哈希还是旧文件的结论"
    // 会被误判为新鲜缓存——那正是要堵的绕过路径。有些文件只查签名、有些只查哈希，
    // 共用时间戳时这种混合状态出现得相当频繁。
    ULONGLONG signerSize = 0;
    FILETIME signerWriteTime{};
    bool signerStampValid = false;
    ULONGLONG hashSize = 0;
    FILETIME hashWriteTime{};
    bool hashStampValid = false;
};

std::mutex g_identityMutex;
std::unordered_map<std::wstring, IdentityEntry> g_identityCache;

// 缓存上限：防止长时间运行时被大量临时路径撑爆内存。
// 满了整体清空而不做 LRU——实现简单，最坏代价只是重新计算一遍。
constexpr size_t kMaxIdentityCacheEntries = 4096;

// 读取文件的大小与最后写入时间。取不到（文件不存在/被占用）时返回 false，
// 调用方据此把 stampValid 置为 false，后续每次都重算而不是信任可能过期的缓存。
bool QueryFileStamp(const std::wstring& path, ULONGLONG& size, FILETIME& writeTime) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
        return false;
    }
    size = (static_cast<ULONGLONG>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    writeTime = data.ftLastWriteTime;
    return true;
}

// 判断某个维度记录的缓存时间戳是否与当前文件一致。
// valid 为 false 表示写入缓存时就没取到时间戳，此时一律视为不匹配，强制重算。
bool SameStamp(bool valid, ULONGLONG cachedSize, const FILETIME& cachedWriteTime,
               ULONGLONG size, const FILETIME& writeTime) {
    return valid && cachedSize == size &&
           cachedWriteTime.dwLowDateTime == writeTime.dwLowDateTime &&
           cachedWriteTime.dwHighDateTime == writeTime.dwHighDateTime;
}

std::wstring LowerCopy(const std::wstring& text) {
    std::wstring result = text;
    for (wchar_t& ch : result) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return result;
}

void LookupCachedSigner(const std::wstring& path, std::wstring& signer) {
    const std::wstring key = LowerCopy(path);

    ULONGLONG size = 0;
    FILETIME writeTime{};
    const bool stampOk = QueryFileStamp(path, size, writeTime);

    {
        std::lock_guard<std::mutex> lock(g_identityMutex);
        const auto it = g_identityCache.find(key);
        if (it != g_identityCache.end() && it->second.signerResolved &&
            SameStamp(it->second.signerStampValid, it->second.signerSize,
                      it->second.signerWriteTime, size, writeTime)) {
            signer = it->second.signer;
            return;
        }
    }

    std::wstring computed;
    const bool verified = GetFileSignerName(path, computed);

    {
        std::lock_guard<std::mutex> lock(g_identityMutex);
        if (g_identityCache.size() >= kMaxIdentityCacheEntries) {
            g_identityCache.clear();
        }
        IdentityEntry& entry = g_identityCache[key];
        entry.signerResolved = true;
        entry.signer = verified ? computed : std::wstring();
        entry.signerSize = size;
        entry.signerWriteTime = writeTime;
        entry.signerStampValid = stampOk;
    }

    signer = verified ? computed : std::wstring();
}

void LookupCachedHash(const std::wstring& path, std::wstring& hash) {
    const std::wstring key = LowerCopy(path);

    ULONGLONG size = 0;
    FILETIME writeTime{};
    const bool stampOk = QueryFileStamp(path, size, writeTime);

    {
        std::lock_guard<std::mutex> lock(g_identityMutex);
        const auto it = g_identityCache.find(key);
        if (it != g_identityCache.end() && it->second.hashResolved &&
            SameStamp(it->second.hashStampValid, it->second.hashSize,
                      it->second.hashWriteTime, size, writeTime)) {
            hash = it->second.hash;
            return;
        }
    }

    std::wstring computed;
    const bool computedOk = ComputeFileSha256(path, computed);

    {
        std::lock_guard<std::mutex> lock(g_identityMutex);
        if (g_identityCache.size() >= kMaxIdentityCacheEntries) {
            g_identityCache.clear();
        }
        IdentityEntry& entry = g_identityCache[key];
        entry.hashResolved = true;
        entry.hash = computedOk ? computed : std::wstring();
        entry.hashSize = size;
        entry.hashWriteTime = writeTime;
        entry.hashStampValid = stampOk;
    }

    hash = computedOk ? computed : std::wstring();
}

} // namespace

void Matcher::ClearIdentityCache() {
    std::lock_guard<std::mutex> lock(g_identityMutex);
    g_identityCache.clear();
}

const wchar_t* Matcher::DimensionName(MatchDimension dimension) {
    switch (dimension) {
        case MatchDimension::ProcessName: return L"进程名";
        case MatchDimension::Path:        return L"路径";
        case MatchDimension::Signer:      return L"签名者";
        case MatchDimension::Hash:        return L"哈希";
        default:                          return L"未知";
    }
}

std::wstring MatchResult::Describe() const {
    std::wstring detailText;
    for (size_t i = 0; i < dimensions.size(); ++i) {
        if (!detailText.empty()) {
            detailText += L"、";
        }
        detailText += Matcher::DimensionName(dimensions[i]);
        if (i < details.size() && !details[i].empty()) {
            detailText += L"[" + details[i] + L"]";
        }
    }

    if (whitelisted) {
        if (detailText.empty()) {
            return L"命中白名单，已放行";
        }
        return L"命中白名单（" + detailText + L"），已放行";
    }

    if (matched) {
        std::wstring text = L"命中黑名单规则[" + ruleName + L"]";
        if (!detailText.empty()) {
            text += L"（" + detailText + L"）";
        }
        return text;
    }

    return L"未命中黑名单";
}

std::wstring Matcher::FileNameOf(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

bool Matcher::WildcardMatch(const std::wstring& pattern, const std::wstring& text) {
    // 经典双指针 + 单星号回溯算法：不用递归，避免长路径下的深递归风险
    size_t p = 0;
    size_t t = 0;
    size_t starPattern = std::wstring::npos;
    size_t starText = 0;

    while (t < text.size()) {
        if (p < pattern.size() &&
            (pattern[p] == L'?' || towlower(pattern[p]) == towlower(text[t]))) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pattern[p] == L'*') {
            starPattern = p++;
            starText = t;
        } else if (starPattern != std::wstring::npos) {
            p = starPattern + 1;
            t = ++starText;
        } else {
            return false;
        }
    }

    while (p < pattern.size() && pattern[p] == L'*') {
        ++p;
    }
    return p == pattern.size();
}

bool Matcher::PathRuleMatch(const std::wstring& pattern, const std::wstring& path) {
    if (pattern.empty() || path.empty()) {
        return false;
    }

    if (WildcardMatch(pattern, path)) {
        return true;
    }

    // 目录前缀语义：配置里写 "C:\Program Files\流氓软件" 时，应当命中该目录下的所有文件。
    // 但必须要求下一个字符是路径分隔符，否则 "C:\X" 会误命中 "C:\XY\a.exe"。
    if (pattern.find(L'*') == std::wstring::npos && pattern.find(L'?') == std::wstring::npos &&
        path.size() > pattern.size()) {
        if (_wcsnicmp(path.c_str(), pattern.c_str(), pattern.size()) == 0) {
            const wchar_t next = path[pattern.size()];
            if (next == L'\\' || next == L'/') {
                return true;
            }
        }
    }

    return false;
}

bool Matcher::MatchStringList(const std::vector<std::wstring>& rules, const std::wstring& value,
                              bool usePathRule, MatchDimension dimension, MatchResult& result) {
    if (rules.empty() || value.empty()) {
        return false;
    }

    bool hit = false;
    for (const std::wstring& rule : rules) {
        if (rule.empty()) {
            continue;
        }
        const bool matched = usePathRule ? PathRuleMatch(rule, value) : WildcardMatch(rule, value);
        if (matched) {
            hit = true;
            result.dimensions.push_back(dimension);
            result.details.push_back(rule);
        }
    }
    return hit;
}

bool Matcher::ConfigUsesSigner(const Config& config) {
    for (const BlacklistEntry& entry : config.blacklist) {
        if (entry.enabled && !entry.signers.empty()) {
            return true;
        }
    }
    return !config.whitelist.signers.empty();
}

bool Matcher::ConfigUsesHash(const Config& config) {
    for (const BlacklistEntry& entry : config.blacklist) {
        if (entry.enabled && !entry.hashes.empty()) {
            return true;
        }
    }
    return !config.whitelist.hashes.empty();
}

MatchResult Matcher::Evaluate(const Config& config, const std::wstring& imagePath) {
    MatchResult result;
    if (imagePath.empty()) {
        return result;
    }

    const std::wstring fileName = FileNameOf(imagePath);

    std::wstring signer;
    std::wstring sha256;
    bool signerLoaded = false;
    bool hashLoaded = false;

    // 惰性求值：只有在真要比较签名者/哈希时才触发昂贵计算
    const auto ensureSigner = [&]() {
        if (!signerLoaded) {
            LookupCachedSigner(imagePath, signer);
            signerLoaded = true;
        }
    };
    const auto ensureHash = [&]() {
        if (!hashLoaded) {
            LookupCachedHash(imagePath, sha256);
            hashLoaded = true;
        }
    };
    const auto signerMatchesWhitelist = [&]() {
        if (config.whitelist.signers.empty()) {
            return false;
        }
        ensureSigner();
        return !signer.empty() && MatchStringList(config.whitelist.signers, signer, false,
                                                  MatchDimension::Signer, result);
    };
    const auto hashMatchesWhitelist = [&]() {
        if (config.whitelist.hashes.empty()) {
            return false;
        }
        ensureHash();
        return !sha256.empty() && MatchStringList(config.whitelist.hashes, sha256, false,
                                                  MatchDimension::Hash, result);
    };

    // ---- 判定顺序刻意如此排列，目的是把昂贵计算（签名校验、文件哈希）
    //      压到"真的需要"的时刻，而不是对每个进程都做一遍 ----

    // 第 1 步：白名单的便宜维度（进程名 / 路径），命中即放行，连黑名单都不用查
    {
        MatchResult whiteResult;
        const bool nameOrPathHit =
            MatchStringList(config.whitelist.processNames, fileName, false,
                            MatchDimension::ProcessName, whiteResult) |
            MatchStringList(config.whitelist.paths, imagePath, true, MatchDimension::Path,
                            whiteResult);
        if (nameOrPathHit) {
            whiteResult.whitelisted = true;
            return whiteResult;
        }
    }

    // 第 2 步：黑名单的便宜维度
    MatchResult candidate;
    bool hit = false;
    for (const BlacklistEntry& entry : config.blacklist) {
        if (!entry.enabled) {
            continue;
        }

        MatchResult perRule;
        bool ruleHit = false;
        ruleHit |= MatchStringList(entry.processNames, fileName, false, MatchDimension::ProcessName,
                                   perRule);
        ruleHit |= MatchStringList(entry.paths, imagePath, true, MatchDimension::Path, perRule);

        if (ruleHit) {
            hit = true;
            candidate.ruleName = entry.name;
            candidate.dimensions = std::move(perRule.dimensions);
            candidate.details = std::move(perRule.details);
            break;
        }
    }

    // 第 3 步：只有黑名单里真的存在签名者/哈希规则时，才去算这两项。
    // 常见配置（只按进程名/路径拦截）因此完全不会为无关进程付出签名校验的代价。
    if (!hit && (ConfigUsesSigner(config) || ConfigUsesHash(config))) {
        for (const BlacklistEntry& entry : config.blacklist) {
            if (!entry.enabled) {
                continue;
            }

            MatchResult perRule;
            bool ruleHit = false;

            if (!entry.signers.empty()) {
                ensureSigner();
                if (!signer.empty()) {
                    ruleHit |= MatchStringList(entry.signers, signer, false, MatchDimension::Signer,
                                               perRule);
                }
            }
            if (!ruleHit && !entry.hashes.empty()) {
                ensureHash();
                if (!sha256.empty()) {
                    ruleHit |= MatchStringList(entry.hashes, sha256, false, MatchDimension::Hash,
                                               perRule);
                }
            }

            if (ruleHit) {
                hit = true;
                candidate.ruleName = entry.name;
                candidate.dimensions = std::move(perRule.dimensions);
                candidate.details = std::move(perRule.details);
                break;
            }
        }
    }

    if (!hit) {
        return result;  // 未命中黑名单：不需要算签名与哈希，直接给结论
    }

    // 第 4 步：白名单终检。
    // 这是防误杀的最后一道闸门——只有"确实即将被处置"的目标才值得付出签名/哈希代价。
    // 白名单的签名者规则在这里才生效，而不是对每个进程预先算一遍。
    {
        MatchResult whiteResult;
        const bool whiteHitBySignerOrHash = signerMatchesWhitelist() | hashMatchesWhitelist();
        if (whiteHitBySignerOrHash) {
            whiteResult.dimensions = std::move(result.dimensions);
            whiteResult.details = std::move(result.details);
            whiteResult.whitelisted = true;
            return whiteResult;
        }
        result.dimensions.clear();
        result.details.clear();
    }

    candidate.matched = true;
    return candidate;
}

bool Matcher::IsInBlacklist(const Config& config, const std::wstring& imagePath) {
    const MatchResult result = Evaluate(config, imagePath);
    return result.matched && !result.whitelisted;
}

bool Matcher::QuickMatchNameOrPath(const Config& config, const std::wstring& nameOrPath) {
    if (nameOrPath.empty()) {
        return false;
    }

    const std::wstring fileName = FileNameOf(nameOrPath);

    // 白名单优先：命中白名单的进程连队都不该进
    MatchResult whiteResult;
    if (MatchStringList(config.whitelist.processNames, fileName, false, MatchDimension::ProcessName,
                        whiteResult) ||
        MatchStringList(config.whitelist.paths, nameOrPath, true, MatchDimension::Path,
                        whiteResult)) {
        return false;
    }

    for (const BlacklistEntry& entry : config.blacklist) {
        if (!entry.enabled) {
            continue;
        }

        MatchResult candidate;
        if (MatchStringList(entry.processNames, fileName, false, MatchDimension::ProcessName,
                            candidate) ||
            MatchStringList(entry.paths, nameOrPath, true, MatchDimension::Path, candidate)) {
            return true;
        }
    }

    return false;
}

} // namespace GuardDog