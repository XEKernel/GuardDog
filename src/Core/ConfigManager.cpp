#include "Core/ConfigManager.h"

#include "Core/Constants.h"
#include "Core/FileInfo.h"
#include "Core/Json.h"
#include "Core/Logger.h"
#include "Core/ScopeHandle.h"

#include <cstdio>
#include <utility>

namespace GuardDog {

namespace {

// 内嵌默认配置。
// 之所以内嵌而不是读同目录的 config.default.json：服务以 LocalSystem 运行、
// 工作目录不可控，从 exe 相对路径加载文件会因为部署方式不同而失败。
// 源码树里的 config/config.default.json 是这份内容的镜像，供用户参考/手工部署。
constexpr char kDefaultConfigJson[] = R"JSON({
  "_说明": "GuardDog 配置。白名单优先级高于黑名单；保存后服务会自动热重载，无需重启。",

  "blacklist": [
    {
      "name": "示例规则（默认停用，请改成你要拦截的软件）",
      "enabled": false,
      "process_names": ["流氓进程.exe", "推广*.exe"],
      "paths": ["C:\\Program Files\\流氓软件\\*", "C:\\Program Files (x86)\\流氓软件\\*"],
      "signers": ["某某公司"],
      "hashes": ["sha256:0000000000000000000000000000000000000000000000000000000000000000"]
    }
  ],

  "whitelist": {
    "process_names": [
      "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
      "services.exe", "wininit.exe", "smss.exe", "dwm.exe", "taskhostw.exe",
      "sihost.exe", "ctfmon.exe", "fontdrvhost.exe", "runtimebroker.exe",
      "searchindexer.exe", "spoolsv.exe", "audiodg.exe", "conhost.exe", "dllhost.exe",
      "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
      "sppsvc.exe", "trustedinstaller.exe", "tiworker.exe", "wuauclt.exe",
      "mousocoreworker.exe", "usoclient.exe", "taskmgr.exe", "regedit.exe",
      "chrome.exe", "msedge.exe", "firefox.exe", "wechat.exe", "qq.exe", "dingtalk.exe"
    ],
    "paths": [
      "C:\\Windows\\System32\\*",
      "C:\\Windows\\SysWOW64\\*",
      "C:\\Windows\\WinSxS\\*",
      "C:\\Windows\\servicing\\*",
      "C:\\Program Files\\Windows Defender\\*",
      "C:\\Program Files\\Windows NT\\*",
      "C:\\Program Files\\Windows Mail\\*",
      "C:\\Program Files\\Microsoft*",
      "C:\\Program Files (x86)\\Microsoft*",
      "C:\\Program Files\\Google\\*",
      "C:\\Program Files (x86)\\Google\\*"
    ],
    "signers": [
      "Microsoft Corporation",
      "Microsoft Windows"
    ],
    "hashes": []
  },

  "settings": {
    "poll_interval_ms": 500,
    "wmi_enabled": true,
    "destroy_pe_header": true,
    "delay_delete_on_reboot": true,
    "observe_after_kill_seconds": 300,
    "clean_wmi_subscriptions": true,
    "clean_legacy_on_start": false,
    "remove_whole_directory": false,
    "log_level": "info"
  }
}
)JSON";

int ClampInt(int value, int minimum, int maximum) {
    if (value < minimum) {
        return minimum;
    }
    if (value > maximum) {
        return maximum;
    }
    return value;
}

std::vector<std::wstring> ReadStringArray(const JsonValue& value) {
    std::vector<std::wstring> result;
    if (!value.IsArray()) {
        return result;
    }
    for (size_t i = 0; i < value.GetSize(); ++i) {
        const JsonValue& item = value.At(i);
        if (!item.IsString()) {
            continue;
        }
        std::wstring text = item.AsString();
        if (!text.empty()) {
            result.push_back(std::move(text));
        }
    }
    return result;
}

std::wstring DefaultConfigPath() {
    return std::wstring(Constants::kProgramDataDir) + L"\\" + Constants::kConfigFileName;
}

std::wstring Join(const std::wstring& directory, const std::wstring& fileName) {
    std::wstring result = directory;
    while (!result.empty() && (result.back() == L'\\' || result.back() == L'/')) {
        result.pop_back();
    }
    return result + L"\\" + fileName;
}

DWORD EnsureDirectoryExists(const std::wstring& path) {
    if (path.empty()) {
        return ERROR_BAD_PATHNAME;
    }

    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? ERROR_SUCCESS : ERROR_DIRECTORY;
    }
    if (path.size() <= 3 && path.size() >= 2 && path[1] == L':') {
        return ERROR_SUCCESS;
    }

    const size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos && pos > 0) {
        const DWORD parentResult = EnsureDirectoryExists(path.substr(0, pos));
        if (parentResult != ERROR_SUCCESS) {
            return parentResult;
        }
    }

    if (CreateDirectoryW(path.c_str(), nullptr)) {
        return ERROR_SUCCESS;
    }
    const DWORD error = GetLastError();
    return error == ERROR_ALREADY_EXISTS ? ERROR_SUCCESS : error;
}

} // namespace

ConfigManager& ConfigManager::Instance() {
    static ConfigManager instance;
    return instance;
}

std::wstring ConfigManager::GetConfigPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_path;
}

std::shared_ptr<const Config> ConfigManager::GetSnapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

size_t ConfigManager::CountEnabledRules(const Config& config) {
    size_t count = 0;
    for (const BlacklistEntry& entry : config.blacklist) {
        if (entry.enabled) {
            ++count;
        }
    }
    return count;
}

std::wstring ConfigManager::Describe(const Config& config) {
    wchar_t buffer[512] = {};
    swprintf_s(buffer,
               L"黑名单规则 %llu 条（启用 %llu）；白名单：进程 %llu / 路径 %llu / 签名者 %llu / "
               L"哈希 %llu；轮询 %dms；WMI %s；日志级别 %s",
               static_cast<unsigned long long>(config.blacklist.size()),
               static_cast<unsigned long long>(CountEnabledRules(config)),
               static_cast<unsigned long long>(config.whitelist.processNames.size()),
               static_cast<unsigned long long>(config.whitelist.paths.size()),
               static_cast<unsigned long long>(config.whitelist.signers.size()),
               static_cast<unsigned long long>(config.whitelist.hashes.size()),
               config.settings.pollIntervalMs, config.settings.wmiEnabled ? L"启用" : L"停用",
               config.settings.logLevel.c_str());
    return std::wstring(buffer);
}

bool ConfigManager::QueryFileStamp(const std::wstring& path, FILETIME& writeTime,
                                   ULONGLONG& size) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
        return false;
    }
    writeTime = data.ftLastWriteTime;
    size = (static_cast<ULONGLONG>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    return true;
}

bool ConfigManager::WriteDefaultFile(const std::wstring& path, std::wstring& error) const {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        const DWORD dirResult = EnsureDirectoryExists(path.substr(0, slash));
        if (dirResult != ERROR_SUCCESS) {
            error = L"创建配置目录失败，错误码 " + std::to_wstring(dirResult);
            return false;
        }
    }

    ScopeHandle file;
    file.Reset(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.IsValid()) {
        error = L"创建默认配置文件失败，错误码 " + std::to_wstring(GetLastError());
        return false;
    }

    // 带 BOM 写出：用户很可能用记事本直接编辑，没有 BOM 时中文会显示成乱码
    const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
    DWORD written = 0;
    if (!WriteFile(file.Get(), bom, sizeof(bom), &written, nullptr)) {
        error = L"写入默认配置失败，错误码 " + std::to_wstring(GetLastError());
        return false;
    }

    const size_t length = sizeof(kDefaultConfigJson) - 1;
    if (!WriteFile(file.Get(), kDefaultConfigJson, static_cast<DWORD>(length), &written, nullptr)) {
        error = L"写入默认配置失败，错误码 " + std::to_wstring(GetLastError());
        return false;
    }

    FlushFileBuffers(file.Get());
    return true;
}

void ConfigManager::EnsureFallbackConfig(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_config) {
        // 已经有可用配置（例如上一次加载成功），保持不动——
        // 失败时沿用旧配置比清空更安全
        return;
    }

    auto fallback = std::make_shared<Config>();
    fallback->sourcePath = path;
    m_config = fallback;
    m_path = path;
    GD_LOG_WARN(L"配置不可用，已启用内置默认值（黑名单为空），请修复配置文件");
}

bool ConfigManager::ParseConfig(const JsonValue& root, Config& config, std::wstring& error) const {
    if (!root.IsObject()) {
        error = L"配置文件的顶层必须是一个 JSON 对象";
        return false;
    }

    // ---- blacklist ----
    const JsonValue& blacklist = root.Find(L"blacklist");
    if (blacklist.IsArray()) {
        for (size_t i = 0; i < blacklist.GetSize(); ++i) {
            const JsonValue& item = blacklist.At(i);
            if (!item.IsObject()) {
                error = L"blacklist 的第 " + std::to_wstring(i + 1) + L" 项不是对象";
                return false;
            }

            BlacklistEntry entry;
            entry.name = item.Find(L"name").AsString(L"(未命名规则)");
            entry.enabled = item.Find(L"enabled").AsBool(true);
            entry.processNames = ReadStringArray(item.Find(L"process_names"));
            entry.paths = ReadStringArray(item.Find(L"paths"));
            entry.signers = ReadStringArray(item.Find(L"signers"));

            // 哈希统一归一化，避免用户写法差异（大小写、sha256: 前缀、空格）导致匹配不上
            for (std::wstring& hash : ReadStringArray(item.Find(L"hashes"))) {
                std::wstring normalized = NormalizeHash(hash);
                if (!normalized.empty()) {
                    entry.hashes.push_back(std::move(normalized));
                }
            }

            config.blacklist.push_back(std::move(entry));
        }
    } else if (!blacklist.IsNull()) {
        error = L"blacklist 必须是数组";
        return false;
    }

    // ---- whitelist ----
    const JsonValue& whitelist = root.Find(L"whitelist");
    if (whitelist.IsObject()) {
        config.whitelist.processNames = ReadStringArray(whitelist.Find(L"process_names"));
        config.whitelist.paths = ReadStringArray(whitelist.Find(L"paths"));
        config.whitelist.signers = ReadStringArray(whitelist.Find(L"signers"));
        for (std::wstring& hash : ReadStringArray(whitelist.Find(L"hashes"))) {
            std::wstring normalized = NormalizeHash(hash);
            if (!normalized.empty()) {
                config.whitelist.hashes.push_back(std::move(normalized));
            }
        }
    } else if (!whitelist.IsNull()) {
        error = L"whitelist 必须是对象";
        return false;
    }

    // ---- settings ----
    const JsonValue& settings = root.Find(L"settings");
    if (settings.IsObject()) {
        // 数值一律夹取到合理区间：这些值直接决定 CPU 开销与处置力度，
        // 用户写错一个 0 就可能让轮询变成忙等
        config.settings.pollIntervalMs =
            ClampInt(settings.Find(L"poll_interval_ms").AsInt(config.settings.pollIntervalMs), 100, 60000);
        config.settings.wmiEnabled = settings.Find(L"wmi_enabled").AsBool(config.settings.wmiEnabled);
        config.settings.destroyPeHeader =
            settings.Find(L"destroy_pe_header").AsBool(config.settings.destroyPeHeader);
        config.settings.delayDeleteOnReboot =
            settings.Find(L"delay_delete_on_reboot").AsBool(config.settings.delayDeleteOnReboot);
        config.settings.observeAfterKill =
            settings.Find(L"observe_after_kill_seconds").AsInt(config.settings.observeSeconds) > 0;
        config.settings.observeSeconds =
            ClampInt(settings.Find(L"observe_after_kill_seconds").AsInt(config.settings.observeSeconds),
                     0, 86400);
        config.settings.cleanWmiSubscriptions =
            settings.Find(L"clean_wmi_subscriptions").AsBool(config.settings.cleanWmiSubscriptions);
        config.settings.cleanLegacyOnStart =
            settings.Find(L"clean_legacy_on_start").AsBool(config.settings.cleanLegacyOnStart);
        config.settings.removeWholeDirectory =
            settings.Find(L"remove_whole_directory").AsBool(config.settings.removeWholeDirectory);
        config.settings.logLevel = settings.Find(L"log_level").AsString(config.settings.logLevel);
    } else if (!settings.IsNull()) {
        error = L"settings 必须是对象";
        return false;
    }

    return true;
}

HRESULT ConfigManager::Load(const std::wstring& path, std::wstring* error) {
    std::wstring targetError;
    std::wstring* errorOut = (error != nullptr) ? error : &targetError;
    errorOut->clear();

    const std::wstring target = path.empty() ? DefaultConfigPath() : path;

    if (GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (!WriteDefaultFile(target, *errorOut)) {
            GD_LOG_ERROR(L"生成默认配置失败：%s", errorOut->c_str());
            EnsureFallbackConfig(target);
            return HRESULT_FROM_WIN32(ERROR_CANNOT_MAKE);
        }
        GD_LOG_INFO(L"配置文件不存在，已生成默认配置：%s", target.c_str());
    }

    std::wstring parseError;
    const JsonValue root = JsonValue::ParseFile(target, &parseError);
    if (root.IsNull()) {
        *errorOut = L"解析失败：" + parseError;
        EnsureFallbackConfig(target);
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }

    auto config = std::make_shared<Config>();
    if (!ParseConfig(root, *config, parseError)) {
        *errorOut = L"内容校验失败：" + parseError;
        EnsureFallbackConfig(target);
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }
    config->sourcePath = target;

    FILETIME writeTime{};
    ULONGLONG size = 0;
    QueryFileStamp(target, writeTime, size);

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_config = config;
        m_path = target;
        m_observedWriteTime = writeTime;
        m_observedSize = size;
        m_hasObservedStamp = true;
    }

    GD_LOG_INFO(L"配置已加载：%s", Describe(*config).c_str());
    if (CountEnabledRules(*config) == 0) {
        // 明确提示"防护未生效"，避免用户以为已经在防了
        GD_LOG_WARN(L"当前没有启用的黑名单规则，防护处于观察状态（不会处置任何程序）");
    }
    return S_OK;
}

bool ConfigManager::ReloadIfChanged() {
    std::wstring path;
    bool hasStamp = false;
    FILETIME observedWriteTime{};
    ULONGLONG observedSize = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_config) {
            return false;
        }
        path = m_path;
        hasStamp = m_hasObservedStamp;
        observedWriteTime = m_observedWriteTime;
        observedSize = m_observedSize;
    }

    FILETIME writeTime{};
    ULONGLONG size = 0;
    if (!QueryFileStamp(path, writeTime, size)) {
        return false;
    }

    if (hasStamp && writeTime.dwLowDateTime == observedWriteTime.dwLowDateTime &&
        writeTime.dwHighDateTime == observedWriteTime.dwHighDateTime && size == observedSize) {
        return false;  // 文件未变化
    }

    std::wstring error;
    const HRESULT result = Load(path, &error);
    if (FAILED(result)) {
        // 关键安全设计：重载失败必须继续沿用旧配置。
        // 用户编辑配置时手滑漏一个逗号，不应该让正在运行的防护瞬间失效。
        GD_LOG_ERROR(L"配置热重载失败，继续使用旧配置：%s", error.c_str());
        // Load 未更新观察戳，这里补上，避免每 500ms 重复报同一个错误刷屏
        std::lock_guard<std::mutex> lock(m_mutex);
        m_observedWriteTime = writeTime;
        m_observedSize = size;
        m_hasObservedStamp = true;
        return false;
    }

    GD_LOG_INFO(L"检测到配置文件变更，已热重载（无需重启服务）");
    return true;
}

} // namespace GuardDog