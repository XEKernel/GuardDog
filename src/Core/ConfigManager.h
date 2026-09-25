#pragma once

#include <windows.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace GuardDog {

class JsonValue;

// 黑名单规则条目：任一维度命中即视为命中该规则。
// 维度之间是"或"关系（便于把同一软件的不同变体写进同一条规则），
// 规则之间也是"或"关系。
struct BlacklistEntry {
    std::wstring name;                       // 规则名，用于日志与 UI 展示
    bool enabled = true;                     // 支持临时停用而不删规则
    std::vector<std::wstring> processNames;  // 进程名，支持通配符（推广*.exe）
    std::vector<std::wstring> paths;         // 路径，支持通配符与前缀语义
    std::vector<std::wstring> signers;       // 数字签名者名称
    std::vector<std::wstring> hashes;        // SHA-256，已归一化为小写十六进制
};

struct WhitelistRules {
    std::vector<std::wstring> processNames;
    std::vector<std::wstring> paths;
    std::vector<std::wstring> signers;
    std::vector<std::wstring> hashes;
};

struct Settings {
    int  pollIntervalMs = 500;          // 兜底轮询间隔（WMI 漏事件时靠它）
    bool wmiEnabled = true;             // 是否启用 WMI 进程创建事件订阅
    bool destroyPeHeader = true;        // 删不掉时是否覆写 PE 头
    bool delayDeleteOnReboot = true;    // 是否登记重启后删除
    bool observeAfterKill = true;       // 处置后是否进入复活观察期
    int  observeSeconds = 300;          // 复活观察期时长（默认 5 分钟）
    bool cleanWmiSubscriptions = true;  // 是否清理 WMI 永久事件订阅
    bool cleanLegacyOnStart = false;    // 服务启动时是否执行一次存量扫描
    // 是否"整套软件"处置：命中目标后，把它所在目录树下的所有可执行载体
    // （exe/dll/sys/ocx/cpl）一并删除或破坏，而不只是被捕获的那一个进程文件。
    // 默认关闭：开启后如果黑名单规则写得过宽（例如只写了进程名而目标恰好与
    // 自己的其他工具同目录），会连带清除同目录的正常程序。开启前请确认目录归属。
    bool removeWholeDirectory = false;
    std::wstring logLevel = L"info";    // debug / info / warn / error
};

struct Config {
    std::vector<BlacklistEntry> blacklist;
    WhitelistRules whitelist;
    Settings settings;
    std::wstring sourcePath;            // 用于日志定位"哪份配置在生效"
};

// 配置管理：加载、默认值生成、热重载。
//
// 并发模型：写少读多。热重载时整体替换 shared_ptr<const Config>，
// 读侧（匹配引擎、监控线程）拿到快照后在锁外使用，互不阻塞。
class ConfigManager {
public:
    static ConfigManager& Instance();

    // 加载配置；文件不存在时先生成默认配置。
    // 失败时返回 HRESULT_FROM_WIN32(错误码)，error 里带可读原因（含行列号）
    HRESULT Load(const std::wstring& path = std::wstring(), std::wstring* error = nullptr);

    // 检测配置文件是否变化（修改时间或大小），变化则重载。
    // 由服务工作循环周期调用即可，无需独立线程。
    // 返回 true 表示本次确实重载成功。
    bool ReloadIfChanged();

    // 取配置快照。返回不可变指针，调用方可在锁外自由使用
    std::shared_ptr<const Config> GetSnapshot() const;

    std::wstring GetConfigPath() const;

    // 一行摘要，用于日志：规则数量、白名单规模、关键设置
    static std::wstring Describe(const Config& config);

    // 统计启用的黑名单规则数（0 表示防护实际未生效，需要提示用户）
    static size_t CountEnabledRules(const Config& config);

private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    bool ParseConfig(const JsonValue& root, Config& config, std::wstring& error) const;
    bool WriteDefaultFile(const std::wstring& path, std::wstring& error) const;
    static bool QueryFileStamp(const std::wstring& path, FILETIME& writeTime, ULONGLONG& size);

    // 加载失败时兜底：保证 GetSnapshot() 永远返回非空指针。
    // 否则调用方每次取配置都要判空，一旦漏判就是空指针崩溃。
    void EnsureFallbackConfig(const std::wstring& path);

    mutable std::mutex m_mutex;
    std::shared_ptr<const Config> m_config;
    std::wstring m_path;

    // 单独记录"已观察到的文件版本"，与配置内容分开保存：
    // 这样重载失败时也能更新它，避免每 500ms 重复报同一个错误刷屏日志
    FILETIME m_observedWriteTime{};
    ULONGLONG m_observedSize = 0;
    bool m_hasObservedStamp = false;
};

} // namespace GuardDog