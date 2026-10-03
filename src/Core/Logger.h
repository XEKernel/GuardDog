#pragma once

#include <windows.h>

#include <atomic>
#include <cstdarg>
#include <mutex>
#include <string>

namespace GuardDog {

enum class LogLevel : int {
    Debug = 0,
    Info  = 1,
    Warn  = 2,
    Error = 3,
};

// 全局日志器（进程内单例）。
// 设计取舍：
//  1) 用互斥锁 + 单文件追加写，保证多线程（WMI 回调线程 / 轮询线程 / 清理线程）
//     并发写日志时行不交错；
//  2) 文件按天滚动：当天活动文件始终是 guarddog.log，跨天时把旧文件重命名为
//     guarddog-YYYYMMDD.log 归档，这样"当前日志路径"稳定、归档可追溯；
//  3) 写 UTF-8 + BOM，保证中文记事本/其他工具打开不乱码。
class Logger {
public:
    static Logger& Instance();

    // 初始化：建目录、打开当天日志、清理过期归档。幂等，可重复调用。
    // logDir 为空时使用 Constants::kProgramDataDir\logs。
    // 返回 S_OK 或 HRESULT_FROM_WIN32(具体错误)，供服务上报准确的退出码——
    // 服务若因日志不可用而拒绝启动，必须让 SCM 看到真实原因而不是笼统的失败。
    HRESULT Initialize(const std::wstring& logDir = std::wstring());
    void Shutdown();

    void SetLevel(LogLevel level) noexcept { m_level.store(level); }
    LogLevel GetLevel() const noexcept { return m_level.load(); }

    // 解析 "debug"/"info"/"warn"/"error"（大小写不敏感），非法值回退 Info
    static LogLevel ParseLevel(const std::wstring& text) noexcept;
    static const wchar_t* LevelTag(LogLevel level) noexcept;

    void Log(LogLevel level, const wchar_t* format, ...);

    void Debug(const wchar_t* format, ...);
    void Info(const wchar_t* format, ...);
    void Warn(const wchar_t* format, ...);
    void Error(const wchar_t* format, ...);

    // 危险操作前的原始值备份（模块 D/F 要求：删除/覆写前必须留痕）。
    // 独立标记 [BACKUP] 便于事后审计与人工恢复。
    void LogBackup(const wchar_t* category, const wchar_t* item, const std::wstring& originalValue);

    std::wstring GetCurrentLogPath() const;

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void LogV(LogLevel level, const wchar_t* format, va_list args);

    // 确保文件句柄指向"今天"的日志；跨天时归档并重建。调用方必须持有 m_mutex
    HRESULT EnsureOpenFileLocked();
    // 删除超过 Constants::kLogKeepDays 天的归档日志。调用方必须持有 m_mutex
    void PurgeOldLogsLocked();
    void WriteLineLocked(LogLevel level, const std::wstring& message);

    mutable std::mutex m_mutex;
    HANDLE            m_file = INVALID_HANDLE_VALUE;
    std::wstring      m_dir;
    std::wstring      m_currentPath;
    int               m_currentDayStamp = 0;   // YYYYMMDD
    // 原子类型：SetLevel 可能由控制线程调用，而 LogV 在 WMI 回调等多个线程上读取，
    // 非原子读写构成数据竞争。
    std::atomic<LogLevel> m_level{LogLevel::Info};
    bool              m_initialized = false;
};

} // namespace GuardDog

// 使用宏而不是直接调用单例，是为了让调用点更短，且后续替换实现时不必改调用方
#define GD_LOG_DEBUG(...) ::GuardDog::Logger::Instance().Debug(__VA_ARGS__)
#define GD_LOG_INFO(...)  ::GuardDog::Logger::Instance().Info(__VA_ARGS__)
#define GD_LOG_WARN(...)  ::GuardDog::Logger::Instance().Warn(__VA_ARGS__)
#define GD_LOG_ERROR(...) ::GuardDog::Logger::Instance().Error(__VA_ARGS__)