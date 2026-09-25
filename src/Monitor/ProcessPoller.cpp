#include "Monitor/ProcessPoller.h"

#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/Matcher.h"
#include "Core/ScopeHandle.h"
#include "Monitor/ProcessKiller.h"

#include <tlhelp32.h>

namespace GuardDog {

void ProcessPoller::PollIfDue(const Config& config, const ProcessCallback& callback) {
    const int intervalMs =
        config.settings.pollIntervalMs > 0 ? config.settings.pollIntervalMs : 500;

    const ULONGLONG now = GetTickCount64();
    if (m_lastScanTick != 0 && (now - m_lastScanTick) < static_cast<ULONGLONG>(intervalMs)) {
        return;
    }

    Scan(config, callback);
}

void ProcessPoller::ScanNow(const Config& config, const ProcessCallback& callback) {
    Scan(config, callback);
}

void ProcessPoller::Scan(const Config& config, const ProcessCallback& callback) {
    ScopeHandle snapshot;
    snapshot.Reset(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.IsValid()) {
        GD_LOG_WARN(L"创建进程快照失败：错误码 %lu", GetLastError());
        return;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.Get(), &entry)) {
        GD_LOG_WARN(L"枚举进程失败：错误码 %lu", GetLastError());
        return;
    }

    const DWORD selfProcessId = GetCurrentProcessId();
    size_t scanned = 0;
    size_t matched = 0;

    do {
        ++scanned;

        // PID 0 是 Idle、PID 4 是 System，都没有可执行映像；自己也不需要被监控
        if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4 ||
            entry.th32ProcessID == selfProcessId) {
            continue;
        }

        std::wstring imagePath = ProcessKiller::QueryImagePath(entry.th32ProcessID);

        // 取不到路径时（受保护进程、权限不足）退回用进程名匹配，
        // 这样至少还能命中"进程名"维度的规则，不会整条规则失效
        const std::wstring target =
            imagePath.empty() ? std::wstring(entry.szExeFile) : imagePath;

        const MatchResult result = Matcher::Evaluate(config, target);
        if (!result.matched || result.whitelisted) {
            continue;
        }

        ++matched;
        GD_LOG_INFO(L"轮询发现目标：pid=%lu 名称=%s —— %s", entry.th32ProcessID, entry.szExeFile,
                    result.Describe().c_str());

        if (callback) {
            callback(entry.th32ProcessID, imagePath);
        }
    } while (Process32NextW(snapshot.Get(), &entry));

    m_lastScanTick = GetTickCount64();
    m_lastMatchedCount = matched;

    // 未命中时只写 debug：500ms 一轮的扫描如果每次都写 info，日志会被瞬间淹没
    GD_LOG_DEBUG(L"轮询扫描完成：扫描 %llu 个进程，命中 %llu 个",
                 static_cast<unsigned long long>(scanned),
                 static_cast<unsigned long long>(matched));
}

} // namespace GuardDog