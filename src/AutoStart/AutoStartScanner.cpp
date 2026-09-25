#include "AutoStart/AutoStartScanner.h"

#include "Core/Logger.h"

namespace GuardDog {

namespace {

struct CleanerEntry {
    const wchar_t* name;
    CleanResult (*function)(const Config&, const AutoStartTarget&, bool);
};

// 8 类自启动位置。顺序上没有强依赖（服务内部自己保证"先清恢复策略再停止"这类次序），
// 但把最常见、代价最低的注册表项放在最前面，便于日志阅读时快速定位。
constexpr CleanerEntry kCleaners[] = {
    {L"注册表 Run/RunOnce", &Cleaners::CleanRegistryRun},
    {L"启动文件夹", &Cleaners::CleanStartupFolder},
    {L"Windows 服务", &Cleaners::CleanServices},
    {L"计划任务", &Cleaners::CleanScheduledTasks},
    {L"WMI 永久事件订阅", &Cleaners::CleanWmiSubscriptions},
    {L"IFEO 映像劫持", &Cleaners::CleanIfeo},
    {L"AppInit_DLLs", &Cleaners::CleanAppInit},
    {L"Winlogon", &Cleaners::CleanWinlogon},
};

CleanResult RunAllCleaners(const Config& config, const AutoStartTarget& target, bool clean) {
    CleanResult total;
    for (const CleanerEntry& entry : kCleaners) {
        const CleanResult result = entry.function(config, target, clean);
        total.Accumulate(result);
    }
    return total;
}

} // namespace

CleanResult AutoStartScanner::ScanAndClean(const Config& config, const AutoStartTarget& target) {
    GD_LOG_WARN(L"===== 开始自启动项断根：%s =====", target.Describe().c_str());

    const CleanResult removed = RunAllCleaners(config, target, true);
    GD_LOG_WARN(L"断根完成：%s", removed.Describe().c_str());

    // 需求要求"清除完成后重新扫描一遍验证，确保没有漏网"。
    // 复查仍以同一套 cleaner 执行，只是切到只读模式，避免两套逻辑走偏。
    GD_LOG_INFO(L"开始断根复查（只扫描，不修改）");
    const CleanResult remaining = RunAllCleaners(config, target, false);

    if (remaining.matched > 0) {
        // 残留通常意味着权限不足或该项由系统保护；具体明细见上面的 debug 记录
        GD_LOG_ERROR(L"断根复查：仍有 %d 项指向该目标的自启动项残留，可能需要人工处理",
                     remaining.matched);
    } else {
        GD_LOG_INFO(L"断根复查通过：未发现残留自启动项");
    }

    return removed;
}

CleanResult AutoStartScanner::ScanOnly(const Config& config, const AutoStartTarget& target) {
    return RunAllCleaners(config, target, false);
}

} // namespace GuardDog