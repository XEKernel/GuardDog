#pragma once

#include "AutoStart/AutoStartTypes.h"

namespace GuardDog {

struct Config;

// 自启动项断根调度器。
//
// 这是对抗"杀了又起"的核心：只终止进程而不清除自启动项，目标下一次开机（甚至几秒后
// 被守护进程拉起）就会回来。因此处置流程的第二步（挂起之后、终止之前）必须先把
// 8 类自启动位置全部扫一遍。
class AutoStartScanner {
public:
    // 扫描并清除所有指向目标的自启动项。
    // 清除完成后会自动复查一遍（以"只扫描"模式重跑），确认没有残留。
    static CleanResult ScanAndClean(const Config& config, const AutoStartTarget& target);

    // 只扫描不修改：服务启动时预检，或 UI 展示用
    static CleanResult ScanOnly(const Config& config, const AutoStartTarget& target);
};

namespace Cleaners {

// 8 类自启动位置各自的清理器。
// clean = false 表示只统计不修改（复查与预检都复用它，避免两套逻辑走偏）。
CleanResult CleanRegistryRun(const Config& config, const AutoStartTarget& target, bool clean);
CleanResult CleanStartupFolder(const Config& config, const AutoStartTarget& target, bool clean);
CleanResult CleanServices(const Config& config, const AutoStartTarget& target, bool clean);
CleanResult CleanScheduledTasks(const Config& config, const AutoStartTarget& target, bool clean);
CleanResult CleanWmiSubscriptions(const Config& config, const AutoStartTarget& target, bool clean);
CleanResult CleanIfeo(const Config& config, const AutoStartTarget& target, bool clean);
CleanResult CleanAppInit(const Config& config, const AutoStartTarget& target, bool clean);
CleanResult CleanWinlogon(const Config& config, const AutoStartTarget& target, bool clean);

} // namespace Cleaners
} // namespace GuardDog