#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace GuardDog {

struct ProcessInfo {
    DWORD processId = 0;
    DWORD parentProcessId = 0;
    std::wstring imagePath;  // 完整路径；受保护进程可能取不到，此时为空
    std::wstring imageName;  // 文件名（来自进程快照，通常总能拿到）
};

// 进程操作与处置编排。
//
// 处置顺序刻意设计为"先挂起、再动手"：
// 流氓软件被终止前往往还有最后几毫秒，足够它弹出残留窗口、拉起守护进程、
// 或删掉自己的自启动项证据。先冻结它，后续的清理动作才是对着"静止靶子"做的。
class ProcessKiller {
public:
    // ---------- 原语 ----------
    static bool SuspendProcess(DWORD processId);
    static bool ResumeProcess(DWORD processId);
    static bool TerminateProcessById(DWORD processId, unsigned int exitCode = 1);
    // TerminateProcess 失败时的降级手段：taskkill /F /T 能连带处理受保护子进程
    static bool ForceKillWithTaskkill(DWORD processId);
    static bool IsAlive(DWORD processId);

    static std::wstring QueryImagePath(DWORD processId);
    static bool QueryProcessInfo(DWORD processId, ProcessInfo& info);
    static std::vector<DWORD> QueryChildProcesses(DWORD parentProcessId);

    // ---------- 处置编排 ----------
    // 对已确认命中黑名单的进程执行：挂起自身与子进程 → 收集信息 →
    // （批次 4 在此插入自启动项断根）→ 终止进程树 →（批次 5 在此插入文件处置）
    // 返回 true 表示目标已被终止。
    static bool HandleBlacklistedProcess(DWORD processId, const std::wstring& reason);
};

} // namespace GuardDog