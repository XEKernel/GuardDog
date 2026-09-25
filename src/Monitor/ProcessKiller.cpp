#include "Monitor/ProcessKiller.h"

#include "AutoStart/AutoStartScanner.h"
#include "Cleaner/FileDestroyer.h"
#include "Cleaner/SoftwareRemover.h"
#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/Matcher.h"
#include "Core/ProcessRunner.h"
#include "Core/ScopeHandle.h"

#include <tlhelp32.h>
#include <winternl.h>

namespace GuardDog {

namespace {

// 处置动作的退出码，便于在事件日志/进程退出码里一眼看出"是被 GuardDog 干掉的"
constexpr unsigned int kTerminatedExitCode = 0xDEAD;

constexpr DWORD kTerminateWaitMs = 3000;
constexpr DWORD kTaskkillTimeoutMs = 10000;

// NtSuspendProcess / NtResumeProcess 的签名（ntdll 导出，未文档化但长期稳定）
using NtProcessControlFn = NTSTATUS(NTAPI*)(HANDLE);

NtProcessControlFn ResolveNtProcessControl(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<NtProcessControlFn>(GetProcAddress(ntdll, name));
}

// 只在首次调用时解析，避免每次处置都走一遍 GetProcAddress
NtProcessControlFn GetNtSuspendProcess() {
    static NtProcessControlFn function = ResolveNtProcessControl("NtSuspendProcess");
    return function;
}

NtProcessControlFn GetNtResumeProcess() {
    static NtProcessControlFn function = ResolveNtProcessControl("NtResumeProcess");
    return function;
}

// 逐个线程挂起/恢复：Nt* 系列不可用时的回退路径
bool SuspendByThreads(DWORD processId, bool suspend) {
    ScopeHandle snapshot;
    snapshot.Reset(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.IsValid()) {
        return false;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot.Get(), &entry)) {
        return false;
    }

    const DWORD desiredAccess = suspend ? THREAD_SUSPEND_RESUME : THREAD_SUSPEND_RESUME;
    bool touchedAny = false;

    do {
        if (entry.th32OwnerProcessID != processId) {
            continue;
        }

        ScopeHandle thread;
        thread.Reset(OpenThread(desiredAccess, FALSE, entry.th32ThreadID));
        if (!thread.IsValid()) {
            continue;
        }

        if (suspend) {
            if (SuspendThread(thread.Get()) != static_cast<DWORD>(-1)) {
                touchedAny = true;
            }
        } else {
            // 恢复时要保证挂起计数归零：SuspendThread 可能被调用过多次
            while (ResumeThread(thread.Get()) > 1) {
                // 继续恢复，直到计数降到 1（即仅剩初始挂起之外的计数）
            }
            touchedAny = true;
        }
    } while (Thread32Next(snapshot.Get(), &entry));

    return touchedAny;
}

} // namespace

bool ProcessKiller::IsAlive(DWORD processId) {
    if (processId == 0) {
        return false;
    }

    ScopeHandle process;
    process.Reset(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process.IsValid()) {
        return false;  // 打不开通常意味着进程已经不存在（或权限不足）
    }

    return WaitForSingleObject(process.Get(), 0) == WAIT_TIMEOUT;
}

std::wstring ProcessKiller::QueryImagePath(DWORD processId) {
    if (processId == 0) {
        return std::wstring();
    }

    ScopeHandle process;
    process.Reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process.IsValid()) {
        // 旧系统或特殊进程上 PROCESS_QUERY_LIMITED_INFORMATION 可能失败，退回更宽的查询权限
        process.Reset(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId));
        if (!process.IsValid()) {
            return std::wstring();
        }
    }

    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        DWORD size = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(process.Get(), 0, path.data(), &size)) {
            path.resize(size);
            return path;
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return std::wstring();
        }
        path.resize(path.size() * 2);
    }
}

bool ProcessKiller::QueryProcessInfo(DWORD processId, ProcessInfo& info) {
    info = ProcessInfo{};
    if (processId == 0) {
        return false;
    }

    info.processId = processId;
    info.imagePath = QueryImagePath(processId);

    ScopeHandle snapshot;
    snapshot.Reset(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.IsValid()) {
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot.Get(), &entry)) {
            do {
                if (entry.th32ProcessID != processId) {
                    continue;
                }
                info.parentProcessId = entry.th32ParentProcessID;
                info.imageName.assign(entry.szExeFile);
                break;
            } while (Process32NextW(snapshot.Get(), &entry));
        }
    }

    return info.processId != 0;
}

std::vector<DWORD> ProcessKiller::QueryChildProcesses(DWORD parentProcessId) {
    std::vector<DWORD> children;
    if (parentProcessId == 0) {
        return children;
    }

    ScopeHandle snapshot;
    snapshot.Reset(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.IsValid()) {
        return children;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.Get(), &entry)) {
        return children;
    }

    do {
        if (entry.th32ParentProcessID == parentProcessId && entry.th32ProcessID != parentProcessId) {
            children.push_back(entry.th32ProcessID);
        }
    } while (Process32NextW(snapshot.Get(), &entry));

    return children;
}

bool ProcessKiller::SuspendProcess(DWORD processId) {
    if (processId == 0) {
        return false;
    }

    // 优先用 NtSuspendProcess：一次调用冻结全部线程，
    // 避免"挂到一半时进程又新建了一个线程"，导致终止时仍有代码在跑。
    if (NtProcessControlFn suspend = GetNtSuspendProcess()) {
        ScopeHandle process;
        process.Reset(OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId));
        if (process.IsValid()) {
            const NTSTATUS status = suspend(process.Get());
            if (status >= 0) {
                return true;
            }
        }
    }

    return SuspendByThreads(processId, true);
}

bool ProcessKiller::ResumeProcess(DWORD processId) {
    if (processId == 0) {
        return false;
    }

    if (NtProcessControlFn resume = GetNtResumeProcess()) {
        ScopeHandle process;
        process.Reset(OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId));
        if (process.IsValid()) {
            const NTSTATUS status = resume(process.Get());
            if (status >= 0) {
                return true;
            }
        }
    }

    return SuspendByThreads(processId, false);
}

bool ProcessKiller::TerminateProcessById(DWORD processId, unsigned int exitCode) {
    if (processId == 0) {
        return false;
    }

    ScopeHandle process;
    process.Reset(OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, processId));
    if (!process.IsValid()) {
        GD_LOG_WARN(L"打开进程失败（pid=%lu，错误 %lu）", processId, GetLastError());
        return false;
    }

    if (!TerminateProcess(process.Get(), exitCode)) {
        GD_LOG_WARN(L"TerminateProcess 失败（pid=%lu，错误 %lu）", processId, GetLastError());
        return false;
    }

    // TerminateProcess 是异步的：等待它真正结束，后续的文件处置才不会被占用句柄挡住
    WaitForSingleObject(process.Get(), kTerminateWaitMs);
    return true;
}

bool ProcessKiller::ForceKillWithTaskkill(DWORD processId) {
    wchar_t commandLine[128] = {};
    swprintf_s(commandLine, L"taskkill.exe /F /T /PID %lu", processId);

    DWORD exitCode = 0;
    if (!RunHiddenProcess(commandLine, kTaskkillTimeoutMs, exitCode)) {
        GD_LOG_WARN(L"调用 taskkill 失败（pid=%lu，错误 %lu）", processId, GetLastError());
        return false;
    }

    if (exitCode != 0) {
        GD_LOG_WARN(L"taskkill 返回非零退出码（pid=%lu，exit=%lu）", processId, exitCode);
        return false;
    }
    return true;
}

// 守护型父进程识别。
//
// 流氓软件的守护进程通常是"目标的父进程"：它负责把目标拉起来，目标被杀后它会重新拉起。
// 只处理目标与其子进程是不够的——必须把这种父进程一并冻住，否则目标会立刻复活。
//
// 判定依据是"父进程与目标位于同一目录"：同一软件的多个组件基本都同目录部署，
// 而用户手动启动目标时，父进程往往是 explorer.exe / cmd.exe / pwsh.exe 等系统程序，
// 目录不同，因此不会被误伤。
DWORD FindRelatedParentProcess(const ProcessInfo& info) {
    if (info.parentProcessId == 0 || info.parentProcessId == 4 || info.imagePath.empty()) {
        return 0;
    }

    const std::wstring parentPath = ProcessKiller::QueryImagePath(info.parentProcessId);
    if (parentPath.empty()) {
        return 0;
    }

    const std::wstring parentDirectory = ParentDirectoryOf(parentPath);
    const std::wstring targetDirectory = ParentDirectoryOf(info.imagePath);
    if (parentDirectory.empty() || targetDirectory.empty()) {
        return 0;
    }

    if (_wcsicmp(parentDirectory.c_str(), targetDirectory.c_str()) != 0) {
        return 0;
    }

    return info.parentProcessId;
}

// 断根：清除所有指向该目标的自启动项。
// 必须发生在"终止进程"之前——目标还活着的时候清自启动项，它的守护进程来不及补写新的；
// 反过来先杀进程再清理，往往会被守护进程在中间空隙里重新注册。
void CleanAutoStartEntries(const ProcessInfo& info) {
    const auto config = ConfigManager::Instance().GetSnapshot();
    if (!config) {
        GD_LOG_WARN(L"[处置] 配置不可用，跳过自启动项断根");
        return;
    }

    AutoStartTarget target;
    target.imagePath = info.imagePath;
    target.imageName = info.imageName;
    if (target.imageName.empty() && !info.imagePath.empty()) {
        target.imageName = Matcher::FileNameOf(info.imagePath);
    }

    const CleanResult result = AutoStartScanner::ScanAndClean(*config, target);
    GD_LOG_WARN(L"[处置] 自启动项断根结果：%s", result.Describe().c_str());
}

// 文件处置：处置"整套软件"，而不只是被捕获的那一个进程文件。
//
// 只删一个 exe 是不够的：流氓软件目录里通常还有守护进程、插件 DLL、升级器、卸载器，
// 删掉主程序后其余的仍然能跑，甚至卸载器能把主程序重新装回来。
// 因此这里以目标目录为根，把目录树里的可执行载体逐个删除或破坏 PE 头。
//
// 放在终止进程之后执行——文件被占用是删除失败的头号原因，
// 先让写它的进程消失，删除成功率会高得多。
void DisposeTargetFile(const ProcessInfo& info) {
    if (info.imagePath.empty()) {
        GD_LOG_WARN(L"[处置] 目标路径未知，跳过文件处置");
        return;
    }

    const auto config = ConfigManager::Instance().GetSnapshot();
    if (!config) {
        GD_LOG_WARN(L"[处置] 配置不可用，跳过文件处置");
        return;
    }

    const SoftwareDisposalResult result = SoftwareRemover::RemoveSoftware(*config, info.imagePath);
    if (result.filesFailed > 0) {
        GD_LOG_ERROR(L"[处置] 软件整体处置存在失败项：%s", result.Describe().c_str());
    } else {
        GD_LOG_WARN(L"[处置] 软件整体处置：%s", result.Describe().c_str());
    }
}

bool ProcessKiller::HandleBlacklistedProcess(DWORD processId, const std::wstring& reason) {
    GD_LOG_WARN(L"[处置] 命中目标：pid=%lu，依据：%s", processId, reason.c_str());

    // Step 1：立刻挂起目标，防止它在被杀前做最后反抗（拉起守护进程、销毁证据、弹残留窗口）
    const bool suspended = SuspendProcess(processId);
    if (suspended) {
        GD_LOG_INFO(L"[处置] 已挂起目标 pid=%lu", processId);
    } else {
        // 挂不起来不放弃处置：可能只是权限受限，终止仍然值得尝试
        GD_LOG_WARN(L"[处置] 挂起失败，仍继续终止（pid=%lu）", processId);
    }

    // Step 2：挂起之后再收集信息，保证收集到的是"冻结状态下"的事实
    ProcessInfo info;
    QueryProcessInfo(processId, info);
    GD_LOG_INFO(L"[处置] 目标信息：路径=%s，父进程=%lu，进程名=%s",
                info.imagePath.empty() ? L"(未知)" : info.imagePath.c_str(), info.parentProcessId,
                info.imageName.empty() ? L"(未知)" : info.imageName.c_str());

    // Step 3：子进程一并挂起。
    // 流氓软件常把真正的动作放在子进程里（父进程只是个壳），只杀父进程等于没杀。
    const std::vector<DWORD> children = QueryChildProcesses(processId);
    for (const DWORD child : children) {
        if (SuspendProcess(child)) {
            GD_LOG_INFO(L"[处置] 已挂起子进程 pid=%lu", child);
        }
    }

    // Step 3.5：识别并挂起守护型父进程（与目标同目录的父进程）
    const DWORD relatedParent = FindRelatedParentProcess(info);
    if (relatedParent != 0) {
        GD_LOG_WARN(L"[处置] 父进程与目标同目录，判定为守护进程并连带处置：pid=%lu 路径=%s",
                    relatedParent, QueryImagePath(relatedParent).c_str());
        SuspendProcess(relatedParent);
    }

    // Step 4：断根 —— 清除所有指向该目标的自启动项。
    // 这是"杀了又起"的关键一环：不清自启动项，目标下次开机（或被守护进程拉起）就会回来。
    CleanAutoStartEntries(info);

    // Step 5：终止进程树
    bool terminated = TerminateProcessById(processId, kTerminatedExitCode);
    if (!terminated) {
        GD_LOG_WARN(L"[处置] TerminateProcess 失败，降级为 taskkill /F /T（pid=%lu）", processId);
        terminated = ForceKillWithTaskkill(processId);
    }

    for (const DWORD child : children) {
        if (!IsAlive(child)) {
            continue;
        }
        if (!TerminateProcessById(child, kTerminatedExitCode)) {
            GD_LOG_WARN(L"[处置] 子进程 TerminateProcess 失败，降级为 taskkill（pid=%lu）", child);
            ForceKillWithTaskkill(child);
        }
    }

    if (relatedParent != 0 && IsAlive(relatedParent)) {
        if (!TerminateProcessById(relatedParent, kTerminatedExitCode)) {
            ForceKillWithTaskkill(relatedParent);
        }
        GD_LOG_WARN(L"[处置] 守护型父进程已终止：pid=%lu", relatedParent);
    }

    if (!terminated) {
        // 关键：终止失败时把进程恢复运行。
        // 留一个被挂起的进程，比留一个运行中的进程更糟——用户会看到一个"假死"的程序，
        // 而且它持有的锁和句柄会一直卡住系统资源。
        GD_LOG_ERROR(L"[处置] 终止失败，恢复目标运行以免留下挂起态进程（pid=%lu）", processId);
        ResumeProcess(processId);
        if (relatedParent != 0) {
            ResumeProcess(relatedParent);
        }
        return false;
    }

    GD_LOG_WARN(L"[处置] 目标已终止：pid=%lu，路径=%s", processId,
                info.imagePath.empty() ? L"(未知)" : info.imagePath.c_str());

    // Step 6：文件处置 —— 删除源文件，删不掉则覆写 PE 头使其永久报废
    DisposeTargetFile(info);

    // Step 7：复活观察由监控循环天然承担——
    // 目标若被守护进程或计划任务重新拉起，会立刻再次命中并入队处置；
    // 由于自启动项已在 Step 4 清空，残余的引导者通常在几轮内被耗光。
    return true;
}

} // namespace GuardDog