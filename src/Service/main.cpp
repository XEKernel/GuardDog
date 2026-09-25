// GuardDog 服务主程序入口。
//
// 该 exe 有三种运行形态，通过命令行区分：
//   1) 无参数        —— 由 SCM 启动，走 StartServiceCtrlDispatcherW 进入 SvcMain；
//   2) install/uninstall —— 注册/卸载服务（需要管理员权限）；
//   3) console       —— 前台调试模式，便于开发期观察日志而无须装服务。
//
// 编译为 WIN32 子系统（无窗口），入口点显式指定为 wmainCRTStartup，
// 这样既能使用 wmain 接收宽字符参数，又不会弹出控制台窗口。

#include <windows.h>

#include <fcntl.h>
#include <io.h>

#include <atomic>
#include <cstdio>
#include <cwctype>
#include <deque>
#include <mutex>
#include <string>

#include "Cleaner/FileDestroyer.h"
#include "Cleaner/LegacyScanner.h"
#include "Core/ConfigManager.h"
#include "Core/Constants.h"
#include "Core/Logger.h"
#include "Core/Matcher.h"
#include "Core/ScopeHandle.h"
#include "Monitor/ProcessKiller.h"
#include "Monitor/ProcessPoller.h"
#include "Monitor/WmiMonitor.h"
#include "Service/ServiceInstaller.h"

namespace {

using GuardDog::ConfigManager;
using GuardDog::Constants::kServiceName;
using GuardDog::DestroyResult;
using GuardDog::FileDestroyer;
using GuardDog::LegacyScanner;
using GuardDog::LegacyScanResult;
using GuardDog::Logger;
using GuardDog::LogLevel;
using GuardDog::MatchResult;
using GuardDog::Matcher;
using GuardDog::ProcessKiller;
using GuardDog::ProcessPoller;
using GuardDog::ScopeHandle;
using GuardDog::WmiMonitor;

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS        g_serviceStatus = {};
std::mutex            g_statusMutex;

// 停止/关机信号：worker 线程等待它退出，保证服务停止时任务优雅收尾
HANDLE g_stopEvent = nullptr;
HANDLE g_workerThread = nullptr;

// 暂停标志：SERVICE_CONTROL_PAUSE 时置位，worker 线程应停止执行处置动作
// （暂停语义 = 不再动手，而不是终止进程）
std::atomic<bool> g_paused{false};

constexpr DWORD kWorkerWaitOnStopMs = 30000;
constexpr DWORD kMainLoopIntervalMs = 200;           // 主循环节拍，同时决定停止命令的响应延迟
constexpr ULONGLONG kConfigCheckIntervalMs = 1000;   // 配置热重载检查周期
constexpr ULONGLONG kWmiReconnectIntervalMs = 30000; // WMI 订阅重建的最小重试间隔
constexpr ULONGLONG kWatchdogCheckIntervalMs = 60000;  // 反向守望看门狗的检查周期

void CloseServiceHandleCompat(HANDLE handle) {
    CloseServiceHandle(reinterpret_cast<SC_HANDLE>(handle));
}

// 反向守望：主服务也定期确认看门狗服务在运行。
// 只有看门狗守主服务是不够的——看门狗自己被停掉（或崩溃）之后就没有人恢复它，
// 两侧互相检查才能避免单点失效。
void EnsureWatchdogRunning() {
    ScopeHandle scm;
    scm.Reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT), CloseServiceHandleCompat);
    if (!scm.IsValid()) {
        return;
    }

    ScopeHandle service;
    service.Reset(OpenServiceW(reinterpret_cast<SC_HANDLE>(scm.Get()),
                               GuardDog::Constants::kWatchdogServiceName,
                               SERVICE_QUERY_STATUS | SERVICE_START),
                  CloseServiceHandleCompat);
    if (!service.IsValid()) {
        // 没装看门狗属于正常部署形态，只提示不报错
        GD_LOG_DEBUG(L"看门狗服务不存在或无法打开（错误 %lu）", GetLastError());
        return;
    }

    SERVICE_STATUS status{};
    if (!QueryServiceStatus(reinterpret_cast<SC_HANDLE>(service.Get()), &status)) {
        return;
    }
    if (status.dwCurrentState == SERVICE_RUNNING ||
        status.dwCurrentState == SERVICE_START_PENDING) {
        return;
    }

    GD_LOG_WARN(L"检测到看门狗服务未运行（状态 %lu），尝试拉起", status.dwCurrentState);
    if (!StartServiceW(reinterpret_cast<SC_HANDLE>(service.Get()), 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            GD_LOG_ERROR(L"拉起看门狗服务失败（错误 %lu）", error);
        }
    }
}

std::wstring ToLower(const std::wstring& text) {
    std::wstring result = text;
    for (wchar_t& ch : result) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return result;
}

// 服务程序编译为 WIN32 子系统，没有控制台。
// install/uninstall/console/help 这些交互命令需要输出，所以临时接管父进程控制台，
// 没有父控制台（例如资源管理器双击）时自己开一个。
void EnsureConsoleSink() {
    if (GetConsoleWindow() == nullptr) {
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
            AllocConsole();
        }
    }

    FILE* stream = nullptr;
    freopen_s(&stream, "CONOUT$", "w", stdout);
    freopen_s(&stream, "CONOUT$", "w", stderr);
    freopen_s(&stream, "CONIN$", "r", stdin);

    // 切到 UTF-16 文本模式，否则 wprintf 输出的中文在控制台会乱码
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
}

void PrintUsage() {
    wprintf(L"GuardDog 安全防护服务 版本 %s（%s）\n\n", GuardDog::Constants::kVersion,
            GuardDog::Constants::kBuildStage);
    wprintf(L"用法：\n");
    wprintf(L"  GuardDogService.exe install     安装并启动服务（需管理员权限）\n");
    wprintf(L"  GuardDogService.exe uninstall   停止并卸载服务（需管理员权限）\n");
    wprintf(L"  GuardDogService.exe console     前台调试模式运行（Ctrl+C 退出）\n");
    wprintf(L"  GuardDogService.exe             无参数，由服务控制管理器启动\n\n");
    wprintf(L"常用服务命令：\n");
    wprintf(L"  sc query %s\n", kServiceName);
    wprintf(L"  sc start %s\n", kServiceName);
    wprintf(L"  sc stop  %s\n", kServiceName);
    wprintf(L"  sc qfailure %s\n\n", kServiceName);
    wprintf(L"日志目录：%s\\%s\n", GuardDog::Constants::kProgramDataDir,
            GuardDog::Constants::kLogDirName);
}

// 向 SCM 上报服务状态。
// 注意：ServiceMain 线程与控制处理线程都可能调用它（SCM 会用新线程调用控制处理函数），
// 而 SetServiceStatus 不是线程安全的，因此加锁串行化。
void ReportStatus(DWORD currentState, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
    std::lock_guard<std::mutex> lock(g_statusMutex);

    static DWORD checkpoint = 1;

    g_serviceStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState     = currentState;
    g_serviceStatus.dwWin32ExitCode    = exitCode;
    g_serviceStatus.dwWaitHint         = waitHint;
    g_serviceStatus.dwCheckPoint       = 0;
    g_serviceStatus.dwControlsAccepted = 0;

    switch (currentState) {
        case SERVICE_START_PENDING:
        case SERVICE_STOP_PENDING:
        case SERVICE_PAUSE_PENDING:
        case SERVICE_CONTINUE_PENDING:
            // 过渡状态不接受控制命令，并递增 checkpoint 让 SCM 知道进展
            g_serviceStatus.dwCheckPoint = checkpoint++;
            break;
        case SERVICE_RUNNING:
        case SERVICE_PAUSED:
            g_serviceStatus.dwControlsAccepted =
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE;
            break;
        default:
            break;
    }

    if (g_statusHandle != nullptr) {
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
    }
}

// 服务控制处理函数（SCM 在服务进程的独立线程中调用）
DWORD WINAPI ServiceCtrlHandlerEx(DWORD control, DWORD /*eventType*/, LPVOID /*eventData*/,
                                  LPVOID /*context*/) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN: {
            const bool isShutdown = (control == SERVICE_CONTROL_SHUTDOWN);
            ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, kWorkerWaitOnStopMs);
            GD_LOG_INFO(isShutdown ? L"收到系统关机通知，开始停止服务" : L"收到停止命令，开始停止服务");
            if (g_stopEvent != nullptr) {
                SetEvent(g_stopEvent);
            }
            return NO_ERROR;
        }

        case SERVICE_CONTROL_PAUSE:
            if (g_serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                g_paused.store(true);
                ReportStatus(SERVICE_PAUSED);
                GD_LOG_INFO(L"服务已暂停：不再执行监控与处置动作");
            }
            return NO_ERROR;

        case SERVICE_CONTROL_CONTINUE:
            if (g_serviceStatus.dwCurrentState == SERVICE_PAUSED) {
                g_paused.store(false);
                ReportStatus(SERVICE_RUNNING);
                GD_LOG_INFO(L"服务已恢复运行");
            }
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            ReportStatus(g_serviceStatus.dwCurrentState, NO_ERROR, 0);
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// 把配置里的 log_level 应用到日志器。
// 配置热重载后也要调用一次，否则改了日志级别要重启服务才生效。
void ApplyLogLevelFromConfig() {
    const auto config = ConfigManager::Instance().GetSnapshot();
    if (!config) {
        return;
    }
    const LogLevel level = Logger::ParseLevel(config->settings.logLevel);
    if (level != Logger::Instance().GetLevel()) {
        Logger::Instance().SetLevel(level);
        GD_LOG_INFO(L"日志级别已调整为 %s", Logger::LevelTag(level));
    }
}

// 加载配置。
// 注意：配置读取失败不阻止服务启动——服务本身要活着才能继续清理与监控，
// 而 ConfigManager 会保证 GetSnapshot() 返回一个可用的兜底配置。
void LoadConfigOrReport() {
    std::wstring error;
    const HRESULT result = ConfigManager::Instance().Load(std::wstring(), &error);
    if (FAILED(result)) {
        GD_LOG_ERROR(L"配置加载失败（将使用内置默认值）：%s", error.c_str());
        return;
    }
    ApplyLogLevelFromConfig();

    const auto config = ConfigManager::Instance().GetSnapshot();
    if (config) {
        GD_LOG_INFO(L"配置来源：%s", config->sourcePath.c_str());

        // 关于复活观察期：GuardDog 的监控是常态化的（WMI 事件 + 每 500ms 全量扫描），
        // 处置后目标若被拉起会立刻再次命中并入队处置，因此无需单独的"观察期"计时器。
        // 这里显式说明，避免用户以为 observe_after_kill_seconds 是个没生效的开关。
        GD_LOG_INFO(L"复活对抗方式：常态化监控（配置中的 observe_after_kill_seconds=%d 秒用于标注策略意图，"
                    L"实际由持续监控承担）",
                    config->settings.observeSeconds);
    }
}

// ---------------------------------------------------------------------------
// 待处置目标队列
//
// WMI 回调跑在 COM 的线程池线程上，轮询跑在主循环线程上。两者只负责"发现并入队"，
// 真正的处置统一由主循环串行执行：否则两个执行流可能同时挂起/终止同一个进程，
// 出现"一个在挂起、另一个在终止"的竞态，日志也会互相穿插难以复盘。
// ---------------------------------------------------------------------------
struct ThreatTarget {
    DWORD processId = 0;
    std::wstring pathHint;
    std::wstring reason;
};

std::mutex g_threatMutex;
std::deque<ThreatTarget> g_threatQueue;
constexpr size_t kMaxPendingThreats = 256;

void EnqueueThreat(DWORD processId, const std::wstring& pathHint, const std::wstring& reason) {
    if (processId == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_threatMutex);

    // 去重：同一个进程常常被 WMI 与轮询同时捕获
    for (const ThreatTarget& pending : g_threatQueue) {
        if (pending.processId == processId) {
            return;
        }
    }

    if (g_threatQueue.size() >= kMaxPendingThreats) {
        GD_LOG_WARN(L"待处置队列已满，丢弃目标 pid=%lu", processId);
        return;
    }

    g_threatQueue.push_back(ThreatTarget{processId, pathHint, reason});
}

bool DequeueThreat(ThreatTarget& target) {
    std::lock_guard<std::mutex> lock(g_threatMutex);
    if (g_threatQueue.empty()) {
        return false;
    }
    target = g_threatQueue.front();
    g_threatQueue.pop_front();
    return true;
}

// 处置队列中的全部目标
void HandlePendingThreats() {
    ThreatTarget target;
    while (DequeueThreat(target)) {
        const auto config = ConfigManager::Instance().GetSnapshot();
        if (!config) {
            continue;
        }

        // 二次校验：从入队到执行的这段时间里，PID 可能已被回收、进程可能已退出。
        // 危险操作必须基于"此刻的事实"重新判定，绝不能凭队列里的旧信息动手。
        const std::wstring imagePath = ProcessKiller::QueryImagePath(target.processId);
        if (imagePath.empty()) {
            GD_LOG_DEBUG(L"目标进程已不存在，跳过处置：pid=%lu", target.processId);
            continue;
        }

        const MatchResult verdict = Matcher::Evaluate(*config, imagePath);
        if (verdict.whitelisted) {
            // 白名单放行属于安全决策，用 info 留痕，便于事后核对"为什么没处理它"
            GD_LOG_INFO(L"二次校验命中白名单，跳过处置：pid=%lu 路径=%s 结论=%s", target.processId,
                        imagePath.c_str(), verdict.Describe().c_str());
            continue;
        }
        if (!verdict.matched) {
            GD_LOG_DEBUG(L"二次校验未命中黑名单，跳过处置：pid=%lu 路径=%s", target.processId,
                         imagePath.c_str());
            continue;
        }

        ProcessKiller::HandleBlacklistedProcess(target.processId, verdict.Describe());
    }
}

// 工作线程。
// 批次 3 起它承担监控调度：WMI 事件订阅（主）+ 轮询（兜底）+ 串行处置。
// 批次 4/5 会在此基础上挂载自启动清理与文件处置。
DWORD WINAPI WorkerThread(LPVOID /*param*/) {
    GD_LOG_INFO(L"工作线程启动（当前阶段：%s）", GuardDog::Constants::kBuildStage);

    ProcessPoller poller;
    WmiMonitor wmiMonitor;

    const auto submitFromWmi = [](DWORD processId, const std::wstring& processName) {
        // 回调线程上的轻量预筛：只做进程名/路径比较，把绝大多数无关进程挡在队列外。
        // 签名者与哈希维度的目标交给轮询（完整匹配）兜底——那两类匹配代价高，
        // 放在 COM 回调线程上做会拖慢事件投递。
        const auto config = ConfigManager::Instance().GetSnapshot();
        if (config && !Matcher::QuickMatchNameOrPath(*config, processName)) {
            return;
        }
        EnqueueThreat(processId, processName, L"WMI 进程创建事件");
    };
    const auto submitFromScan = [](DWORD processId, const std::wstring& imagePath) {
        EnqueueThreat(processId, imagePath, L"轮询扫描命中");
    };

    auto config = ConfigManager::Instance().GetSnapshot();

    // 主方案：WMI 进程创建事件（延迟远低于轮询）
    if (config && config->settings.wmiEnabled) {
        const HRESULT hr = wmiMonitor.Start(submitFromWmi);
        if (FAILED(hr)) {
            GD_LOG_ERROR(L"WMI 订阅启动失败（0x%08X），本次仅依赖 %dms 轮询兜底", hr,
                         config->settings.pollIntervalMs);
        }
    } else {
        GD_LOG_INFO(L"配置已停用 WMI 订阅，仅使用轮询监控");
    }

    // 服务启动时先检查"已经在运行"的进程，覆盖服务启动前就已存在的目标
    if (config) {
        GD_LOG_INFO(L"执行启动存量检查：扫描当前运行中的进程");
        poller.ScanNow(*config, submitFromScan);
        HandlePendingThreats();
    }

    // 存量清理（模块 E）：由配置项 clean_legacy_on_start 控制，默认关闭。
    // 默认关闭的理由：它会大范围扫描磁盘与注册表，并可能删除已存在的软件，
    // 这类动作应当由用户明确开启，而不是装上服务就自动发生。
    if (config && config->settings.cleanLegacyOnStart) {
        const LegacyScanResult legacyResult = LegacyScanner::Scan(*config);

        for (const LegacyScanResult::Hit& hit : legacyResult.hits) {
            if (hit.processId != 0) {
                // 运行中的进程走标准处置流程（挂起 → 断根 → 终止 → 删文件）
                EnqueueThreat(hit.processId, hit.path, L"存量扫描-运行进程");
                continue;
            }

            // 静态文件不在运行，无需挂起与终止，直接处置文件本身
            const DestroyResult destroyResult = FileDestroyer::DestroyFile(*config, hit.path);
            if (destroyResult.IsHandled()) {
                GD_LOG_WARN(L"[存量清理] %s", destroyResult.Describe().c_str());
            } else {
                GD_LOG_ERROR(L"[存量清理] %s", destroyResult.Describe().c_str());
            }
        }

        HandlePendingThreats();
    }

    ULONGLONG lastConfigCheck = GetTickCount64();
    ULONGLONG lastWmiReconnectAttempt = GetTickCount64();
    ULONGLONG lastWatchdogCheck = GetTickCount64();

    for (;;) {
        const DWORD waitResult = WaitForSingleObject(g_stopEvent, kMainLoopIntervalMs);
        if (waitResult == WAIT_OBJECT_0) {
            break;  // 停止/关机
        }

        if (g_paused.load()) {
            continue;  // 暂停期间不产生任何处置动作
        }

        const ULONGLONG now = GetTickCount64();
        config = ConfigManager::Instance().GetSnapshot();

        // 1) 配置热重载：由主循环驱动即可，无需独立线程
        if (now - lastConfigCheck >= kConfigCheckIntervalMs) {
            lastConfigCheck = now;
            if (ConfigManager::Instance().ReloadIfChanged()) {
                ApplyLogLevelFromConfig();
                // 规则集变了，之前缓存的"某路径的签名者/哈希"结论不再对应新配置，清掉重算
                Matcher::ClearIdentityCache();
                poller.Reset();  // 轮询间隔可能被改过
                config = ConfigManager::Instance().GetSnapshot();
            }
        }

        if (!config) {
            continue;
        }

        // 2) 兜底轮询：WMI 漏事件时靠它把目标捞回来
        poller.PollIfDue(*config, submitFromScan);

        // 3) 让 WMI 订阅状态与配置保持一致：
        //    - 配置要求启用但订阅没在跑（启动失败，或 WMI 服务重启导致中断）→ 重建
        //    - 配置被改成停用但订阅还在跑 → 立刻停掉（热重载切换必须真正生效）
        if (config->settings.wmiEnabled) {
            if (!wmiMonitor.IsRunning() &&
                (now - lastWmiReconnectAttempt) >= kWmiReconnectIntervalMs) {
                lastWmiReconnectAttempt = now;
                wmiMonitor.ClearReconnectFlag();
                GD_LOG_INFO(L"尝试建立 WMI 订阅");
                if (FAILED(wmiMonitor.Start(submitFromWmi))) {
                    GD_LOG_WARN(L"建立 WMI 订阅失败，%llu 秒后重试",
                                static_cast<unsigned long long>(kWmiReconnectIntervalMs / 1000));
                }
            }
        } else if (wmiMonitor.IsRunning()) {
            GD_LOG_INFO(L"配置已停用 WMI 订阅，正在停止订阅");
            wmiMonitor.Stop();
        }

        // 4) 反向守望：确认看门狗服务还在运行（互相守护，避免单点失效）
        if ((now - lastWatchdogCheck) >= kWatchdogCheckIntervalMs) {
            lastWatchdogCheck = now;
            EnsureWatchdogRunning();
        }

        // 5) 串行处置（放在最后，确保本轮的所有发现路径都已执行过）
        HandlePendingThreats();
    }

    wmiMonitor.Stop();
    GD_LOG_INFO(L"工作线程收到停止信号，开始退出");
    return 0;
}

void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceCtrlHandlerEx, nullptr);
    if (g_statusHandle == nullptr) {
        // 上报通道都拿不到，只能直接退出，SCM 会按启动失败处理
        return;
    }

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stopEvent == nullptr) {
        ReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    const HRESULT logResult = Logger::Instance().Initialize();
    if (FAILED(logResult)) {
        // 日志是后续所有危险操作（删除文件、覆写 PE 头、禁用服务）的唯一审计来源。
        // 写不了日志就不允许服务运行，避免出现"无声无息把系统改坏"的黑箱状态。
        // 上报真实错误码（HRESULT_CODE 取低 16 位），便于直接用 net helpmsg 定位原因。
        ReportStatus(SERVICE_STOPPED, HRESULT_CODE(logResult), 0);
        return;
    }

    GD_LOG_INFO(L"================================================================");
    GD_LOG_INFO(L"GuardDog 服务启动：版本 %s，阶段 %s", GuardDog::Constants::kVersion,
                GuardDog::Constants::kBuildStage);
    GD_LOG_INFO(L"进程 PID=%lu，运行账户=%s", GetCurrentProcessId(), L"LocalSystem");
    GD_LOG_INFO(L"日志文件：%s", Logger::Instance().GetCurrentLogPath().c_str());

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    LoadConfigOrReport();

    g_workerThread = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    if (g_workerThread == nullptr) {
        const DWORD error = GetLastError();
        GD_LOG_ERROR(L"创建工作线程失败：%lu", error);
        Logger::Instance().Shutdown();
        ReportStatus(SERVICE_STOPPED, error, 0);
        return;
    }

    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    GD_LOG_INFO(L"服务状态：RUNNING");

    // 第一步：无限等待停止/关机信号（由控制处理函数置位 g_stopEvent）。
    // 这里必须是无限等待——若给这个等待设超时，服务会在超时后自行走到收尾流程，
    // 表现为"服务启动约半分钟就自动停止"的假服务。
    WaitForSingleObject(g_stopEvent, INFINITE);
    GD_LOG_INFO(L"收到停止信号，开始等待工作线程收尾");

    // 第二步：给工作线程一段有限时间完成手头的处置动作（批次 3 起它可能正在
    // 挂起进程或清理自启动项，贸然退出会留下半完成状态）
    const DWORD waitResult = WaitForSingleObject(g_workerThread, kWorkerWaitOnStopMs);
    if (waitResult == WAIT_TIMEOUT) {
        // 不调用 TerminateThread：强杀线程会让文件/注册表句柄处于未定义状态，
        // 这里只记录，随后由进程退出统一回收资源。
        GD_LOG_WARN(L"等待工作线程退出超时（%lu 毫秒），继续执行收尾",
                    kWorkerWaitOnStopMs);
    }

    if (g_workerThread != nullptr) {
        CloseHandle(g_workerThread);
        g_workerThread = nullptr;
    }

    GD_LOG_INFO(L"GuardDog 服务已停止");
    GD_LOG_INFO(L"================================================================");
    Logger::Instance().Shutdown();

    if (g_stopEvent != nullptr) {
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
    }

    ReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

BOOL WINAPI ConsoleCtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        if (g_stopEvent != nullptr) {
            SetEvent(g_stopEvent);
        }
        return TRUE;
    }
    return FALSE;
}

int RunAsService() {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        const DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // 从 SCM 之外的地方启动（多半是双击 exe），给出可操作指引而不是静默失败
            MessageBoxW(nullptr,
                        L"GuardDog 服务需要由 Windows 服务控制管理器启动。\n\n"
                        L"请以管理员身份执行：\n"
                        L"    GuardDogService.exe install\n\n"
                        L"或使用 console 参数在前台调试运行。",
                        L"GuardDog 安全防护", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
            return 2;
        }
        return static_cast<int>(error);
    }
    return 0;
}

int RunConsoleMode() {
    EnsureConsoleSink();
    (void)Logger::Instance().Initialize();
    LoadConfigOrReport();
    // 前台调试模式固定用 debug 级别，方便观察监控与清理的每一步
    Logger::Instance().SetLevel(LogLevel::Debug);

    wprintf(L"[GuardDog] 前台调试模式，版本 %s（%s）\n", GuardDog::Constants::kVersion,
            GuardDog::Constants::kBuildStage);
    wprintf(L"[GuardDog] 日志文件：%s\n", Logger::Instance().GetCurrentLogPath().c_str());
    wprintf(L"[GuardDog] 按 Ctrl+C 退出。\n\n");

    GD_LOG_INFO(L"进入前台调试模式");

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stopEvent == nullptr) {
        const DWORD error = GetLastError();
        wprintf(L"[错误] 创建停止事件失败：%lu\n", error);
        return 1;
    }

    g_workerThread = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    if (g_workerThread == nullptr) {
        const DWORD error = GetLastError();
        wprintf(L"[错误] 创建工作线程失败：%lu\n", error);
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return 1;
    }

    WaitForSingleObject(g_workerThread, INFINITE);

    CloseHandle(g_workerThread);
    g_workerThread = nullptr;

    GD_LOG_INFO(L"前台调试模式退出");
    Logger::Instance().Shutdown();

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;

    wprintf(L"[GuardDog] 已退出。\n");
    return 0;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    const std::wstring command = (argc >= 2) ? ToLower(argv[1]) : std::wstring();

    if (command.empty()) {
        return RunAsService();
    }

    if (command == L"install") {
        EnsureConsoleSink();
        return GuardDog::ServiceInstaller::Install(GuardDog::MainServiceDefinition());
    }

    if (command == L"uninstall") {
        EnsureConsoleSink();
        return GuardDog::ServiceInstaller::Uninstall(GuardDog::MainServiceDefinition());
    }

    if (command == L"console") {
        return RunConsoleMode();
    }

    if (command == L"help" || command == L"-h" || command == L"--help" || command == L"/?") {
        EnsureConsoleSink();
        PrintUsage();
        return GuardDog::kInstallerOk;
    }

    EnsureConsoleSink();
    wprintf(L"[错误] 未知参数：%s\n\n", argv[1]);
    PrintUsage();
    return GuardDog::kInstallerBadUsage;
}