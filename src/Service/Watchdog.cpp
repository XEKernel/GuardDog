// GuardDog 看门狗服务（独立进程）。
//
// 职责只有一个：每 30 秒检查主防护服务是否在运行，不在就把它拉起来。
//
// 为什么要独立成服务而不是放在主服务内部：
//  1) 主服务被流氓软件干掉（或崩溃、被用户误停）时，进程内部的看门狗也一起没了；
//  2) 两个服务互相独立注册，即使主服务的可执行文件被替换/破坏，
//     看门狗仍在运行并会尝试恢复它；
//  3) 主服务侧还会反向检查看门狗（互相守望），见主服务的监控循环。
//
// 编译为 WIN32 子系统，与其他服务一致：无窗口，入口点 wmainCRTStartup。

#include <windows.h>

#include <fcntl.h>
#include <io.h>

#include <atomic>
#include <cstdio>
#include <cwctype>
#include <mutex>
#include <string>

#include "Core/Constants.h"
#include "Core/Logger.h"
#include "Core/ScopeHandle.h"
#include "Service/ServiceInstaller.h"

namespace {

using GuardDog::Constants::kServiceName;
using GuardDog::Constants::kWatchdogServiceName;
using GuardDog::Logger;
using GuardDog::LogLevel;
using GuardDog::ScopeHandle;
using GuardDog::ServiceInstaller;

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS        g_serviceStatus = {};
std::mutex            g_statusMutex;
HANDLE                g_stopEvent = nullptr;
HANDLE                g_workerThread = nullptr;

constexpr DWORD kWorkerWaitOnStopMs = 15000;
constexpr DWORD kCheckIntervalMs = 30000;  // 需求指定：每 30 秒检查一次

std::wstring ToLower(const std::wstring& text) {
    std::wstring result = text;
    for (wchar_t& ch : result) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return result;
}

void CloseServiceHandleCompat(HANDLE handle) {
    CloseServiceHandle(reinterpret_cast<SC_HANDLE>(handle));
}

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

    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
}

void PrintUsage() {
    wprintf(L"GuardDog 看门狗服务 版本 %s\n\n", GuardDog::Constants::kVersion);
    wprintf(L"用法：\n");
    wprintf(L"  GuardDogWatchdog.exe install     安装并启动看门狗服务（需管理员权限）\n");
    wprintf(L"  GuardDogWatchdog.exe uninstall   停止并卸载看门狗服务（需管理员权限）\n");
    wprintf(L"  GuardDogWatchdog.exe console     前台调试模式运行（Ctrl+C 退出）\n");
    wprintf(L"  GuardDogWatchdog.exe             无参数，由服务控制管理器启动\n\n");
    wprintf(L"看门狗每 %lu 秒检查一次主服务 %s，发现其未运行则自动拉起。\n",
            kCheckIntervalMs / 1000, kServiceName);
}

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
            g_serviceStatus.dwCheckPoint = checkpoint++;
            break;
        case SERVICE_RUNNING:
        case SERVICE_PAUSED:
            g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
            break;
        default:
            break;
    }

    if (g_statusHandle != nullptr) {
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
    }
}

// 检查主服务状态；未运行则尝试拉起。返回 true 表示本次检查确认主服务正常。
bool EnsureMainServiceRunning() {
    ScopeHandle scm;
    scm.Reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT), CloseServiceHandleCompat);
    if (!scm.IsValid()) {
        GD_LOG_ERROR(L"看门狗：打开服务控制管理器失败（错误 %lu）", GetLastError());
        return false;
    }

    ScopeHandle service;
    service.Reset(OpenServiceW(reinterpret_cast<SC_HANDLE>(scm.Get()), kServiceName,
                               SERVICE_QUERY_STATUS | SERVICE_START),
                  CloseServiceHandleCompat);
    if (!service.IsValid()) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            // 主服务没装：反复报错没有意义，只记录一次提示
            GD_LOG_WARN(L"看门狗：主服务 %s 未安装，无法拉起", kServiceName);
        } else {
            GD_LOG_ERROR(L"看门狗：打开主服务失败（错误 %lu）", error);
        }
        return false;
    }

    SERVICE_STATUS status{};
    if (!QueryServiceStatus(reinterpret_cast<SC_HANDLE>(service.Get()), &status)) {
        GD_LOG_ERROR(L"看门狗：查询主服务状态失败（错误 %lu）", GetLastError());
        return false;
    }

    if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING) {
        GD_LOG_DEBUG(L"看门狗：主服务运行正常（状态 %lu）", status.dwCurrentState);
        return true;
    }

    // 主服务已停止或已暂停：请求启动。
    // 处于 STOP_PENDING 时启动会失败（服务正在停止），下一轮再试即可。
    GD_LOG_WARN(L"看门狗：检测到主服务未运行（状态 %lu），尝试拉起", status.dwCurrentState);

    if (!StartServiceW(reinterpret_cast<SC_HANDLE>(service.Get()), 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            return true;
        }
        GD_LOG_ERROR(L"看门狗：拉起主服务失败（错误 %lu）", error);
        return false;
    }

    GD_LOG_WARN(L"看门狗：已向主服务发出启动请求");
    return true;
}

DWORD WINAPI WorkerThread(LPVOID /*param*/) {
    GD_LOG_INFO(L"看门狗工作线程启动，检查间隔 %lu 秒", kCheckIntervalMs / 1000);

    // 启动时先立刻检查一次：服务被手动停止后重启看门狗，应当马上把主服务带起来
    EnsureMainServiceRunning();

    for (;;) {
        if (WaitForSingleObject(g_stopEvent, kCheckIntervalMs) == WAIT_OBJECT_0) {
            break;
        }
        EnsureMainServiceRunning();
    }

    GD_LOG_INFO(L"看门狗工作线程收到停止信号，开始退出");
    return 0;
}

DWORD WINAPI ServiceCtrlHandlerEx(DWORD control, DWORD /*eventType*/, LPVOID /*eventData*/,
                                  LPVOID /*context*/) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, kWorkerWaitOnStopMs);
            GD_LOG_INFO(L"看门狗收到停止命令");
            if (g_stopEvent != nullptr) {
                SetEvent(g_stopEvent);
            }
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            ReportStatus(g_serviceStatus.dwCurrentState, NO_ERROR, 0);
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kWatchdogServiceName, ServiceCtrlHandlerEx,
                                                  nullptr);
    if (g_statusHandle == nullptr) {
        return;
    }

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stopEvent == nullptr) {
        ReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    if (FAILED(Logger::Instance().Initialize())) {
        ReportStatus(SERVICE_STOPPED, ERROR_PATH_NOT_FOUND, 0);
        return;
    }

    GD_LOG_INFO(L"================================================================");
    GD_LOG_INFO(L"GuardDog 看门狗启动：版本 %s，进程 PID=%lu", GuardDog::Constants::kVersion,
                GetCurrentProcessId());
    GD_LOG_INFO(L"监视目标：%s（每 %lu 秒检查一次）", kServiceName, kCheckIntervalMs / 1000);

    g_workerThread = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    if (g_workerThread == nullptr) {
        GD_LOG_ERROR(L"看门狗：创建工作线程失败（错误 %lu）", GetLastError());
        Logger::Instance().Shutdown();
        ReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    GD_LOG_INFO(L"看门狗状态：RUNNING");

    // 与主服务一致：必须无限等待停止信号，否则服务会在超时后自行退出
    WaitForSingleObject(g_stopEvent, INFINITE);

    const DWORD waitResult = WaitForSingleObject(g_workerThread, kWorkerWaitOnStopMs);
    if (waitResult == WAIT_TIMEOUT) {
        GD_LOG_WARN(L"看门狗：等待工作线程退出超时，继续收尾");
    }

    CloseHandle(g_workerThread);
    g_workerThread = nullptr;

    GD_LOG_INFO(L"GuardDog 看门狗已停止");
    GD_LOG_INFO(L"================================================================");
    Logger::Instance().Shutdown();

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;

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
        {const_cast<LPWSTR>(kWatchdogServiceName), ServiceMain},
        {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        const DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            MessageBoxW(nullptr,
                        L"GuardDog 看门狗服务需要由 Windows 服务控制管理器启动。\n\n"
                        L"请以管理员身份执行：\n"
                        L"    GuardDogWatchdog.exe install\n\n"
                        L"或使用 console 参数在前台调试运行。",
                        L"GuardDog 看门狗", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
            return 2;
        }
        return static_cast<int>(error);
    }
    return 0;
}

int RunConsoleMode() {
    EnsureConsoleSink();
    (void)Logger::Instance().Initialize();
    Logger::Instance().SetLevel(LogLevel::Debug);

    wprintf(L"[GuardDog] 看门狗前台调试模式，版本 %s\n", GuardDog::Constants::kVersion);
    wprintf(L"[GuardDog] 日志文件：%s\n", Logger::Instance().GetCurrentLogPath().c_str());
    wprintf(L"[GuardDog] 按 Ctrl+C 退出。\n\n");

    GD_LOG_INFO(L"看门狗进入前台调试模式");

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stopEvent == nullptr) {
        wprintf(L"[错误] 创建停止事件失败：%lu\n", GetLastError());
        return 1;
    }

    g_workerThread = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    if (g_workerThread == nullptr) {
        wprintf(L"[错误] 创建工作线程失败：%lu\n", GetLastError());
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return 1;
    }

    WaitForSingleObject(g_workerThread, INFINITE);

    CloseHandle(g_workerThread);
    g_workerThread = nullptr;

    GD_LOG_INFO(L"看门狗前台调试模式退出");
    Logger::Instance().Shutdown();

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;

    wprintf(L"[GuardDog] 看门狗已退出。\n");
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
        return ServiceInstaller::Install(GuardDog::WatchdogServiceDefinition());
    }

    if (command == L"uninstall") {
        EnsureConsoleSink();
        return ServiceInstaller::Uninstall(GuardDog::WatchdogServiceDefinition());
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