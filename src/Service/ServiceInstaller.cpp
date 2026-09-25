#include "Service/ServiceInstaller.h"

#include "Core/Constants.h"
#include "Core/Logger.h"
#include "Core/ScopeHandle.h"

#include <windows.h>

#include <cstdarg>
#include <cstdio>

namespace GuardDog {

namespace {

constexpr DWORD kStartWaitTimeoutMs = 10000;
constexpr DWORD kStopWaitTimeoutMs  = 15000;
constexpr DWORD kPollIntervalMs     = 200;

// SC_HANDLE 与 HANDLE 是同一类型，但必须用 CloseServiceHandle 关闭。
// 这里包一层，满足 ScopeHandle 自定义关闭器的签名要求。
void CloseServiceHandleCompat(HANDLE handle) {
    CloseServiceHandle(reinterpret_cast<SC_HANDLE>(handle));
}

std::wstring FormatWin32Error(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buffer),
        0, nullptr);

    std::wstring result;
    if (length != 0 && buffer != nullptr) {
        result.assign(buffer, length);
        while (!result.empty() &&
               (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
            result.pop_back();
        }
    }
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    if (result.empty()) {
        result = L"未知错误";
    }
    return result;
}

void PrintLine(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    vwprintf(format, args);
    va_end(args);
    wprintf(L"\n");
}

// SCM 的状态切换是异步的：ControlService 返回时服务通常还在 STOP_PENDING，
// 此时立即 DeleteService 会因为"服务正在运行"而失败，所以必须轮询等待。
bool WaitForServiceState(SC_HANDLE service, DWORD desiredState, DWORD timeoutMs) {
    const DWORD deadline = GetTickCount() + timeoutMs;
    for (;;) {
        SERVICE_STATUS status{};
        if (!QueryServiceStatus(service, &status)) {
            return false;
        }
        if (status.dwCurrentState == desiredState) {
            return true;
        }
        if (GetTickCount() >= deadline) {
            return false;
        }
        Sleep(kPollIntervalMs);
    }
}

} // namespace

std::wstring ServiceInstaller::GetExecutablePath() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return std::wstring();
        }
        if (length < path.size()) {
            path.resize(length);
            return path;
        }
        // 返回长度等于缓冲区大小说明被截断（长路径场景），扩大后重试
        path.resize(path.size() * 2);
    }
}

bool ServiceInstaller::IsElevated() {
    ScopeHandle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.Put())) {
        return false;
    }

    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    if (!GetTokenInformation(token.Get(), TokenElevation, &elevation, sizeof(elevation), &returned)) {
        return false;
    }
    return elevation.TokenIsElevated != 0;
}

int ServiceInstaller::Install() {
    // 安装阶段日志目录可能还不存在，初始化失败不阻断安装
    (void)Logger::Instance().Initialize();
    GD_LOG_INFO(L"开始安装服务：%s", Constants::kServiceName);

    PrintLine(L"[GuardDog] 正在安装服务 %s ...", Constants::kServiceName);

    if (!IsElevated()) {
        PrintLine(L"[失败] 需要管理员权限。请以管理员身份打开终端后重试。");
        GD_LOG_ERROR(L"安装失败：当前进程无管理员权限");
        return kInstallerNotElevated;
    }

    ScopeHandle scm;
    scm.Reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS), CloseServiceHandleCompat);
    if (!scm.IsValid()) {
        const DWORD error = GetLastError();
        PrintLine(L"[失败] 打开服务控制管理器失败：%lu (%s)", error, FormatWin32Error(error).c_str());
        GD_LOG_ERROR(L"OpenSCManager 失败：%lu", error);
        return kInstallerOpenScmFailed;
    }

    // 已存在则拒绝安装：直接覆盖会丢掉用户调整过的启动类型/恢复策略，
    // 也可能把服务指向一个已被替换的旧 exe 路径。
    {
        ScopeHandle existing;
        existing.Reset(
            OpenServiceW(reinterpret_cast<SC_HANDLE>(scm.Get()), Constants::kServiceName,
                         SERVICE_ALL_ACCESS),
            CloseServiceHandleCompat);
        if (existing.IsValid()) {
            PrintLine(L"[失败] 服务已存在。如需重装，请先执行：GuardDogService.exe uninstall");
            GD_LOG_WARN(L"安装中止：服务 %s 已存在", Constants::kServiceName);
            return kInstallerExists;
        }
        const DWORD queryError = GetLastError();
        if (queryError != ERROR_SERVICE_DOES_NOT_EXIST) {
            PrintLine(L"[失败] 查询服务状态失败：%lu (%s)", queryError,
                      FormatWin32Error(queryError).c_str());
            GD_LOG_ERROR(L"OpenService 失败：%lu", queryError);
            return kInstallerOpenScmFailed;
        }
    }

    const std::wstring executablePath = GetExecutablePath();
    if (executablePath.empty()) {
        PrintLine(L"[失败] 无法获取自身可执行文件路径。");
        GD_LOG_ERROR(L"GetExecutablePath 失败：%lu", GetLastError());
        return kInstallerFailed;
    }

    // 路径加引号：Program Files 等含空格路径不加引号会被 SCM 截断
    const std::wstring binaryPath = L"\"" + executablePath + L"\"";

    ScopeHandle service;
    service.Reset(
        CreateServiceW(reinterpret_cast<SC_HANDLE>(scm.Get()), Constants::kServiceName,
                       Constants::kServiceDisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                       SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binaryPath.c_str(), nullptr, nullptr,
                       nullptr, nullptr, nullptr),
        CloseServiceHandleCompat);
    if (!service.IsValid()) {
        const DWORD error = GetLastError();
        PrintLine(L"[失败] 创建服务失败：%lu (%s)", error, FormatWin32Error(error).c_str());
        GD_LOG_ERROR(L"CreateService 失败：%lu", error);
        return kInstallerCreateFailed;
    }

    // 服务描述（sc description 的编程等价物）
    SERVICE_DESCRIPTIONW description{};
    description.lpDescription = const_cast<LPWSTR>(Constants::kServiceDescription);
    if (!ChangeServiceConfig2W(reinterpret_cast<SC_HANDLE>(service.Get()),
                               SERVICE_CONFIG_DESCRIPTION, &description)) {
        GD_LOG_WARN(L"设置服务描述失败：%lu", GetLastError());
    }

    // 恢复策略：等价于 sc failure GuardDogService reset= 0
    //          actions= restart/5000/restart/5000/restart/5000
    // reset= 0 在 API 侧对应 dwResetPeriod = INFINITE（失败计数永不重置）
    SC_ACTION actions[3] = {
        {SC_ACTION_RESTART, 5000},
        {SC_ACTION_RESTART, 5000},
        {SC_ACTION_RESTART, 5000},
    };
    SERVICE_FAILURE_ACTIONSW failureActions{};
    failureActions.dwResetPeriod = INFINITE;
    failureActions.lpRebootMsg   = nullptr;
    failureActions.lpCommand     = nullptr;
    failureActions.cActions      = static_cast<DWORD>(sizeof(actions) / sizeof(actions[0]));
    failureActions.lpsaActions   = actions;

    if (!ChangeServiceConfig2W(reinterpret_cast<SC_HANDLE>(service.Get()),
                               SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions)) {
        // 不致命：服务仍可手动启动，恢复策略可事后用 sc failure 补设
        const DWORD error = GetLastError();
        PrintLine(L"[警告] 设置服务恢复策略失败：%lu (%s)", error, FormatWin32Error(error).c_str());
        GD_LOG_WARN(L"设置恢复策略失败：%lu", error);
    } else {
        GD_LOG_INFO(L"已设置恢复策略：失败后 5 秒重启，最多重试 3 次");
    }

    PrintLine(L"[成功] 服务已注册：");
    PrintLine(L"        服务名  ：%s", Constants::kServiceName);
    PrintLine(L"        显示名  ：%s", Constants::kServiceDisplayName);
    PrintLine(L"        启动类型：自动");
    PrintLine(L"        运行账户：LocalSystem");
    PrintLine(L"        可执行  ：%s", executablePath.c_str());

    if (!StartServiceW(reinterpret_cast<SC_HANDLE>(service.Get()), 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            PrintLine(L"[信息] 服务已在运行。");
        } else {
            PrintLine(L"[警告] 服务已注册，但自动启动失败：%lu (%s)", error,
                      FormatWin32Error(error).c_str());
            PrintLine(L"        可稍后手动启动：sc start %s", Constants::kServiceName);
            GD_LOG_WARN(L"StartService 失败：%lu", error);
        }
        GD_LOG_INFO(L"服务安装完成（未自动启动）");
        return kInstallerOk;
    }

    if (WaitForServiceState(reinterpret_cast<SC_HANDLE>(service.Get()), SERVICE_RUNNING,
                            kStartWaitTimeoutMs)) {
        PrintLine(L"[成功] 服务已启动，当前状态 RUNNING。");
        GD_LOG_INFO(L"服务安装完成并已启动");
    } else {
        PrintLine(L"[警告] 已触发启动，但未在 %lu 秒内进入 RUNNING，请用 sc query 检查。",
                  kStartWaitTimeoutMs / 1000);
        GD_LOG_WARN(L"等待服务进入 RUNNING 超时");
    }
    return kInstallerOk;
}

int ServiceInstaller::Uninstall() {
    (void)Logger::Instance().Initialize();
    GD_LOG_INFO(L"开始卸载服务：%s", Constants::kServiceName);

    PrintLine(L"[GuardDog] 正在卸载服务 %s ...", Constants::kServiceName);

    if (!IsElevated()) {
        PrintLine(L"[失败] 需要管理员权限。请以管理员身份打开终端后重试。");
        GD_LOG_ERROR(L"卸载失败：当前进程无管理员权限");
        return kInstallerNotElevated;
    }

    ScopeHandle scm;
    scm.Reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS), CloseServiceHandleCompat);
    if (!scm.IsValid()) {
        const DWORD error = GetLastError();
        PrintLine(L"[失败] 打开服务控制管理器失败：%lu (%s)", error, FormatWin32Error(error).c_str());
        GD_LOG_ERROR(L"OpenSCManager 失败：%lu", error);
        return kInstallerOpenScmFailed;
    }

    ScopeHandle service;
    service.Reset(OpenServiceW(reinterpret_cast<SC_HANDLE>(scm.Get()), Constants::kServiceName,
                               SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE),
                  CloseServiceHandleCompat);
    if (!service.IsValid()) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            PrintLine(L"[信息] 服务未安装，无需卸载。");
            GD_LOG_INFO(L"服务未安装，跳过卸载");
            return kInstallerOk;
        }
        PrintLine(L"[失败] 打开服务失败：%lu (%s)", error, FormatWin32Error(error).c_str());
        GD_LOG_ERROR(L"OpenService 失败：%lu", error);
        return kInstallerOpenScmFailed;
    }

    // 必须先停再删：DeleteService 只打删除标记，不会终止服务进程，
    // 不先停止会留下"已标记删除但仍在运行"的幽灵服务。
    SERVICE_STATUS status{};
    if (QueryServiceStatus(reinterpret_cast<SC_HANDLE>(service.Get()), &status)) {
        if (status.dwCurrentState != SERVICE_STOPPED) {
            if (status.dwCurrentState != SERVICE_STOP_PENDING) {
                SERVICE_STATUS controlStatus{};
                if (!ControlService(reinterpret_cast<SC_HANDLE>(service.Get()), SERVICE_CONTROL_STOP,
                                    &controlStatus)) {
                    const DWORD error = GetLastError();
                    if (error != ERROR_SERVICE_NOT_ACTIVE) {
                        PrintLine(L"[警告] 停止服务请求失败：%lu (%s)", error,
                                  FormatWin32Error(error).c_str());
                        GD_LOG_WARN(L"ControlService(STOP) 失败：%lu", error);
                    }
                }
            }
            if (WaitForServiceState(reinterpret_cast<SC_HANDLE>(service.Get()), SERVICE_STOPPED,
                                    kStopWaitTimeoutMs)) {
                PrintLine(L"[信息] 服务已停止。");
                GD_LOG_INFO(L"服务已停止");
            } else {
                PrintLine(L"[警告] 等待服务停止超时，继续尝试删除。");
                GD_LOG_WARN(L"等待服务停止超时");
            }
        }
    }

    if (!DeleteService(reinterpret_cast<SC_HANDLE>(service.Get()))) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            PrintLine(L"[信息] 服务已处于待删除状态，最后一个句柄关闭后即消失。");
            GD_LOG_INFO(L"服务已标记删除");
            return kInstallerOk;
        }
        PrintLine(L"[失败] 删除服务失败：%lu (%s)", error, FormatWin32Error(error).c_str());
        GD_LOG_ERROR(L"DeleteService 失败：%lu", error);
        return kInstallerDeleteFailed;
    }

    PrintLine(L"[成功] 服务已卸载（配置与日志保留在 %s，如需彻底清理可手动删除该目录）。",
              Constants::kProgramDataDir);
    GD_LOG_INFO(L"服务卸载完成");
    return kInstallerOk;
}

} // namespace GuardDog