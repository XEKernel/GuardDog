#include "AutoStart/AutoStartScanner.h"

#include "Core/ConfigManager.h"
#include "Core/Constants.h"
#include "Core/Logger.h"
#include "Core/ProcessRunner.h"
#include "Core/RegKey.h"
#include "Core/ScopeHandle.h"

#include <mutex>
#include <set>

namespace GuardDog {
namespace Cleaners {

namespace {

constexpr DWORD kStopWaitMs = 6000;
constexpr DWORD kPollIntervalMs = 200;

// 本次运行中已经成功打上删除标记的服务。
//
// 为什么需要它：DeleteService 只是把服务标记为删除，注册表项要等所有句柄关闭
// （实践中往往要等系统重启）才真正消失。如果不记录，清除后的"复查"会把刚刚
// 处理好的服务当成残留报出来，误导用户去手工处理一个其实已经解决的目标。
std::mutex g_removedServicesMutex;
std::set<std::wstring> g_removedServices;

bool IsServiceAlreadyRemoved(const std::wstring& serviceName) {
    std::lock_guard<std::mutex> lock(g_removedServicesMutex);
    return g_removedServices.count(serviceName) > 0;
}

void MarkServiceRemoved(const std::wstring& serviceName) {
    std::lock_guard<std::mutex> lock(g_removedServicesMutex);
    g_removedServices.insert(serviceName);
}

void CloseServiceHandleCompat(HANDLE handle) {
    CloseServiceHandle(reinterpret_cast<SC_HANDLE>(handle));
}

bool WaitForStopped(SC_HANDLE service, DWORD timeoutMs) {
    const DWORD deadline = GetTickCount() + timeoutMs;
    for (;;) {
        SERVICE_STATUS status{};
        if (!QueryServiceStatus(service, &status)) {
            return false;
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            return true;
        }
        if (GetTickCount() >= deadline) {
            return false;
        }
        Sleep(kPollIntervalMs);
    }
}

// 卸载一个服务。顺序不能改：
//   清恢复策略 → 停止 → 禁用 → 删除
// 其中"先清恢复策略"是关键：带恢复策略的服务被停止后会被 SCM 自动拉起，
// 表现为"服务停不掉"，而且 DeleteService 也会因为它仍在运行而失败。
bool RemoveService(const std::wstring& serviceName) {
    // 自我保护：绝不能把 GuardDog 自己的服务当成目标删掉
    if (serviceName == Constants::kServiceName ||
        serviceName == Constants::kWatchdogServiceName) {
        GD_LOG_ERROR(L"拒绝删除 GuardDog 自身服务：%s", serviceName.c_str());
        return false;
    }

    ScopeHandle scm;
    scm.Reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS), CloseServiceHandleCompat);
    if (!scm.IsValid()) {
        GD_LOG_ERROR(L"打开服务控制管理器失败：错误 %lu", GetLastError());
        return false;
    }

    ScopeHandle service;
    service.Reset(OpenServiceW(reinterpret_cast<SC_HANDLE>(scm.Get()), serviceName.c_str(),
                               SERVICE_ALL_ACCESS),
                  CloseServiceHandleCompat);
    if (!service.IsValid()) {
        GD_LOG_ERROR(L"打开服务失败：%s（错误 %lu）", serviceName.c_str(), GetLastError());
        return false;
    }

    SC_HANDLE handle = reinterpret_cast<SC_HANDLE>(service.Get());

    // 第一步：清除恢复策略（等价于 sc failure <name> reset= 0 actions= ""）
    SERVICE_FAILURE_ACTIONSW failureActions{};
    failureActions.dwResetPeriod = INFINITE;
    failureActions.cActions = 0;
    failureActions.lpsaActions = nullptr;
    if (!ChangeServiceConfig2W(handle, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions)) {
        // 不致命：没有恢复策略的服务本来就会失败，继续走后面的步骤
        GD_LOG_WARN(L"清除服务恢复策略失败：%s（错误 %lu）", serviceName.c_str(), GetLastError());
    } else {
        GD_LOG_INFO(L"已清除服务恢复策略：%s", serviceName.c_str());
    }

    // 第二步：停止
    SERVICE_STATUS status{};
    if (QueryServiceStatus(handle, &status) && status.dwCurrentState != SERVICE_STOPPED) {
        if (status.dwCurrentState != SERVICE_STOP_PENDING) {
            if (!ControlService(handle, SERVICE_CONTROL_STOP, &status)) {
                const DWORD error = GetLastError();
                if (error != ERROR_SERVICE_NOT_ACTIVE) {
                    GD_LOG_WARN(L"停止服务失败：%s（错误 %lu）", serviceName.c_str(), error);
                }
            }
        }
        if (WaitForStopped(handle, kStopWaitMs)) {
            GD_LOG_INFO(L"服务已停止：%s", serviceName.c_str());
        } else {
            // 服务进程多半正被 GuardDog 挂起（处置流程的第一步就是挂起目标），
            // 因此它无法响应 SCM 的优雅停止请求。这里直接终止它的进程，
            // 否则 DeleteService 会因为"服务仍在运行"而反复失败。
            SERVICE_STATUS_PROCESS processStatus{};
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(handle, SC_STATUS_PROCESS_INFO,
                                     reinterpret_cast<LPBYTE>(&processStatus), sizeof(processStatus),
                                     &bytesNeeded) &&
                processStatus.dwProcessId != 0) {
                const DWORD processId = processStatus.dwProcessId;
                GD_LOG_WARN(L"等待服务停止超时，直接终止服务进程：%s（pid=%lu）", serviceName.c_str(),
                            processId);

                wchar_t command[128] = {};
                swprintf_s(command, L"taskkill.exe /F /PID %lu", processId);
                RunHiddenCommand(command);

                WaitForStopped(handle, 3000);
            } else {
                GD_LOG_WARN(L"等待服务停止超时且无法获取服务进程：%s", serviceName.c_str());
            }
        }
    }

    // 第三步：禁用（删除失败时，至少要保证它不再自启动）
    if (!ChangeServiceConfigW(handle, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                              nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
        GD_LOG_WARN(L"禁用服务失败：%s（错误 %lu）", serviceName.c_str(), GetLastError());
    } else {
        GD_LOG_INFO(L"服务已禁用：%s", serviceName.c_str());
    }

    // 第四步：删除
    if (DeleteService(handle)) {
        GD_LOG_INFO(L"服务已删除：%s", serviceName.c_str());
        MarkServiceRemoved(serviceName);

        // DeleteService 只是打删除标记，注册表项要等"所有句柄关闭"才消失。
        // 主动关闭我们自己持有的句柄并短暂等待，让随后的"清除后复查"拿到准确结论。
        service.Reset();
        scm.Reset();

        const std::wstring registryPath =
            L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
        bool gone = false;
        for (int attempt = 0; attempt < 15; ++attempt) {
            RegKey probe;
            if (!probe.Open(HKEY_LOCAL_MACHINE, registryPath, KEY_READ)) {
                gone = true;
                break;
            }
            Sleep(200);
        }

        if (!gone) {
            // 若服务正被其他组件（例如 SCM 在处理强制终止的进程）持有句柄，
            // 注册表项会保留到系统重启；此时它已处于"删除标记 + 禁用"状态，不会再自启动。
            GD_LOG_WARN(L"服务已标记删除但注册表项尚未消失，将在重启后彻底移除：%s",
                        serviceName.c_str());
        }
        return true;
    }

    const DWORD error = GetLastError();
    if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
        GD_LOG_INFO(L"服务已处于待删除状态：%s", serviceName.c_str());
        MarkServiceRemoved(serviceName);
        return true;
    }

    // 需求要求：删除失败时保留 disabled 状态即可
    GD_LOG_ERROR(L"删除服务失败：%s（错误 %lu），已保留为禁用状态", serviceName.c_str(), error);
    return false;
}

} // namespace

CleanResult CleanServices(const Config& config, const AutoStartTarget& /*target*/, bool clean) {
    CleanResult result;

    // SCM 句柄用于探测"服务是否已被标记删除"
    ScopeHandle scm;
    scm.Reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT), CloseServiceHandleCompat);

    RegKey services;
    if (!services.Open(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services",
                       KEY_READ | KEY_ENUMERATE_SUB_KEYS)) {
        GD_LOG_WARN(L"打开服务注册表根失败：错误 %lu", GetLastError());
        return result;
    }

    DWORD index = 0;
    for (;;) {
        wchar_t serviceName[512] = {};
        DWORD nameLength = _countof(serviceName);
        if (RegEnumKeyExW(services.Get(), index, serviceName, &nameLength, nullptr, nullptr, nullptr,
                          nullptr) != ERROR_SUCCESS) {
            break;
        }
        ++index;

        // 跳过本次运行中已经成功删除的服务（注册表项会滞后消失，见上面的说明）。
        // 同时用 DELETE 权限探测一次：若句柄申请删除权限时被拒且错误码是
        // ERROR_SERVICE_MARKED_FOR_DELETE，说明它此前已被标记删除。
        if (IsServiceAlreadyRemoved(serviceName)) {
            continue;
        }

        if (scm.IsValid()) {
            ScopeHandle probe;
            probe.Reset(OpenServiceW(reinterpret_cast<SC_HANDLE>(scm.Get()), serviceName, DELETE),
                        CloseServiceHandleCompat);
            if (!probe.IsValid() && GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE) {
                GD_LOG_DEBUG(L"服务 %s 已处于删除标记状态，跳过（重启后注册表项消失）", serviceName);
                continue;
            }
        }

        RegKey serviceKey;
        if (!serviceKey.Open(services.Get(), serviceName, KEY_READ)) {
            continue;
        }

        std::wstring imagePath;
        if (!ReadRegistryString(serviceKey.Get(), L"ImagePath", imagePath) || imagePath.empty()) {
            continue;
        }

        // 内核驱动等用 "\??\C:\..." 形式登记，去掉前缀才能与黑名单路径比较
        if (imagePath.rfind(L"\\??\\", 0) == 0) {
            imagePath.erase(0, 4);
        }

        ++result.scanned;

        if (!IsTargetCommand(config, imagePath)) {
            continue;
        }

        ++result.matched;
        ReportAutoStartHit(L"Windows 服务", serviceName, imagePath, clean);

        if (!clean) {
            continue;
        }

        if (RemoveService(serviceName)) {
            ++result.removed;
        } else {
            ++result.failed;
        }
    }

    return result;
}

} // namespace Cleaners
} // namespace GuardDog