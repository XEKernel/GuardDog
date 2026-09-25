#include "AutoStart/AutoStartScanner.h"

#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/RegKey.h"

namespace GuardDog {
namespace Cleaners {

namespace {

constexpr wchar_t kIfeoKey[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
constexpr wchar_t kIfeoKeyWow64[] =
    L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

// 该子键下是否还有内容（用于判断删除 Debugger 后能否连子键一起删掉）
bool HasAnyContent(HKEY key) {
    DWORD valueCount = 0;
    DWORD subKeyCount = 0;
    DWORD maxNameLength = 0;
    DWORD maxDataLength = 0;
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subKeyCount, &maxNameLength,
                         nullptr, &valueCount, &maxNameLength, &maxDataLength, nullptr,
                         nullptr) != ERROR_SUCCESS) {
        return true;  // 查不到就保守认为还有内容
    }
    return valueCount > 0 || subKeyCount > 0;
}

CleanResult CleanIfeoRoot(HKEY root, const std::wstring& subKey, const Config& config, bool clean) {
    CleanResult result;

    RegKey ifeo;
    if (!ifeo.Open(root, subKey, KEY_READ | KEY_ENUMERATE_SUB_KEYS)) {
        return result;
    }

    DWORD index = 0;
    for (;;) {
        wchar_t applicationName[512] = {};
        DWORD nameLength = _countof(applicationName);
        if (RegEnumKeyExW(ifeo.Get(), index, applicationName, &nameLength, nullptr, nullptr, nullptr,
                          nullptr) != ERROR_SUCCESS) {
            break;
        }
        ++index;

        RegKey application;
        if (!application.Open(ifeo.Get(), applicationName,
                              KEY_READ | KEY_WRITE | KEY_ENUMERATE_SUB_KEYS)) {
            continue;
        }

        std::wstring debuggerPath;
        if (!ReadRegistryString(application.Get(), L"Debugger", debuggerPath) ||
            debuggerPath.empty()) {
            continue;
        }

        ++result.scanned;

        // IFEO 的 Debugger 值就是"当有人启动 X.exe 时改跑这个程序"，
        // 指向黑名单路径即为典型的映像劫持。
        if (!IsTargetCommand(config, debuggerPath)) {
            continue;
        }

        ++result.matched;
        ReportAutoStartHit(L"IFEO 映像劫持", subKey + L"\\" + applicationName + L"\\Debugger",
                           debuggerPath, clean);

        if (!clean) {
            continue;
        }

        if (RegDeleteValueW(application.Get(), L"Debugger") != ERROR_SUCCESS) {
            ++result.failed;
            GD_LOG_ERROR(L"删除 IFEO Debugger 值失败：%s（错误 %lu）", applicationName,
                         GetLastError());
            continue;
        }

        // 删除 Debugger 后如果该子键已无其他内容，连子键一起删掉；
        // 否则保留，避免破坏用户自己配置的调试器设置。
        if (!HasAnyContent(application.Get())) {
            application.Close();
            if (RegDeleteTreeW(ifeo.Get(), applicationName) == ERROR_SUCCESS) {
                GD_LOG_INFO(L"已删除空的 IFEO 子键：%s", applicationName);
            }
        }

        ++result.removed;
        GD_LOG_INFO(L"已清除 IFEO 劫持：%s", applicationName);
    }

    return result;
}

} // namespace

CleanResult CleanIfeo(const Config& config, const AutoStartTarget& /*target*/, bool clean) {
    CleanResult result;
    result.Accumulate(CleanIfeoRoot(HKEY_LOCAL_MACHINE, kIfeoKey, config, clean));
    result.Accumulate(CleanIfeoRoot(HKEY_LOCAL_MACHINE, kIfeoKeyWow64, config, clean));
    return result;
}

} // namespace Cleaners
} // namespace GuardDog