#include "AutoStart/AutoStartScanner.h"

#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/RegKey.h"

#include <vector>

namespace GuardDog {
namespace Cleaners {

namespace {

struct RunLocation {
    HKEY root;
    const wchar_t* subKey;
    const wchar_t* displayName;
};

// 当前用户配置单元 + 机器级（含 WOW6432Node 的 32 位视图）
// 注意用 const 而不是 constexpr：HKEY 是宏转换出来的指针，
// 其值不满足常量表达式要求（C++ 不允许 reinterpret_cast 出现在常量表达式里）。
const RunLocation kMachineLocations[] = {
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
     L"HKLM\\...\\Run"},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
     L"HKLM\\...\\RunOnce"},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
     L"HKLM\\WOW6432Node\\...\\Run"},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
     L"HKLM\\WOW6432Node\\...\\RunOnce"},
};

constexpr wchar_t kUserRunSuffix[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kUserRunOnceSuffix[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";

// 系统账户的配置单元不需要清理：那里不会有用户态流氓软件的启动项，
// 而且误删可能影响系统服务的行为
bool IsSystemAccountHive(const std::wstring& sid) {
    return sid == L"S-1-5-18" ||  // LocalSystem
           sid == L"S-1-5-19" ||  // LocalService
           sid == L"S-1-5-20" ||  // NetworkService
           sid == L".DEFAULT";
}

// 清理单个 Run/RunOnce 键
CleanResult CleanOneKey(HKEY root, const std::wstring& subKey, const wchar_t* displayName,
                        const Config& config, bool clean) {
    CleanResult result;

    RegKey key;
    if (!key.Open(root, subKey, clean ? (KEY_READ | KEY_WRITE) : KEY_READ)) {
        return result;  // 键不存在属于正常情况
    }

    // 先收集要删除的值名，再统一删除：边枚举边删会让枚举索引错位
    std::vector<std::wstring> victims;

    DWORD index = 0;
    for (;;) {
        wchar_t valueName[1024] = {};
        DWORD nameLength = _countof(valueName);
        BYTE dataBuffer[4096] = {};
        DWORD dataSize = sizeof(dataBuffer);
        DWORD type = 0;

        const LONG status = RegEnumValueW(key.Get(), index, valueName, &nameLength, nullptr, &type,
                                          dataBuffer, &dataSize);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (status != ERROR_SUCCESS) {
            ++index;
            continue;
        }
        ++index;

        // 默认值（空名）不是自启动项
        if (nameLength == 0) {
            continue;
        }

        ++result.scanned;

        if (type != REG_SZ && type != REG_EXPAND_SZ) {
            continue;
        }

        const std::wstring command(reinterpret_cast<const wchar_t*>(dataBuffer));
        if (!IsTargetCommand(config, command)) {
            continue;
        }

        ++result.matched;
        // 命中上报：清理模式写 warn 并备份原始值（需求要求清除前必须留痕），扫描模式只写 debug
        ReportAutoStartHit(L"注册表自启动项", std::wstring(displayName) + L"\\" + valueName,
                           command, clean);

        if (clean) {
            victims.push_back(valueName);
        }
    }

    for (const std::wstring& name : victims) {
        if (RegDeleteValueW(key.Get(), name.c_str()) == ERROR_SUCCESS) {
            ++result.removed;
            GD_LOG_INFO(L"已删除自启动项：%s\\%s", displayName, name.c_str());
        } else {
            ++result.failed;
            GD_LOG_ERROR(L"删除自启动项失败：%s\\%s（错误 %lu）", displayName, name.c_str(),
                         GetLastError());
        }
    }

    return result;
}

// 遍历所有已加载的用户配置单元（HKEY_USERS\S-1-5-21-...）清理 Run/RunOnce。
// 为什么要这样做：服务运行在 LocalSystem 账户下，HKCU 指向的是 SYSTEM 自己的配置单元，
// 直接读 HKCU 根本看不到登录用户的启动项——这是很多同类工具漏项的地方。
CleanResult CleanUserHives(const Config& config, bool clean) {
    CleanResult result;

    RegKey users;
    if (!users.Open(HKEY_USERS, L"", KEY_READ | KEY_ENUMERATE_SUB_KEYS)) {
        return result;
    }

    DWORD index = 0;
    for (;;) {
        wchar_t sid[256] = {};
        DWORD sidLength = _countof(sid);
        const LONG status = RegEnumKeyExW(users.Get(), index, sid, &sidLength, nullptr, nullptr,
                                          nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        ++index;
        if (status != ERROR_SUCCESS) {
            continue;
        }

        const std::wstring sidString(sid);
        if (IsSystemAccountHive(sidString)) {
            continue;
        }

        result.Accumulate(CleanOneKey(HKEY_USERS, sidString + L"\\" + kUserRunSuffix,
                                      L"HKEY_USERS\\<用户>\\Run", config, clean));
        result.Accumulate(CleanOneKey(HKEY_USERS, sidString + L"\\" + kUserRunOnceSuffix,
                                      L"HKEY_USERS\\<用户>\\RunOnce", config, clean));
    }

    return result;
}

} // namespace

CleanResult CleanRegistryRun(const Config& config, const AutoStartTarget& /*target*/, bool clean) {
    CleanResult result;

    for (const RunLocation& location : kMachineLocations) {
        result.Accumulate(
            CleanOneKey(location.root, location.subKey, location.displayName, config, clean));
    }

    // 当前账户的 HKCU（前台调试模式下有意义）
    result.Accumulate(CleanOneKey(HKEY_CURRENT_USER, kUserRunSuffix, L"HKCU\\...\\Run", config,
                                 clean));
    result.Accumulate(CleanOneKey(HKEY_CURRENT_USER, kUserRunOnceSuffix, L"HKCU\\...\\RunOnce",
                                 config, clean));

    // 所有已登录用户的配置单元
    result.Accumulate(CleanUserHives(config, clean));

    return result;
}

} // namespace Cleaners
} // namespace GuardDog