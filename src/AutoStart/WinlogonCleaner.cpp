#include "AutoStart/AutoStartScanner.h"

#include "Core/ConfigManager.h"
#include "Core/Logger.h"
#include "Core/RegKey.h"

namespace GuardDog {
namespace Cleaners {

namespace {

constexpr wchar_t kWinlogonKey[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

// Winlogon 这三个值的正常形态。
// Userinit 末尾那个逗号不是笔误：系统会把它当作"命令分隔符"，
// 恢复时写少一个逗号会直接导致登录后不执行用户初始化脚本。
constexpr wchar_t kDefaultShell[] = L"explorer.exe";

std::wstring DefaultUserinit() {
    wchar_t systemRoot[MAX_PATH] = {};
    if (GetWindowsDirectoryW(systemRoot, _countof(systemRoot)) == 0) {
        return L"C:\\Windows\\system32\\userinit.exe,";
    }
    return std::wstring(systemRoot) + L"\\system32\\userinit.exe,";
}

// 判定某个 Winlogon 值是否被劫持：
// 只有当值里出现的可执行文件命中黑名单时才算——不能因为值和默认值不同就一律还原，
// 用户可能自己改过 Shell（例如换成第三方桌面）。
bool IsHijacked(const Config& config, const std::wstring& value) {
    if (value.empty()) {
        return false;
    }

    // Userinit 这类值可能是 "a.exe,b.exe," 形式，逐个片段判断
    size_t start = 0;
    while (start <= value.size()) {
        const size_t comma = value.find(L',', start);
        const std::wstring segment =
            value.substr(start, comma == std::wstring::npos ? std::wstring::npos : comma - start);
        if (!segment.empty() && IsTargetCommand(config, segment)) {
            return true;
        }
        if (comma == std::wstring::npos) {
            break;
        }
        start = comma + 1;
    }

    return false;
}

CleanResult RestoreOrCheck(const Config& config, RegKey& key, const wchar_t* valueName,
                           const std::wstring& defaultValue, bool removeInsteadOfRestore,
                           bool clean, CleanResult result) {
    std::wstring currentValue;
    if (!ReadRegistryString(key.Get(), valueName, currentValue)) {
        return result;
    }

    ++result.scanned;

    if (!IsHijacked(config, currentValue)) {
        return result;
    }

    ++result.matched;
    ReportAutoStartHit(L"Winlogon", std::wstring(kWinlogonKey) + L"\\" + valueName, currentValue,
                       clean);

    if (!clean) {
        return result;
    }

    if (removeInsteadOfRestore) {
        // Taskman 正常情况下根本不存在，被写进来本身就是劫持信号，直接删值
        if (RegDeleteValueW(key.Get(), valueName) == ERROR_SUCCESS) {
            ++result.removed;
            GD_LOG_INFO(L"已删除被劫持的 Winlogon 值：%s", valueName);
        } else {
            ++result.failed;
            GD_LOG_ERROR(L"删除 Winlogon 值失败：%s（错误 %lu）", valueName, GetLastError());
        }
        return result;
    }

    if (WriteRegistryString(key.Get(), valueName, defaultValue)) {
        ++result.removed;
        GD_LOG_INFO(L"已恢复 Winlogon 默认值：%s = %s", valueName, defaultValue.c_str());
    } else {
        ++result.failed;
        GD_LOG_ERROR(L"恢复 Winlogon 值失败：%s（错误 %lu）", valueName, GetLastError());
    }

    return result;
}

} // namespace

CleanResult CleanWinlogon(const Config& config, const AutoStartTarget& /*target*/, bool clean) {
    CleanResult result;

    RegKey key;
    if (!key.Open(HKEY_LOCAL_MACHINE, kWinlogonKey, KEY_READ | KEY_WRITE)) {
        GD_LOG_WARN(L"打开 Winlogon 注册表键失败：错误 %lu", GetLastError());
        return result;
    }

    result = RestoreOrCheck(config, key, L"Shell", kDefaultShell, false, clean, result);
    result = RestoreOrCheck(config, key, L"Userinit", DefaultUserinit(), false, clean, result);
    result = RestoreOrCheck(config, key, L"Taskman", std::wstring(), true, clean, result);

    return result;
}

} // namespace Cleaners
} // namespace GuardDog